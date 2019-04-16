use futures::prelude::*;
use futures::Stream;
use futures_locks::RwLock;
use log::{debug, error, info, warn};
use packet::ether::{self, Packet as EtherPacket};
use packet::ip;
use packet::udp::Packet as UdpPacket;
use packet::Packet as _;
use pcap::stream::PacketCodec;
use pcap::Packet;
use std::collections::{hash_map as hash, HashMap};
use std::convert::From;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::reactor::Handle;
use tokio::timer::Interval;

struct PayloadStream<T: AsRef<[u8]>>(std::marker::PhantomData<T>);

impl<T: AsRef<[u8]>> PayloadStream<T> {
  fn new() -> PayloadStream<T> {
    PayloadStream(std::marker::PhantomData)
  }
}

impl PacketCodec for PayloadStream<Vec<u8>> {
  type Type = EtherPacket<Vec<u8>>;

  fn decode(&mut self, packet: Packet) -> Result<Self::Type, pcap::Error> {
    let owned = Box::new(packet.data.to_vec());
    let e = EtherPacket::new(*owned).unwrap();
    Ok(e)
  }
}

#[derive(Debug)]
struct TaggedMetric {
  source: SocketAddr,
  metric: statsd_parser::Message,
  seen: std::time::SystemTime,
}

impl TaggedMetric {
  fn from_frame<T: AsRef<[u8]>>(p: EtherPacket<T>) -> Result<Vec<Self>, packet::Error> {
    let (host, ip_data) = match p.protocol() {
      ether::Protocol::Ipv4 => {
        let ip_packet = ip::v4::Packet::new(p.payload())?;
        Ok((ip_packet.source(), ip_packet.to_owned()))
      }
      x => Err(packet::Error::from(format!("Invalid protocol {:?}", x))),
    }?;
    let udp_packet = UdpPacket::new(ip_data.split().1)
      .map_err(|e| packet::Error::from(format!("UDP packet decode error! {:?}", e)))?;
    let source = SocketAddrV4::new(host, udp_packet.source());
    let (_header, data) = udp_packet.split();
    let str_data = String::from_utf8(data.to_vec())
      .map_err(|e| packet::Error::from(format!("UTF-8 decode error! {:?}", e)))?;
    let metrics = str_data
      .lines()
      .map(|line| {
        let metric = statsd_parser::parse(line.trim());
        match metric {
          Err(e) => {
            error!("Line decode error! {:?}", e);
            None
          }
          Ok(metric) => Some(TaggedMetric {
            source: SocketAddr::from(source),
            metric,
            seen: std::time::SystemTime::now(),
          }),
        }
      })
      .flat_map(|x| x);
    Ok(metrics.collect())
  }
}

fn main() -> io::Result<()> {
  simple_logger::init_with_level(log::Level::Debug).unwrap();
  info!("starting");
  let capture = pcap::Capture::from_device("lo").unwrap();
  let mut capture = capture
    .open()
    .expect("Cap open failed")
    .setnonblock()
    .expect("cant set nonblocking");
  capture
    .filter("port 8125 and udp")
    .expect("Filter incorrect");

  let seen_metrics: RwLock<HashMap<SocketAddr, TaggedMetric>> = RwLock::new(HashMap::new());
  let stream = capture
    .stream(&Handle::default(), PayloadStream::new())
    .unwrap()
    .map_err(|e| error!("[SNIFF] Got error {}", e))
    .map(|p| TaggedMetric::from_frame(p));

  let gc_secs = 5;
  let ttl = 30;

  let to_clean = seen_metrics.clone();

  let garbage = Interval::new_interval(Duration::from_secs(gc_secs))
    .map_err(|e| error!("Garbage collector timer error! {:?}", e))
    .for_each({
      let gc_secs = gc_secs.clone();
      let to_clean = to_clean.clone();
      move |_| {
        info!("[GC] {} seconds have passed, tidying up", gc_secs);
        to_clean
          .write()
          .map(move |mut seen_metrics| {
            seen_metrics.retain(|_k, v: &mut TaggedMetric| match v.seen.elapsed() {
              Ok(delta) => {
                let expired = delta.as_secs() > ttl;
                if expired {
                  debug!("Haven't heard from {}:{:?} in too long, purging", v.source, v.metric)
                }
                return !expired;
              },
              Err(e) => {
                error!("[GC] system time error! {}", e);
                true
              }
            });
          })
          .map_err(|e| error!("[GC] write lock error {:?}", e))
      }
    })
    .map(|_| ())
    .map_err(|e| error!("[GC] overall error {:?}", e));

  let dumper = Interval::new_interval(Duration::from_secs(5))
    .map_err(|e| error!("[DUMP] Timer error {:?}", e))
    .for_each({
      let seen_metrics = seen_metrics.clone();
      move |_| {
        info!("[DUMP] Starting dump of seen metrics");
        seen_metrics.read().map(move |seen_metrics| {
          println!("[DUMP] {:#?}", *seen_metrics);
        })
      }
    });

  let (metric_tx, metric_rx) = tokio::sync::mpsc::channel(100);
  let unpacker = stream
    .filter(|x| x.is_ok())
    .map(|u| u.unwrap())
    .for_each(move |u| {
      let metric_tx = metric_tx.clone();
      metric_tx
        .send_all(futures::stream::iter_ok(u))
        .into_future()
        .map(|_| ())
        .map_err(|e| error!("[UNPACK] Sink error {:?}", e))
    });

  let seen_metrics = seen_metrics.clone();
  let map_handler = metric_rx
    .map_err(|e| error!("[SCRIBE] Recv error {:?}", e))
    .for_each(move |metric| {
      seen_metrics.write().map(|mut seen_metrics| {
        println!("[SCRIBE] Saving entry {:?}", &metric);
        match seen_metrics.entry(metric.source) {
          hash::Entry::Occupied(mut e) => {
            e.insert(metric);
          }
          hash::Entry::Vacant(e) => {
            e.insert(metric);
          }
        }
      })
      .into_future()
      .map(|_| ())
      .map_err(|_| ())
    });

  let dumper = dumper.into_future().map(|_| ()).map_err(|_| ());
  let garbage = garbage.into_future().map(|_| ()).map_err(|_| ());
  let map_handler = map_handler.into_future().map(|_| ()).map_err(|_| ());

  let fut = unpacker.join(garbage);
  let fut = fut.join(map_handler);
  let fut = fut.join(dumper);

  Ok(tokio::run(fut.map(|_| ())))
}
