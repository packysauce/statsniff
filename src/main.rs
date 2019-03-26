use futures::{IntoFuture, Stream};
use log::{debug, error, info, warn};
use packet::ether::{self, Packet as EtherPacket};
use packet::ip;
use packet::udp::Packet as UdpPacket;
use packet::Packet as _;
use pcap::stream::{PacketCodec};
use pcap::Packet;
use std::collections::HashMap;
use std::convert::From;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use tokio::reactor::Handle;

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
    fn from_frame<T: AsRef<[u8]>>(p: EtherPacket<T>) -> Result<Self, packet::Error> {
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
        let metric = statsd_parser::parse(str_data.trim())
            .map_err(|e| packet::Error::from(format!("Message decode error! {:?}", e)))?;
        Ok(TaggedMetric {
            source: SocketAddr::from(source),
            metric,
            seen: std::time::SystemTime::now(),
        })
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
        .filter("port 1234 and udp")
        .expect("Filter incorrect");

    let mut seen_metrics: HashMap<SocketAddr, String> = HashMap::new();
    let stream = capture
        .stream(&Handle::default(), PayloadStream::new())
        .unwrap()
        .map_err(|_| ())
        .map(|p| TaggedMetric::from_frame(p));

    let fut = stream.map_err(|_| ()).for_each(move |u| {
        if u.is_err() {
            warn!("Bad packet");
            return Ok(())
        }
        let u = u.unwrap();
        seen_metrics.entry(u.source).or_insert(format!("{:?}", u));
        Ok(println!("{:#?}", seen_metrics))
    });

    Ok(tokio::run(fut.into_future()))
}
