use crossbeam::channel::Receiver;
use std::net::IpAddr;
use trust_dns_resolver::Resolver;

use crate::{
    packet::{icmp, ip},
    ping::Result,
};

pub struct Statistics {
    addr: IpAddr,
    resource_name: String,
}

pub struct PacketInfo {
    pub ip_packet: ip::IPV4Packet,
    pub packet: icmp::ICMPacket,
    pub received_bytes: usize,
    pub time: std::time::Duration,
}

impl Statistics {
    pub fn new(resource: String, addr: IpAddr) -> Self {
        Self {
            addr: addr,
            resource_name: resource,
        }
    }

    pub fn run(self, packet: Receiver<Result<PacketInfo>>) {
        let mut transmitted = 0;
        let mut received = 0;
        let time = std::time::Instant::now();
        println!("PING {} ({})", self.addr, self.resource_name);
        while let Ok(Ok(info)) = packet.recv() {
            let dns_name = reverse_address(IpAddr::from(info.ip_packet.source_ip))
                .map_or(String::from("gateway"), |n| n);

            let s = match info.packet.tp {
                tp if tp == icmp::PacketType::EchoReply as u8 => format!(
                    "icmp_seq={} ttl={} time={}",
                    info.packet.seq,
                    info.ip_packet.ttl,
                    display_duration(info.time)
                ),
                tp if tp == icmp::PacketType::TimeExceeded as u8 => {
                    format!("icmp_seq={} Time to live exceeded", info.packet.seq)
                }
                _ => String::from("Pss: Unimplemented :("),
            };

            if info.packet.tp == icmp::PacketType::EchoReply as u8 {
                received += 1;
            }

            println!(
                "{} bytes from {} ({}): {}",
                info.received_bytes, dns_name, info.ip_packet.source_ip, s
            );

            transmitted += 1;
        }

        let time = time.elapsed();

        println!();
        println!("------- {} statistics -------", self.resource_name);
        println!(
            "{} packets transmitted, received {}, time {}",
            transmitted,
            received,
            display_duration(time)
        );
    }
}

fn display_duration(d: std::time::Duration) -> String {
    format!("{} ms", d.as_millis())
}

fn reverse_address(addr: IpAddr) -> Option<String> {
    let resolver = Resolver::default().unwrap();
    let response = resolver.reverse_lookup(addr);
    if let Ok(response) = response {
        let addr = response.iter().next().unwrap();
        return Some(addr.to_string());
    }

    None
}
