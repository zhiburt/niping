use crossbeam::channel::Receiver;
use std::net::IpAddr;
use std::time::{self, Duration};
use trust_dns_resolver::Resolver;

use crate::{
    packet::{icmp, ip},
    ping::{Result, DATA_SIZE},
};

pub struct Statistics {
    addr: IpAddr,
    resource_name: String,
    data_size: usize,
}

pub struct PacketInfo {
    pub ip_packet: ip::IPV4Packet,
    pub packet: icmp::ICMPacket,
    pub received_bytes: usize,
    pub time: Duration,
}

impl Statistics {
    pub fn new(resource: String, addr: IpAddr) -> Self {
        Self {
            addr: addr,
            resource_name: resource,
            data_size: DATA_SIZE,
        }
    }

    pub fn run(self, packet: Receiver<Result<PacketInfo>>) {
        let mut transmitted = 0;
        let mut received = 0;
        let mut rtt = Vec::new();
        let time = time::Instant::now();

        println!(
            "PING {} ({}) {} bytes of data",
            self.addr, self.resource_name, self.data_size
        );

        while let Ok(Ok(info)) = packet.recv() {
            transmitted += 1;
            rtt.push(info.time);
            if info.packet.tp == icmp::PacketType::EchoReply as u8 {
                received += 1;
            }

            println!("{}", display_packet(info));
        }

        let time = time.elapsed();

        let rtt_min = rtt.iter().min().unwrap();
        let rtt_max = rtt.iter().max().unwrap();
        let rtt_len = rtt.len();
        let rtt_avg = rtt.iter().sum::<Duration>() / rtt_len as u32;

        println!();
        println!("------- {} statistics -------", self.resource_name);
        println!(
            "{} packets transmitted, received {}, time {}",
            transmitted,
            received,
            display_duration(time)
        );
        println!(
            "rtt min/max/avg = {}/{}/{}",
            display_duration(*rtt_min),
            display_duration(*rtt_max),
            display_duration(rtt_avg),
        );
    }
}

fn display_packet(info: PacketInfo) -> String {
    let specific_info = packet_info(&info);
    let dns_name = reverse_address(IpAddr::from(info.ip_packet.source_ip))
        .map_or(String::from("gateway"), |n| n);

    format!(
        "{} bytes from {} ({}): {}",
        info.received_bytes, dns_name, info.ip_packet.source_ip, specific_info
    )
}

fn packet_info(info: &PacketInfo) -> String {
    match info.packet.tp {
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
    }
}

fn display_duration(d: Duration) -> String {
    format!("{:.2?}", d)
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
