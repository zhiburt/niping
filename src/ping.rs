use crate::{
    packet::{icmp, ip, Packet, PacketError},
    stats::PacketInfo,
};
use crossbeam::channel::Sender;
use std::io;
use std::net;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct Settings {
    pub addr: net::IpAddr,
    pub ttl: Option<u32>,
    pub read_timeout: Option<u32>,
    pub packets_limit: Option<usize>,
}

pub type Result<T> = std::result::Result<T, PingError>;

#[derive(Debug)]
pub enum PingError {
    PacketError(PacketError),
    IO(io::Error),
}

impl From<io::Error> for PingError {
    fn from(e: io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<PacketError> for PingError {
    fn from(e: PacketError) -> Self {
        Self::PacketError(e)
    }
}

pub fn ping_loop(cfg: Settings, stats: Sender<Result<PacketInfo>>, terminated: Arc<AtomicBool>) {
    let sock = open_socket(&cfg.addr);
    let sock_addr = socket_address(cfg.addr);
    sock.set_read_timeout(Some(
        cfg.read_timeout
            .map_or(std::time::Duration::from_secs(10), |seconds| {
                std::time::Duration::from_secs(seconds as u64)
            }),
    ))
    .unwrap();
    if let Some(ttl) = cfg.ttl {
        sock.set_ttl(ttl).unwrap();
    }

    let mut req = icmp::EchoRequest::new(10, 0);
    let payload = uniq_payload();
    req.add_payload(&payload);
    let header_size = req.hint_size().unwrap();

    let mut packets_limit = cfg.packets_limit;

    let mut buf = vec![0; 300];
    while terminated.load(Ordering::SeqCst) && {
        match packets_limit {
            Some(ref limit) if *limit == 0 => false,
            Some(ref mut limit) => {
                *limit -= 1;
                true
            }
            _ => true,
        }
    } {
        req.seq += 1;
        req.build(&mut buf[..header_size]).unwrap();

        sock.send_to(&buf[..header_size], &sock_addr).unwrap();
        let now = std::time::Instant::now();
        let received_bytes = sock.recv(&mut buf).unwrap();
        let time = now.elapsed();
        let ip = ip::IPV4Packet::parse(&buf[..received_bytes]).unwrap();
        let icmp = icmp::ICMPacket::parse(&ip.data).unwrap();

        let info = PacketInfo {
            ip_packet: ip,
            packet: icmp,
            received_bytes: received_bytes,
            time: time,
        };
        stats.send(Ok(info)).unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn open_socket(addr: &net::IpAddr) -> socket2::Socket {
    socket2::Socket::new(
        socket2::Domain::ipv4(),
        socket2::Type::raw(),
        Some(socket2::Protocol::icmpv4()),
    )
    .unwrap()
}

fn socket_address(addr: net::IpAddr) -> socket2::SockAddr {
    socket2::SockAddr::from(net::SocketAddr::new(addr, 0))
}

fn uniq_payload() -> Vec<u8> {
    const SIZE: usize = 48;
    let mut p = Vec::new();
    for _ in 0..SIZE {
        p.push(rand::random())
    }
    p
}
