use crate::{
    packet::{
        icmp::{self, ICMPacket},
        ip::IPV4Packet,
        Packet, PacketError,
    },
    stats::PacketInfo,
};
use crossbeam::channel::Sender;
use std::io;
use std::net;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{self, Duration};

pub const DATA_SIZE: usize = 32;

pub struct Settings {
    pub addr: net::IpAddr,
    pub ttl: Option<u32>,
    pub read_timeout: Option<u32>,
    pub packets_limit: Option<usize>,
    pub send_interval: Option<Duration>,
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
            .map_or(Duration::from_secs(10), |s| Duration::from_secs(s as u64)),
    ))
    .unwrap();
    if let Some(ttl) = cfg.ttl {
        sock.set_ttl(ttl).unwrap();
    }

    let mut req = icmp::EchoRequest::new(uniq_ident(), 0);
    let payload = uniq_payload();
    req.add_payload(&payload);
    let header_size = req.hint_size().unwrap();

    let mut packets_limit = cfg.packets_limit;

    let send_interval = cfg.send_interval.map_or(Duration::from_secs(1), |i| i);

    let mut buf = vec![0; 300];
    while terminated.load(Ordering::SeqCst) {
        req.seq += 1;
        req.build(&mut buf[..header_size]).unwrap();

        sock.send_to(&buf[..header_size], &sock_addr).unwrap();
        let now = time::Instant::now();
        let info = loop {
            let received_bytes = sock.recv(&mut buf).unwrap();
            let time = now.elapsed();
            let ip = IPV4Packet::parse(&buf[..received_bytes]).unwrap();
            let repl = ICMPacket::parse_verified(&ip.data).unwrap();
            if own_packet(&req, &repl) {
                break PacketInfo {
                    ip_packet: ip,
                    packet: repl,
                    received_bytes: received_bytes,
                    time: time,
                };
            }
        };

        stats.send(Ok(info)).unwrap();

        if let Some(ref mut limit) = packets_limit {
            *limit -= 1;
            if *limit == 0 {
                break;
            }
        }

        thread::sleep(send_interval);
    }
}

fn own_packet(req: &ICMPacket, repl: &ICMPacket) -> bool {
    match repl.tp {
        tp if tp == icmp::PacketType::EchoReply as u8 => req.payload == repl.payload,
        tp if tp == icmp::PacketType::TimeExceeded as u8 => {
            let ip = IPV4Packet::parse(repl.payload.as_ref().unwrap()).unwrap();
            let icmp = icmp::ICMPacket::parse(&ip.data).unwrap();

            // even though we might have to verify payload according to rhe rfc-792,
            // there are gateways that not include the payload in internal icmp header
            // so there's only one option to verify
            // identificator which is required by rfc-1812 and rfc-792 as well.
            //
            // rfc792  page 8
            // rfc1812 section 4.3.2.3
            icmp.ident == req.ident
        }
        _ => true, // unimplemented
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
    let mut p = Vec::new();
    for _ in 0..DATA_SIZE {
        p.push(rand::random())
    }
    p
}

fn uniq_ident() -> u16 {
    rand::random()
}
