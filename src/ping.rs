use crate::{
    packet::{
        icmp::{self, IcmpBuilder, IcmpPacket},
        ip::IPV4Packet,
        Builder, Packet, PacketError,
    },
    stats::PacketInfo,
};
use crossbeam::channel::Sender;
use socket2::{SockAddr, Socket};
use std::io;
use std::net;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{self, Duration};

pub const DATA_SIZE: usize = 32;

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

pub struct Settings {
    pub addr: net::IpAddr,
    pub ttl: Option<u32>,
    pub read_timeout: Option<u32>,
    pub packets_limit: Option<usize>,
    pub send_interval: Option<Duration>,
}

impl Settings {
    pub fn build(self) -> Ping {
        let sock = open_socket(&self.addr);
        sock.set_read_timeout(Some(
            self.read_timeout
                .map_or(Duration::from_secs(10), |s| Duration::from_secs(s as u64)),
        ))
        .unwrap();

        if let Some(ttl) = self.ttl {
            sock.set_ttl(ttl).unwrap();
        }

        let send_interval = self.send_interval.map_or(Duration::from_secs(1), |i| i);
        let sock_addr = socket_address(self.addr);

        Ping {
            addr: sock_addr,
            sock: sock,
            send_interval: send_interval,
            packets_limit: self.packets_limit,
        }
    }
}

pub struct Ping {
    addr: SockAddr,
    sock: Socket,
    send_interval: Duration,
    packets_limit: Option<usize>,
}

impl Ping {
    pub fn ping_loop(self, stats: Sender<Result<PacketInfo>>, terminated: Arc<AtomicBool>) {
        let payload = uniq_payload();
        let mut req = icmp::EchoRequest::new(uniq_ident(), 0).with_payload(&payload);

        let mut packets_limit = self.packets_limit;
        let mut buf = vec![0; 300];
        while terminated.load(Ordering::SeqCst) {
            req.seq += 1;
            let size = req.build(&mut buf).unwrap();

            self.send_to(&buf[..size]).unwrap();
            let info = self.recv(&req, &mut buf);

            stats.send(Ok(info)).unwrap();

            if let Some(ref mut limit) = packets_limit {
                *limit -= 1;
                if *limit == 0 {
                    break;
                }
            }

            thread::sleep(self.send_interval);
        }
    }

    fn recv(&self, req: &IcmpBuilder, mut buf: &mut [u8]) -> PacketInfo {
        let now = time::Instant::now();
        loop {
            let received_bytes = self.sock.recv(&mut buf).unwrap();
            let time = now.elapsed();
            let ip = IPV4Packet::parse(&buf[..received_bytes]).unwrap();
            let repl = IcmpPacket::parse(&ip.payload()).unwrap();
            if own_packet(&req, &repl) {
                break PacketInfo {
                    ip_source_ip: std::net::IpAddr::from(ip.source_ip()),
                    ip_ttl: ip.ttl(),
                    icmp_seq: repl.seq(),
                    icmp_type: repl.tp(),
                    received_bytes: received_bytes,
                    time: time,
                };
            }
        }
    }

    fn send_to(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.sock.send_to(buf, &self.addr)
    }
}

fn own_packet(req: &IcmpBuilder, repl: &IcmpPacket) -> bool {
    match repl.tp() {
        tp if tp == icmp::PacketType::EchoReply as u8 => req.payload.unwrap() == repl.payload(),
        tp if tp == icmp::PacketType::TimeExceeded as u8 => {
            let ip = IPV4Packet::parse(repl.payload()).unwrap();
            let icmp = IcmpPacket::parse(&ip.payload()).unwrap();

            // even though we might have to verify payload according to rhe rfc-792,
            // there are gateways that not include the payload in internal icmp header
            // so there's only one option to verify
            // identificator which is required by rfc-1812 and rfc-792 as well.
            //
            // rfc792  page 8
            // rfc1812 section 4.3.2.3
            icmp.ident() == req.ident
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
