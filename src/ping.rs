use crate::packet::{
    icmp::{self, IcmpBuilder, IcmpPacket, PacketType},
    ip::IPV4Packet,
    Builder, Packet, PacketError,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net;
use std::time::{self, Duration};

pub const DATA_SIZE: usize = 32;

pub type Result<T> = std::result::Result<T, PingError>;

#[derive(Debug)]
pub enum PingError {
    PacketError(PacketError),
    Send(io::Error),
    Recv(io::Error),
}

impl From<PacketError> for PingError {
    fn from(e: PacketError) -> Self {
        Self::PacketError(e)
    }
}

pub struct PacketInfo {
    pub ip_source_ip: net::IpAddr,
    pub ip_ttl: u8,
    pub icmp_seq: u16,
    pub icmp_type: u8,
    pub received_bytes: usize,
    pub time: Duration,
}

pub struct Settings {
    pub addr: net::IpAddr,
    pub ttl: Option<u32>,
    pub read_timeout: Duration,
}

impl Settings {
    pub fn build(self) -> Ping {
        let sock = Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap();
        sock.set_nonblocking(true).unwrap();
        sock.set_read_timeout(Some(self.read_timeout)).unwrap();
        if let Some(ttl) = self.ttl {
            sock.set_ttl(ttl).unwrap();
        }
        let sock = smol::Async::new(sock).unwrap();

        let payload = uniq_payload();
        let req = icmp::EchoRequest::new(uniq_ident(), 0).with_payload(&payload);

        let addr = std::net::SocketAddr::new(self.addr, 0);
        Ping { addr, sock, req }
    }
}

pub struct Ping {
    addr: net::SocketAddr,
    sock: smol::Async<Socket>,
    req: IcmpBuilder,
}

impl Ping {
    pub async fn run(&mut self) -> Result<PacketInfo> {
        let mut buf = vec![0; 300];
        self.req.seq += 1;

        self.ping(&mut buf).await
    }

    async fn ping(&mut self, mut buf: &mut [u8]) -> Result<PacketInfo> {
        let size = self.req.build(&mut buf).unwrap();
        self.sock
            .write_with(|sock| sock.send_to(&buf[..size], &self.addr.into()))
            .await
            .map_err(|err| PingError::Send(err))?;

        let now = time::Instant::now();
        loop {
            let received_bytes = self
                .sock
                .read_with_mut(|sock| sock.recv(&mut buf))
                .await
                .map_err(|err| PingError::Recv(err))?;

            let time = now.elapsed();
            let ip = IPV4Packet::parse(&buf[..received_bytes]).unwrap();
            let repl = IcmpPacket::parse(ip.payload().unwrap()).unwrap();
            if own_packet(&self.req, &repl) {
                break Ok(PacketInfo {
                    ip_source_ip: std::net::IpAddr::from(ip.source_ip()),
                    ip_ttl: ip.ttl(),
                    icmp_seq: repl.seq(),
                    icmp_type: repl.tp(),
                    received_bytes: received_bytes,
                    time: time,
                });
            }
        }
    }
}

fn own_packet(req: &IcmpBuilder, repl: &IcmpPacket) -> bool {
    match PacketType::new(repl.tp()) {
        Some(PacketType::EchoReply) => req.payload.as_ref().unwrap().as_slice() == repl.payload(),
        Some(PacketType::TimeExceeded) => {
            let ip = IPV4Packet::parse(repl.payload()).unwrap();
            let icmp = IcmpPacket::parse(ip.payload().unwrap()).unwrap();

            // even though we might have to verify payload according to rhe rfc-792,
            // there are gateways that not include the payload in internal icmp header
            // so there's only one option to verify
            // identificator which is required by rfc-1812 and rfc-792 as well.
            //
            // rfc792  page 8
            // rfc1812 section 4.3.2.3
            icmp.ident() == req.ident
        }
        Some(PacketType::EchoRequest)
            if req.payload.as_ref().unwrap().as_slice() == repl.payload()
                && req.ident == repl.ident() =>
        {
            // req == replay
            // most likely we ping localhost so we should skip our own request
            false
        }
        _ => true, // unimplemented
    }
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
