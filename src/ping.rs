use crate::{
    packet::{
        icmp::{self, IcmpBuilder, IcmpPacket, PacketType},
        ip::IPV4Packet,
        Builder, Packet, PacketError,
    },
    socket::{Socket, Socket2},
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

pub struct Settings {
    pub addr: net::IpAddr,
    pub ttl: Option<u32>,
    pub read_timeout: Option<u32>,
    pub packets_limit: Option<usize>,
    pub send_interval: Option<Duration>,
}

impl Settings {
    pub fn build(self) -> Ping<Socket2> {
        let mut sock = Socket2::icmp();
        sock.as_mut()
            .set_read_timeout(Some(
                self.read_timeout
                    .map_or(Duration::from_secs(10), |s| Duration::from_secs(s as u64)),
            ))
            .unwrap();

        if let Some(ttl) = self.ttl {
            sock.as_mut().set_ttl(ttl).unwrap();
        }

        let send_interval = self.send_interval.map_or(Duration::from_secs(1), |i| i);

        Ping {
            addr: std::net::SocketAddr::new(self.addr, 0),
            sock: sock,
            send_interval: send_interval,
            packets_limit: self.packets_limit,
        }
    }
}

pub struct Ping<S: Socket> {
    addr: std::net::SocketAddr,
    sock: S,
    send_interval: Duration,
    packets_limit: Option<usize>,
}

impl<S: Socket> Ping<S> {
    pub fn ping_loop(self, stats: Sender<Result<PacketInfo>>, terminated: Arc<AtomicBool>) {
        let payload = uniq_payload();
        let mut req = icmp::EchoRequest::new(uniq_ident(), 0).with_payload(&payload);

        let mut packets_limit = self.packets_limit;
        let mut buf = vec![0; 300];
        while terminated.load(Ordering::SeqCst) {
            req.seq += 1;

            let info = self.ping(&mut buf, &req);
            stats.send(info).unwrap();

            if let Some(ref mut limit) = packets_limit {
                *limit -= 1;
                if *limit == 0 {
                    break;
                }
            }

            thread::sleep(self.send_interval);
        }
    }

    fn ping(&self, mut buf: &mut [u8], req: &IcmpBuilder) -> Result<PacketInfo> {
        let size = req.build(&mut buf).unwrap();
        self.send_to(&buf[..size])
            .map_err(|err| PingError::Send(err))?;
        self.recv(&req, &mut buf)
    }

    fn recv(&self, req: &IcmpBuilder, mut buf: &mut [u8]) -> Result<PacketInfo> {
        let now = time::Instant::now();
        loop {
            let received_bytes = self
                .sock
                .recv(&mut buf)
                .map_err(|err| PingError::Recv(err))?;
            let time = now.elapsed();
            let ip = IPV4Packet::parse(&buf[..received_bytes]).unwrap();
            let repl = IcmpPacket::parse(ip.payload().unwrap()).unwrap();
            if own_packet(&req, &repl) {
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

    fn send_to(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.sock.send_to(buf, &self.addr)
    }
}

fn own_packet(req: &IcmpBuilder, repl: &IcmpPacket) -> bool {
    match PacketType::new(repl.tp()) {
        Some(PacketType::EchoReply) => req.payload.unwrap() == repl.payload(),
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
            if req.payload == Some(repl.payload()) && req.ident == repl.ident() =>
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::ip::{IPV4Builder, Protocol};
    use crossbeam::channel::unbounded;
    use std::{cell::RefCell, collections::HashMap, io, net};

    #[test]
    fn ping() {
        let ping = default_ping();
        let packet_limit = 10;
        let info = sandbox(ping, packet_limit);

        assert_eq!(info.len(), packet_limit);
        assert!(info.iter().all(|p| p.is_ok()))
    }

    #[test]
    fn ping_limited() {
        let packets_count = 5;
        let mut ping = default_ping();
        ping.packets_limit = Some(packets_count);
        let packet_limit = 10;
        let info = sandbox(ping, packet_limit);

        assert_eq!(info.len(), packets_count);
        assert!(info.iter().all(|p| p.is_ok()))
    }

    #[test]
    fn ping_send_error() {
        let mut ping = default_ping();
        ping.sock
            .raise_send_error(1, io::Error::from(io::ErrorKind::Other));
        let packet_limit = 10;
        let info = sandbox(ping, packet_limit);

        assert_eq!(info.len(), packet_limit);
        assert!(
            matches!(&info[1], Err(PingError::Send(err)) if err.kind() == io::ErrorKind::Other)
        );
    }

    #[test]
    fn ping_recv_error() {
        let mut ping = default_ping();
        ping.sock
            .raise_recv_error(1, io::Error::from(io::ErrorKind::Other));
        let packet_limit = 10;
        let info = sandbox(ping, packet_limit);

        assert_eq!(info.len(), packet_limit);
        assert!(
            matches!(&info[1], Err(PingError::Recv(err)) if err.kind() == io::ErrorKind::Other)
        );
    }

    fn sandbox<S: Socket + Send + 'static>(ping: Ping<S>, limit: usize) -> Vec<Result<PacketInfo>> {
        let (sender, recv) = unbounded();
        let term = Arc::new(AtomicBool::new(true));
        let ping_term = term.clone();
        let pinger = thread::spawn(move || ping.ping_loop(sender, ping_term));

        let mut limit = limit;
        let mut packets = Vec::new();
        while let Ok(info) = recv.recv() {
            packets.push(info);

            if limit != 1 {
                limit -= 1;
            } else {
                term.store(false, Ordering::Relaxed);
                break;
            }
        }

        pinger.join().unwrap();

        packets
    }

    fn default_ping() -> Ping<TestSocket> {
        Ping {
            addr: net::SocketAddr::new(net::IpAddr::V4(net::Ipv4Addr::UNSPECIFIED), 0),
            packets_limit: None,
            send_interval: Duration::from_secs(0),
            sock: TestSocket::new(),
        }
    }

    struct TestSocket {
        send: RefCell<usize>,
        received: RefCell<usize>,
        send_errors: RefCell<HashMap<usize, io::Error>>,
        recv_errors: RefCell<HashMap<usize, io::Error>>,
        last_sent_ident: RefCell<u16>,
        last_sent_playground: RefCell<Vec<u8>>,
    }

    impl Socket for TestSocket {
        fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            if self
                .recv_errors
                .borrow()
                .contains_key(&self.received.borrow())
            {
                return Err(self
                    .recv_errors
                    .borrow_mut()
                    .remove(&self.received.borrow())
                    .unwrap());
            }

            *self.received.borrow_mut() += 1;

            let size = self.emulate_recv(buf);
            Ok(size)
        }

        fn send_to(&self, buf: &[u8], addr: &net::SocketAddr) -> io::Result<usize> {
            if self.send_errors.borrow().contains_key(&self.send.borrow()) {
                return Err(self
                    .send_errors
                    .borrow_mut()
                    .remove(&self.send.borrow())
                    .unwrap());
            }

            *self.send.borrow_mut() += 1;

            let icmp = IcmpPacket::parse(buf).unwrap();

            *self.last_sent_ident.borrow_mut() = icmp.ident();
            *self.last_sent_playground.borrow_mut() = icmp.payload().to_vec();

            Ok(buf.len())
        }
    }

    impl TestSocket {
        fn new() -> Self {
            Self {
                last_sent_ident: RefCell::new(0),
                last_sent_playground: RefCell::new(Vec::new()),
                received: RefCell::new(0),
                send: RefCell::new(0),
                send_errors: RefCell::new(HashMap::new()),
                recv_errors: RefCell::new(HashMap::new()),
            }
        }

        fn emulate_recv(&self, buf: &mut [u8]) -> usize {
            let mut icmp_buf = [0; 1024];
            let icmp_size = IcmpBuilder::new()
                .with_ident(*self.last_sent_ident.borrow())
                .with_payload(&*self.last_sent_playground.borrow())
                .build(&mut icmp_buf)
                .unwrap();

            let size = IPV4Builder::new(
                0,
                Protocol::ICMP,
                net::Ipv4Addr::new(0, 0, 0, 0),
                net::Ipv4Addr::new(127, 0, 0, 1),
                &icmp_buf[..icmp_size],
            )
            .build(buf)
            .unwrap();

            size
        }

        fn raise_send_error(&mut self, op_index: usize, err: io::Error) {
            self.send_errors.borrow_mut().insert(op_index, err);
        }

        fn raise_recv_error(&mut self, op_index: usize, err: io::Error) {
            self.recv_errors.borrow_mut().insert(op_index, err);
        }
    }
}
