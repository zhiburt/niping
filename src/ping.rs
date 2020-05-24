use crate::packet::{
    icmp::{self, IcmpBuilder, IcmpPacket, PacketType},
    ip::IPV4Packet,
    Builder, Packet, PacketError,
};
use socket2::{Domain, Protocol, Type};
use std::{
    io, net,
    os::unix::io::AsRawFd,
    time::{self, Duration},
};

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
    pub fn build(self) -> Ping<Socket2> {
        let sock =
            socket2::Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap();
        sock.set_nonblocking(true).unwrap();
        sock.set_read_timeout(Some(self.read_timeout)).unwrap();
        if let Some(ttl) = self.ttl {
            sock.set_ttl(ttl).unwrap();
        }
        let addr = std::net::SocketAddr::new(self.addr, 0);
        let sock = Socket2(sock, addr);
        Ping::new(sock)
    }
}

pub struct Ping<S: Socket> {
    sock: smol::Async<S>,
    req: IcmpBuilder,
}

impl<S: Socket> Ping<S> {
    fn new(sock: S) -> Self {
        let payload = uniq_payload();
        let req = icmp::EchoRequest::new(uniq_ident(), 0).with_payload(&payload);
        let sock = smol::Async::new(sock).unwrap();

        Self { req, sock }
    }

    pub async fn run(&mut self) -> Result<PacketInfo> {
        let mut buf = vec![0; 300];
        self.req.seq += 1;

        self.ping(&mut buf).await
    }

    async fn ping(&mut self, mut buf: &mut [u8]) -> Result<PacketInfo> {
        let size = self.req.build(&mut buf).unwrap();
        self.sock
            .write_with(|sock| sock.send(&buf[..size]))
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

pub trait Socket: AsRawFd {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn send(&self, buf: &[u8]) -> io::Result<usize>;
}

pub struct Socket2(socket2::Socket, net::SocketAddr);

impl Socket for Socket2 {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf)
    }

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.send_to(buf, &self.1.into())
    }
}

impl AsRawFd for Socket2 {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::ip::{self, IPV4Builder};
    use std::{cell::RefCell, collections::HashMap};

    #[derive(Default)]
    struct TestSocket {
        builder: RefCell<IcmpBuilder>,
        recv_errors: HashMap<usize, io::Error>,
        send_errors: HashMap<usize, io::Error>,
        changer: HashMap<usize, Box<fn(&mut IcmpBuilder)>>,
        recv: usize,
        send: RefCell<usize>,
        // test_socket_fd: RefCell<i32>,
    }

    impl Socket for TestSocket {
        fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.recv += 1;
            match self.recv_errors.get(&self.recv) {
                Some(err) => Err(io::Error::new(err.kind(), err.to_string())),
                None => {
                    if let Some(callback) = self.changer.get(&self.recv) {
                        callback(self.builder.get_mut());
                    }

                    let mut icmp = [0; 300];
                    let icmp_size = self.builder.borrow().build(&mut icmp).unwrap();
                    let ip = IPV4Builder::new(
                        0,
                        ip::Protocol::ICMP,
                        net::Ipv4Addr::LOCALHOST,
                        net::Ipv4Addr::LOCALHOST,
                        &icmp[..icmp_size],
                    );
                    let send_size = ip.build(buf).unwrap();

                    Ok(send_size)
                }
            }
        }

        fn send(&self, buf: &[u8]) -> io::Result<usize> {
            *self.send.borrow_mut() += 1;
            match self.send_errors.get(&self.send.borrow()) {
                Some(err) => Err(io::Error::new(err.kind(), err.to_string())),
                None => {
                    self.builder.borrow_mut().seq += 1;
                    Ok(buf.len())
                }
            }
        }
    }

    impl AsRawFd for TestSocket {
        fn as_raw_fd(&self) -> i32 {
            // *self.test_socket_fd.borrow_mut() += 1;
            // *self.test_socket_fd.borrow()
            0
        }
    }

    fn test_ping() -> Ping<TestSocket> {
        let mut ping = Ping::new(TestSocket::default());
        ping.sock.get_mut().builder = RefCell::new(ping.req.clone());
        ping.sock.get_mut().builder.borrow_mut().tp = icmp::PacketType::EchoReply as u8;
        ping
    }

    fn counts(ping: &Ping<TestSocket>) -> (usize, usize) {
        let send_count = *ping.sock.get_ref().send.borrow();
        let recv_count = ping.sock.get_ref().recv;

        (send_count, recv_count)
    }

    #[test]
    pub fn ping() {
        let mut ping = test_ping();

        for seq in 1..=2 {
            let packet = smol::block_on(ping.run());
            assert!(packet.is_ok());
            assert_eq!(packet.unwrap().icmp_seq, seq);
        }

        let (send, recv) = counts(&ping);
        assert_eq!(send, 2);
        assert_eq!(recv, 2);
    }

    #[test]
    pub fn ping_send_error() {
        let mut ping = test_ping();

        ping.sock
            .get_mut()
            .send_errors
            .insert(2, io::ErrorKind::Other.into());

        let packet = smol::block_on(ping.run());
        assert!(packet.is_ok());
        assert_eq!(packet.unwrap().icmp_seq, 1);

        let packet = smol::block_on(ping.run());
        assert!(packet.is_err());

        let packet = smol::block_on(ping.run());
        assert!(packet.is_ok());
        assert_eq!(packet.unwrap().icmp_seq, 2);

        let (send, recv) = counts(&ping);
        assert_eq!(send, 3);
        assert_eq!(recv, 2);
    }

    #[test]
    pub fn ping_recv_error() {
        let mut ping = test_ping();

        ping.sock
            .get_mut()
            .recv_errors
            .insert(2, io::ErrorKind::Other.into());

        let packet = smol::block_on(ping.run());
        assert!(packet.is_ok());
        assert_eq!(packet.unwrap().icmp_seq, 1);

        let packet = smol::block_on(ping.run());
        assert!(packet.is_err());

        let packet = smol::block_on(ping.run());
        assert!(packet.is_ok());
        assert_eq!(packet.unwrap().icmp_seq, 3);

        let (send, recv) = counts(&ping);
        assert_eq!(send, 3);
        assert_eq!(recv, 3);
    }

    #[test]
    pub fn ping_recv_unexpected_icmp_packet() {
        let mut ping = test_ping();

        // spoil the playgound
        ping.sock.get_mut().changer.insert(
            2,
            Box::new(|builder| {
                builder.payload.as_mut().map(|p| p.reverse());
            }),
        );

        ping.sock.get_mut().changer.insert(
            4,
            Box::new(|builder| {
                builder.payload.as_mut().map(|p| p.reverse());
            }),
        );

        let packet = smol::block_on(ping.run());
        assert!(packet.is_ok());
        assert_eq!(packet.unwrap().icmp_seq, 1);

        let packet = smol::block_on(ping.run());
        assert!(packet.is_ok());
        assert_eq!(packet.unwrap().icmp_seq, 2);

        let (send, recv) = counts(&ping);
        assert_eq!(send, 2);
        assert_eq!(recv, 4);
    }
}
