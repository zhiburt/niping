use std::io;
use std::net;

pub trait Socket {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn send_to(&self, buf: &[u8], addr: &net::SocketAddr) -> io::Result<usize>;
}

pub struct Socket2 {
    s: socket2::Socket,
}

impl Socket2 {
    pub fn icmp() -> Self {
        Self {
            s: socket2::Socket::new(
                socket2::Domain::ipv4(),
                socket2::Type::raw(),
                Some(socket2::Protocol::icmpv4()),
            )
            .unwrap(),
        }
    }
}

impl Socket for Socket2 {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.s.recv(buf)
    }

    fn send_to(&self, buf: &[u8], addr: &net::SocketAddr) -> io::Result<usize> {
        let addr = socket2::SockAddr::from(addr.clone());
        self.s.send_to(buf, &addr)
    }
}

impl AsMut<socket2::Socket> for Socket2 {
    fn as_mut(&mut self) -> &mut socket2::Socket {
        &mut self.s
    }
}
