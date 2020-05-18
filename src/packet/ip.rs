use super::{Builder, Packet, PacketError, Result};
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
pub struct IPV4Packet<'a> {
    buf: &'a [u8],
}

impl IPV4Packet<'_> {
    pub fn ttl(&self) -> u8 {
        self.buf[8]
    }

    pub fn protocol(&self) -> u8 {
        self.buf[9]
    }

    pub fn source_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[12], self.buf[13], self.buf[14], self.buf[15])
    }

    pub fn destination_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[16], self.buf[17], self.buf[18], self.buf[19])
    }

    pub fn payload(&self) -> Option<&[u8]> {
        let size = 4 * (self.buf[0] & 0x0f) as usize;
        match size {
            0 => None,
            _ => Some(&self.buf[size..]),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Protocol {
    ICMP = 1,
    IP = 4,
}

impl Protocol {
    fn new(protocol: u8) -> Option<Self> {
        match protocol {
            1 => Some(Protocol::ICMP),
            4 => Some(Protocol::IP),
            _ => None,
        }
    }
}

const IPV4_VERSION: u8 = 4;
const MINIMUM_HEADER_SIZE: usize = 20;

impl<'a> Packet<'a> for IPV4Packet<'a> {
    type Builder = IPV4Builder<'a>;

    fn parse(buf: &'a [u8]) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        if buf.len() < MINIMUM_HEADER_SIZE {
            return Err(PacketError::InvalidBufferSize);
        }

        let version = buf[0] >> 4;
        if version != IPV4_VERSION {
            return Err(PacketError::InvalidVersion);
        }

        let size = 4 * (buf[0] & 0x0f) as usize;
        if buf.len() < size {
            return Err(PacketError::InvalidHeaderSize);
        }

        Ok(Self { buf })
    }
}

pub struct IPV4Builder<'a> {
    ttl: u8,
    protocol: Protocol,
    source: Ipv4Addr,
    dst: Ipv4Addr,
    payload: &'a [u8],
}

impl<'a> IPV4Builder<'a> {
    pub fn new(ttl: u8, p: Protocol, source: Ipv4Addr, dst: Ipv4Addr, payload: &'a [u8]) -> Self {
        Self {
            ttl,
            protocol: p,
            dst,
            source,
            payload,
        }
    }
}

impl Builder for IPV4Builder<'_> {
    fn build(&self, buf: &mut [u8]) -> Result<usize> {
        use std::io::Write;

        let header_size = 20;
        let size = header_size + self.payload.len();
        if buf.len() < size {
            return Err(PacketError::InvalidBufferSize);
        }

        buf.iter_mut().take(size).for_each(|b| *b = 0);

        buf[0] = (4 << 4) + (self.payload.len() / 4) as u8;

        buf[2] = (size << 8) as u8;
        buf[3] = size as u8;

        buf[8] = self.ttl;
        buf[9] = self.protocol as u8;

        (&mut buf[12..]).write(&self.source.octets()).unwrap();
        (&mut buf[16..]).write(&self.dst.octets()).unwrap();
        (&mut buf[header_size..]).write(self.payload).unwrap();

        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let (buf, expected) = setup();

        let p = IPV4Packet::parse(&buf);

        assert!(p.is_ok());
        assert_eq!(expected, p.unwrap())
    }

    #[test]
    fn parse_cut_buffer() {
        let (buf, _) = setup();

        let p = IPV4Packet::parse(&buf[..8]);

        assert!(p.is_err());
    }

    #[test]
    fn parse_incorrect_version() {
        let (mut buf, _) = setup();
        buf[0] = (6 << 4) + (buf[0] & 0x0f);

        let p = IPV4Packet::parse(&buf);

        assert!(p.is_err());
    }

    #[test]
    fn parse_incorrect_packet_size_field() {
        let (mut buf, _) = setup();
        buf[0] = (4 << 4) + ((buf.len() / 4) as u8 + 1);

        let p = IPV4Packet::parse(&buf);

        assert!(p.is_err());
    }

    #[test]
    fn build() {
        let (_, expected) = setup();

        let mut buf = [0; 1024];
        let size = IPV4Builder::new(
            expected.ttl(),
            Protocol::new(expected.protocol()).unwrap(),
            expected.source_ip(),
            expected.destination_ip(),
            &[],
        )
        .build(&mut buf);

        assert!(size.is_ok());

        let ip = IPV4Packet::parse(&buf[..size.unwrap()]);
        assert!(ip.is_ok());
        let ip = ip.unwrap();

        assert_eq!(ip.protocol(), expected.protocol());
        assert_eq!(ip.ttl(), expected.ttl());
        assert_eq!(ip.source_ip(), expected.source_ip());
        assert_eq!(ip.destination_ip(), expected.destination_ip());
        assert_eq!(ip.payload(), expected.payload());
    }

    fn setup<'a>() -> (Vec<u8>, IPV4Packet<'a>) {
        let b: &'static [u8] = &[
            64, 0, 0, 60, 35, 24, 0, 0, 56, 1, 230, 134, 127, 0, 0, 1, 192, 168, 100, 10,
        ];
        let p = IPV4Packet::parse(&b).unwrap();

        (b.to_vec(), p)
    }
}
