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

    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.buf[9])
    }

    pub fn source_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[12], self.buf[13], self.buf[14], self.buf[15])
    }

    pub fn payload(&self) -> &[u8] {
        let size = 4 * (self.buf[0] & 0x0f) as usize;
        &self.buf[size..]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    ICMP,
    IP,
}

const IPV4_VERSION: u8 = 4;
const MINIMUM_HEADER_SIZE: usize = 20;

impl<'a> Packet<'a> for IPV4Packet<'a> {
    type Builder = IPV4Builder;

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

pub struct IPV4Builder;

impl Builder for IPV4Builder {
    fn build(&self, _: &mut [u8]) -> Result<usize> {
        unimplemented!()
    }
}

impl From<u8> for Protocol {
    fn from(i: u8) -> Protocol {
        match i {
            1 => Protocol::ICMP,
            4 => Protocol::IP,
            _ => unimplemented!(),
        }
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

    fn setup<'a>() -> (Vec<u8>, IPV4Packet<'a>) {
        let b: &'static [u8] = &[
            69, 0, 0, 60, 35, 24, 0, 0, 56, 1, 230, 134, 127, 0, 0, 1, 192, 168, 100, 10,
        ];
        let p = IPV4Packet::parse(&b).unwrap();

        (b.to_vec(), p)
    }
}
