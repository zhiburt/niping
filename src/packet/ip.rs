use super::{Packet, PacketError, Result};

pub enum IPacket {
    V4(IPV4Packet),
}

#[derive(Debug, PartialEq, Eq)]
pub struct IPV4Packet {
    pub source_ip: std::net::Ipv4Addr,
    pub ttl: u8,
    pub protocol: Protocol,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    ICMP,
    IP,
}

const IPV4_VERSION: u8 = 4;
const MINIMUM_HEADER_SIZE: usize = 20;

impl<'a> Packet<'a> for IPV4Packet {
    fn build(&self, buff: &mut [u8]) -> Result<usize> {
        unimplemented!()
    }

    fn hint_size(&self) -> Option<usize> {
        unimplemented!()
    }

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

        let ttl = buf[8];
        let protocol = Protocol::from(buf[9]);
        let source_ip = std::net::Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);

        let data = buf[size..].to_vec();

        Ok(Self {
            source_ip,
            ttl,
            protocol,
            data,
        })
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

    fn setup() -> (Vec<u8>, IPV4Packet) {
        let b = [
            69, 0, 0, 60, 35, 24, 0, 0, 56, 1, 230, 134, 127, 0, 0, 1, 192, 168, 100, 10,
        ];
        let p = IPV4Packet {
            source_ip: std::net::Ipv4Addr::new(127, 0, 0, 1),
            ttl: 56,
            protocol: Protocol::ICMP,
            data: Vec::new(),
        };

        (b.to_vec(), p)
    }
}
