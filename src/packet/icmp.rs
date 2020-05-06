use super::{Packet, PacketError, Result};
use std::borrow::Cow;

pub enum PacketType {
    EchoReply = 0,
    EchoRequest = 8,
    TimeExceeded = 11,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ICMPacket<'a> {
    buf: Cow<'a, [u8]>,
}

const MINIMUM_HEADER_SIZE: usize = 8;

impl ICMPacket<'_> {
    pub fn new(tp: u8, code: u8, ident: u16, seq: u16) -> Self {
        Self {
            buf: Cow::Owned(vec![
                tp,
                code,
                0,
                0,
                (ident >> 8) as u8,
                ident as u8,
                (seq >> 8) as u8,
                seq as u8,
            ]),
        }
    }

    pub fn with_payload(mut self, payload: &[u8]) -> Self {
        use std::io::Write;
        self.buf.to_mut().write(payload).unwrap();
        self
    }

    // todo: if we support icmpv6 we should store the checksum function
    // by function sign_by and here call it
    pub fn sign(mut self) -> Self {
        self.buf.to_mut()[2] = 0;
        self.buf.to_mut()[3] = 0;

        let checksum = checksum(&self.buf);
        self.buf.to_mut()[2] = (checksum >> 8) as u8;
        self.buf.to_mut()[3] = checksum as u8;

        self
    }

    pub fn tp(&self) -> u8 {
        self.buf[0]
    }

    pub fn code(&self) -> u8 {
        self.buf[1]
    }

    pub fn ident(&self) -> u16 {
        (u16::from(self.buf[4]) << 8) + self.buf[5] as u16
    }

    pub fn seq(&self) -> u16 {
        (u16::from(self.buf[6]) << 8) + self.buf[7] as u16
    }

    pub fn payload(&self) -> &[u8] {
        &self.buf[8..]
    }

    pub fn set_seq(&mut self, seq: u16) {
        self.buf.to_mut()[6] = (seq >> 8) as u8;
        self.buf.to_mut()[7] = seq as u8;
    }

    pub fn is_checksum_correct(&self) -> bool {
        match checksum(&self.buf) {
            0 => true,
            _ => false,
        }
    }
}

impl<'a> Packet<'a> for ICMPacket<'a> {
    fn build(&self) -> &[u8] {
        &self.buf
    }

    fn parse(buf: &'a [u8]) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        if buf.len() < MINIMUM_HEADER_SIZE {
            return Err(PacketError::InvalidBufferSize);
        }

        Ok(Self {
            buf: Cow::Borrowed(buf),
        })
    }
}

pub fn checksum(buf: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in buf.chunks(2) {
        let word = match word {
            &[b1, b2] => ((b1 as u16) << 8) + b2 as u16,
            &[b1] => b1 as u16,
            _ => unreachable!(),
        };

        sum = sum.wrapping_add(word as u32);
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

pub struct EchoRequest;

impl EchoRequest {
    pub fn new<'a>(ident: u16, seq: u16) -> ICMPacket<'a> {
        ICMPacket::new(PacketType::EchoRequest as u8, 0, ident, seq)
    }
}

mod tests {
    use super::*;

    #[test]
    fn checksum() {
        let buffer = [0, 0, 0, 1, 2, 3, 4];
        let sum = super::checksum(&buffer);

        assert_eq!(65015, sum);
    }

    #[test]
    fn build() {
        let p = ICMPacket::new(20, 0, 2020, 24).sign();
        let res = p.build();
        assert_eq!([20, 0, 228, 3, 7, 228, 0, 24], res);
    }

    #[test]
    fn parse() {
        let buf = [20, 0, 228, 3, 7, 228, 0, 24];
        let p = ICMPacket::parse(&buf);

        assert!(p.is_ok());
        assert_eq!(ICMPacket::new(20, 0, 2020, 24).sign(), p.unwrap());
    }

    #[test]
    fn parse_cut_buffer() {
        let buf = [20, 0, 228];
        let p = ICMPacket::parse(&buf);

        assert!(p.is_err());
    }

    #[test]
    fn secure_parse() {
        let mut buf = [20, 0, 228, 3, 7, 228, 0, 24];
        let p = ICMPacket::parse(&buf);
        assert!(p.is_ok());
        assert!(p.unwrap().is_checksum_correct());

        buf[2] = 0;
        let p = ICMPacket::parse(&buf);
        assert!(p.is_ok());
        assert!(!p.unwrap().is_checksum_correct());
    }
}
