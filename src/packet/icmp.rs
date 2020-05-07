use super::{Builder, Packet, PacketError, Result};

pub struct IcmpPacket<'a>(&'a [u8]);

impl<'a> Packet<'a> for IcmpPacket<'a> {
    type Builder = IcmpBuilder<'a>;

    fn parse(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < MINIMUM_HEADER_SIZE {
            return Err(PacketError::InvalidBufferSize);
        }

        Ok(Self(buf))
    }
}

impl IcmpPacket<'_> {
    pub fn tp(&self) -> u8 {
        self.0[0]
    }

    pub fn code(&self) -> u8 {
        self.0[1]
    }

    pub fn ident(&self) -> u16 {
        (u16::from(self.0[4]) << 8) + self.0[5] as u16
    }

    pub fn seq(&self) -> u16 {
        (u16::from(self.0[6]) << 8) + self.0[7] as u16
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[8..]
    }

    pub fn is_checksum_correct(&self) -> bool {
        match checksum(self.0) {
            0 => true,
            _ => false,
        }
    }
}

impl AsRef<[u8]> for IcmpPacket<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

pub enum PacketType {
    EchoReply = 0,
    EchoRequest = 8,
    TimeExceeded = 11,
}

const MINIMUM_HEADER_SIZE: usize = 8;

#[derive(Default)]
pub struct IcmpBuilder<'a> {
    pub tp: u8,
    pub code: u8,
    pub seq: u16,
    pub ident: u16,
    pub payload: Option<&'a [u8]>,
}

impl<'a> IcmpBuilder<'a> {
    fn new() -> Self {
        Default::default()
    }

    pub fn with_type(mut self, tp: u8) -> Self {
        self.tp = tp;
        self
    }

    pub fn with_code(mut self, code: u8) -> Self {
        self.code = code;
        self
    }

    pub fn with_seq(mut self, seq: u16) -> Self {
        self.seq = seq;
        self
    }

    pub fn with_ident(mut self, ident: u16) -> Self {
        self.ident = ident;
        self
    }

    pub fn with_payload(mut self, buf: &'a [u8]) -> Self {
        self.payload = Some(buf);
        self
    }

    fn hint_size(&self) -> usize {
        MINIMUM_HEADER_SIZE + self.payload.map_or(0, |p| p.len())
    }
}

impl Builder for IcmpBuilder<'_> {
    fn build(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < self.hint_size() {
            return Err(PacketError::InvalidBufferSize);
        }

        buf[0] = self.tp;
        buf[1] = self.code;
        buf[4] = (self.ident >> 8) as u8;
        buf[5] = self.ident as u8;
        buf[6] = (self.seq >> 8) as u8;
        buf[7] = self.seq as u8;

        if let Some(payload) = &self.payload {
            use std::io::Write;
            (&mut buf[8..]).write(payload)?;
        }

        buf[2] = 0;
        buf[3] = 0;

        // we take only the affected part of the buffer to calculate
        // checksum without the bytes which are goes after.
        //
        // might it's better to provide hint_size method,
        // and put the responsibility on the caller for this?
        let checksum = checksum(&buf[..self.hint_size()]);
        buf[2] = (checksum >> 8) as u8;
        buf[3] = checksum as u8;

        Ok(self.hint_size())
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
    pub fn new<'a>(ident: u16, seq: u16) -> IcmpBuilder<'a> {
        IcmpBuilder::new()
            .with_type(PacketType::EchoRequest as u8)
            .with_code(0)
            .with_seq(seq)
            .with_ident(ident)
    }
}

mod tests {
    use super::*;

    #[test]
    fn build() {
        let mut buf = [0; 8];
        let (expected, builder) = default_setup();
        let res = builder.build(&mut buf);

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 8);
        assert_eq!(expected, buf);
    }

    #[test]
    fn build_cleaning_checksum_bytes() {
        let mut buf = [0; 8];
        buf[2] = 1;
        buf[3] = 2;

        let (expected, builder) = default_setup();
        let res = builder.build(&mut buf);

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 8);
        assert_eq!(expected, buf);
    }

    #[test]
    fn build_in_small_buffer() {
        let mut buf = [0; 3];
        let (_, builder) = default_setup();

        let res = builder.build(&mut buf);
        assert!(res.is_err());
    }

    #[test]
    fn parse() {
        let (buf, buffer) = default_setup();

        let packet = IcmpPacket::parse(&buf);

        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.tp(), buffer.tp);
        assert_eq!(packet.code(), buffer.code);
        assert_eq!(packet.ident(), buffer.ident);
        assert_eq!(packet.seq(), buffer.seq);
        assert!(packet.payload().is_empty());
    }

    #[test]
    fn parse_cut_buffer() {
        let buf = [20, 0, 228];
        let p = IcmpPacket::parse(&buf);

        assert!(p.is_err());
    }

    #[test]
    fn checksum_validity() {
        let (mut buf, _) = default_setup();
        let packet = IcmpPacket::parse(&buf);
        assert!(packet.is_ok());
        assert!(packet.unwrap().is_checksum_correct());

        buf[2] = 0;
        let packet = IcmpPacket::parse(&buf);
        assert!(packet.is_ok());
        assert!(!packet.unwrap().is_checksum_correct());
    }

    #[test]
    fn checksum() {
        let buffer = [0, 0, 0, 1, 2, 3, 4];
        let sum = super::checksum(&buffer);

        assert_eq!(65015, sum);
    }

    fn default_setup<'a>() -> (Vec<u8>, IcmpBuilder<'a>) {
        let buffer = vec![20, 0, 228, 3, 7, 228, 0, 24];
        let builder = IcmpBuilder::new()
            .with_type(20)
            .with_code(0)
            .with_ident(2020)
            .with_seq(24);

        (buffer, builder)
    }
}
