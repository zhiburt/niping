use super::{Packet, PacketError, Result};

pub enum PacketType {
    EchoReply = 0,
    EchoRequest = 8,
    TimeExceeded = 11,
}

#[derive(Debug)]
pub struct ICMPacket {
    pub tp: u8,
    pub code: u8,
    pub ident: u16,
    pub seq: u16,
    pub payload: Option<Vec<u8>>,
}

const MINIMUM_HEADER_SIZE: usize = 8;

impl ICMPacket {
    pub fn new(tp: u8, code: u8, ident: u16, seq: u16) -> Self {
        Self {
            tp,
            code,
            ident,
            seq,
            payload: None,
        }
    }

    pub fn add_payload(&mut self, payload: &[u8]) {
        self.payload = Some(payload.to_vec());
    }
}

impl<'a> Packet<'a> for ICMPacket {
    fn build(&self, buff: &mut [u8]) -> Result<usize> {
        buff[0] = self.tp;
        buff[1] = self.code;
        buff[4] = (self.ident >> 8) as u8;
        buff[5] = self.ident as u8;
        buff[6] = (self.seq >> 8) as u8;
        buff[7] = self.seq as u8;

        if let Some(payload) = &self.payload {
            use std::io::Write;
            (&mut buff[8..]).write(payload)?;
        }

        buff[2] = 0;
        buff[3] = 0;

        let checksum = checksum(buff);
        buff[2] = (checksum >> 8) as u8;
        buff[3] = checksum as u8;

        Ok(self.hint_size().unwrap())
    }

    fn hint_size(&self) -> Option<usize> {
        let payload_size = self.payload.as_ref().map_or(0, |p| p.len());
        Some(MINIMUM_HEADER_SIZE + payload_size)
    }

    fn parse(buf: &'a [u8]) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        if buf.len() < MINIMUM_HEADER_SIZE {
            return Err(PacketError::InvalidBufferSize);
        }

        let tp = buf[0];
        let code = buf[1];

        let ident = (u16::from(buf[4]) << 8) + buf[5] as u16;
        let seq_count = (u16::from(buf[6]) << 8) + buf[7] as u16;

        let mut header = Self::new(tp, code, ident, seq_count);
        header.add_payload(&buf[8..]);
        Ok(header)
    }

    fn verify(buf: &'a [u8]) -> Result<()> {
        let checksum = checksum(buf);
        if checksum != 0 {
            return Err(PacketError::ChecksumFailed);
        }

        Ok(())
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
    pub fn new(ident: u16, seq: u16) -> ICMPacket {
        ICMPacket::new(PacketType::EchoRequest as u8, 0, ident, seq)
    }
}
