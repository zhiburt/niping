pub type Result<T> = std::result::Result<T, PacketError>;

#[derive(Debug)]
pub enum PacketError {
    ChecksumFailed,
    InvalidHeaderSize,
    WrongFormat,
    InvalidVersion,
    InvalidBufferSize,
    IO(std::io::Error),
}

impl From<std::io::Error> for PacketError {
    fn from(err: std::io::Error) -> Self {
        Self::IO(err)
    }
}

pub trait Packet<'a> {
    fn build(&self) -> &[u8];
    fn parse(buf: &'a [u8]) -> Result<Self>
    where
        Self: std::marker::Sized;
}

pub mod icmp;
pub mod ip;
