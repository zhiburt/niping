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
    fn build(&self, buf: &mut [u8]) -> Result<usize>;
    fn parse(buf: &'a [u8]) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn verify(_: &'a [u8]) -> Result<()> {
        Ok(())
    }

    fn parse_verified(buf: &'a [u8]) -> Result<Self>
    where
        Self: std::marker::Sized,
    {
        Self::verify(buf)?;
        Self::parse(buf)
    }

    fn hint_size(&self) -> Option<usize> {
        None
    }
}

pub mod icmp;
pub mod ip;
