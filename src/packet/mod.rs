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

pub(crate) trait Builder {
    fn build(&self, _: &mut [u8]) -> Result<usize>;
}

pub(crate) trait Packet<'a>
where
    Self: Sized,
{
    type Builder: Builder;

    fn parse(_: &'a [u8]) -> Result<Self>; 
}

pub mod icmp;
pub mod ip;
