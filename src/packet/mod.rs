//! This module contains abstractions and implementations of network packets
//! such as [`IcmpPacket`] and [`IPV4Packet`].
//!
//! ## Examples
//!
//! ```rust
//!     use niping::packet::{
//!         icmp::{IcmpBuilder, IcmpPacket, PacketType},
//!         Builder, Packet,
//!     };
//!
//!     let mut buf = vec![0; 1024];
//!     let builder = IcmpBuilder::new()
//!         .with_type(8);
//!     let size = builder.build(&mut buf).unwrap();
//!
//!     assert_eq!(size, 8);
//!     assert_eq!(&buf[..size], &[8, 0, 247, 255, 0, 0, 0, 0]);
//!
//!     let packet = IcmpPacket::parse(&buf).unwrap();
//!     assert_eq!(packet.tp(), PacketType::EchoRequest as u8);
//! ```

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

/// A trait for packets which can be constructed on [u8] buffers.
pub trait Builder {
    /// Construct the bytes representation of this packet.
    ///
    /// Returns the amount of bytes were written in the buffer.
    fn build(&self, _: &mut [u8]) -> Result<usize>;
}

/// Packet trait is responsible only for rendering the packet.
///
/// The good example of this trait is [`IcmpHeader`].
///
/// [`IcmpHeader`]: struct.IcmpHeader.html
pub trait Packet<'a>
where
    Self: Sized,
{
    /// The builder object which can construct this packet.
    type Builder: Builder;

    /// Constructs this packet object by representation of the buffer.
    ///
    /// The 'a lifetime can be used to keep the reference in the object.
    /// Which allow not to copy the bytes.
    fn parse(_: &'a [u8]) -> Result<Self>;
}

pub mod icmp;
pub mod ip;
