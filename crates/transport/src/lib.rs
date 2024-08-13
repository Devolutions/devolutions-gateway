// Used by tests.
#[cfg(test)]
use anyhow as _;

mod copy_bidirectional;
mod ws;

pub use self::copy_bidirectional::*;
pub use self::ws::*;

use tokio::io::{AsyncRead, AsyncWrite};

pub type ErasedRead = Box<dyn AsyncRead + Send + Unpin>;
pub type ErasedWrite = Box<dyn AsyncWrite + Send + Unpin>;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

pub type ErasedReadWrite = Box<dyn AsyncReadWrite + Send + Unpin>;
