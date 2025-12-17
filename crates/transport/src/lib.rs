// Used by tests.
#[cfg(test)]
use anyhow as _;

mod copy_bidirectional;
mod pinnable;
mod shared;
mod ws;

use tokio::io::{AsyncRead, AsyncWrite};

pub use self::copy_bidirectional::*;
pub use self::pinnable::*;
pub use self::shared::*;
pub use self::ws::*;

pub type ErasedRead = Box<dyn AsyncRead + Send + Unpin>;
pub type ErasedWrite = Box<dyn AsyncWrite + Send + Unpin>;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

pub type ErasedReadWrite = Box<dyn AsyncReadWrite + Send + Unpin>;
