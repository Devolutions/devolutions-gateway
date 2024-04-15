mod forward;
mod ws;
mod copy_bidirectional;
mod copy_buffer;

pub use copy_bidirectional::*;
pub use self::forward::*;
pub use self::ws::*;

use tokio::io::{AsyncRead, AsyncWrite};

pub type ErasedRead = Box<dyn AsyncRead + Send + Unpin>;
pub type ErasedWrite = Box<dyn AsyncWrite + Send + Unpin>;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

pub type ErasedReadWrite = Box<dyn AsyncReadWrite + Send + Unpin>;
