mod socks4;
mod socks5;

pub use socks4::Socks4Stream;
pub use socks5::{Socks5Acceptor, Socks5AcceptorConfig, Socks5FailureCode, Socks5Listener, Socks5Stream};
use tokio::io::{AsyncRead, AsyncWrite};

/// We need a super-trait in order to have additional non-auto-trait traits in trait objects.
///
/// The reason for using trait objects is monomorphization prevention in generic code.
/// This is for reducing code size by avoiding function duplication.
///
/// See:
/// - https://doc.rust-lang.org/std/keyword.dyn.html
/// - https://doc.rust-lang.org/reference/types/trait-object.html
trait ReadWriteStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<S> ReadWriteStream for S where S: AsyncRead + AsyncWrite + Unpin + Send {}
