#[cfg(not(loom))]
pub(crate) use self::tokio::*;

#[cfg(not(loom))]
mod tokio {
    pub use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    pub use tokio::net::{lookup_host, TcpStream};
}

#[cfg(loom)]
pub(crate) use self::loom::*;

#[cfg(loom)]
mod loom {
    pub use mock_net::{lookup_host, TcpStream};
    pub type OwnedReadHalf = tokio::io::ReadHalf<self::TcpStream>;
    pub type OwnedWriteHalf = tokio::io::WriteHalf<self::TcpStream>;
}
