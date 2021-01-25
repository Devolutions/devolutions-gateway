pub mod client;
pub mod pipe;
pub mod server;

mod io;
mod utils;

pub enum ProxyConfig {
    Socks4 { addr: String },
    Socks5 { addr: String },
}
