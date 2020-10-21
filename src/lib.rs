#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

pub mod config;
//pub mod http;
pub mod interceptor;
//pub mod jet;
//pub mod jet_client;
pub mod logger;
//pub mod proxy;
pub mod rdp;
//pub mod routing_client;
//pub mod transport;
pub mod utils;
//pub mod websocket_client;

//pub use proxy::Proxy;

use lazy_static::lazy_static;
use std::sync::atomic::AtomicU64;

lazy_static! {
    pub static ref SESSION_IN_PROGRESS_COUNT: AtomicU64 = AtomicU64::new(0);
}
