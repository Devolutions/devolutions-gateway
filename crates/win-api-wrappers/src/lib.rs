extern crate tracing;

pub mod dst;
pub mod raw_buffer;
pub mod scope_guard;
pub mod str;

#[cfg(target_os = "windows")]
#[path = ""]
mod lib_win {
    mod error;

    pub mod event;
    pub mod fs;
    pub mod handle;
    pub mod identity;
    pub mod memory;
    pub mod netmgmt;
    pub mod process;
    pub mod rpc;
    pub mod security;
    pub mod semaphore;
    pub mod service;
    pub mod thread;
    pub mod token;
    pub mod token_groups;
    pub mod ui;
    pub mod undoc;
    pub mod user;
    pub mod utils;
    pub mod wts;

    #[rustfmt::skip]
    pub use windows as raw;
    #[rustfmt::skip]
    pub use error::Error;
}

#[cfg(target_os = "windows")]
#[rustfmt::skip]
pub use lib_win::*;
