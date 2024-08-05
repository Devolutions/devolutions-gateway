mod error;
pub use error::Error;

pub mod handle;
pub mod identity;
pub mod process;
pub mod security;
pub mod thread;
pub mod token;
pub mod utils;

// Allowed since the goal is to replicate the Windows API crate so that it's familiar, which itself uses the raw names from the API.
#[allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
pub mod undoc;

pub mod rpc;

pub use windows as raw;
