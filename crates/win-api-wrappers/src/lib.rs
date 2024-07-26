mod error;
pub use error::Error;

pub mod win;

#[allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
pub mod undoc;

pub mod rpc;

pub use windows as raw;
