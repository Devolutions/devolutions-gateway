#[macro_use]
extern crate tracing;

#[cfg(windows)]
mod dvc;

mod config;
mod log;

pub use config::{get_data_dir, ConfHandle};
pub use log::init_log;

#[cfg(windows)]
pub use dvc::loop_dvc;
