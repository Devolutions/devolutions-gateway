#[macro_use]
extern crate serde;
extern crate tracing;

use ::{ctrlc as _, devolutions_gateway_task as _, futures as _, tokio as _};

#[cfg(all(windows, feature = "dvc"))]
pub mod dvc;

mod config;
mod log;

pub use config::{Conf, ConfHandle, get_data_dir};
pub use log::init_log;
