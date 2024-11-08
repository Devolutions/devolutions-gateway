#[macro_use]
extern crate tracing;

use ::{ctrlc as _, devolutions_gateway_task as _, futures as _, tokio as _};

#[cfg(all(windows, feature = "dvc"))]
pub mod dvc;

mod config;
mod log;

pub use config::{get_data_dir, Conf, ConfHandle};
pub use log::init_log;
