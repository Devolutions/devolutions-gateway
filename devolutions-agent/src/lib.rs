// Used by devolutions-agent binary.
use {ceviche as _, ctrlc as _};

#[macro_use]
extern crate tracing;

pub mod config;
mod log;
mod remote_desktop;
pub mod service;

#[cfg(windows)]
mod updater;
