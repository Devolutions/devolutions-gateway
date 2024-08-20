// Start the program without a console window.
// It has no effect on platforms other than Windows.
#![windows_subsystem = "windows"]

#[macro_use]
extern crate tracing;

use devolutions_host::{get_data_dir, init_log, ConfHandle};

#[cfg(windows)]
use devolutions_host::loop_dvc;

use anyhow::Context;

use std::sync::mpsc;

fn main() -> anyhow::Result<()> {
    // Ensure per-user data dir exists

    std::fs::create_dir_all(get_data_dir()).context("Failed to create data directory")?;

    let config = ConfHandle::init().context("Failed to initialize configuration")?;

    let _logger_guard = init_log(config.clone());

    info!("Starting Devolutions Host");

    // TMP: Copy-paste from MSRDPEX project for testing purposes
    #[cfg(windows)]
    loop_dvc(config);

    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    ctrlc::set_handler(move || {
        info!("Ctrl-C received, exiting");
        shutdown_tx.send(()).expect("BUG: Failed to send shutdown signal");
    })
    .expect("BUG: Failed to set Ctrl-C handler");

    info!("Waiting for shutdown signal");
    shutdown_rx.recv().expect("BUG: Shutdown signal was lost");

    info!("Exiting Devolutions Host");

    Ok(())
}
