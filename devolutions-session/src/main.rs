// Start the program without a console window.
// It has no effect on platforms other than Windows.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[macro_use]
extern crate tracing;

use devolutions_session::{get_data_dir, init_log, ConfHandle};

#[cfg(windows)]
use devolutions_session::loop_dvc;

use anyhow::Context;

use std::sync::mpsc;

fn main() -> anyhow::Result<()> {
    // Ensure per-user data dir exists.

    std::fs::create_dir_all(get_data_dir()).context("Failed to create data directory")?;

    let conf = ConfHandle::init()
        .context("Failed to initialize configuration")?
        .get_conf();

    let _logger_guard = init_log(&conf);

    info!("Starting Devolutions Session");

    // TMP: Copy-paste from MSRDPEX project for testing purposes.
    #[cfg(windows)]
    {
        if conf.debug.enable_unstable {
            loop_dvc();
        } else {
            debug!("DVC loop is disabled");
        }
    }

    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    ctrlc::set_handler(move || {
        info!("Ctrl-C received, exiting");
        shutdown_tx.send(()).expect("BUG: Failed to send shutdown signal");
    })
    .expect("BUG: Failed to set Ctrl-C handler");

    info!("Waiting for shutdown signal");
    shutdown_rx.recv().expect("BUG: Shutdown signal was lost");

    info!("Exiting Devolutions Session");

    Ok(())
}
