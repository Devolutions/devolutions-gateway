#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

// Used by devolutions-gateway library.
#[cfg(windows)]
use rustls_cng as _;
#[cfg(feature = "openapi")]
use utoipa as _;
use {
    argon2 as _, async_trait as _, axum as _, axum_extra as _, backoff as _, bytes as _, camino as _,
    devolutions_agent_shared as _, dlopen as _, dlopen_derive as _, dunce as _, etherparse as _, hostname as _,
    http_body_util as _, hyper as _, hyper_util as _, ironrdp_core as _, ironrdp_pdu as _, ironrdp_rdcleanpath as _,
    jmux_proxy as _, job_queue as _, job_queue_libsql as _, multibase as _, network_scanner as _, ngrok as _,
    nonempty as _, pcap_file as _, picky as _, picky_krb as _, pin_project_lite as _, portpicker as _, reqwest as _,
    serde as _, serde_urlencoded as _, smol_str as _, sysinfo as _, thiserror as _, time as _, tokio_rustls as _,
    tokio_tungstenite as _, tower as _, tower_http as _, transport as _, tungstenite as _, typed_builder as _,
    url as _, uuid as _, zeroize as _,
};
// Used by tests.
#[cfg(test)]
use {
    devolutions_gateway_generators as _, http_body_util as _, proptest as _, rstest as _, tokio_test as _,
    tracing_cov_mark as _,
};

#[macro_use]
extern crate tracing;

mod service;

use std::sync::mpsc;

use anyhow::Context;
use ceviche::controller::{Controller, ControllerInterface, dispatch};
use ceviche::{Service, ServiceEvent};
use cfg_if::cfg_if;
use devolutions_gateway::SYSTEM_LOGGER;
use devolutions_gateway::config::ConfHandle;
use tap::prelude::*;

use crate::service::{DESCRIPTION, DISPLAY_NAME, GatewayService, SERVICE_NAME};

enum CliAction {
    ShowHelp,
    RegisterService,
    UnregisterService,
    Run { service_mode: bool },
    ConfigInitOnly,
}

fn main() -> anyhow::Result<()> {
    run().inspect_err(|error| {
        let bootstacktrace_path = devolutions_gateway::config::get_data_dir().join("boot.stacktrace");

        if let Err(write_error) = std::fs::write(&bootstacktrace_path, format!("{error:?}")) {
            eprintln!("Failed to write the boot stacktrace to {bootstacktrace_path}: {write_error}");
        }
    })
}

fn run() -> anyhow::Result<()> {
    let mut args = std::env::args();
    let executable = args.next().context("executable name is missing from the environment")?;

    // Extract and remove --config-path argument if provided
    let mut config_path = None;
    let mut remaining_args = Vec::new();

    while let Some(arg) = args.next() {
        if arg == "--config-path" {
            if let Some(path) = args.next() {
                config_path = Some(path);
            } else {
                anyhow::bail!("missing value for --config-path");
            }
        } else {
            remaining_args.push(arg);
        }
    }

    // Set the DGATEWAY_CONFIG_PATH if --config-path was provided
    if let Some(path) = config_path {
        // SAFETY: At this point the program is single-threaded.
        unsafe { std::env::set_var("DGATEWAY_CONFIG_PATH", &path) };
    }

    // Parse remaining arguments for CLI actions
    let action = match remaining_args.first().map(String::as_str) {
        Some("--service") => CliAction::Run { service_mode: true },
        Some("service") => match args.next().as_deref() {
            Some("register") => CliAction::RegisterService,
            Some("unregister") => CliAction::UnregisterService,
            _ => CliAction::ShowHelp,
        },
        Some("--config-init-only") => CliAction::ConfigInitOnly,
        None => CliAction::Run { service_mode: false },
        Some(_) => CliAction::ShowHelp,
    };

    match action {
        CliAction::ShowHelp => {
            println!(
                r#"HELP:

    Run:
        "{executable}"

    Run as service:
        "{executable}" --service

    Initialize configuration only (will not override existing configuration):
        "{executable}" --config-init-only

    Install service:
        "{executable}" service register

    Uninstall service:
        "{executable}" service unregister

        
    Options:
        --config-path <CONFIG_PATH>
"#
            )
        }
        CliAction::RegisterService => {
            let mut controller = service_controller();

            cfg_if! { if #[cfg(target_os = "linux")] {
                controller.config = Some(r#"
                        [Unit]
                        After=network-online.target

                        [Service]
                        ExecStart=/usr/bin/devolutions-gateway --service
                        Restart=on-failure

                        [Install]
                        WantedBy=multi-user.target
                    "#.to_owned());
            }}

            controller.create().context("failed to register service")?;
        }
        CliAction::UnregisterService => {
            service_controller().delete().context("failed to unregister service")?;
        }
        CliAction::ConfigInitOnly => {
            let conf_file = devolutions_gateway::config::load_conf_file_or_generate_new()?;
            let conf_file_json =
                serde_json::to_string_pretty(&conf_file).context("couldn't represent config file as JSON")?;
            println!("{conf_file_json}");
        }
        CliAction::Run { service_mode } => {
            devolutions_gateway::tls::install_default_crypto_provider();

            if service_mode {
                service_controller()
                    .register(service_main_wrapper)
                    .context("failed to register service")?;
            } else {
                let conf_handle = ConfHandle::init().context("unable to initialize configuration")?;
                let mut service = GatewayService::load(conf_handle).context("service loading failed")?;

                service
                    .start()
                    .tap_err(|error| error!(error = format!("{error:#}"), "Failed to start"))?;

                // Waiting for some stop signal (CTRL-C…)
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .context("failed to build the async runtime")?;
                rt.block_on(build_signals_fut())?;

                service.stop();
            }
        }
    }

    Ok(())
}

fn service_controller() -> Controller {
    Controller::new(SERVICE_NAME, DISPLAY_NAME, DESCRIPTION)
}

enum GatewayServiceEvent {}

const BAD_CONFIG_ERR_CODE: u32 = 1;
const START_FAILED_ERR_CODE: u32 = 2;

fn gateway_service_main(
    rx: mpsc::Receiver<ServiceEvent<GatewayServiceEvent>>,
    _tx: mpsc::Sender<ServiceEvent<GatewayServiceEvent>>,
    _args: Vec<String>,
    _standalone_mode: bool,
) -> u32 {
    let conf_handle = match ConfHandle::init() {
        Ok(conf_handle) => conf_handle,
        Err(error) => {
            let _ = SYSTEM_LOGGER.emit(sysevent_codes::config_invalid(
                &error,
                devolutions_gateway::config::get_data_dir().join("gateway.json"),
            ));
            return BAD_CONFIG_ERR_CODE;
        }
    };

    let mut service = match GatewayService::load(conf_handle) {
        Ok(service) => service,
        Err(error) => {
            // At this point, the logger may or may not be initialized.
            error!(error = format!("{error:#}"), "Failed to load service");
            let _ = SYSTEM_LOGGER.emit(sysevent_codes::start_failed(&error, "service_load"));
            return START_FAILED_ERR_CODE;
        }
    };

    match service.start() {
        Ok(()) => {
            info!("{} service started", SERVICE_NAME);
            let _ = SYSTEM_LOGGER.emit(sysevent_codes::service_started(env!("CARGO_PKG_VERSION")));
        }
        Err(error) => {
            error!(error = format!("{error:#}"), "Failed to start");
            let _ = SYSTEM_LOGGER.emit(sysevent_codes::start_failed(&error, "service_start"));
            return START_FAILED_ERR_CODE;
        }
    }

    loop {
        if let Ok(control_code) = rx.recv() {
            debug!(%control_code, "Received control code");

            if let ServiceEvent::Stop = control_code {
                service.stop();
                break;
            }
        }
    }

    info!("{} service stopping", SERVICE_NAME);
    let _ = SYSTEM_LOGGER.emit(sysevent_codes::service_stopping("received stop control code"));

    0
}

Service!("gateway", gateway_service_main);

#[cfg(unix)]
async fn build_signals_fut() -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate_signal = signal(SignalKind::terminate()).context("failed to create terminate signal stream")?;
    let mut quit_signal = signal(SignalKind::quit()).context("failed to create quit signal stream failed")?;
    let mut interrupt_signal =
        signal(SignalKind::interrupt()).context("failed to create interrupt signal stream failed")?;

    futures::future::select_all(vec![
        Box::pin(terminate_signal.recv()),
        Box::pin(quit_signal.recv()),
        Box::pin(interrupt_signal.recv()),
    ])
    .await;

    Ok(())
}

#[cfg(not(unix))]
async fn build_signals_fut() -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await.context("CTRL_C signal failed")
}
