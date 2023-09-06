#[macro_use]
extern crate tracing;

mod service;

use anyhow::Context;
use ceviche::controller::{dispatch, Controller, ControllerInterface};
use ceviche::{Service, ServiceEvent};
use cfg_if::cfg_if;
use devolutions_gateway::config::ConfHandle;
use std::sync::mpsc;
use tap::prelude::*;

use crate::service::{GatewayService, DESCRIPTION, DISPLAY_NAME, SERVICE_NAME};

enum CliAction {
    ShowHelp,
    RegisterService,
    UnregisterService,
    Run { service_mode: bool },
    ConfigInitOnly,
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args();

    let executable = args.next().unwrap();

    let action = match args.next().as_deref() {
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
"#
            )
        }
        CliAction::RegisterService => {
            let mut controller = service_controller();

            cfg_if! { if #[cfg(target_os = "linux")] {
                controller.config = Some(r#"
                        [Unit]
                        After=
                        After=network-online.target

                        [Service]
                        ExecStart=
                        ExecStart=/usr/bin/devolutions-gateway --service
                        Restart=on-failure

                        [Install]
                        WantedBy=
                        WantedBy=multi-user.target
                    "#.to_string());
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
            if service_mode {
                service_controller()
                    .register(service_main_wrapper)
                    .context("failed to register service")?;
            } else {
                let conf_handle = ConfHandle::init().context("unable to initialize configuration")?;
                let mut service = GatewayService::load(conf_handle).context("Service loading failed")?;

                service.start().tap_err(|error| error!(?error, "Failed to start"))?;

                // Waiting for some stop signal (CTRL-C…)
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .unwrap();
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

fn gateway_service_main(
    rx: mpsc::Receiver<ServiceEvent<GatewayServiceEvent>>,
    _tx: mpsc::Sender<ServiceEvent<GatewayServiceEvent>>,
    args: Vec<String>,
    _standalone_mode: bool,
) -> u32 {
    let conf_handle = ConfHandle::init().expect("unable to initialize configuration");
    let mut service = GatewayService::load(conf_handle).expect("unable to load service");

    info!("{} service started", SERVICE_NAME);
    info!("args: {:?}", args);

    service
        .start()
        .tap_err(|error| error!(?error, "Failed to start"))
        .expect("start service");

    loop {
        if let Ok(control_code) = rx.recv() {
            info!("Received control code: {}", control_code);

            if let ServiceEvent::Stop = control_code {
                service.stop();
                break;
            }
        }
    }

    info!("{} service stopping", SERVICE_NAME);

    0
}

Service!("gateway", gateway_service_main);

#[cfg(unix)]
async fn build_signals_fut() -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

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
