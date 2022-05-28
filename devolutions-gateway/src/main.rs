use anyhow::Context;
use ceviche::controller::{dispatch, Controller, ControllerInterface};
use ceviche::{Service, ServiceEvent};
use cfg_if::cfg_if;
use clap::{crate_name, crate_version, App, SubCommand};
use devolutions_gateway::config::Config;
use devolutions_gateway::service::GatewayService;
use std::sync::mpsc;
use tracing::info;

enum GatewayServiceEvent {}

fn gateway_service_main(
    rx: mpsc::Receiver<ServiceEvent<GatewayServiceEvent>>,
    _tx: mpsc::Sender<ServiceEvent<GatewayServiceEvent>>,
    args: Vec<String>,
    _standalone_mode: bool,
) -> u32 {
    let config = Config::init();
    let mut service = GatewayService::load(config).expect("unable to load service");

    info!("{} service started", service.get_service_name());
    info!("args: {:?}", args);

    service.start();

    loop {
        if let Ok(control_code) = rx.recv() {
            info!("Received control code: {}", control_code);

            if let ServiceEvent::Stop = control_code {
                service.stop();
                break;
            }
        }
    }

    info!("{} service stopping", service.get_service_name());

    0
}

Service!("gateway", gateway_service_main);

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if (args.len() > 1) && (!args[1].starts_with('-')) {
        let cli_app = App::new(crate_name!())
            .author("Devolutions Inc.")
            .version(concat!(crate_version!(), "\n"))
            .version_short("v")
            .about("Devolutions Gateway")
            .subcommand(
                SubCommand::with_name("service")
                    .subcommand(SubCommand::with_name("register"))
                    .subcommand(SubCommand::with_name("unregister")),
            );

        match cli_app.get_matches().subcommand() {
            ("service", Some(matches)) => {
                let service_name = devolutions_gateway::config::SERVICE_NAME;
                let display_name = devolutions_gateway::config::DISPLAY_NAME;
                let description = devolutions_gateway::config::DESCRIPTION;
                let mut controller = Controller::new(service_name, display_name, description);

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

                match matches.subcommand() {
                    ("register", Some(_matches)) => {
                        controller.create().context("failed to register service")?;
                    }
                    ("unregister", Some(_matches)) => {
                        controller.delete().context("failed to unregister service")?;
                    }
                    _ => anyhow::bail!("invalid service subcommand"),
                }
            }
            _ => anyhow::bail!("invalid command"),
        }
    } else {
        let config = Config::init();

        if !config.service_mode {
            let mut service = GatewayService::load(config).context("Service loading failed")?;

            service.start();

            // Waiting for some stop signals (CTRL-C…)
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap();
            rt.block_on(build_signals_fut())?;

            service.stop();
        } else {
            let mut controller = Controller::new(
                config.service_name.as_str(),
                config.display_name.as_str(),
                config.description.as_str(),
            );

            controller
                .register(service_main_wrapper)
                .context("failed to register service")?;
        }
    }

    Ok(())
}

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
