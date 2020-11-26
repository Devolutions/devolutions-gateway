use devolutions_gateway::{config::Config, service::GatewayService};

use ceviche::{
    controller::{dispatch, Controller},
    Service, ServiceEvent,
};
use slog_scope::info;
use std::sync::mpsc;

enum GatewayServiceEvent {}

fn gateway_service_main(
    rx: mpsc::Receiver<ServiceEvent<GatewayServiceEvent>>,
    _tx: mpsc::Sender<ServiceEvent<GatewayServiceEvent>>,
    args: Vec<String>,
    _standalone_mode: bool,
) -> u32 {
    let mut service = GatewayService::load().expect("unable to load service");

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

#[tokio::main]
async fn main() -> Result<(), String> {
    let config = Config::init();

    if !config.service_mode {
        let mut service = GatewayService::load().expect("error loading service");

        service.start();

        // future waiting for some stop signals (CTRL-C…)
        let _ = build_signals_fut().await?;

        service.stop();
    } else {
        let mut controller = Controller::new(
            config.service_name.as_str(),
            config.display_name.as_str(),
            config.description.as_str(),
        );

        controller
            .register(service_main_wrapper)
            .map_err(|err| format!("failed to register service - {}", err))?;
    }
    Ok(())
}

#[cfg(unix)]
async fn build_signals_fut() -> Result<(), String> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate_signal =
        signal(SignalKind::terminate()).map_err(|err| format!("creating  terminate signal stream failed - {}", err))?;
    let mut quit_signal =
        signal(SignalKind::quit()).map_err(|err| format!("creating quit signal stream failed - {}", err))?;
    let mut interrupt_signal =
        signal(SignalKind::interrupt()).map_err(|err| format!("creating interrupt signal stream failed - {}", err))?;

    futures::future::select_all(vec![
        Box::pin(terminate_signal.recv()),
        Box::pin(quit_signal.recv()),
        Box::pin(interrupt_signal.recv()),
    ])
    .await;

    Ok(())
}

#[cfg(not(unix))]
async fn build_signals_fut() -> Result<(), String> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|err| format!("CTRL_C signal error - {:?}", err))
}
