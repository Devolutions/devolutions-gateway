mod config;
mod service;

use ceviche::{controller::*, Service, ServiceEvent};
use futures::{Future, Stream};
use config::Config;
use service::GatewayService;
use slog_scope::info;
use std::sync::mpsc;

#[allow(dead_code)]
enum GatewayServiceEvent {}

#[allow(dead_code)]
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

fn main() {
    let config = Config::load().unwrap_or_else(|| Config::init());

    if config.console_mode {
        let mut service = GatewayService::load().expect("error loading service");

        service.start();
    
        // future waiting for some stop signals (CTRL-C…)
        let signals_fut = build_signals_fut();
        let mut runtime = tokio::runtime::Runtime::new().expect("failed to create runtime");
        runtime
            .block_on(signals_fut)
            .expect("couldn't block waiting for signals");
    
        service.stop();
    } else {
        let mut controller = Controller::new(config.service_name.as_str(),
            config.display_name.as_str(), config.description.as_str());

        controller.register(service_main_wrapper).expect("failed to register service");
    }
}

#[cfg(unix)]
fn build_signals_fut() -> Box<dyn Future<Item = (), Error = ()> + Send> {
    use tokio_signal::unix::{Signal, SIGINT, SIGQUIT, SIGTERM};

    let fut = futures::future::select_all(vec![
        Signal::new(SIGTERM).flatten_stream().into_future(),
        Signal::new(SIGQUIT).flatten_stream().into_future(),
        Signal::new(SIGINT).flatten_stream().into_future(),
    ]);

    Box::new(fut.map(|_| ()).map_err(|_| ()))
}

#[cfg(not(unix))]
fn build_signals_fut() -> Box<dyn Future<Item = (), Error = ()> + Send> {
    let fut = futures::future::select_all(vec![tokio_signal::ctrl_c().flatten_stream().into_future()]);
    Box::new(fut.map(|_| ()).map_err(|_| ()))
}
