
use slog_scope::{info};

use std::{
    sync::mpsc
};

use ceviche::controller::*;
use ceviche::{Service, ServiceEvent};

mod service;
use service::GatewayService;

enum GatewayServiceEvent {}

fn gateway_service_main(
    rx: mpsc::Receiver<ServiceEvent<GatewayServiceEvent>>,
    _tx: mpsc::Sender<ServiceEvent<GatewayServiceEvent>>,
    args: Vec<String>,
    standalone_mode: bool,
) -> u32 {
    let service = GatewayService::load().expect("unable to load service");
    //init_logging(&service, standalone_mode);
    info!("{} service started", service.get_service_name());
    info!("args: {:?}", args);

    service.start();

    loop {
        if let Ok(control_code) = rx.recv() {
            info!("Received control code: {}", control_code);
            match control_code {
                ServiceEvent::Stop => {
                    service.stop();
                    break
                }
                _ => (),
            }
        }
    }

    info!("{} service stopping", service.get_service_name());
    0
}

Service!("gateway", gateway_service_main);

fn main() {
    let mut service = GatewayService::load().expect("unable to load service");
    service.run();
}
