#[macro_use]
extern crate tracing;

use std::env;
use std::sync::mpsc;

use ceviche::controller::*;
use ceviche::{Service, ServiceEvent};

use devolutions_agent::config::ConfHandle;
use devolutions_agent::service::{AgentService, DESCRIPTION, DISPLAY_NAME, SERVICE_NAME};

const BAD_CONFIG_ERR_CODE: u32 = 1;
const START_FAILED_ERR_CODE: u32 = 2;

enum AgentServiceEvent {}

fn agent_service_main(
    rx: mpsc::Receiver<ServiceEvent<AgentServiceEvent>>,
    _tx: mpsc::Sender<ServiceEvent<AgentServiceEvent>>,
    _args: Vec<String>,
    _standalone_mode: bool,
) -> u32 {
    let Ok(conf_handle) = ConfHandle::init() else {
        // At this point, the logger is not yet initialized.
        return BAD_CONFIG_ERR_CODE;
    };

    let mut service = match AgentService::load(conf_handle) {
        Ok(service) => service,
        Err(error) => {
            // At this point, the logger may or may not be initialized.
            error!(error = format!("{error:#}"), "Failed to load service");
            return START_FAILED_ERR_CODE;
        }
    };

    match service.start() {
        Ok(()) => info!("{} service started", SERVICE_NAME),
        Err(error) => {
            error!(error = format!("{error:#}"), "Failed to start");
            return START_FAILED_ERR_CODE;
        }
    }

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

Service!("agent", agent_service_main);

fn main() {
    let mut controller = Controller::new(SERVICE_NAME, DISPLAY_NAME, DESCRIPTION);

    if let Some(cmd) = env::args().nth(1) {
        match cmd.as_str() {
            "create" => {
                if let Err(e) = controller.create() {
                    println!("{}", e);
                }
            }
            "delete" => {
                if let Err(e) = controller.delete() {
                    println!("{}", e);
                }
            }
            "start" => {
                if let Err(e) = controller.start() {
                    println!("{}", e);
                }
            }
            "stop" => {
                if let Err(e) = controller.stop() {
                    println!("{}", e);
                }
            }
            "run" => {
                let (tx, rx) = mpsc::channel();
                let _tx = tx.clone();

                ctrlc::set_handler(move || {
                    let _ = tx.send(ServiceEvent::Stop);
                })
                .expect("Failed to register Ctrl-C handler");

                agent_service_main(rx, _tx, vec![], true);
            }
            "config" => {
                let subcommand = env::args().nth(2).expect("missing config subcommand");
                if let Err(e) = devolutions_agent::config::handle_cli(subcommand.as_str()) {
                    eprintln!("[ERROR] Agent configuration failed: {}", e);
                }
            }
            _ => {
                eprintln!("invalid command: {}", cmd);
            }
        }
    } else {
        let _result = controller.register(service_main_wrapper);
    }
}
