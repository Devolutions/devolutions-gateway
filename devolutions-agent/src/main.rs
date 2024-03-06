use std::env;
use std::sync::mpsc;

use ceviche::controller::*;
use ceviche::{Service, ServiceEvent};

pub const SERVICE_NAME: &str = "devolutions-agent";
pub const DISPLAY_NAME: &str = "Devolutions Agent";
pub const DESCRIPTION: &str = "Devolutions Agent service";
pub const COMPANY_NAME: &str = "Devolutions";

pub struct AgentService {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub company_name: String,
}

impl AgentService {
    pub fn load() -> Option<Self> {
        Some(AgentService {
            service_name: SERVICE_NAME.to_string(),
            display_name: DISPLAY_NAME.to_string(),
            description: DESCRIPTION.to_string(),
            company_name: COMPANY_NAME.to_string(),
        })
    }

    pub fn get_service_name(&self) -> &str {
        self.service_name.as_str()
    }

    pub fn get_display_name(&self) -> &str {
        self.display_name.as_str()
    }

    pub fn get_description(&self) -> &str {
        self.service_name.as_str()
    }

    pub fn get_company_name(&self) -> &str {
        self.company_name.as_str()
    }

    pub fn start(&self) {}

    pub fn stop(&self) {}
}

enum AgentServiceEvent {}

fn agent_service_main(
    rx: mpsc::Receiver<ServiceEvent<AgentServiceEvent>>,
    _tx: mpsc::Sender<ServiceEvent<AgentServiceEvent>>,
    _args: Vec<String>,
    _standalone_mode: bool,
) -> u32 {
    let service = AgentService::load().expect("unable to load agent");

    service.start();

    loop {
        if let Ok(control_code) = rx.recv() {
            match control_code {
                ServiceEvent::Stop => {
                    service.stop();
                    break;
                }
                _ => (),
            }
        }
    }

    0
}

Service!("agent", agent_service_main);

fn main() {
    let service = AgentService::load().expect("unable to load agent service");
    let mut controller = Controller::new(
        service.get_service_name(),
        service.get_display_name(),
        service.get_description(),
    );

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
            _ => {
                println!("invalid command: {}", cmd);
            }
        }
    } else {
        let _result = controller.register(service_main_wrapper);
    }
}
