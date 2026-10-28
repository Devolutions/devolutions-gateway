#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

// Used by devolutions-agent library.
use agent_tunnel_proto as _;
use anyhow as _;
use async_trait as _;
use camino as _;
use devolutions_agent_shared as _;
use devolutions_gateway_task as _;
use devolutions_log as _;
use futures as _;
use http_client_proxy as _;
use ipnetwork as _;
use ironrdp as _;
use parking_lot as _;
use prost as _;
use prost_types as _;
use quinn as _;
use rand as _;
use reqwest as _;
use serde as _;
use serde_json as _;
use tap as _;
use tokio as _;
use tokio_rustls as _;
use tokio_stream as _;
use tonic as _;
use url as _;
use uuid as _;
#[cfg(windows)]
use {
    aws_lc_rs as _, devolutions_pedm as _, hex as _, notify_debouncer_mini as _, sha2 as _, thiserror as _,
    win_api_wrappers as _, windows as _,
};

#[macro_use]
extern crate tracing;

mod cli;
mod service;

use std::sync::mpsc;

use ceviche::Service;
use ceviche::controller::*;
use devolutions_agent::AgentServiceEvent;
use devolutions_agent::config::ConfHandle;

use self::service::{AgentService, SERVICE_NAME};

const BAD_CONFIG_ERR_CODE: u8 = 1;
const START_FAILED_ERR_CODE: u8 = 2;

fn agent_service_main(
    rx: mpsc::Receiver<AgentServiceEvent>,
    _tx: mpsc::Sender<AgentServiceEvent>,
    _args: Vec<String>,
    _standalone_mode: bool,
) -> u8 {
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

    let mut service_event_tx = service.service_event_tx();

    loop {
        if let Ok(control_code) = rx.recv() {
            info!(%control_code, "Received control code");

            match control_code {
                AgentServiceEvent::Stop => {
                    service.stop();
                    break;
                }
                AgentServiceEvent::SessionConnect(_)
                | AgentServiceEvent::SessionDisconnect(_)
                | AgentServiceEvent::SessionRemoteConnect(_)
                | AgentServiceEvent::SessionRemoteDisconnect(_)
                | AgentServiceEvent::SessionLogon(_)
                | AgentServiceEvent::SessionLogoff(_)
                | AgentServiceEvent::SessionUnlock(_) => {
                    if let Some(tx) = service_event_tx.as_mut() {
                        match tx.blocking_send(control_code) {
                            Ok(()) => {}
                            Err(error) => {
                                error!(%error, "Failed to send event to session manager");
                                service_event_tx = None;
                            }
                        }
                    }
                }

                _ => {}
            }
        }
    }

    info!("{} service stopping", SERVICE_NAME);

    0
}

Service!("agent", agent_service_main);

fn main() {
    cli::run();
}
