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
use quinn as _;
use rand as _;
use reqwest as _;
use rustls as _;
use rustls_pemfile as _;
use rustls_pki_types as _;
use serde as _;
use serde_json as _;
use tap as _;
use tokio as _;
use tokio_rustls as _;
use url as _;
use uuid as _;
#[cfg(windows)]
use {
    aws_lc_rs as _, devolutions_pedm as _, hex as _, notify_debouncer_mini as _, sha2 as _, thiserror as _,
    win_api_wrappers as _, windows as _,
};

#[macro_use]
extern crate tracing;

mod service;

use std::env;
use std::sync::mpsc;

use anyhow::{Context as _, Result, bail};
use ceviche::Service;
use ceviche::controller::*;
use devolutions_agent::AgentServiceEvent;
use devolutions_agent::config::ConfHandle;
use devolutions_agent::enrollment::parse_enrollment_jwt;

use self::service::{AgentService, DESCRIPTION, DISPLAY_NAME, SERVICE_NAME};

const BAD_CONFIG_ERR_CODE: u32 = 1;
const START_FAILED_ERR_CODE: u32 = 2;

#[derive(Debug, PartialEq, Eq)]
struct UpCommand {
    gateway_url: String,
    enrollment_token: String,
    agent_name: String,
    advertise_subnets: Vec<String>,
    /// QUIC endpoint (`host:port`) the agent will connect to for the tunnel.
    /// Source precedence: CLI `--quic-endpoint` > JWT `jet_quic_endpoint` claim.
    /// The gateway does not report this — see `EnrollmentJwtClaims::jet_quic_endpoint`.
    quic_endpoint: String,
}

fn agent_service_main(
    rx: mpsc::Receiver<AgentServiceEvent>,
    _tx: mpsc::Sender<AgentServiceEvent>,
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
                | AgentServiceEvent::SessionLogoff(_) => {
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

fn parse_required_value(args: &[String], index: &mut usize, flag: &str) -> Result<String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .with_context(|| format!("missing value for {flag}"))
}

fn parse_advertise_subnets(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|subnet| !subnet.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_up_command_args(args: &[String]) -> Result<UpCommand> {
    let mut gateway_url = None;
    let mut enrollment_token = None;
    let mut agent_name = None;
    let mut enrollment_string = None;
    let mut advertise_subnets = Vec::new();
    let mut cli_quic_endpoint: Option<String> = None;

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();

        match arg {
            "--gateway" => gateway_url = Some(parse_required_value(args, &mut index, "--gateway")?),
            "--token" | "--enrollment-token" => enrollment_token = Some(parse_required_value(args, &mut index, arg)?),
            "--name" | "--agent-name" => agent_name = Some(parse_required_value(args, &mut index, arg)?),
            "--enrollment-string" => enrollment_string = Some(parse_required_value(args, &mut index, arg)?),
            "--quic-endpoint" => cli_quic_endpoint = Some(parse_required_value(args, &mut index, "--quic-endpoint")?),
            "--advertise-routes" | "--advertise-subnets" => {
                advertise_subnets.extend(parse_advertise_subnets(&parse_required_value(args, &mut index, arg)?))
            }
            unexpected => bail!("unknown argument for up: {unexpected}"),
        }

        index += 1;
    }

    let jwt_quic_endpoint = if let Some(enrollment_string) = enrollment_string {
        let claims = parse_enrollment_jwt(&enrollment_string)?;

        // The JWT itself is the Bearer token; the Gateway verifies the signature.
        gateway_url.get_or_insert(claims.jet_gw_url);
        enrollment_token.get_or_insert(enrollment_string);

        if agent_name.is_none() {
            agent_name = claims.jet_agent_name;
        }

        claims.jet_quic_endpoint
    } else {
        None
    };

    // CLI flag wins over JWT claim. At least one must be provided — the gateway does
    // not self-report a QUIC endpoint (see `EnrollmentJwtClaims::jet_quic_endpoint`).
    let quic_endpoint = cli_quic_endpoint
        .or(jwt_quic_endpoint)
        .context("missing QUIC endpoint: pass --quic-endpoint or include `jet_quic_endpoint` in the enrollment JWT")?;

    Ok(UpCommand {
        gateway_url: gateway_url.context("missing required --gateway")?,
        enrollment_token: enrollment_token.context("missing required --token")?,
        agent_name: agent_name.context("missing required --name")?,
        advertise_subnets,
        quic_endpoint,
    })
}

fn main() {
    let mut controller = Controller::new(SERVICE_NAME, DISPLAY_NAME, DESCRIPTION);

    if let Some(cmd) = env::args().nth(1) {
        match cmd.as_str() {
            "create" => {
                if let Err(e) = controller.create() {
                    println!("{e}");
                }
            }
            "delete" => {
                if let Err(e) = controller.delete() {
                    println!("{e}");
                }
            }
            "start" => {
                if let Err(e) = controller.start() {
                    println!("{e}");
                }
            }
            "stop" => {
                if let Err(e) = controller.stop() {
                    println!("{e}");
                }
            }
            "run" => {
                let (tx, rx) = mpsc::channel();
                let _tx = tx.clone();

                ctrlc::set_handler(move || {
                    let _ = tx.send(AgentServiceEvent::Stop);
                })
                .expect("failed to register Ctrl-C handler");

                agent_service_main(rx, _tx, vec![], true);
            }
            "config" => {
                let subcommand = env::args().nth(2).expect("missing config subcommand");
                if let Err(e) = devolutions_agent::config::handle_cli(subcommand.as_str()) {
                    eprintln!("[ERROR] Agent configuration failed: {e}");
                }
            }
            "enroll" => {
                let gateway_url = env::args()
                    .nth(2)
                    .expect("missing gateway URL (e.g., https://gateway.example.com:7171)");
                let enrollment_token = env::args().nth(3).expect("missing enrollment token");
                let agent_name = env::args().nth(4).expect("missing agent name");
                let quic_endpoint = env::args()
                    .nth(5)
                    .expect("missing QUIC endpoint (host:port) — required; gateway does not self-report it");
                let subnets_arg = env::args().nth(6).unwrap_or_default();

                let advertise_subnets: Vec<String> = if subnets_arg.is_empty() {
                    Vec::new()
                } else {
                    subnets_arg.split(',').map(|s| s.trim().to_owned()).collect()
                };

                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
                rt.block_on(async {
                    if let Err(e) = devolutions_agent::enrollment::enroll_agent(
                        &gateway_url,
                        &enrollment_token,
                        &agent_name,
                        advertise_subnets,
                        quic_endpoint,
                    )
                    .await
                    {
                        eprintln!("[ERROR] Enrollment failed: {e:#}");
                        std::process::exit(1);
                    }
                });
            }
            "up" => {
                let args: Vec<String> = env::args().skip(2).collect();
                let command = match parse_up_command_args(&args) {
                    Ok(command) => command,
                    Err(error) => {
                        eprintln!("[ERROR] Invalid up arguments: {error:#}");
                        std::process::exit(1);
                    }
                };

                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
                let result = rt.block_on(async {
                    devolutions_agent::enrollment::enroll_agent(
                        &command.gateway_url,
                        &command.enrollment_token,
                        &command.agent_name,
                        command.advertise_subnets,
                        command.quic_endpoint,
                    )
                    .await
                });

                if let Err(error) = result {
                    eprintln!("[ERROR] Bootstrap failed: {error:#}");
                    std::process::exit(1);
                }
            }
            _ => {
                eprintln!("[ERROR] Invalid command: {cmd}");
            }
        }
    } else {
        let _result = controller.register(service_main_wrapper);
    }
}

#[cfg(test)]
mod cli_tests;
