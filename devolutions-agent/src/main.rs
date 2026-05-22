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
    /// URL the agent POSTs `/jet/tunnel/enroll` to. When `--enrollment-string`
    /// is provided, `--gateway` may override this to route the enrollment
    /// transport differently (e.g. through a reverse proxy or an alternate
    /// reachable address); otherwise it falls back to the JWT's `jet_gw_url`.
    gateway_url: String,
    enrollment_token: String,
    agent_name: String,
    advertise_subnets: Vec<String>,
    /// Host used for the persisted QUIC tunnel identity (TLS SNI, SAN match).
    ///
    /// `Some(...)` whenever an enrollment JWT is in scope — always the JWT's
    /// validated `jet_gw_url` host, regardless of any `--gateway` transport
    /// override. `None` only in the legacy manual `--gateway + --token` mode,
    /// where the persisted endpoint falls back to `gateway_url`'s host.
    identity_host: Option<String>,
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

/// Default verify-tunnel timeout (matches what the installer CA hardcodes).
const VERIFY_TUNNEL_DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Parse `verify-tunnel` CLI arguments. Currently supports a single `--timeout
/// <secs>` flag and falls back to [`VERIFY_TUNNEL_DEFAULT_TIMEOUT_SECS`] when
/// absent.
fn parse_verify_tunnel_args(args: &[String]) -> Result<std::time::Duration> {
    let mut timeout_secs = VERIFY_TUNNEL_DEFAULT_TIMEOUT_SECS;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--timeout" => {
                let value = parse_required_value(args, &mut index, "--timeout")?;
                timeout_secs = value.parse::<u64>().context("--timeout must be a positive integer (seconds)")?;
                if timeout_secs == 0 {
                    bail!("--timeout must be > 0");
                }
            }
            unexpected => bail!("unknown argument for verify-tunnel: {unexpected}"),
        }
        index += 1;
    }
    Ok(std::time::Duration::from_secs(timeout_secs))
}

fn parse_up_command_args(args: &[String]) -> Result<UpCommand> {
    let mut gateway_url = None;
    let mut enrollment_token = None;
    let mut agent_name = None;
    let mut enrollment_string = None;
    let mut advertise_subnets = Vec::new();

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();

        match arg {
            "--gateway" => gateway_url = Some(parse_required_value(args, &mut index, "--gateway")?),
            "--token" | "--enrollment-token" => enrollment_token = Some(parse_required_value(args, &mut index, arg)?),
            "--name" | "--agent-name" => agent_name = Some(parse_required_value(args, &mut index, arg)?),
            "--enrollment-string" => enrollment_string = Some(parse_required_value(args, &mut index, arg)?),
            "--advertise-routes" | "--advertise-subnets" => {
                advertise_subnets.extend(parse_advertise_subnets(&parse_required_value(args, &mut index, arg)?))
            }
            unexpected => bail!("unknown argument for up: {unexpected}"),
        }

        index += 1;
    }

    let identity_host = if let Some(enrollment_string) = enrollment_string {
        let claims = parse_enrollment_jwt(&enrollment_string)?;

        // The validated `jet_gw_url` is the source of truth for the QUIC
        // tunnel identity (cert SAN match, TLS SNI). A `--gateway` override
        // — if any — only affects where the enrollment HTTP request is sent;
        // it must not bleed into the persisted endpoint.
        let identity_host = url::Url::parse(&claims.jet_gw_url)
            .with_context(|| format!("invalid jet_gw_url in enrollment JWT: {:?}", claims.jet_gw_url))?
            .host_str()
            .map(str::to_owned)
            .context("enrollment JWT jet_gw_url has no host component")?;

        // The JWT itself is the Bearer token; the Gateway verifies the signature.
        gateway_url.get_or_insert(claims.jet_gw_url);
        enrollment_token.get_or_insert(enrollment_string);

        if agent_name.is_none() {
            agent_name = claims.jet_agent_name;
        }

        Some(identity_host)
    } else {
        // Manual `--gateway + --token` mode: no JWT-validated identity, so we
        // fall back to the request URL's host downstream.
        None
    };

    Ok(UpCommand {
        gateway_url: gateway_url.context("missing required --gateway")?,
        enrollment_token: enrollment_token.context("missing required --token")?,
        agent_name: agent_name.context("missing required --name")?,
        advertise_subnets,
        identity_host,
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
                let subnets_arg = env::args().nth(5).unwrap_or_default();

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
                        None,
                    )
                    .await
                    {
                        eprintln!("[ERROR] Enrollment failed: {e:#}");
                        std::process::exit(1);
                    }
                });
            }
            "verify-tunnel" => {
                let args: Vec<String> = env::args().skip(2).collect();
                let timeout = match parse_verify_tunnel_args(&args) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        eprintln!("[ERROR] Invalid verify-tunnel arguments: {error:#}");
                        // Emit a structured unexpected_error triple so the installer CA still
                        // has something parseable on stderr.
                        let triple = devolutions_agent::verify_tunnel::ErrorTriple::new(
                            devolutions_agent::verify_tunnel::ErrorKind::UnexpectedError,
                            format!("verify-tunnel argument parse error: {error:#}"),
                        );
                        triple.emit_to_stderr();
                        std::process::exit(1);
                    }
                };

                let conf_handle = match ConfHandle::init() {
                    Ok(handle) => handle,
                    Err(error) => {
                        let triple = devolutions_agent::verify_tunnel::ErrorTriple::new(
                            devolutions_agent::verify_tunnel::ErrorKind::UnexpectedError,
                            format!("failed to load agent configuration: {error:#}"),
                        );
                        triple.emit_to_stderr();
                        std::process::exit(1);
                    }
                };

                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
                let result = rt.block_on(devolutions_agent::verify_tunnel::verify_tunnel(&conf_handle, timeout));

                match result {
                    Ok(()) => {
                        // Success path: nothing on stderr — installer CA only consumes stderr
                        // and absence of a JSON triple confirms the verification succeeded.
                        println!("verify-tunnel: tunnel is reachable and route-advertise round-trip ok");
                    }
                    Err(triple) => {
                        triple.emit_to_stderr();
                        std::process::exit(1);
                    }
                }
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
                        command.identity_host.as_deref(),
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
mod tests {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn parse_up_command_args_uses_default_config_path() {
        let args = vec![
            "--gateway".to_owned(),
            "https://gateway.example.com:7171".to_owned(),
            "--token".to_owned(),
            "bootstrap-token".to_owned(),
            "--name".to_owned(),
            "site-a-agent".to_owned(),
            "--advertise-routes".to_owned(),
            "10.0.0.0/8,192.168.1.0/24".to_owned(),
        ];

        let parsed = parse_up_command_args(&args).expect("parse up args");

        assert_eq!(
            parsed,
            UpCommand {
                gateway_url: "https://gateway.example.com:7171".to_owned(),
                enrollment_token: "bootstrap-token".to_owned(),
                agent_name: "site-a-agent".to_owned(),
                advertise_subnets: vec!["10.0.0.0/8".to_owned(), "192.168.1.0/24".to_owned()],
                // Manual --gateway + --token mode: no JWT-validated identity.
                identity_host: None,
            }
        );
    }

    #[test]
    fn parse_up_command_args_accepts_aliases() {
        let args = vec![
            "--gateway".to_owned(),
            "https://gateway.example.com:7171".to_owned(),
            "--enrollment-token".to_owned(),
            "bootstrap-token".to_owned(),
            "--agent-name".to_owned(),
            "site-a-agent".to_owned(),
            "--advertise-subnets".to_owned(),
            "10.0.0.0/8".to_owned(),
        ];

        let parsed = parse_up_command_args(&args).expect("parse up args");

        assert_eq!(parsed.advertise_subnets, vec!["10.0.0.0/8".to_owned()]);
    }

    /// Build a JWT with the given payload. The header and signature are placeholders —
    /// the agent does not verify them; only the Gateway does.
    fn make_jwt(payload: serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            b64.encode(header.to_string()),
            b64.encode(payload.to_string()),
            b64.encode("signature-placeholder"),
        )
    }

    #[test]
    fn parse_verify_tunnel_defaults_to_10s() {
        let timeout = parse_verify_tunnel_args(&[]).expect("parse empty");
        assert_eq!(timeout, std::time::Duration::from_secs(10));
    }

    #[test]
    fn parse_verify_tunnel_explicit_timeout() {
        let timeout = parse_verify_tunnel_args(&["--timeout".to_owned(), "30".to_owned()]).expect("parse");
        assert_eq!(timeout, std::time::Duration::from_secs(30));
    }

    #[test]
    fn parse_verify_tunnel_rejects_zero_timeout() {
        let err = parse_verify_tunnel_args(&["--timeout".to_owned(), "0".to_owned()]).expect_err("expect rejection");
        assert!(format!("{err:#}").contains("> 0"), "{err:#}");
    }

    #[test]
    fn parse_verify_tunnel_rejects_unknown_flag() {
        let err = parse_verify_tunnel_args(&["--bogus".to_owned()]).expect_err("expect rejection");
        assert!(format!("{err:#}").contains("--bogus"), "{err:#}");
    }

    #[test]
    fn parse_up_command_args_accepts_enrollment_string() {
        let jwt = make_jwt(serde_json::json!({
            "scope": "gateway.tunnel.enroll",
            "exp": 1_999_999_999i64,
            "jti": "00000000-0000-0000-0000-000000000000",
            "jet_gw_url": "https://gateway.example.com:7171",
            "jet_agent_name": "site-a-agent",
        }));
        let args = vec!["--enrollment-string".to_owned(), jwt.clone()];

        let parsed = parse_up_command_args(&args).expect("parse up args");

        assert_eq!(parsed.gateway_url, "https://gateway.example.com:7171");
        // The JWT itself is used as the Bearer token for /jet/tunnel/enroll.
        assert_eq!(parsed.enrollment_token, jwt);
        assert_eq!(parsed.agent_name, "site-a-agent");
        // Identity host comes from the JWT, even though no override was used.
        assert_eq!(parsed.identity_host.as_deref(), Some("gateway.example.com"));
    }

    /// `--gateway` may override the enrollment transport URL, but it must NOT
    /// affect the persisted QUIC tunnel identity. The validated `jet_gw_url`
    /// host from the JWT remains the source of truth for what the agent
    /// dials at runtime (and therefore what the Gateway's server cert SAN
    /// must contain).
    ///
    /// Regression test for the codex-flagged P2 finding:
    ///   "--gateway override is okay, but it must be enrollment-transport-only.
    ///    The persisted QUIC endpoint must come from the JWT's validated
    ///    jet_gw_url host, not the override URL."
    #[test]
    fn parse_up_command_args_gateway_override_does_not_change_identity_host() {
        let jwt = make_jwt(serde_json::json!({
            "scope": "gateway.tunnel.enroll",
            "exp": 1_999_999_999i64,
            "jti": "00000000-0000-0000-0000-000000000000",
            "jet_gw_url": "https://gateway.corp.example.com:7171",
            "jet_agent_name": "site-a-agent",
        }));
        let args = vec![
            "--enrollment-string".to_owned(),
            jwt,
            "--gateway".to_owned(),
            "http://10.10.0.7:7777".to_owned(),
        ];

        let parsed = parse_up_command_args(&args).expect("parse up args");

        // Transport URL follows the CLI override.
        assert_eq!(parsed.gateway_url, "http://10.10.0.7:7777");
        // Identity stays anchored to the JWT-validated host.
        assert_eq!(parsed.identity_host.as_deref(), Some("gateway.corp.example.com"));
    }

    #[test]
    fn parse_up_command_args_rejects_jwt_without_jet_gw_url_host() {
        let jwt = make_jwt(serde_json::json!({
            "scope": "gateway.tunnel.enroll",
            "exp": 1_999_999_999i64,
            "jti": "00000000-0000-0000-0000-000000000000",
            "jet_gw_url": "not a url",
            "jet_agent_name": "site-a-agent",
        }));
        let args = vec!["--enrollment-string".to_owned(), jwt];

        let err = parse_up_command_args(&args).expect_err("malformed jet_gw_url must fail");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("jet_gw_url"),
            "error should mention the offending field, got: {chain}"
        );
    }
}
