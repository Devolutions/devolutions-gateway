use crate::proxy::ProxyConfig;
use anyhow::Result;
use slog::{debug, info, o, Logger};
use std::any::Any;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum PipeMode {
    Stdio,
    ProcessCmd {
        command: String,
    },
    TcpListener {
        bind_addr: String,
    },
    Tcp {
        addr: String,
    },
    JetTcpAccept {
        addr: String,
        association_id: Uuid,
        candidate_id: Uuid,
    },
    JetTcpConnect {
        addr: String,
        association_id: Uuid,
        candidate_id: Uuid,
    },
    WebSocket {
        url: String,
    },
}

pub struct Pipe {
    name: &'static str,
    read: Box<dyn AsyncRead + Unpin>,
    write: Box<dyn AsyncWrite + Unpin>,

    // Useful when we don't want to drop something before the Pipe
    _handle: Option<Box<dyn Any>>,
}

pub async fn open_pipe(mode: PipeMode, proxy_cfg: Option<ProxyConfig>, log: Logger) -> Result<Pipe> {
    use anyhow::Context as _;
    use std::process::Stdio;
    use tokio::process::Command;

    match mode {
        PipeMode::Stdio => Ok(Pipe {
            name: "stdio",
            read: Box::new(tokio::io::stdin()),
            write: Box::new(tokio::io::stdout()),
            _handle: None,
        }),
        PipeMode::ProcessCmd { command } => {
            info!(log, "Spawn process with command: {}", command);

            #[cfg(target_os = "windows")]
            let mut cmd = Command::new("cmd");
            #[cfg(target_os = "windows")]
            cmd.arg("/C");

            #[cfg(not(target_os = "windows"))]
            let mut cmd = Command::new("sh");
            #[cfg(not(target_os = "windows"))]
            cmd.arg("-c");

            let mut handle = cmd
                .arg(command)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .with_context(|| format!("Spawn with command: {:?}", cmd))?;

            let stdout = handle.stdout.take().expect("spawned above");
            let stdin = handle.stdin.take().expect("spawned above");

            Ok(Pipe {
                name: "process",
                read: Box::new(stdout),
                write: Box::new(stdin),
                _handle: Some(Box::new(handle)), // we need to store the handle because of kill_on_drop(true)
            })
        }
        PipeMode::TcpListener { bind_addr } => {
            use tokio::net::TcpListener;

            info!(log, "Listening for TCP on {}", bind_addr);

            let listener = TcpListener::bind(bind_addr)
                .await
                .with_context(|| "Failed to bind TCP listener")?;
            let (socket, peer_addr) = listener
                .accept()
                .await
                .with_context(|| "TCP listener couldn't accept")?;

            info!(log, "Accepted {}", peer_addr);

            let (read, write) = tokio::io::split(socket);

            Ok(Pipe {
                name: "tcp-listener",
                read: Box::new(read),
                write: Box::new(write),
                _handle: None,
            })
        }
        PipeMode::Tcp { addr } => {
            use crate::utils::tcp_connect;

            info!(log, "Connecting TCP to {}", addr);

            let (read, write) = tcp_connect(addr, proxy_cfg)
                .await
                .with_context(|| "TCP connect failed")?;

            debug!(log, "Connected");

            Ok(Pipe {
                name: "tcp",
                read,
                write,
                _handle: None,
            })
        }
        PipeMode::JetTcpAccept {
            addr,
            association_id,
            candidate_id,
        } => {
            use crate::jet::{read_jet_accept_response, write_jet_accept_request};
            use crate::utils::tcp_connect;

            info!(
                log,
                "Connecting TCP to {} with JET accept protocol for {}/{}", addr, association_id, candidate_id
            );

            let (mut read, mut write) = tcp_connect(addr, proxy_cfg)
                .await
                .with_context(|| "TCP connect failed")?;

            debug!(log, "Sending JET accept request…");
            write_jet_accept_request(&mut write, association_id, candidate_id).await?;
            debug!(log, "JET accept request sent, waiting for response…");
            read_jet_accept_response(&mut read).await?;
            debug!(log, "JET accept response received and processed successfully!");

            debug!(log, "Connected");

            Ok(Pipe {
                name: "jet-tcp-accept",
                read,
                write,
                _handle: None,
            })
        }
        PipeMode::JetTcpConnect {
            addr,
            association_id,
            candidate_id,
        } => {
            use crate::jet::{read_jet_connect_response, write_jet_connect_request};
            use crate::utils::tcp_connect;

            info!(
                log,
                "Connecting TCP to {} with JET connect protocol for {}/{}", addr, association_id, candidate_id
            );

            let (mut read, mut write) = tcp_connect(addr, proxy_cfg)
                .await
                .with_context(|| "TCP connect failed")?;

            debug!(log, "Sending JET connect request…");
            write_jet_connect_request(&mut write, association_id, candidate_id).await?;
            debug!(log, "JET connect request sent, waiting for response…");
            read_jet_connect_response(&mut read).await?;
            debug!(log, "JET connect response received and processed successfully!");

            debug!(log, "Connected");

            Ok(Pipe {
                name: "jet-tcp-connect",
                read,
                write,
                _handle: None,
            })
        }
        PipeMode::WebSocket { url } => {
            use crate::utils::ws_connect;

            info!(log, "Connecting WebSocket at {}", url);

            let (read, write, rsp) = ws_connect(url, proxy_cfg)
                .await
                .with_context(|| "WebSocket connect failed")?;

            debug!(log, "Connected: {:?}", rsp);

            Ok(Pipe {
                name: "websocket",
                read,
                write,
                _handle: None,
            })
        }
    }
}

pub async fn pipe(a: Pipe, b: Pipe, log: slog::Logger) -> Result<()> {
    use crate::io::forward;
    use futures_util::future::Either;
    use futures_util::{future, pin_mut};

    let a_to_b = forward(a.read, b.write, log.new(o!(b.name => format!("← {}", a.name))));
    let b_to_a = forward(b.read, a.write, log.new(o!(b.name => format!("→ {}", a.name))));

    info!(log, "Piping {} with {}", a.name, b.name);

    pin_mut!(b_to_a, a_to_b);
    let result = match future::select(b_to_a, a_to_b).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    };

    info!(log, "Ended");

    result
}
