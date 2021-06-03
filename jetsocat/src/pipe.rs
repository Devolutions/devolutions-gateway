use crate::proxy::ProxyConfig;
use anyhow::Result;
use slog::{debug, info, o, Logger};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::Command;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum PipeMode {
    Stdio,
    ProcessCmd(String),
    TcpListener(String),
    Tcp(String),
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
    WebSocket(String),
}

pub struct Pipe {
    name: &'static str,
    read: Box<dyn AsyncRead + Unpin>,
    write: Box<dyn AsyncWrite + Unpin>,
}

pub async fn open_pipe(mode: PipeMode, proxy_cfg: Option<ProxyConfig>, log: Logger) -> Result<Pipe> {
    use anyhow::Context as _;
    use std::process::Stdio;

    match mode {
        PipeMode::Stdio => Ok(Pipe {
            name: "stdio",
            read: Box::new(tokio::io::stdin()),
            write: Box::new(tokio::io::stdout()),
        }),
        PipeMode::ProcessCmd(command_string) => {
            info!(log, "Spawn process with command: {}", command_string);

            #[cfg(target_os = "windows")]
            let mut cmd = Command::new("cmd");
            #[cfg(target_os = "windows")]
            cmd.arg("/C");

            #[cfg(not(target_os = "windows"))]
            let mut cmd = Command::new("sh");
            #[cfg(not(target_os = "windows"))]
            cmd.arg("-c");

            let mut handle = cmd
                .arg(command_string)
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
            })
        }
        PipeMode::TcpListener(addr) => {
            use tokio::net::TcpListener;

            info!(log, "Listening for TCP on {}", addr);

            let listener = TcpListener::bind(addr)
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
            })
        }
        PipeMode::Tcp(addr) => {
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

            debug!(log, "Sending accept request...");
            write_jet_accept_request(&mut write, association_id, candidate_id).await?;
            debug!(log, "Accept request sent!");
            read_jet_accept_response(&mut read).await?;
            debug!(log, "Accept response received and processed successfully!");

            debug!(log, "Connected");

            Ok(Pipe {
                name: "jet-tcp-accept",
                read,
                write,
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

            debug!(log, "Sending connect request...");
            write_jet_connect_request(&mut write, association_id, candidate_id).await?;
            debug!(log, "Connect request sent!");
            read_jet_connect_response(&mut read).await?;
            debug!(log, "Connect response received and processed successfully!");

            debug!(log, "Connected");

            Ok(Pipe {
                name: "jet-tcp-connect",
                read,
                write,
            })
        }
        PipeMode::WebSocket(addr) => {
            use crate::utils::ws_connect;

            info!(log, "Connecting WebSocket to {}", addr);

            let (read, write, rsp) = ws_connect(addr, proxy_cfg)
                .await
                .with_context(|| "WebSocket connect failed")?;

            debug!(log, "Connected: {:?}", rsp);

            Ok(Pipe {
                name: "websocket",
                read,
                write,
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
