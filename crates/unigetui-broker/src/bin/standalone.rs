//! Standalone UniGetUI broker server for testing.
//!
//! Runs the broker HTTP server on a named pipe (Windows) or TCP loopback (development).
//! By default operates in dry-run mode — builds WinGet commands but only logs them.
//!
//! Usage:
//!   unigetui-broker-standalone [OPTIONS]
//!
//! Options:
//!   --policy <PATH>      Path to policy JSON file (default: %PROGRAMDATA%/Devolutions/Agent/unigetui-policy.json)
//!   --pipe <NAME>        Named pipe name (default: \\.\pipe\UniGetUI.PackageBroker.v1)
//!   --tcp <ADDR:PORT>    Also listen on TCP for development (e.g., 127.0.0.1:8765)
//!   --execute            Enable real command execution (default: dry-run)
//!   --help               Show this help

// CLI binary legitimately uses stderr for user-facing messages.
#![allow(clippy::print_stderr)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Notify;
use unigetui_broker::executor::{CommandExecutor, DryRunExecutor};
use unigetui_broker::pipe::DEFAULT_PIPE_NAME;
use unigetui_broker::policy_loader;
use unigetui_broker::server::BrokerState;

#[derive(Debug)]
struct Args {
    policy_path: Option<PathBuf>,
    pipe_name: String,
    tcp_addr: Option<SocketAddr>,
    execute: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        policy_path: None,
        pipe_name: DEFAULT_PIPE_NAME.to_owned(),
        tcp_addr: None,
        execute: false,
    };

    let raw: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < raw.len() {
        match raw[i].as_str() {
            "--policy" => {
                i += 1;
                if i < raw.len() {
                    args.policy_path = Some(PathBuf::from(&raw[i]));
                }
            }
            "--pipe" => {
                i += 1;
                if i < raw.len() {
                    args.pipe_name = raw[i].clone();
                }
            }
            "--tcp" => {
                i += 1;
                if i < raw.len() {
                    args.tcp_addr = Some(raw[i].parse().expect("invalid TCP address"));
                }
            }
            "--execute" => {
                args.execute = true;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
                print_help();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    args
}

fn print_help() {
    eprintln!(
        r#"UniGetUI Package Broker — Standalone Test Server

Usage: unigetui-broker-standalone [OPTIONS]

Options:
  --policy <PATH>    Path to policy JSON file
                     (default: %PROGRAMDATA%/Devolutions/Agent/unigetui-policy.json)
  --pipe <NAME>      Named pipe name
                     (default: \\.\pipe\UniGetUI.PackageBroker.v1)
  --tcp <ADDR:PORT>  Also listen on TCP for development (e.g., 127.0.0.1:8765)
  --execute          Enable real command execution (default: dry-run)
  --help             Show this help

In dry-run mode (default), the broker evaluates policies and builds commands
but only logs them without executing. Use --execute to actually run WinGet.
"#
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = parse_args();

    // Load policy.
    let policy_path = match args.policy_path {
        Some(p) => p,
        None => policy_loader::find_default_policy()?,
    };
    let policy = policy_loader::load_policy(&policy_path)?;

    let executor: Box<dyn CommandExecutor> = if args.execute {
        tracing::warn!("Running in EXECUTE mode — commands will be run!");
        #[cfg(windows)]
        {
            Box::new(unigetui_broker::executor::WindowsExecutor::new())
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("execute mode is only supported on Windows");
        }
    } else {
        tracing::info!("Running in DRY-RUN mode — commands will only be logged");
        Box::new(DryRunExecutor)
    };

    let state = Arc::new(BrokerState {
        policy: std::sync::RwLock::new(Some(Arc::new(policy))),
        executor,
        pipe_name: args.pipe_name.clone(),
        tracker: unigetui_broker::operation_tracker::OperationTracker::new(),
    });

    let shutdown = Arc::new(Notify::new());

    // Set up Ctrl+C handler.
    let shutdown_signal = Arc::clone(&shutdown);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Received Ctrl+C, shutting down");
        shutdown_signal.notify_waiters();
    });

    // Start TCP listener for development if requested.
    if let Some(tcp_addr) = args.tcp_addr {
        let tcp_state = Arc::clone(&state);
        let tcp_shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move {
            if let Err(error) = run_tcp_server(tcp_state, tcp_addr, tcp_shutdown).await {
                tracing::error!(%error, "TCP server error");
            }
        });
    }

    // Start named pipe server (Windows only).
    #[cfg(windows)]
    {
        tracing::info!(pipe = %args.pipe_name, "Listening on named pipe");
        if let Some(addr) = args.tcp_addr {
            tracing::info!(%addr, "Also listening on TCP");
        }
        unigetui_broker::pipe::run_pipe_server(state, shutdown).await?;
    }

    #[cfg(not(windows))]
    {
        if args.tcp_addr.is_some() {
            tracing::info!("Named pipe not available on this platform, using TCP only");
            // Wait for shutdown.
            shutdown.notified().await;
        } else {
            anyhow::bail!("named pipe is not available on this platform; use --tcp to listen on TCP");
        }
    }

    Ok(())
}

async fn run_tcp_server(state: Arc<BrokerState>, addr: SocketAddr, shutdown: Arc<Notify>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "TCP server listening");

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        tracing::debug!(%peer, "TCP connection accepted");
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            unigetui_broker::server::serve_connection(stream, state).await;
                        });
                    }
                    Err(error) => {
                        tracing::error!(%error, "TCP accept error");
                    }
                }
            }
            _ = shutdown.notified() => {
                return Ok(());
            }
        }
    }
}
