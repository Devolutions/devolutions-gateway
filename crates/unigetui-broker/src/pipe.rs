//! Named pipe transport for Windows.
//!
//! Creates a named pipe server with appropriate ACLs and accepts connections,
//! forwarding them to the HTTP server.

#[cfg(windows)]
mod windows_pipe {
    use std::sync::Arc;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::sync::Notify;

    use crate::server::{BrokerState, serve_connection};

    /// Default pipe name for the UniGetUI package broker.
    pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\UniGetUI.PackageBroker.v1";

    /// Start the named pipe server and accept connections until shutdown.
    pub async fn run_pipe_server(state: Arc<BrokerState>, shutdown: Arc<Notify>) -> anyhow::Result<()> {
        let pipe_name = &state.pipe_name;
        tracing::info!(%pipe_name, "Starting named pipe server");

        loop {
            // Create a new pipe instance for each connection.
            let server = create_pipe_instance(pipe_name)?;

            tokio::select! {
                result = server.connect() => {
                    match result {
                        Ok(()) => {
                            let state = Arc::clone(&state);
                            tokio::spawn(async move {
                                serve_connection(server, state).await;
                            });
                        }
                        Err(error) => {
                            tracing::error!(%error, "Failed to accept pipe connection");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    tracing::info!("Pipe server shutting down");
                    return Ok(());
                }
            }
        }
    }

    fn create_pipe_instance(pipe_name: &str) -> anyhow::Result<NamedPipeServer> {
        // Create pipe with default security for now.
        // In production, this should set an ACL that:
        // 1. Allows SYSTEM full control
        // 2. Allows Administrators full control
        // 3. Allows authenticated interactive users to connect
        // 4. Denies network access
        let server = ServerOptions::new().first_pipe_instance(false).create(pipe_name)?;

        Ok(server)
    }
}

#[cfg(windows)]
pub use windows_pipe::*;

/// Fallback for non-Windows (pipe transport not supported).
#[cfg(not(windows))]
pub const DEFAULT_PIPE_NAME: &str = "not-supported-on-this-platform";

#[cfg(not(windows))]
pub async fn run_pipe_server(
    _state: std::sync::Arc<crate::server::BrokerState>,
    _shutdown: std::sync::Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    anyhow::bail!("named pipe transport is only supported on Windows")
}
