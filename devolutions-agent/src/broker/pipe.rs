//! Named pipe transport for Windows.
//!
//! Creates a named pipe server with appropriate ACLs and accepts connections,
//! forwarding them to the HTTP server.

#[cfg(windows)]
mod windows_pipe {
    use std::sync::Arc;

    use anyhow::Context as _;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::sync::Notify;
    use tracing::{error, info, warn};
    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
    use win_api_wrappers::security::attributes::SecurityAttributesInit;
    use windows::Win32::Foundation::GENERIC_ALL;
    use windows::Win32::Security;
    use windows::Win32::Security::Authorization::SET_ACCESS;
    use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};

    use crate::broker::auth::PipeClient;
    use crate::broker::server::{BrokerState, build_router_for_client, serve_connection};

    /// Default pipe name for the package broker.
    pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\Devolutions.Now.PackageBroker.v1";

    /// Start the named pipe server and accept connections until shutdown.
    pub async fn run_pipe_server(state: Arc<BrokerState>, shutdown: Arc<Notify>) -> anyhow::Result<()> {
        let pipe_name = state.pipe_name.clone();
        info!(%pipe_name, "Starting named pipe server");

        loop {
            // Create a new pipe instance for each connection.
            let server = create_pipe_instance(&pipe_name)?;

            tokio::select! {
                result = server.connect() => {
                    match result {
                        Ok(()) => {
                            let client = match PipeClient::from_connected_pipe(&server) {
                                Ok(client) => client,
                                Err(error) => {
                                    warn!(%error, "Rejected named pipe client");
                                    continue;
                                }
                            };
                            info!("Client connected to named pipe");
                            let router = build_router_for_client(Arc::clone(&state), client);
                            tokio::spawn(async move {
                                serve_connection(server, router).await;
                                info!("Client disconnected from named pipe");
                            });
                        }
                        Err(error) => {
                            error!(%error, "Failed to accept pipe connection");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    info!("Pipe server shutting down");
                    return Ok(());
                }
            }
        }
    }

    fn create_pipe_instance(pipe_name: &str) -> anyhow::Result<NamedPipeServer> {
        let security_attributes =
            build_pipe_security_attributes().context("failed to build pipe security attributes")?;

        // SAFETY: `create_with_security_attributes_raw` requires a pointer to a valid
        // `SECURITY_ATTRIBUTES` that stays alive for the duration of the call. The pointer
        // comes from `security_attributes` (a `win_api_wrappers::security::SecurityAttributes`),
        // a local binding that owns the structure and its security descriptor and is dropped
        // only at the end of this function, well after the call returns. `CreateNamedPipeW`
        // copies the descriptor at creation, so the pointer is not retained afterwards.
        let server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(false)
                .create_with_security_attributes_raw(pipe_name, security_attributes.as_mut_ptr().cast())
        }?;

        Ok(server)
    }

    /// Build a security descriptor that grants:
    /// - SYSTEM: full control
    /// - Administrators: full control
    /// - BUILTIN\Users: read + write (allows interactive users to connect)
    fn build_pipe_security_attributes() -> anyhow::Result<win_api_wrappers::security::attributes::SecurityAttributes> {
        let system_sid =
            Sid::from_well_known(Security::WinLocalSystemSid, None).context("failed to create SYSTEM SID")?;
        let admins_sid = Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None)
            .context("failed to create Administrators SID")?;
        let users_sid =
            Sid::from_well_known(Security::WinBuiltinUsersSid, None).context("failed to create Users SID")?;

        let entries = [
            ExplicitAccess {
                access_permissions: GENERIC_ALL.0,
                access_mode: SET_ACCESS,
                inheritance: Security::ACE_FLAGS(0),
                trustee: Trustee::Sid(system_sid),
            },
            ExplicitAccess {
                access_permissions: GENERIC_ALL.0,
                access_mode: SET_ACCESS,
                inheritance: Security::ACE_FLAGS(0),
                trustee: Trustee::Sid(admins_sid),
            },
            ExplicitAccess {
                access_permissions: FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                access_mode: SET_ACCESS,
                inheritance: Security::ACE_FLAGS(0),
                trustee: Trustee::Sid(users_sid),
            },
        ];

        let empty_acl = Acl::new().context("failed to create empty ACL")?;
        let dacl = empty_acl.set_entries(&entries).context("failed to set ACL entries")?;

        let attrs = SecurityAttributesInit {
            dacl: Some(InheritableAcl {
                kind: InheritableAclKind::Protected,
                acl: dacl,
            }),
            ..Default::default()
        }
        .init();

        Ok(attrs)
    }
}

#[cfg(windows)]
pub use windows_pipe::*;

/// Fallback for non-Windows (pipe transport not supported).
#[cfg(not(windows))]
pub const DEFAULT_PIPE_NAME: &str = "not-supported-on-this-platform";

#[cfg(not(windows))]
pub async fn run_pipe_server(
    _state: std::sync::Arc<crate::broker::server::BrokerState>,
    _shutdown: std::sync::Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    anyhow::bail!("named pipe transport is only supported on Windows")
}
