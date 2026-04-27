//! Shared upstream (server-side) connection machinery.
//!
//! All proxy paths that forward a client to some upstream target share the same
//! routing decision + connect sequence:
//!
//! 1. For each target in the token's `jet_cm: Fwd { targets }` list:
//!    - If the JWT named a specific `jet_agent_id`, route via that agent or fail.
//!    - Otherwise ask the registry for agents that cover the target (subnet /
//!      domain match); route via the best match, or fall back to direct TCP.
//! 2. On the first successful connection, optionally wrap in client TLS.
//!
//! The two consumer patterns differ only in whether they want the TLS wrap
//! applied here (fwd.rs) or manage their own TLS upgrade (rd_clean_path.rs does
//! X224 first, then TLS). Both share `UpstreamLeg` and [`connect_upstream`].

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use agent_tunnel::AgentTunnelHandle;
use agent_tunnel::registry::AgentPeer;
use agent_tunnel::routing::{RoutingDecision, resolve_route};
use agent_tunnel::stream::TunnelStream;
use anyhow::{Context as _, Result, anyhow};
use nonempty::NonEmpty;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use uuid::Uuid;

use crate::target_addr::TargetAddr;
use crate::tls::thumbprint::Sha256Thumbprint;
use crate::utils;

// ---------------------------------------------------------------------------
// Upstream transport types
// ---------------------------------------------------------------------------

/// Upstream transport to the target server.
///
/// An enum (not `Box<dyn>`) because the surrounding proxy futures must be
/// `Send` with a concrete type, and trait-object projections block that proof
/// on the `ws.on_upgrade()` boundary.
pub enum UpstreamLeg {
    /// Direct TCP to the target.
    Tcp(TcpStream),
    /// Tunnelled through an enrolled agent via QUIC.
    Tunnel(TunnelStream),
}

impl AsyncRead for UpstreamLeg {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tunnel(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamLeg {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tunnel(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tunnel(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tunnel(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// An `UpstreamLeg` optionally wrapped in a client TLS session.
pub enum UpstreamSession {
    Tcp(UpstreamLeg),
    Tls(Box<TlsStream<UpstreamLeg>>),
}

impl AsyncRead for UpstreamSession {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamSession {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Whether the caller wants the upstream wrapped in client TLS before being
/// handed back from [`prepare_upstream`].
#[derive(Debug, Clone, Copy)]
pub enum UpstreamMode {
    Tcp,
    Tls,
}

// ---------------------------------------------------------------------------
// Result structs
// ---------------------------------------------------------------------------

/// A successfully-connected upstream leg. The transport is either direct TCP
/// or an agent-tunnel stream; a TLS wrap has not yet been applied.
pub struct ConnectedUpstream {
    pub leg: UpstreamLeg,
    /// Remote peer address. For direct routing this is the resolved TCP peer.
    /// For agent-tunnel routing the real TCP peer lives on the agent side, so
    /// we surface the target IP:port (when the target is an IP literal) or
    /// `0.0.0.0:<target_port>` (when the target is a hostname the gateway
    /// never resolves) — both are more useful in logs/PCAP than a true zero.
    pub server_addr: SocketAddr,
    pub selected_target: TargetAddr,
}

/// A [`ConnectedUpstream`] that has gone through [`prepare_upstream`]; the
/// session may or may not be wrapped in TLS depending on [`UpstreamMode`].
pub struct PreparedUpstream {
    pub session: UpstreamSession,
    pub server_addr: SocketAddr,
    pub selected_target: TargetAddr,
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// A routing decision for a single target.
pub(crate) enum RoutePlan<'a> {
    Direct(&'a TargetAddr),
    ViaAgent {
        target: &'a TargetAddr,
        candidates: Vec<Arc<AgentPeer>>,
    },
}

impl<'a> RoutePlan<'a> {
    /// Pick how to reach `target`:
    /// - Explicit `jet_agent_id` → route via that agent (or error if missing).
    /// - Otherwise registry subnet/domain match → best candidates, else Direct.
    pub(crate) async fn resolve(
        handle: Option<&AgentTunnelHandle>,
        explicit_agent_id: Option<Uuid>,
        target: &'a TargetAddr,
    ) -> Result<Self> {
        if let Some(agent_id) = explicit_agent_id {
            let handle = handle.ok_or_else(|| {
                anyhow!(
                    "agent {agent_id} specified in token requires agent tunnel routing, but no tunnel handle is configured"
                )
            })?;

            let agent = handle
                .registry()
                .get(&agent_id)
                .await
                .ok_or_else(|| anyhow!("agent {agent_id} specified in token not found in registry"))?;

            return Ok(Self::ViaAgent {
                target,
                candidates: vec![agent],
            });
        }

        let Some(handle) = handle else {
            return Ok(Self::Direct(target));
        };

        match resolve_route(handle.registry(), None, target.host()).await {
            RoutingDecision::ViaAgent(candidates) => Ok(Self::ViaAgent { target, candidates }),
            RoutingDecision::Direct => Ok(Self::Direct(target)),
            RoutingDecision::ExplicitAgentNotFound(agent_id) => {
                // resolve_route only returns this when an explicit agent_id is passed
                // in; we pass None above. Treat as a soft failure rather than panic
                // so a future change in the routing crate cannot crash the gateway.
                warn!(
                    %agent_id,
                    "routing crate returned ExplicitAgentNotFound for an implicit lookup; falling back to direct"
                );
                Ok(Self::Direct(target))
            }
        }
    }

    /// Establish a concrete transport based on the plan.
    ///
    /// For `Direct`, does a TCP connect. For `ViaAgent`, tries each candidate
    /// in order until one succeeds.
    pub(crate) async fn execute(self, handle: Option<&AgentTunnelHandle>, session_id: Uuid) -> Result<ConnectedUpstream> {
        match self {
            Self::Direct(target) => {
                trace!(%target, "Connecting to target directly");

                let (stream, server_addr) = utils::tcp_connect(target).await?;

                trace!(%target, "Connected");

                Ok(ConnectedUpstream {
                    leg: UpstreamLeg::Tcp(stream),
                    server_addr,
                    selected_target: target.clone(),
                })
            }
            Self::ViaAgent { target, candidates } => {
                let handle = handle.expect("route plan requires configured agent tunnel");
                let mut last_error = None;

                for agent in &candidates {
                    info!(
                        agent_id = %agent.agent_id,
                        agent_name = %agent.name,
                        target = %target.as_addr(),
                        "Routing via agent tunnel"
                    );

                    match handle
                        .connect_via_agent(agent.agent_id, session_id, target.as_addr())
                        .await
                    {
                        Ok(stream) => {
                            // The TCP peer lives on the agent side; surface the target
                            // IP:port for logs/PCAP when the target is a literal IP, or
                            // 0.0.0.0:<port> when it's a hostname the gateway never
                            // resolved itself. Either is more useful than 0.0.0.0:0.
                            let server_addr = match target.host_ip() {
                                Some(ip) => SocketAddr::new(ip, target.port()),
                                None => SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, target.port())),
                            };

                            return Ok(ConnectedUpstream {
                                leg: UpstreamLeg::Tunnel(stream),
                                server_addr,
                                selected_target: target.clone(),
                            });
                        }
                        Err(error) => {
                            warn!(
                                agent_id = %agent.agent_id,
                                agent_name = %agent.name,
                                target = %target.as_addr(),
                                error = format!("{error:#}"),
                                "Agent tunnel candidate failed"
                            );
                            last_error = Some(error);
                        }
                    }
                }

                Err(last_error.unwrap_or_else(|| anyhow!("all agent tunnel candidates failed")))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Iterate `targets` in token order, resolving and connecting each. The first
/// successful connection wins.
///
/// Errors from earlier targets are chained onto the final error so the caller
/// sees the full failure story.
pub async fn connect_upstream(
    targets: &NonEmpty<TargetAddr>,
    explicit_agent_id: Option<Uuid>,
    session_id: Uuid,
    handle: Option<&AgentTunnelHandle>,
) -> Result<ConnectedUpstream> {
    let mut accumulated: Option<anyhow::Error> = None;

    for target in targets {
        let attempt = async {
            RoutePlan::resolve(handle, explicit_agent_id, target)
                .await?
                .execute(handle, session_id)
                .await
        };

        match attempt.await {
            Ok(connected) => return Ok(connected),
            Err(error) => {
                let annotated = error.context(format!("{target} failed"));
                accumulated = Some(match accumulated.take() {
                    Some(prev) => prev.context(annotated),
                    None => annotated,
                });
            }
        }
    }

    Err(accumulated.unwrap_or_else(|| anyhow!("no target candidates available")))
}

/// Optionally wrap a [`ConnectedUpstream`] in a client TLS session.
///
/// When `mode` is [`UpstreamMode::Tls`] the TLS handshake uses the gateway's
/// safe verifier with an optional SHA-256 thumbprint pin; otherwise the
/// session is returned as a plain TCP transport.
pub async fn prepare_upstream(
    connected: ConnectedUpstream,
    mode: UpstreamMode,
    cert_thumb256: Option<Sha256Thumbprint>,
) -> Result<PreparedUpstream> {
    let ConnectedUpstream {
        leg,
        server_addr,
        selected_target,
    } = connected;

    let session = match mode {
        UpstreamMode::Tcp => UpstreamSession::Tcp(leg),
        UpstreamMode::Tls => {
            trace!(target = %selected_target, "Establishing TLS connection with upstream");

            let tls_stream = crate::tls::safe_connect(selected_target.host().to_owned(), leg, cert_thumb256)
                .await
                .context("TLS connect")?;

            UpstreamSession::Tls(Box::new(tls_stream))
        }
    };

    Ok(PreparedUpstream {
        session,
        server_addr,
        selected_target,
    })
}
