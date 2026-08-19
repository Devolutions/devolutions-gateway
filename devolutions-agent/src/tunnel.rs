//! QUIC-based Agent Tunnel client implementation (Quinn).
//!
//! This module implements a QUIC client that connects to the Gateway's agent tunnel
//! endpoint, advertises reachable subnets, and handles incoming TCP proxy requests.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use agent_tunnel_proto::{
    ConnectResponse, ControlMessage, ControlStream, DomainAdvertisement, DomainName, FramedRecv, SessionStream,
    current_time_millis,
};
use anyhow::{Context as _, anyhow, bail};
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use ipnetwork::Ipv4Network;
use sha2::Digest as _;

use crate::config::ConfHandle;
use crate::tunnel_helpers::{Target, connect_to_target, resolve_target};

// ---------------------------------------------------------------------------
// Custom TLS verifier: chain + hostname validation + SPKI pinning
// ---------------------------------------------------------------------------

/// Wraps a standard `WebPkiServerVerifier` and additionally verifies that the
/// server certificate's SPKI (Subject Public Key Info) matches the expected
/// SHA-256 hash obtained during enrollment.
///
/// Verification order:
/// 1. Full chain validation + hostname matching (via inner `WebPkiServerVerifier`)
/// 2. SPKI pin check — rejects if the server's public key doesn't match
///
/// This is strictly MORE secure than standard TLS: even a compromised CA
/// cannot mint a server cert that passes the SPKI check.
#[derive(Debug)]
struct SpkiPinnedVerifier {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    expected_spki_sha256: String,
}

impl rustls::client::danger::ServerCertVerifier for SpkiPinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // 1. Standard chain + hostname validation.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // 2. SPKI pin check.
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

        let spki_hash = hex::encode(sha2::Sha256::digest(cert.public_key().raw));

        if spki_hash != self.expected_spki_sha256 {
            return Err(rustls::Error::General(
                "server SPKI hash does not match pinned value from enrollment".into(),
            ));
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
// TunnelTask — service task with auto-reconnect
// ---------------------------------------------------------------------------

pub struct TunnelTask {
    conf_handle: ConfHandle,
}

impl TunnelTask {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[async_trait]
impl Task for TunnelTask {
    type Output = anyhow::Result<()>;
    const NAME: &'static str = "tunnel";

    /// Reconnect loop with exponential backoff (using the `backoff` crate).
    ///
    /// Resets to initial interval after a connection survives 30s (considered stable).
    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        use backoff::backoff::Backoff as _;

        const RETRY_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
        const RETRY_MAX_INTERVAL: Duration = Duration::from_secs(60);
        const RETRY_MULTIPLIER: f64 = 2.0;
        const CONNECTED_THRESHOLD: Duration = Duration::from_secs(30);

        info!("Starting QUIC agent tunnel (with auto-reconnect)");

        let mut backoff = backoff::ExponentialBackoffBuilder::default()
            .with_initial_interval(RETRY_INITIAL_INTERVAL)
            .with_max_interval(RETRY_MAX_INTERVAL)
            .with_multiplier(RETRY_MULTIPLIER)
            .with_max_elapsed_time(None) // retry forever
            .build();

        loop {
            let start = std::time::Instant::now();

            match run_single_connection(&self.conf_handle, &mut shutdown_signal).await {
                Ok(ConnectionOutcome::Shutdown) => {
                    info!("Tunnel task stopped");
                    return Ok(());
                }
                Ok(ConnectionOutcome::CertRenewed) => {
                    // Renewal is a successful outcome, not a failure, we release the backpressure (backoff.reset()).
                    info!("Certificate renewed; reconnecting with new cert immediately");
                    backoff.reset();
                    continue;
                }
                Err(error) => {
                    warn!(error = %format!("{error:#}"), "Tunnel connection lost");
                }
            }

            // Reset backoff if the connection was stable long enough.
            if start.elapsed() > CONNECTED_THRESHOLD {
                backoff.reset();
            }

            let wait = match backoff.next_backoff() {
                Some(w) => w,
                None => {
                    // Should never happen with max_elapsed_time(None); fall through
                    // with a 1s floor to guarantee no hot-spin on adversarial clocks.
                    warn!("Backoff exhausted, resetting");
                    backoff.reset();
                    Duration::from_secs(1)
                }
            };

            info!(?wait, "Reconnecting after backoff");

            tokio::select! {
                _ = shutdown_signal.wait() => {
                    info!("Shutdown during reconnect backoff");
                    return Ok(());
                }
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }
}

/// Decide which domains to advertise, given what the operator configured and what
/// auto-detection found.
///
/// Auto-detection is a **fallback**, not an addition. Once someone has named DNS routes
/// explicitly, adding another route that was inferred from machine state would violate the
/// explicit routing policy.
fn resolve_advertise_domains(
    configured: &[String],
    auto_detect_enabled: bool,
    detected: Option<String>,
) -> Vec<DomainAdvertisement> {
    match (configured, auto_detect_enabled, detected) {
        (configured @ [_, ..], _, detected) => {
            if let Some(detected) = detected {
                debug!(
                    %detected,
                    "Ignoring auto-detected domain because advertise_domains is set explicitly"
                );
            }

            configured
                .iter()
                .map(|domain| DomainAdvertisement {
                    domain: DomainName::new(domain),
                    auto_detected: false,
                })
                .collect()
        }
        ([], false, _) => Vec::new(),
        ([], true, Some(detected)) => {
            info!(domain = %detected, "Auto-detected DNS domain");
            let route = format!("*.{detected}");
            if !DomainName::is_valid_route(&route) {
                warn!(%detected, "Ignoring invalid auto-detected DNS domain");
                return Vec::new();
            }
            vec![DomainAdvertisement {
                domain: DomainName::new(route),
                auto_detected: true,
            }]
        }
        ([], true, None) => {
            warn!(
                "No advertise_domains configured and domain auto-detection found nothing; \
                 set advertise_domains in agent config"
            );
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Single connection lifetime
// ---------------------------------------------------------------------------

/// Outcome of a single connection lifetime, telling the outer loop what to do next.
enum ConnectionOutcome {
    /// Shutdown signal received — exit the tunnel task cleanly.
    Shutdown,
    /// Certificate was renewed successfully; reconnect immediately with the new cert.
    CertRenewed,
}

/// Run a single QUIC tunnel connection lifetime: config → connect → event loop.
///
/// - `Ok(Shutdown)`: graceful shutdown, exit the task.
/// - `Ok(CertRenewed)`: certificate renewed; caller should reconnect immediately.
/// - `Err(_)`: connection lost or handshake failed — caller should retry with backoff.
async fn run_single_connection(
    conf_handle: &ConfHandle,
    shutdown_signal: &mut ShutdownSignal,
) -> anyhow::Result<ConnectionOutcome> {
    let agent_conf = conf_handle.get_conf();
    let tunnel_conf = &agent_conf.tunnel;

    let cert_path = &tunnel_conf.client_cert_path;
    let key_path = &tunnel_conf.client_key_path;
    let ca_path = &tunnel_conf.gateway_ca_cert_path;

    let advertise_subnets: Vec<Ipv4Network> = tunnel_conf
        .advertise_subnets
        .iter()
        .map(|subnet| subnet.parse())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse advertise_subnets")?;

    if advertise_subnets.is_empty() {
        warn!("No subnets configured to advertise");
    }

    if let Some(route) = tunnel_conf
        .advertise_domains
        .iter()
        .find(|route| !DomainName::is_valid_route(route))
    {
        bail!("invalid advertise domain route: {route}");
    }

    let detected_domain = if tunnel_conf.auto_detect_domain && tunnel_conf.advertise_domains.is_empty() {
        crate::domain_detect::detect_domain()
    } else {
        None
    };

    let advertise_domains = resolve_advertise_domains(
        &tunnel_conf.advertise_domains,
        tunnel_conf.auto_detect_domain,
        detected_domain,
    );

    info!(
        subnet_count = advertise_subnets.len(),
        domain_count = advertise_domains.len(),
        domains = ?advertise_domains.iter().map(|d| {
            let source = if d.auto_detected { "auto" } else { "explicit" };
            format!("{} ({})", d.domain, source)
        }).collect::<Vec<_>>(),
        "Advertising subnets and domains"
    );

    let (_endpoint, connection) = connect_to_gateway(tunnel_conf).await?;

    // -- Open control stream --

    let mut ctrl: ControlStream<_, _> = connection.open_bi().await.context("open control stream")?.into();

    // Send initial RouteAdvertise.
    let epoch = 1u64;
    let msg = ControlMessage::route_advertise(epoch, advertise_subnets.clone(), advertise_domains.clone());

    ctrl.send(&msg).await.context("send initial RouteAdvertise")?;

    info!(epoch, "Sent initial RouteAdvertise");

    // -- Certificate renewal (post-connect, pre-traffic) --
    //
    // Run once per reconnect rather than on a periodic timer: the QUIC session
    // has a 120s idle timeout and 15s keep-alive, so any blip / VPN reconnect
    // / host sleep / gateway restart drops the connection within minutes and
    // sends us back through this path. With a 1-year cert and a 15-day
    // threshold, the renewal window will be hit on the first reconnect after
    // T-15d, which is more than often enough in any real deployment.
    if let Some(outcome) = try_renew_certificate(&mut ctrl, cert_path, key_path, ca_path).await? {
        connection.close(0u32.into(), b"cert-renewed");
        return Ok(outcome);
    }

    // Split: recv half goes to a reader task, send half stays for periodic messages.
    let (mut ctrl_send, ctrl_recv) = ctrl.into_split();
    let mut task_handles = tokio::task::JoinSet::new();
    task_handles.spawn(run_control_reader(ctrl_recv));

    // -- Main loop: accept incoming session streams + periodic tasks --

    let route_interval = tunnel_conf.route_advertise_interval_secs;
    let heartbeat_interval_secs = tunnel_conf.heartbeat_interval_secs;
    let mut route_tick = tokio::time::interval(Duration::from_secs(route_interval));
    let mut heartbeat_tick = tokio::time::interval(Duration::from_secs(heartbeat_interval_secs));
    // Skip the first immediate tick (we already sent the initial RouteAdvertise).
    route_tick.tick().await;
    heartbeat_tick.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = shutdown_signal.wait() => {
                info!("Tunnel task shutting down");
                connection.close(0u32.into(), b"shutting down");
                break;
            }

            _ = route_tick.tick() => {
                let msg = ControlMessage::route_advertise(epoch, advertise_subnets.clone(), advertise_domains.clone());
                let _ = ctrl_send.send(&msg).await
                    .inspect(|_| trace!(epoch, "Sent RouteAdvertise (refresh)"))
                    .inspect_err(|e| error!(%e, "Failed to send RouteAdvertise"));
            }

            _ = heartbeat_tick.tick() => {
                // TODO: track actual active_stream_count instead of hardcoded 0.
                let msg = ControlMessage::heartbeat(current_time_millis(), 0);
                let _ = ctrl_send.send(&msg).await
                    .inspect(|_| trace!("Sent Heartbeat"))
                    .inspect_err(|e| error!(%e, "Failed to send Heartbeat"));
            }

            result = connection.accept_bi() => {
                let (send, recv) = result.context("accept incoming bidi stream")?;
                let subnets = advertise_subnets.clone();
                let domains = advertise_domains.clone();
                task_handles.spawn(run_session_proxy(subnets, domains, send, recv));
            }

            // Reap completed session tasks.
            Some(_) = task_handles.join_next() => {}
        }
    }

    task_handles.shutdown().await;

    Ok(ConnectionOutcome::Shutdown)
}

/// Build the mTLS client config, resolve the gateway endpoint, and perform the
/// QUIC handshake, returning the live endpoint and connection.
async fn connect_to_gateway(
    tunnel_conf: &crate::config::TunnelConf,
) -> anyhow::Result<(quinn::Endpoint, quinn::Connection)> {
    // Ensure rustls crypto provider is installed (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // -- Build rustls ClientConfig --

    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(tunnel_conf.client_cert_path.as_str()).context("open client cert file")?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("parse client certificates")?;

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(tunnel_conf.client_key_path.as_str()).context("open client key file")?,
    ))
    .context("parse private key file")?
    .context("no private key found in file")?;

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(tunnel_conf.gateway_ca_cert_path.as_str()).context("open CA cert file")?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("parse CA certificates")?;
    for cert in ca_certs {
        roots.add(cert)?;
    }

    // Build verifier: standard chain + hostname validation, plus SPKI pinning if available.
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .context("build server cert verifier")?;

    let effective_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        if let Some(ref expected_spki) = tunnel_conf.server_spki_sha256 {
            Arc::new(SpkiPinnedVerifier {
                inner: verifier,
                expected_spki_sha256: expected_spki.clone(),
            })
        } else {
            warn!("No server SPKI pin configured — re-enroll to enable pinning");
            verifier
        };

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(effective_verifier)
        .with_client_auth_cert(certs, key)
        .context("build rustls client config with client auth")?;

    client_crypto.alpn_protocols = vec![agent_tunnel_proto::ALPN_PROTOCOL.to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            Duration::from_secs(120).try_into().context("idle timeout conversion")?,
        ))
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .max_concurrent_bidi_streams(100u32.into());

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .context("build QuicClientConfig from rustls config")?,
    ));
    client_config.transport_config(Arc::new(transport));

    // -- DNS resolve --

    // Extract hostname for TLS server name validation.
    let (gateway_hostname, _) = tunnel_conf
        .gateway_endpoint
        .rsplit_once(':')
        .context("gateway_endpoint missing port separator")?;

    let gateway_addr = tokio::net::lookup_host(&tunnel_conf.gateway_endpoint)
        .await
        .context("failed to resolve gateway endpoint")?
        .next()
        .context("no addresses resolved for gateway endpoint")?;

    info!(gateway_addr = %gateway_addr, %gateway_hostname, "Connecting to gateway");

    // -- Connect --

    // Match the local bind family to the resolved gateway address. A v4 socket
    // cannot send to a v6 peer and vice versa, and on Linux the OS default for
    // `IPV6_V6ONLY` is `1` (RFC 3493) so a `[::]:0` bind is not portably
    // dual-stack without extra socket-level work. Picking the family that
    // matches `gateway_addr` sidesteps both issues without needing socket2 on
    // the client side.
    let bind_addr: SocketAddr = if gateway_addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint =
        quinn::Endpoint::client(bind_addr).with_context(|| format!("create QUIC endpoint (bind {bind_addr})"))?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(gateway_addr, gateway_hostname)
        .context("initiate QUIC connection")?
        .await
        .context("QUIC handshake")?;

    info!("QUIC connection established");

    Ok((endpoint, connection))
}

/// Reachability probe: confirm the gateway's QUIC/UDP endpoint answers within `timeout`.
///
/// This deliberately does NOT complete a QUIC/mTLS handshake. A real handshake would register
/// this agent's connection on the gateway (keyed by the enrolled `agent_id`) and, on close,
/// unregister it — so a probe run against a machine whose service tunnel is live would evict the
/// real connection. Instead we send a QUIC long-header packet carrying an unsupported version and
/// wait for the gateway to reply with a Version Negotiation packet. That reply proves UDP/4433
/// reaches the gateway while creating zero connection state on it, and needs no client cert.
pub async fn probe_connectivity(tunnel_conf: &crate::config::TunnelConf, timeout: Duration) -> anyhow::Result<()> {
    if !tunnel_conf.enabled {
        bail!("agent tunnel is not enabled");
    }

    // The whole probe — DNS resolution, socket setup, and the retransmit loop — is bounded by
    // `timeout`, so a stalled resolver or a black-holed path can't hang past it.
    match tokio::time::timeout(timeout, reach_gateway(tunnel_conf)).await {
        Ok(result) => result,
        Err(_elapsed) => bail!("gateway QUIC endpoint did not respond within {timeout:?}"),
    }
}

async fn reach_gateway(tunnel_conf: &crate::config::TunnelConf) -> anyhow::Result<()> {
    let gateway_addr = tokio::net::lookup_host(&tunnel_conf.gateway_endpoint)
        .await
        .context("failed to resolve gateway endpoint")?
        .next()
        .context("no addresses resolved for gateway endpoint")?;

    // Match the local bind family to the resolved gateway address (see connect_to_gateway).
    let bind_addr: SocketAddr = if gateway_addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };

    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("bind probe socket ({bind_addr})"))?;
    socket
        .connect(gateway_addr)
        .await
        .with_context(|| format!("connect probe socket to {gateway_addr}"))?;

    info!(gateway_addr = %gateway_addr, "Probing gateway QUIC reachability");

    let packet = version_negotiation_probe_packet();
    let mut buf = [0u8; 1500];

    // Retransmit until we get a reply (the caller's timeout cancels us otherwise) — UDP can drop the
    // probe, and on some platforms a prior ICMP "port unreachable" surfaces here as a recv error.
    loop {
        let next_attempt_at = tokio::time::Instant::now() + Duration::from_millis(100);

        let _ = socket.send(&packet).await;

        match tokio::time::timeout(Duration::from_millis(100), socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                info!("Gateway QUIC endpoint is reachable");
                return Ok(());
            }
            // A fast recv error must not turn the retransmit into a tight resend flood — hold off
            // until the next interval before trying again.
            _ => tokio::time::sleep_until(next_attempt_at).await,
        }
    }
}

/// A QUIC long-header packet whose version (`0x1a2a3a4a`) is reserved to always trigger Version
/// Negotiation (RFC 9000 §15), padded to the 1200-byte minimum so the server won't drop it. Any
/// reply to it proves the path is open without establishing a connection.
fn version_negotiation_probe_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(1200);
    packet.push(0xC0); // long header + fixed bit
    packet.extend_from_slice(&[0x1a, 0x2a, 0x3a, 0x4a]); // force-VN version
    packet.push(8); // Destination Connection ID length
    packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
    packet.push(0); // Source Connection ID length
    packet.resize(1200, 0);
    packet
}

// ---------------------------------------------------------------------------
// Certificate renewal
// ---------------------------------------------------------------------------

/// Check if the client cert is near expiry; if so, renew it via the control
/// stream before opening real traffic.
///
/// Returns:
/// - `Ok(Some(CertRenewed))` — renewed successfully; outer loop must reconnect
///   so the new cert takes effect on the next mTLS handshake.
/// - `Ok(None)` — no renewal needed (or attempted renewal failed in a recoverable
///   way, e.g. the gateway said no); proceed with the existing cert.
/// - `Err(_)` — IO / protocol error on the control stream itself; treat as
///   connection lost.
async fn try_renew_certificate<S, R>(
    ctrl: &mut ControlStream<S, R>,
    cert_path: &camino::Utf8Path,
    key_path: &camino::Utf8Path,
    ca_path: &camino::Utf8Path,
) -> anyhow::Result<Option<ConnectionOutcome>>
where
    S: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    const RENEWAL_THRESHOLD_DAYS: u32 = 15;
    const RENEWAL_TIMEOUT: Duration = Duration::from_secs(30);

    match crate::enrollment::is_cert_expiring(cert_path, RENEWAL_THRESHOLD_DAYS) {
        Ok(false) => {
            debug!("Client certificate not in renewal window");
            return Ok(None);
        }
        Err(error) => {
            warn!(error = %format!("{error:#}"), "Failed to check certificate expiry; skipping renewal");
            return Ok(None);
        }
        Ok(true) => {}
    }

    info!(
        threshold_days = RENEWAL_THRESHOLD_DAYS,
        "Certificate within renewal window; requesting renewal"
    );

    // Reuse the agent name from the existing cert as the renewal CSR's
    // CommonName. The gateway ignores CSR subject and trusts the
    // mTLS-authenticated identity, but matching the existing CN keeps the
    // CSR semantically correct in case validation tightens later.
    let agent_name = crate::enrollment::read_agent_name_from_cert(cert_path)
        .context("read agent name from existing certificate for renewal")?;
    let csr_pem =
        crate::enrollment::generate_csr_from_existing_key(key_path, &agent_name).context("generate renewal CSR")?;

    ctrl.send(&ControlMessage::cert_renewal_request(csr_pem))
        .await
        .context("send CertRenewalRequest")?;

    let response = tokio::time::timeout(RENEWAL_TIMEOUT, ctrl.recv())
        .await
        .context("timeout waiting for CertRenewalResponse")?
        .context("receive CertRenewalResponse")?;

    match response {
        ControlMessage::CertRenewalResponse {
            result:
                agent_tunnel_proto::CertRenewalResult::Success {
                    client_cert_pem,
                    gateway_ca_cert_pem,
                },
            ..
        } => {
            std::fs::write(cert_path.as_str(), &client_cert_pem).context("write renewed certificate")?;
            std::fs::write(ca_path.as_str(), &gateway_ca_cert_pem).context("write renewed CA certificate")?;
            info!("Certificate renewed; reconnecting so the new cert takes effect");
            Ok(Some(ConnectionOutcome::CertRenewed))
        }
        ControlMessage::CertRenewalResponse {
            result: agent_tunnel_proto::CertRenewalResult::Error { reason },
            ..
        } => {
            warn!(%reason, "Gateway refused certificate renewal; continuing with existing cert");
            Ok(None)
        }
        other => {
            warn!(
                ?other,
                "Unexpected response to renewal request; continuing with existing cert"
            );
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Control stream reader
// ---------------------------------------------------------------------------

async fn run_control_reader<R: tokio::io::AsyncRead + Unpin>(mut ctrl: FramedRecv<R>) {
    let _ = async move {
        loop {
            let message: ControlMessage = ctrl.recv().await.context("recv control message")?;

            let protocol_version = message.protocol_version();
            if agent_tunnel_proto::validate_protocol_version(protocol_version)
                .inspect_err(|e| warn!(%protocol_version, %e, "Ignoring control message: unsupported version"))
                .is_err()
            {
                continue;
            }

            match message {
                ControlMessage::HeartbeatAck { timestamp_ms, .. } => {
                    let rtt = current_time_millis().saturating_sub(timestamp_ms);
                    debug!(rtt_ms = rtt, "Received HeartbeatAck");
                }
                unexpected => {
                    warn!(message = ?unexpected, "Unexpected control message from gateway");
                }
            }
        }

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    }
    .await
    .inspect_err(|e| error!(%e, "Control reader failed"));
}

// ---------------------------------------------------------------------------
// Session proxy
// ---------------------------------------------------------------------------

/// How long we get to resolve the target and open the TCP connection.
///
/// The Gateway stops waiting for the ConnectResponse after 30s
/// (`crates/agent-tunnel/src/listener.rs`). We have to give up before it does, otherwise a
/// black-holed target outlives its deadline and it never hears why we failed.
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);

async fn run_session_proxy<S, R>(
    advertise_subnets: Vec<Ipv4Network>,
    advertise_domains: Vec<DomainAdvertisement>,
    send: S,
    recv: R,
) where
    S: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    let _: anyhow::Result<()> = async {
        let mut session: SessionStream<_, _> = (send, recv).into();

        let connect_msg = tokio::time::timeout(Duration::from_secs(30), session.recv_request())
            .await
            .context("session handshake timeout")?
            .context("recv ConnectRequest")?;

        info!(
            session_id = %connect_msg.session_id(),
            target = %connect_msg.target(),
            "Received ConnectRequest"
        );

        let protocol_version = connect_msg.protocol_version();

        let connect_result = tokio::time::timeout(CONNECT_DEADLINE, async {
            agent_tunnel_proto::validate_protocol_version(protocol_version).context("unsupported protocol version")?;

            let target = Target::parse(connect_msg.target()).context("parse connect target")?;
            let candidates = resolve_target(&target, &advertise_subnets, &advertise_domains).await?;
            connect_to_target(&candidates).await
        })
        .await
        .unwrap_or_else(|_elapsed| {
            Err(anyhow!(
                "timed out after {}s resolving or connecting to target",
                CONNECT_DEADLINE.as_secs()
            ))
        });

        // Whatever went wrong has to travel back as a ConnectResponse::Error — returning
        // early instead drops the stream and the Gateway just sees an unexplained EOF.
        let (tcp_stream, selected_target) = match connect_result {
            Ok(connected) => connected,
            Err(error) => {
                let reason = format!("{error:#}");
                warn!(
                    session_id = %connect_msg.session_id(),
                    target = %connect_msg.target(),
                    protocol_version,
                    error = %reason,
                    "Rejecting ConnectRequest"
                );
                session
                    .send_response(&ConnectResponse::error(reason))
                    .await
                    .context("send ConnectResponse error")?;
                return Err(error);
            }
        };

        info!(target = %selected_target, "TCP connection established");

        session
            .send_response(&ConnectResponse::success())
            .await
            .context("send ConnectResponse")?;
        info!("Sent ConnectResponse::Success");

        let (mut send, mut recv) = session.into_inner();
        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

        // Use join! (not select!) to wait for BOTH directions to finish.
        // select! would cancel in-flight data when one direction closes first.
        let (r1, r2) = tokio::join!(
            tokio::io::copy(&mut recv, &mut tcp_write),
            tokio::io::copy(&mut tcp_read, &mut send),
        );
        r1.inspect_err(|e| debug!(%e, "QUIC->TCP copy ended"))?;
        r2.inspect_err(|e| debug!(%e, "TCP->QUIC copy ended"))?;

        let _ = tokio::io::AsyncWriteExt::shutdown(&mut send).await;

        Ok(())
    }
    .await
    .inspect_err(|e| error!(%e, "Session proxy failed"));
}

#[cfg(test)]
mod tests {
    use agent_tunnel_proto::DomainName;
    use camino::Utf8PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinHandle;
    use uuid::Uuid;

    use super::*;
    use crate::config::TunnelConf;

    type DuplexControlStream =
        ControlStream<tokio::io::WriteHalf<tokio::io::DuplexStream>, tokio::io::ReadHalf<tokio::io::DuplexStream>>;
    type DuplexSessionStream =
        SessionStream<tokio::io::WriteHalf<tokio::io::DuplexStream>, tokio::io::ReadHalf<tokio::io::DuplexStream>>;

    fn tunnel_conf_template() -> TunnelConf {
        TunnelConf {
            enabled: true,
            gateway_endpoint: String::new(),
            client_cert_path: Utf8PathBuf::new(),
            client_key_path: Utf8PathBuf::new(),
            gateway_ca_cert_path: Utf8PathBuf::new(),
            advertise_subnets: Vec::new(),
            advertise_domains: Vec::new(),
            auto_detect_domain: false,
            heartbeat_interval_secs: 15,
            route_advertise_interval_secs: 60,
            server_spki_sha256: None,
        }
    }

    fn write_test_identity(expired: bool) -> (tempfile::TempDir, Utf8PathBuf, Utf8PathBuf, Utf8PathBuf) {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let root = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("use utf-8 temporary path");
        let cert_path = root.join("agent.pem");
        let key_path = root.join("agent.key");
        let ca_path = root.join("ca.pem");
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate test key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "renewal-agent");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = if expired {
            rcgen::date_time_ymd(2020, 1, 2)
        } else {
            rcgen::date_time_ymd(2035, 1, 1)
        };
        let certificate = params.self_signed(&key_pair).expect("sign test certificate");
        std::fs::write(&cert_path, certificate.pem()).expect("write test certificate");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write test key");
        std::fs::write(&ca_path, "old-ca").expect("write test ca");
        (temp_dir, cert_path, key_path, ca_path)
    }

    fn control_streams() -> (DuplexControlStream, DuplexControlStream) {
        let (agent, gateway) = tokio::io::duplex(64 * 1024);
        let (agent_read, agent_write) = tokio::io::split(agent);
        let (gateway_read, gateway_write) = tokio::io::split(gateway);
        ((agent_write, agent_read).into(), (gateway_write, gateway_read).into())
    }

    fn domain_route(domain: &str) -> DomainAdvertisement {
        DomainAdvertisement {
            domain: DomainName::new(domain),
            auto_detected: false,
        }
    }

    fn start_session_proxy(
        advertise_subnets: Vec<Ipv4Network>,
        advertise_domains: Vec<DomainAdvertisement>,
    ) -> (DuplexSessionStream, JoinHandle<()>) {
        let (gateway_io, agent_io) = tokio::io::duplex(64 * 1024);
        let (gateway_read, gateway_write) = tokio::io::split(gateway_io);
        let (agent_read, agent_write) = tokio::io::split(agent_io);
        let proxy_task = tokio::spawn(run_session_proxy(
            advertise_subnets,
            advertise_domains,
            agent_write,
            agent_read,
        ));
        ((gateway_write, gateway_read).into(), proxy_task)
    }

    async fn proxy_error(
        advertise_subnets: Vec<Ipv4Network>,
        advertise_domains: Vec<DomainAdvertisement>,
        target: &str,
    ) -> String {
        let (mut session, proxy_task) = start_session_proxy(advertise_subnets, advertise_domains);
        session
            .send_request(&agent_tunnel_proto::ConnectRequest::tcp(
                Uuid::new_v4(),
                target.to_owned(),
            ))
            .await
            .expect("send rejected connect request");

        let reason = match session.recv_response().await.expect("receive connection error") {
            ConnectResponse::Error { reason, .. } => reason,
            ConnectResponse::Success { .. } => panic!("expected connection error"),
        };
        proxy_task.await.expect("proxy task panicked");
        reason
    }

    async fn assert_proxy_round_trip(
        advertise_subnets: Vec<Ipv4Network>,
        advertise_domains: Vec<DomainAdvertisement>,
        target_host: &str,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo server");
        let target = format!(
            "{target_host}:{}",
            listener.local_addr().expect("read echo server address").port()
        );
        let echo_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept echo connection");
            let (mut read, mut write) = stream.into_split();
            tokio::io::copy(&mut read, &mut write).await.expect("echo data");
        });

        let (mut session, proxy_task) = start_session_proxy(advertise_subnets, advertise_domains);
        session
            .send_request(&agent_tunnel_proto::ConnectRequest::tcp(Uuid::new_v4(), target))
            .await
            .expect("send connect request");
        assert!(
            session
                .recv_response()
                .await
                .expect("receive connect response")
                .is_success()
        );

        let payload = b"agent proxy payload";
        let (mut send, mut recv) = session.into_inner();
        send.write_all(payload).await.expect("write proxy payload");
        let mut response = vec![0; payload.len()];
        recv.read_exact(&mut response).await.expect("read proxy response");
        assert_eq!(response, payload);

        proxy_task.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn probe_fails_fast_when_tunnel_disabled() {
        let mut conf = tunnel_conf_template();
        conf.enabled = false;

        let error = probe_connectivity(&conf, Duration::from_millis(200))
            .await
            .expect_err("probe must fail when the tunnel is disabled");

        assert!(
            format!("{error:#}").contains("not enabled"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn probe_times_out_when_gateway_unreachable() {
        // Bind a local UDP socket and never read/answer it: the port is definitely ours (no flaky
        // assumption about a fixed port being free) and it silently black-holes the probe packets,
        // so the probe never gets a reply and must time out.
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind blackhole socket");
        let blackhole_addr = blackhole.local_addr().expect("blackhole addr");

        let mut conf = tunnel_conf_template();
        conf.gateway_endpoint = blackhole_addr.to_string();

        let started = std::time::Instant::now();
        let result = probe_connectivity(&conf, Duration::from_millis(300)).await;

        assert!(result.is_err(), "probe must fail when the gateway is unreachable");
        // The real runtime is ~300ms; the 5s ceiling only has to stay well under quinn's ~120s idle
        // so it catches a "probe hangs instead of timing out" regression without flaking on a loaded
        // runner where the timer fires late.
        assert!(started.elapsed() < Duration::from_secs(5), "probe must fail fast");
    }

    #[tokio::test]
    async fn session_proxy_relays_ip_target_in_an_advertised_subnet() {
        assert_proxy_round_trip(
            vec!["127.0.0.0/8".parse().expect("parse loopback subnet")],
            vec![],
            "127.0.0.1",
        )
        .await;
    }

    #[tokio::test]
    async fn session_proxy_relays_domain_target_without_an_advertised_subnet() {
        assert_proxy_round_trip(vec![], vec![domain_route("localhost")], "localhost").await;
    }

    #[tokio::test]
    async fn session_proxy_reports_unresolvable_advertised_domain() {
        let reason = proxy_error(vec![], vec![domain_route("*.invalid")], "missing.invalid:443").await;
        assert!(reason.contains("resolve target"), "unexpected error: {reason}");
    }

    #[tokio::test]
    async fn session_proxy_reports_closed_target_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve closed target port");
        let target = format!(
            "localhost:{}",
            listener.local_addr().expect("read reserved port").port()
        );
        drop(listener);

        let reason = proxy_error(vec![], vec![domain_route("localhost")], &target).await;
        assert!(reason.contains("TCP connect failed"), "unexpected error: {reason}");
    }

    #[tokio::test]
    async fn session_proxy_refuses_unadvertised_target() {
        let reason = proxy_error(vec![], vec![], "127.0.0.1:9").await;
        assert!(
            reason.contains("not in advertised subnets"),
            "unexpected error: {reason}"
        );
    }

    #[tokio::test]
    async fn certificate_renewal_persists_response_and_requests_reconnect() {
        let (_temp_dir, cert_path, key_path, ca_path) = write_test_identity(true);
        let (mut agent_ctrl, mut gateway_ctrl) = control_streams();
        let gateway_task = tokio::spawn(async move {
            match gateway_ctrl.recv().await.expect("receive renewal request") {
                ControlMessage::CertRenewalRequest { csr_pem, .. } => {
                    assert!(csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
                }
                other => panic!("expected renewal request, got {other:?}"),
            }
            gateway_ctrl
                .send(&ControlMessage::cert_renewal_response(
                    agent_tunnel_proto::CertRenewalResult::Success {
                        client_cert_pem: "renewed-cert".to_owned(),
                        gateway_ca_cert_pem: "renewed-ca".to_owned(),
                    },
                ))
                .await
                .expect("send renewal response");
        });

        let outcome = try_renew_certificate(&mut agent_ctrl, &cert_path, &key_path, &ca_path)
            .await
            .expect("renew certificate");
        assert!(matches!(outcome, Some(ConnectionOutcome::CertRenewed)));
        gateway_task.await.expect("gateway task panicked");
        assert_eq!(
            std::fs::read_to_string(cert_path).expect("read renewed certificate"),
            "renewed-cert"
        );
        assert_eq!(std::fs::read_to_string(ca_path).expect("read renewed ca"), "renewed-ca");
    }

    #[tokio::test]
    async fn fresh_certificate_skips_renewal() {
        let (_temp_dir, cert_path, key_path, ca_path) = write_test_identity(false);
        let (mut agent_ctrl, _gateway_ctrl) = control_streams();

        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            try_renew_certificate(&mut agent_ctrl, &cert_path, &key_path, &ca_path),
        )
        .await
        .expect("renewal check timed out")
        .expect("check certificate renewal");
        assert!(outcome.is_none());
    }

    #[tokio::test]
    async fn refused_certificate_renewal_preserves_existing_files() {
        let (_temp_dir, cert_path, key_path, ca_path) = write_test_identity(true);
        let original_cert = std::fs::read_to_string(&cert_path).expect("read original certificate");
        let (mut agent_ctrl, mut gateway_ctrl) = control_streams();
        let gateway_task = tokio::spawn(async move {
            gateway_ctrl.recv().await.expect("receive renewal request");
            gateway_ctrl
                .send(&ControlMessage::cert_renewal_response(
                    agent_tunnel_proto::CertRenewalResult::Error {
                        reason: "renewal refused".to_owned(),
                    },
                ))
                .await
                .expect("send renewal refusal");
        });

        let outcome = try_renew_certificate(&mut agent_ctrl, &cert_path, &key_path, &ca_path)
            .await
            .expect("check certificate renewal");
        gateway_task.await.expect("gateway task panicked");
        assert!(outcome.is_none());
        assert_eq!(
            std::fs::read_to_string(cert_path).expect("read preserved certificate"),
            original_cert
        );
        assert_eq!(std::fs::read_to_string(ca_path).expect("read preserved ca"), "old-ca");
    }

    #[tokio::test]
    async fn unexpected_certificate_renewal_response_preserves_existing_files() {
        let (_temp_dir, cert_path, key_path, ca_path) = write_test_identity(true);
        let original_cert = std::fs::read_to_string(&cert_path).expect("read original certificate");
        let (mut agent_ctrl, mut gateway_ctrl) = control_streams();
        let gateway_task = tokio::spawn(async move {
            gateway_ctrl.recv().await.expect("receive renewal request");
            gateway_ctrl
                .send(&ControlMessage::heartbeat(1, 0))
                .await
                .expect("send unexpected response");
        });

        let outcome = try_renew_certificate(&mut agent_ctrl, &cert_path, &key_path, &ca_path)
            .await
            .expect("check certificate renewal");
        gateway_task.await.expect("gateway task panicked");
        assert!(outcome.is_none());
        assert_eq!(
            std::fs::read_to_string(cert_path).expect("read preserved certificate"),
            original_cert
        );
        assert_eq!(std::fs::read_to_string(ca_path).expect("read preserved ca"), "old-ca");
    }

    fn domains_of(advertisements: &[DomainAdvertisement]) -> Vec<(&str, bool)> {
        advertisements
            .iter()
            .map(|d| (d.domain.as_str(), d.auto_detected))
            .collect()
    }

    // The regression this guards: an operator asking for one host used to also get the machine's
    // whole parent domain, which covers every host in it.
    #[test]
    fn explicit_domains_suppress_auto_detection() {
        let advertised = resolve_advertise_domains(
            &["machine.example.com".to_owned()],
            true,
            Some("example.com".to_owned()),
        );

        assert_eq!(domains_of(&advertised), vec![("machine.example.com", false)]);
    }

    #[test]
    fn auto_detection_fills_in_when_nothing_is_configured() {
        let advertised = resolve_advertise_domains(&[], true, Some("example.com".to_owned()));

        assert_eq!(domains_of(&advertised), vec![("*.example.com", true)]);
    }

    #[test]
    fn invalid_auto_detected_domain_is_not_advertised() {
        let advertised = resolve_advertise_domains(&[], true, Some("foo.bar..baz".to_owned()));

        assert!(advertised.is_empty());
    }

    #[test]
    fn all_configured_domains_are_kept() {
        let advertised =
            resolve_advertise_domains(&["a.example.com".to_owned(), "b.example.com".to_owned()], false, None);

        assert_eq!(
            domains_of(&advertised),
            vec![("a.example.com", false), ("b.example.com", false)]
        );
    }

    #[test]
    fn nothing_configured_and_nothing_detected_advertises_no_domains() {
        assert!(resolve_advertise_domains(&[], true, None).is_empty());
    }

    #[test]
    fn disabled_auto_detection_advertises_no_domains() {
        assert!(resolve_advertise_domains(&[], false, None).is_empty());
    }
}
