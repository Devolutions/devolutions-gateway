//! QUIC-based Agent Tunnel client implementation (Quinn).
//!
//! This module implements a QUIC client that connects to the Gateway's agent tunnel
//! endpoint, advertises reachable subnets, and handles incoming TCP proxy requests.

use std::sync::Arc;
use std::time::Duration;

use agent_tunnel_proto::{
    ConnectResponse, ControlMessage, ControlRecvStream, ControlStream, SessionStream, current_time_millis,
};
use anyhow::{Context as _, bail};
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
                Ok(()) => {
                    info!("Tunnel task stopped");
                    return Ok(());
                }
                Err(error) => {
                    warn!(error = %format!("{error:#}"), "Tunnel connection lost");
                }
            }

            // Reset backoff if the connection was stable long enough.
            if start.elapsed() > CONNECTED_THRESHOLD {
                backoff.reset();
            }

            let Some(wait) = backoff.next_backoff() else {
                // Should never happen with max_elapsed_time(None), but just in case.
                warn!("Backoff exhausted, resetting");
                backoff.reset();
                continue;
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

// ---------------------------------------------------------------------------
// Single connection lifetime
// ---------------------------------------------------------------------------

/// Run a single QUIC tunnel connection lifetime: config → connect → event loop.
///
/// Returns `Ok(())` on graceful shutdown (shutdown signal received).
/// Returns `Err(...)` on any failure — the caller should retry with backoff.
async fn run_single_connection(conf_handle: &ConfHandle, shutdown_signal: &mut ShutdownSignal) -> anyhow::Result<()> {
    // Ensure rustls crypto provider is installed (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let agent_conf = conf_handle.get_conf();
    let tunnel_conf = &agent_conf.tunnel;

    let cert_path = tunnel_conf
        .client_cert_path
        .as_ref()
        .context("client_cert_path not configured")?;
    let key_path = tunnel_conf
        .client_key_path
        .as_ref()
        .context("client_key_path not configured")?;
    let ca_path = tunnel_conf
        .gateway_ca_cert_path
        .as_ref()
        .context("gateway_ca_cert_path not configured")?;

    let advertise_subnets: Vec<Ipv4Network> = tunnel_conf
        .advertise_subnets
        .iter()
        .map(|subnet| subnet.parse())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse advertise_subnets")?;

    if advertise_subnets.is_empty() {
        warn!("No subnets configured to advertise");
    }

    // Build domain advertisement list: explicit config + auto-detection.
    let mut advertise_domains: Vec<agent_tunnel_proto::DomainAdvertisement> = tunnel_conf
        .advertise_domains
        .iter()
        .map(|d| agent_tunnel_proto::DomainAdvertisement {
            domain: d.clone(),
            auto_detected: false,
        })
        .collect();

    if tunnel_conf.auto_detect_domain {
        if let Some(detected) = crate::domain_detect::detect_domain() {
            if !advertise_domains
                .iter()
                .any(|d| d.domain.eq_ignore_ascii_case(&detected))
            {
                info!(domain = %detected, "Auto-detected DNS domain");
                advertise_domains.push(agent_tunnel_proto::DomainAdvertisement {
                    domain: detected,
                    auto_detected: true,
                });
            }
        } else if tunnel_conf.advertise_domains.is_empty() {
            warn!(
                "Domain auto-detection found nothing and no advertise_domains configured. \
                 Set advertise_domains in agent config."
            );
        }
    }

    info!(
        subnet_count = advertise_subnets.len(),
        domain_count = advertise_domains.len(),
        domains = ?advertise_domains.iter().map(|d| {
            let source = if d.auto_detected { "auto" } else { "explicit" };
            format!("{} ({})", d.domain, source)
        }).collect::<Vec<_>>(),
        "Advertising subnets and domains"
    );

    // -- Build rustls ClientConfig --

    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert_path.as_str()).context("open client cert file")?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("parse client certificates")?;

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key_path.as_str()).context("open client key file")?,
    ))
    .context("parse private key file")?
    .context("no private key found in file")?;

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(ca_path.as_str()).context("open CA cert file")?,
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

    client_crypto.alpn_protocols = vec![b"gw-agent-tunnel/1".to_vec()];

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

    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().context("parse bind address")?).context("create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(gateway_addr, gateway_hostname)
        .context("initiate QUIC connection")?
        .await
        .context("QUIC handshake")?;

    info!("QUIC connection established");

    // -- Open control stream --

    let mut ctrl: ControlStream<_, _> = connection.open_bi().await.context("open control stream")?.into();

    // Send initial RouteAdvertise.
    let epoch = 1u64;
    let msg = ControlMessage::route_advertise(epoch, advertise_subnets.clone(), advertise_domains.clone());

    ctrl.send(&msg).await.context("send initial RouteAdvertise")?;

    info!(epoch, "Sent initial RouteAdvertise");

    // Split: recv half goes to a reader task, send half stays for periodic messages.
    let (mut ctrl_send, ctrl_recv) = ctrl.into_split();
    let mut task_handles = tokio::task::JoinSet::new();
    task_handles.spawn(run_control_reader(ctrl_recv));

    // -- Main loop: accept incoming session streams + periodic tasks --

    let route_interval = tunnel_conf.route_advertise_interval_secs.unwrap_or(30);
    let heartbeat_interval_secs = tunnel_conf.heartbeat_interval_secs.unwrap_or(60);
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
                task_handles.spawn(run_session_proxy(subnets, send, recv));
            }

            // Reap completed session tasks.
            Some(_) = task_handles.join_next() => {}
        }
    }

    task_handles.shutdown().await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Control stream reader
// ---------------------------------------------------------------------------

async fn run_control_reader<R: tokio::io::AsyncRead + Unpin>(mut ctrl: ControlRecvStream<R>) {
    let _ = async move {
        loop {
            let message = ctrl.recv().await.context("recv control message")?;

            match message {
                ControlMessage::HeartbeatAck {
                    protocol_version,
                    timestamp_ms,
                } => {
                    if let Err(e) = agent_tunnel_proto::validate_protocol_version(protocol_version) {
                        warn!(%protocol_version, %e, "Ignoring HeartbeatAck: unsupported protocol version");
                        continue;
                    }
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

async fn run_session_proxy(advertise_subnets: Vec<Ipv4Network>, send: quinn::SendStream, recv: quinn::RecvStream) {
    let _: anyhow::Result<()> = async {
        let mut session: SessionStream<_, _> = (send, recv).into();

        let connect_msg = tokio::time::timeout(Duration::from_secs(30), session.recv_request())
            .await
            .context("session handshake timeout")?
            .context("recv ConnectRequest")?;

        info!(
            session_id = %connect_msg.session_id,
            target = %connect_msg.target,
            "Received ConnectRequest"
        );

        if let Err(e) = agent_tunnel_proto::validate_protocol_version(connect_msg.protocol_version) {
            warn!(
                protocol_version = %connect_msg.protocol_version,
                %e,
                "Rejecting ConnectRequest: unsupported protocol version"
            );
            let response = ConnectResponse::error(format!("unsupported protocol version: {e}"));
            session
                .send_response(&response)
                .await
                .context("send ConnectResponse error for unsupported version")?;
            bail!("unsupported protocol version in ConnectRequest");
        }

        let target = Target::parse(&connect_msg.target).context("parse connect target")?;
        let candidates = resolve_target(&target, &advertise_subnets).await?;
        let (tcp_stream, selected_target) = connect_to_target(&candidates).await?;
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

        Ok(())
    }
    .await
    .inspect_err(|e| error!(%e, "Session proxy failed"));
}
