//! QUIC-based Agent Tunnel client implementation (Quinn).
//!
//! This module implements a QUIC client that connects to the Gateway's agent tunnel
//! endpoint, advertises reachable subnets, and handles incoming TCP proxy requests.

use std::sync::Arc;
use std::time::Duration;

use agent_tunnel_proto::{ConnectResponse, ControlMessage, ControlRecvStream, ControlStream, SessionStream};
use anyhow::{Context as _, bail};
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use ipnetwork::Ipv4Network;

use crate::config::ConfHandle;
use crate::tunnel_helpers::{connect_to_target, current_time_millis, resolve_target_candidates};

// ---------------------------------------------------------------------------
// Custom TLS verifier: verify cert chain against CA, skip hostname check
// ---------------------------------------------------------------------------

/// Wraps a `WebPkiServerVerifier` but skips the hostname verification step.
///
/// For our private PKI, the agent may connect by IP address (e.g., `127.0.0.1`)
/// while the server cert has the gateway's hostname (e.g., `devolutions432`).
/// The cert chain is still validated against our private CA — only the
/// hostname-to-SAN matching is bypassed.
#[derive(Debug)]
struct SkipHostnameVerification(Arc<dyn rustls::client::danger::ServerCertVerifier>);

impl rustls::client::danger::ServerCertVerifier for SkipHostnameVerification {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Verify the cert chain against our CA, skipping hostname verification.
        // We call the inner verifier with a dummy name; if it fails specifically
        // because of hostname mismatch (CertNotValidForName), we accept it.
        // All other errors (expired cert, unknown CA, bad signature) propagate.
        self.0
            .verify_server_cert(
                end_entity,
                intermediates,
                &rustls_pki_types::ServerName::try_from("dummy.local").expect("valid dummy server name"),
                ocsp_response,
                now,
            )
            .or_else(|e| match e {
                rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName) => {
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                }
                other => Err(other),
            })
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
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

    /// Reconnect loop with exponential backoff and jitter.
    ///
    /// Backoff strategy:
    /// - Starts at 1s, doubles each retry (with ±25% jitter), caps at 60s.
    /// - Resets to 1s after a connection survives 30s (considered stable).
    ///
    /// Example progression (without jitter):
    ///   attempt 1: fail immediately  → wait ~1s
    ///   attempt 2: fail immediately  → wait ~2s
    ///   attempt 3: fail immediately  → wait ~4s
    ///   attempt 4: fail immediately  → wait ~8s
    ///   ...
    ///   attempt N: fail immediately  → wait 60s (cap)
    ///   attempt M: connected 45s    → next backoff resets to 1s
    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
        const MAX_BACKOFF: Duration = Duration::from_secs(60);
        const CONNECTED_THRESHOLD: Duration = Duration::from_secs(30);

        info!("Starting QUIC agent tunnel (with auto-reconnect)");

        let mut backoff = INITIAL_BACKOFF;

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
                backoff = INITIAL_BACKOFF;
            }

            info!(?backoff, "Reconnecting after backoff");

            tokio::select! {
                _ = shutdown_signal.wait() => {
                    info!("Shutdown during reconnect backoff");
                    return Ok(());
                }
                _ = tokio::time::sleep(backoff) => {}
            }

            // Exponential backoff with ±25% jitter to avoid thundering herd.
            let jitter_factor = rand::Rng::gen_range(&mut rand::thread_rng(), 0.75..1.25);
            backoff =
                Duration::from_secs_f64((backoff.as_secs_f64() * 2.0 * jitter_factor).min(MAX_BACKOFF.as_secs_f64()));
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

    // Use a custom verifier that validates the cert chain against our private CA
    // but skips hostname verification. This is correct for a private PKI where the
    // agent connects by IP address but the server cert has the gateway's hostname.
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .context("build server cert verifier")?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipHostnameVerification(verifier)))
        .with_client_auth_cert(certs, key)
        .context("build rustls client config with client auth")?;

    client_crypto.alpn_protocols = vec![b"devolutions-agent-tunnel".to_vec()];

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

    let gateway_addr = tokio::net::lookup_host(&tunnel_conf.gateway_endpoint)
        .await
        .context("failed to resolve gateway endpoint")?
        .next()
        .context("no addresses resolved for gateway endpoint")?;

    info!(gateway_addr = %gateway_addr, "Connecting to gateway");

    // -- Connect --

    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().context("parse bind address")?).context("create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(gateway_addr, "gateway")
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
    let mut task_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    task_handles.push(tokio::spawn(run_control_reader(ctrl_recv)));

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
                let msg = ControlMessage::heartbeat(current_time_millis(), 0);
                let _ = ctrl_send.send(&msg).await
                    .inspect(|_| trace!("Sent Heartbeat"))
                    .inspect_err(|e| error!(%e, "Failed to send Heartbeat"));
            }

            result = connection.accept_bi() => {
                let (send, recv) = result.context("accept incoming bidi stream")?;
                let subnets = advertise_subnets.clone();
                task_handles.push(tokio::spawn(run_session_proxy(subnets, send, recv)));
            }
        }
    }

    // Abort all spawned tasks on shutdown.
    for handle in &task_handles {
        handle.abort();
    }
    for handle in task_handles {
        let _ = handle.await;
    }

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

        let connect_msg = session.recv_request().await.context("recv ConnectRequest")?;

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

        let candidates = resolve_target_candidates(&connect_msg.target, &advertise_subnets).await?;
        let (tcp_stream, selected_target) = connect_to_target(&candidates).await?;
        info!(target = %selected_target, "TCP connection established");

        session
            .send_response(&ConnectResponse::success())
            .await
            .context("send ConnectResponse")?;
        info!("Sent ConnectResponse::Success");

        let (mut send, mut recv) = session.into_inner();
        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

        tokio::select! {
            r = tokio::io::copy(&mut recv, &mut tcp_write) => {
                r.inspect_err(|e| debug!(%e, "QUIC->TCP copy ended"))?;
            }
            r = tokio::io::copy(&mut tcp_read, &mut send) => {
                r.inspect_err(|e| debug!(%e, "TCP->QUIC copy ended"))?;
            }
        }

        Ok(())
    }
    .await
    .inspect_err(|e| error!(%e, "Session proxy failed"));
}
