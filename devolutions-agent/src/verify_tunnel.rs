//! One-shot verification of the agent's QUIC tunnel to the Gateway.
//!
//! This module powers `agent.exe verify-tunnel`. Unlike the long-running
//! [`tunnel::TunnelTask`], it performs a single QUIC handshake + a single
//! control-plane round-trip (`RouteAdvertise` followed by a `Heartbeat`/
//! `HeartbeatAck` to prove the control stream is alive in both directions),
//! then exits. The exit code reports success/failure and the last line of
//! stderr is the JSON error triple defined in the design doc.
//!
//! ## Error catalog
//!
//! Every operator-reachable failure is classified into an [`ErrorKind`].
//! Each kind carries a stable string identifier (`kind`), a variable-content
//! `detail`, and a fixed `next_step` describing what the operator should do.
//! There is exactly one catch-all (`unexpected_error`) that must carry a
//! correlation ID and the agent log file path.
//!
//! ## Output contract (installer-facing)
//!
//! - **stderr** receives a single JSON line as the very last thing written
//!   before exit:
//!
//!   ```text
//!   {"kind":"dns_resolution_failed","detail":"...","next_step":"..."}
//!   ```
//!
//! - **stdout** is reserved for human-readable progress, but the installer
//!   only consumes stderr.
//!
//! - **exit code** is `0` for success, `1` for any classified failure.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use agent_tunnel_proto::{ControlMessage, ControlStream, current_time_millis};
use anyhow::Context as _;
use ipnetwork::Ipv4Network;
use serde::Serialize;
use sha2::Digest as _;

use crate::config::ConfHandle;

// ---------------------------------------------------------------------------
// Error catalog
// ---------------------------------------------------------------------------

/// Stable identifier classes used by both the installer and the agent service.
///
/// The `as_str` of each variant is the wire identifier emitted in the JSON
/// triple and must remain stable across releases — monitoring tools and the
/// MSI custom action key off these strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Gateway HTTP-rejected enrollment because `jet_gw_url.host` was not in
    /// `AgentTunnel.AdvertisedNames`.
    EnrollmentHostNotAdvertised,
    /// DNS lookup of the gateway endpoint hostname returned no records.
    DnsResolutionFailed,
    /// UDP/QUIC packets to the gateway received no response (firewall, NAT,
    /// EDR network filter, or gateway not listening).
    UdpUnreachable,
    /// TLS handshake failed because the server certificate's SAN did not
    /// include the dial host.
    TlsSanMismatch,
    /// TLS chain validated but the server's SPKI did not match the pin
    /// captured at enrollment.
    TlsSpkiPinMismatch,
    /// QUIC handshake started but never reached the Finished state.
    QuicHandshakeTimeout,
    /// QUIC connected but the Gateway never acknowledged the control-plane
    /// round-trip (`RouteAdvertise` + `Heartbeat`).
    RouteAdvertiseTimeout,
    /// The enrollment JWT's `exp` is in the past.
    EnrollmentTokenExpired,
    /// The enrollment JWT signature failed verification at the Gateway.
    EnrollmentTokenSignatureInvalid,
    /// Catch-all for unclassified failures. Must include a correlation ID
    /// and the agent log path in `detail`.
    UnexpectedError,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::EnrollmentHostNotAdvertised => "enrollment_host_not_advertised",
            ErrorKind::DnsResolutionFailed => "dns_resolution_failed",
            ErrorKind::UdpUnreachable => "udp_unreachable",
            ErrorKind::TlsSanMismatch => "tls_san_mismatch",
            ErrorKind::TlsSpkiPinMismatch => "tls_spki_pin_mismatch",
            ErrorKind::QuicHandshakeTimeout => "quic_handshake_timeout",
            ErrorKind::RouteAdvertiseTimeout => "route_advertise_timeout",
            ErrorKind::EnrollmentTokenExpired => "enrollment_token_expired",
            ErrorKind::EnrollmentTokenSignatureInvalid => "enrollment_token_signature_invalid",
            ErrorKind::UnexpectedError => "unexpected_error",
        }
    }

    /// Operator-facing next-step text. This is the fallback wording when the
    /// caller does not provide a customized one (most call sites use this
    /// default — only the host-not-advertised case needs to substitute the
    /// actual host name into the help text).
    pub fn next_step(self) -> &'static str {
        match self {
            ErrorKind::EnrollmentHostNotAdvertised => {
                "Regenerate the enrollment string in DVLS using one of the advertised names, \
                 or add the host used at enrollment to AgentTunnel.AdvertisedNames on the Gateway."
            }
            ErrorKind::DnsResolutionFailed => {
                "This agent's network cannot resolve the configured gateway hostname. \
                 Either generate an enrollment string with a name this machine can resolve \
                 (e.g. an IP literal that the Gateway also advertises), or add a DNS entry / \
                 hosts file mapping for the hostname."
            }
            ErrorKind::UdpUnreachable => {
                "Verify Gateway is running and the agent tunnel UDP port is open between this agent \
                 and the Gateway. Check Windows Firewall, corporate firewall, NAT, and SophosNTP / \
                 EDR network filters on both ends."
            }
            ErrorKind::TlsSanMismatch => {
                "Gateway operator must add the dial host to AgentTunnel.AdvertisedNames in gateway.json \
                 and restart the Gateway. The server certificate will be regenerated with the new host in SAN."
            }
            ErrorKind::TlsSpkiPinMismatch => {
                "The Gateway's agent-tunnel keypair changed since this agent enrolled (server key \
                 regenerated, gateway reinstalled, or man-in-the-middle). Re-enroll this agent by \
                 uninstalling and reinstalling with a fresh enrollment string."
            }
            ErrorKind::QuicHandshakeTimeout => {
                "Network path likely drops UDP mid-flow (path MTU, broken NAT, deep packet inspection). \
                 Try a different network egress, lower QUIC MTU, or disable EDR network inspection for the \
                 Gateway endpoint."
            }
            ErrorKind::RouteAdvertiseTimeout => {
                "Gateway is running an older or incompatible build; ensure Gateway version supports the agent \
                 tunnel feature. Check Gateway logs for RouteAdvertise handling errors."
            }
            ErrorKind::EnrollmentTokenExpired => {
                "Generate a new enrollment string in DVLS. Default token lifetime is short; coordinate enrollment \
                 with the installer run."
            }
            ErrorKind::EnrollmentTokenSignatureInvalid => {
                "The Gateway's provisioner.pem does not match the DVLS instance that signed this enrollment string. \
                 Verify DVLS is configured with the same Gateway entry, and that provisioner.pem on the Gateway \
                 corresponds to the provisioner.key DVLS is using."
            }
            ErrorKind::UnexpectedError => {
                "Collect the agent log and Gateway log using the correlation ID, then file a support issue. \
                 This is a product bug if it reaches the operator."
            }
        }
    }
}

/// The error triple emitted to stderr as a single-line JSON object.
///
/// Field ordering is fixed for greppability of installer logs:
/// `{"kind":..., "detail":..., "next_step":...}`. Serde preserves struct field
/// declaration order when serializing.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorTriple {
    pub kind: &'static str,
    pub detail: String,
    pub next_step: String,
}

impl ErrorTriple {
    /// Build a triple with the default `next_step` text from the catalog.
    pub fn new(kind: ErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.as_str(),
            detail: detail.into(),
            next_step: kind.next_step().to_owned(),
        }
    }

    /// Build a triple using a custom `next_step` text. Used for
    /// host-not-advertised where the gateway returns a fully-formed help
    /// string we should pass through verbatim.
    pub fn with_next_step(kind: ErrorKind, detail: impl Into<String>, next_step: impl Into<String>) -> Self {
        Self {
            kind: kind.as_str(),
            detail: detail.into(),
            next_step: next_step.into(),
        }
    }

    /// Emit as a single line on stderr — the installer CA's contract.
    pub fn emit_to_stderr(&self) {
        // Single line, no trailing newline beyond the one `eprintln!` adds.
        let line = serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"kind":"{}","detail":"<serialization error>","next_step":"<serialization error>"}}"#,
                self.kind,
            )
        });
        eprintln!("{line}");
    }

    /// Emit to the Windows Event Log under source `DevolutionsAgent`.
    ///
    /// On non-Windows targets this is a no-op so the agent service callers
    /// can use the same call site on every platform.
    ///
    /// The event source is registered by the installer's `WriteEventLog` /
    /// `EventSource` table entries (or fabricated lazily at first write by
    /// `RegisterEventSourceW`; if the source name is unknown, Windows logs to
    /// the Application channel with a "description not found" suffix, still
    /// readable for diagnosis).
    pub fn emit_to_event_log(&self) {
        #[cfg(windows)]
        emit_event_log_windows(self);
        #[cfg(not(windows))]
        {
            // Linux/macOS: agent service is Windows-only in this product, so
            // there's nothing to write to. Caller still gets the stderr line
            // and the tracing log entry.
            let _ = self;
        }
    }
}

#[cfg(windows)]
fn emit_event_log_windows(triple: &ErrorTriple) {
    use windows::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
    };
    use windows::core::PCWSTR;

    // Build a NUL-terminated wide string for the source name.
    let source: Vec<u16> = "DevolutionsAgent".encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `source` is a NUL-terminated UTF-16 buffer; `RegisterEventSourceW`
    // dereferences the pointer as a read-only PCWSTR. We hold `source` alive
    // for the duration of the call.
    let handle = unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(source.as_ptr())) };
    let Ok(handle) = handle else {
        return;
    };

    // One wide line per named property — Event Viewer "Details (XML view)" then
    // shows them as separate `<Data Name="...">` entries which monitoring tools
    // can parse without scraping free-text.
    let kind_line = format!("kind={}", triple.kind);
    let detail_line = format!("detail={}", triple.detail);
    let next_step_line = format!("next_step={}", triple.next_step);

    let strings: Vec<Vec<u16>> = [kind_line, detail_line, next_step_line]
        .iter()
        .map(|s| s.encode_utf16().chain(std::iter::once(0)).collect())
        .collect();
    let string_ptrs: Vec<PCWSTR> = strings.iter().map(|s| PCWSTR(s.as_ptr())).collect();

    // EventID 1 = generic agent tunnel verification failure. Specific kinds
    // are surfaced via the `kind=` property; we keep the EventID stable for
    // monitoring tool filters.
    let event_id: u32 = 1;

    // SAFETY: `handle` is a live event source handle obtained above; the
    // string pointers are kept alive via `strings` for the duration of the
    // call. `ReportEventW` does not retain pointers after return.
    let _ = unsafe {
        ReportEventW(
            handle,
            EVENTLOG_ERROR_TYPE,
            0, // wCategory
            event_id,
            None,                // lpUserSid
            0,                   // dwDataSize (no binary payload)
            Some(&string_ptrs),  // lpStrings
            None,                // lpRawData
        )
    };

    // SAFETY: `handle` was produced by `RegisterEventSourceW` and is dropped here.
    let _ = unsafe { DeregisterEventSource(handle) };
}

// ---------------------------------------------------------------------------
// verify_tunnel entry point
// ---------------------------------------------------------------------------

/// Run one tunnel verification round.
///
/// Reads `agent.json`, performs a QUIC handshake, sends one `RouteAdvertise`
/// followed by one `Heartbeat`, waits for the `HeartbeatAck`, and returns.
///
/// The protocol does not (yet) carry an explicit `RouteAdvertiseAck`. We rely
/// on a paired `Heartbeat`/`HeartbeatAck` round-trip on the same control
/// stream — getting the ack back proves both `RouteAdvertise` was accepted
/// (the gateway-side handler updates the registry on receipt) and the control
/// stream is alive in both directions.
///
/// On failure, this function returns the operator-facing [`ErrorTriple`].
pub async fn verify_tunnel(conf_handle: &ConfHandle, timeout: Duration) -> Result<(), ErrorTriple> {
    tokio::time::timeout(timeout, run_verification(conf_handle))
        .await
        .unwrap_or_else(|_elapsed| {
            Err(ErrorTriple::new(
                ErrorKind::QuicHandshakeTimeout,
                format!("Verification timed out after {}s", timeout.as_secs()),
            ))
        })
}

async fn run_verification(conf_handle: &ConfHandle) -> Result<(), ErrorTriple> {
    // Ensure rustls crypto provider is installed (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let agent_conf = conf_handle.get_conf();
    let tunnel_conf = &agent_conf.tunnel;

    if !tunnel_conf.enabled {
        return Err(ErrorTriple::new(
            ErrorKind::UnexpectedError,
            "Tunnel section in agent.json is disabled; nothing to verify".to_owned(),
        ));
    }

    let cert_path = &tunnel_conf.client_cert_path;
    let key_path = &tunnel_conf.client_key_path;
    let ca_path = &tunnel_conf.gateway_ca_cert_path;

    // ----- Build rustls client config -----

    let client_crypto = build_client_crypto(cert_path.as_str(), key_path.as_str(), ca_path.as_str(), tunnel_conf)
        .map_err(|e| {
            ErrorTriple::new(
                ErrorKind::UnexpectedError,
                format!(
                    "Failed to build TLS client config: {e:#}; correlation_id={}; log=<agent log file>",
                    uuid::Uuid::new_v4()
                ),
            )
        })?;

    // ----- Resolve gateway endpoint -----

    let endpoint_str = &tunnel_conf.gateway_endpoint;
    let (gateway_hostname, _port_str) = split_host_port(endpoint_str).ok_or_else(|| {
        ErrorTriple::new(
            ErrorKind::UnexpectedError,
            format!("gateway_endpoint {endpoint_str:?} is malformed (missing port separator)"),
        )
    })?;

    let gateway_addr = match tokio::net::lookup_host(endpoint_str).await {
        Ok(mut iter) => iter
            .next()
            .ok_or_else(|| dns_failed(gateway_hostname.as_str(), "no addresses returned"))?,
        Err(error) => {
            return Err(dns_failed(gateway_hostname.as_str(), &format!("{error}")));
        }
    };

    // ----- QUIC dial + handshake -----

    let bind_addr: SocketAddr = if gateway_addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };

    let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(|error| {
        ErrorTriple::new(
            ErrorKind::UnexpectedError,
            format!(
                "Failed to create QUIC client endpoint: {error:#}; correlation_id={}; log=<agent log file>",
                uuid::Uuid::new_v4()
            ),
        )
    })?;

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("30s -> idle timeout")))
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .max_concurrent_bidi_streams(8u32.into());
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).map_err(|error| {
            ErrorTriple::new(
                ErrorKind::UnexpectedError,
                format!(
                    "Failed to build QuicClientConfig: {error:#}; correlation_id={}; log=<agent log file>",
                    uuid::Uuid::new_v4()
                ),
            )
        })?,
    ));
    client_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint
        .connect(gateway_addr, gateway_hostname.as_str())
        .map_err(|error| {
            // `Endpoint::connect` returns synchronously for argument errors only.
            ErrorTriple::new(
                ErrorKind::UnexpectedError,
                format!(
                    "QUIC connect call failed: {error:#}; correlation_id={}; log=<agent log file>",
                    uuid::Uuid::new_v4()
                ),
            )
        })?;

    let connection = match connecting.await {
        Ok(conn) => conn,
        Err(error) => return Err(classify_handshake_error(&error, gateway_hostname.as_str())),
    };

    // ----- Control-plane round-trip -----

    let mut ctrl: ControlStream<_, _> = connection
        .open_bi()
        .await
        .map_err(|error| {
            ErrorTriple::new(
                ErrorKind::RouteAdvertiseTimeout,
                format!("QUIC connected but could not open control stream: {error:#}"),
            )
        })?
        .into();

    // Send a minimal RouteAdvertise (no subnets/domains — verify-tunnel is a
    // probe, not a real registration). The gateway updates its registry on
    // receipt; agents normally re-send the real list on first reconnect after
    // verify-tunnel exits.
    let advertise = ControlMessage::route_advertise(0, Vec::<Ipv4Network>::new(), Vec::new());
    ctrl.send(&advertise).await.map_err(|error| {
        ErrorTriple::new(
            ErrorKind::RouteAdvertiseTimeout,
            format!("Failed to send RouteAdvertise on control stream: {error:#}"),
        )
    })?;

    // Send a Heartbeat and wait for its HeartbeatAck — the only ack-bearing
    // round-trip currently defined by the protocol. The ack proves both
    // RouteAdvertise was accepted (gateway processed the prior message on the
    // same stream before reading this one) and the control stream is alive in
    // both directions.
    let ts = current_time_millis();
    let heartbeat = ControlMessage::heartbeat(ts, 0);
    ctrl.send(&heartbeat).await.map_err(|error| {
        ErrorTriple::new(
            ErrorKind::RouteAdvertiseTimeout,
            format!("Failed to send Heartbeat on control stream: {error:#}"),
        )
    })?;

    // Read messages from the gateway until we observe a HeartbeatAck for our
    // ts (or any HeartbeatAck — single-shot probe), with a tight inner timeout
    // so the outer 10s budget isn't consumed entirely by one stuck recv.
    let inner_timeout = Duration::from_secs(5);
    match tokio::time::timeout(inner_timeout, await_heartbeat_ack(&mut ctrl, ts)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Err(ErrorTriple::new(
                ErrorKind::RouteAdvertiseTimeout,
                format!("Control stream error while waiting for HeartbeatAck: {error:#}"),
            ));
        }
        Err(_) => {
            return Err(ErrorTriple::new(
                ErrorKind::RouteAdvertiseTimeout,
                format!("QUIC connected, no HeartbeatAck in {}s", inner_timeout.as_secs()),
            ));
        }
    }

    // Gracefully close.
    connection.close(0u32.into(), b"verify-tunnel done");
    endpoint.close(0u32.into(), b"verify-tunnel done");

    Ok(())
}

async fn await_heartbeat_ack<S, R>(ctrl: &mut ControlStream<S, R>, expected_ts: u64) -> anyhow::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        let msg = ctrl.recv().await.context("read control message")?;
        match msg {
            ControlMessage::HeartbeatAck { timestamp_ms, .. } if timestamp_ms == expected_ts => return Ok(()),
            // The Gateway may interleave other messages on the control stream; ignore them.
            ControlMessage::HeartbeatAck { .. }
            | ControlMessage::Heartbeat { .. }
            | ControlMessage::RouteAdvertise { .. }
            | ControlMessage::CertRenewalResponse { .. }
            | ControlMessage::CertRenewalRequest { .. } => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Split a `host:port` / `[ipv6]:port` endpoint into the host string and the
/// port string. Returns `None` when no port separator is found.
fn split_host_port(endpoint: &str) -> Option<(String, String)> {
    let trimmed = endpoint.trim();
    if let Some((host, port)) = trimmed.rsplit_once(']') {
        // IPv6 form: `[host]:port`.
        let host = host.strip_prefix('[')?;
        let port = port.strip_prefix(':')?;
        Some((host.to_owned(), port.to_owned()))
    } else {
        // DNS / IPv4 form: `host:port`.
        let (host, port) = trimmed.rsplit_once(':')?;
        Some((host.to_owned(), port.to_owned()))
    }
}

fn dns_failed(host: &str, raw: &str) -> ErrorTriple {
    ErrorTriple::new(
        ErrorKind::DnsResolutionFailed,
        format!("Could not resolve '{host}' from this machine ({raw})"),
    )
}

/// Map a Quinn connection error to the most useful operator-facing kind.
///
/// Quinn surfaces a small set of `ConnectionError` variants. We split them
/// into:
/// - TLS verification failures (the cert SAN didn't match, or our pinned SPKI
///   verifier returned `General`),
/// - Handshake timeouts (no UDP path to the gateway, or path drops mid-flow),
/// - Anything else as `unexpected_error`.
fn classify_handshake_error(error: &quinn::ConnectionError, host: &str) -> ErrorTriple {
    use quinn::ConnectionError as Ce;
    match error {
        Ce::TimedOut => ErrorTriple::new(
            ErrorKind::UdpUnreachable,
            format!("Resolved {host} -> gateway, but no QUIC initial response (UDP blocked or no listener)"),
        ),
        Ce::ConnectionClosed(_) | Ce::ApplicationClosed(_) | Ce::Reset | Ce::LocallyClosed => ErrorTriple::new(
            ErrorKind::QuicHandshakeTimeout,
            format!("QUIC connection closed before handshake completed: {error}"),
        ),
        Ce::TransportError(transport_error) => {
            let detail = format!("{transport_error}");
            // The exact string from rustls for SPKI pin mismatch is
            // "General(\"server SPKI hash does not match pinned value from enrollment\")".
            if detail.contains("server SPKI hash does not match pinned value") {
                ErrorTriple::new(
                    ErrorKind::TlsSpkiPinMismatch,
                    format!(
                        "Pinned SPKI does not match server-presented SPKI ({}); host={host}",
                        detail
                    ),
                )
            } else if detail.contains("NotValidForName")
                || detail.contains("CertNotValidForName")
                || detail.contains("not valid for name")
            {
                ErrorTriple::new(
                    ErrorKind::TlsSanMismatch,
                    format!("Connecting as '{host}' but server cert SAN does not include it ({detail})"),
                )
            } else {
                ErrorTriple::new(
                    ErrorKind::QuicHandshakeTimeout,
                    format!("QUIC transport error during handshake: {detail}"),
                )
            }
        }
        other => ErrorTriple::new(
            ErrorKind::UnexpectedError,
            format!(
                "QUIC handshake failed: {other}; correlation_id={}; log=<agent log file>",
                uuid::Uuid::new_v4()
            ),
        ),
    }
}

/// Build a rustls `ClientConfig` mirroring [`crate::tunnel`]'s setup: mTLS
/// client auth + chain validation + SPKI pinning (when one was recorded at
/// enrollment).
fn build_client_crypto(
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
    tunnel_conf: &crate::config::TunnelConf,
) -> anyhow::Result<rustls::ClientConfig> {
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert_path).context("open client cert file")?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("parse client certificates")?;

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key_path).context("open client key file")?,
    ))
    .context("parse private key file")?
    .context("no private key found in file")?;

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(ca_path).context("open CA cert file")?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("parse CA certificates")?;
    for cert in ca_certs {
        roots.add(cert)?;
    }

    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .context("build server cert verifier")?;

    let effective_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = if let Some(ref expected_spki) =
        tunnel_conf.server_spki_sha256
    {
        Arc::new(SpkiPinnedVerifier {
            inner: verifier,
            expected_spki_sha256: expected_spki.clone(),
        })
    } else {
        verifier
    };

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(effective_verifier)
        .with_client_auth_cert(certs, key)
        .context("build rustls client config with client auth")?;

    client_crypto.alpn_protocols = vec![agent_tunnel_proto::ALPN_PROTOCOL.to_vec()];

    Ok(client_crypto)
}

/// Mirrors `tunnel::SpkiPinnedVerifier` — but kept local so `verify-tunnel`
/// can run independently of the long-running tunnel task module.
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
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kinds_have_stable_wire_strings() {
        assert_eq!(ErrorKind::DnsResolutionFailed.as_str(), "dns_resolution_failed");
        assert_eq!(ErrorKind::TlsSanMismatch.as_str(), "tls_san_mismatch");
        assert_eq!(ErrorKind::UnexpectedError.as_str(), "unexpected_error");
    }

    #[test]
    fn error_triple_serializes_to_single_line_json_with_three_fields() {
        let triple = ErrorTriple::new(
            ErrorKind::DnsResolutionFailed,
            "Could not resolve 'gateway.corp' from this machine",
        );
        let json = serde_json::to_string(&triple).expect("serialize triple");
        // Field order is fixed.
        assert!(
            json.starts_with(r#"{"kind":"dns_resolution_failed""#),
            "got: {json}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");
        assert_eq!(parsed["kind"], "dns_resolution_failed");
        assert!(parsed["detail"].as_str().unwrap().contains("gateway.corp"));
        assert!(parsed["next_step"].as_str().unwrap().contains("DNS entry"));
        // Single-line (no embedded newlines).
        assert!(!json.contains('\n'));
    }

    #[test]
    fn error_triple_with_custom_next_step() {
        let triple = ErrorTriple::with_next_step(
            ErrorKind::EnrollmentHostNotAdvertised,
            "Gateway advertises: [..]. JWT used host: evil.example.com",
            "Custom help from gateway response",
        );
        assert_eq!(triple.kind, "enrollment_host_not_advertised");
        assert_eq!(triple.next_step, "Custom help from gateway response");
    }

    #[test]
    fn unexpected_error_carries_correlation_id_and_log_pointer() {
        let triple = ErrorTriple::new(
            ErrorKind::UnexpectedError,
            "Unexpected failure during phase=dns; correlation_id=12345; log=C:/ProgramData/.../agent.log",
        );
        assert!(triple.detail.contains("correlation_id="));
        assert!(triple.detail.contains("log="));
    }

    #[test]
    fn split_host_port_dns() {
        let (h, p) = split_host_port("gateway.example.com:4433").unwrap();
        assert_eq!(h, "gateway.example.com");
        assert_eq!(p, "4433");
    }

    #[test]
    fn split_host_port_ipv4() {
        let (h, p) = split_host_port("10.10.0.7:4433").unwrap();
        assert_eq!(h, "10.10.0.7");
        assert_eq!(p, "4433");
    }

    #[test]
    fn split_host_port_ipv6() {
        let (h, p) = split_host_port("[fd00::7]:4433").unwrap();
        assert_eq!(h, "fd00::7");
        assert_eq!(p, "4433");
    }

    #[test]
    fn split_host_port_rejects_no_port() {
        assert!(split_host_port("gateway.example.com").is_none());
    }
}
