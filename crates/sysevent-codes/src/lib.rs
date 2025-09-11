use std::path::Path;
use sysevent::{Entry, Severity};

// 1000-1099 **Service/Lifecycle**

/// Fired after `GatewayService::start()`
pub const SERVICE_STARTED: u32 = 1000;
/// Graceful stop received
pub const SERVICE_STOPPING: u32 = 1001;
/// Failed to init config
pub const CONFIG_INVALID: u32 = 1010;
/// Top-level start failure (often transient)
pub const START_FAILED: u32 = 1020;
/// A boot crash trace was persisted.
pub const BOOT_STACKTRACE_WRITTEN: u32 = 1030;

pub fn service_started(version: impl ToString) -> Entry {
    Entry::new("Service started")
        .event_code(SERVICE_STARTED)
        .severity(Severity::Info)
        .field("version", version)
}

pub fn service_stopping(reason: impl ToString) -> Entry {
    Entry::new("Service stopping")
        .event_code(SERVICE_STOPPING)
        .severity(Severity::Info)
        .field("reason", reason)
}

pub fn config_invalid(error: impl std::fmt::Display, path: impl AsRef<Path>) -> Entry {
    Entry::new("Configuration invalid")
        .event_code(CONFIG_INVALID)
        .severity(Severity::Critical)
        .field("path", path.as_ref().display())
        .field("error_chain", format!("{error:#}"))
        .field("reason_code", "invalid_config")
}

pub fn start_failed(error: impl std::fmt::Display, cause: impl ToString) -> Entry {
    Entry::new("Start failed")
        .event_code(START_FAILED)
        .severity(Severity::Error)
        .field("cause", cause) // e.g. "bind", "dependency", "tls", "io"
        .field("error_chain", format!("{error:#}"))
}

pub fn boot_stacktrace_written(path: &Path) -> Entry {
    Entry::new("Boot stacktrace written")
        .event_code(BOOT_STACKTRACE_WRITTEN)
        .severity(Severity::Warning)
        .field("path", path.display())
}

// 2000-2099 **Listeners & Networking**

/// Fires with listener start.
pub const LISTENER_STARTED: u32 = 2000;
/// Bind failure with OS error.
pub const LISTENER_BIND_FAILED: u32 = 2001;
/// Fires when listener stops.
pub const LISTENER_STOPPED: u32 = 2002;

pub fn listener_started(address: impl ToString, proto: impl ToString) -> Entry {
    Entry::new("Listener started")
        .event_code(LISTENER_STARTED)
        .severity(Severity::Info)
        .field("address", address)
        .field("proto", proto) // e.g. "tcp", "http", "socks5"
}

pub fn listener_bind_failed(address: impl ToString, error: impl std::fmt::Display) -> Entry {
    Entry::new("Listener bind failed")
        .event_code(LISTENER_BIND_FAILED)
        .severity(Severity::Error)
        .field("address", address)
        .field("error_chain", format!("{error:#}"))
}

pub fn listener_stopped(address: impl ToString, reason: impl ToString) -> Entry {
    Entry::new("Listener stopped")
        .event_code(LISTENER_STOPPED)
        .severity(Severity::Info)
        .field("address", address)
        .field("reason", reason) // "shutdown", "reload", "error"
}

// 3000-3099 **TLS / Certificates**

/// TLS configured (includes which source: file vs system store)
pub const TLS_CONFIGURED: u32 = 3000;
/// Strict verification off (compat mode).
pub const TLS_VERIFY_STRICT_DISABLED: u32 = 3001;
/// Missing SAN or EKU=serverAuth (reject).
pub const TLS_CERTIFICATE_REJECTED: u32 = 3002;
/// Thumbprint/subject; selection criteria.
pub const SYSTEM_CERT_SELECTED: u32 = 3003;
/// Key/cert load failure (path + error).
pub const TLS_KEY_LOAD_FAILED: u32 = 3004;
/// Name mismatch (CN/SAN vs host)
pub const TLS_CERTIFICATE_NAME_MISMATCH: u32 = 3005;
/// No suitable certificate found.
pub const TLS_NO_SUITABLE_CERTIFICATE: u32 = 3006;

pub fn tls_configured(source: impl ToString) -> Entry {
    Entry::new("TLS configured")
        .event_code(TLS_CONFIGURED)
        .severity(Severity::Info)
        .field("source", source) // "file", "system_store"
}

pub fn tls_verify_strict_disabled(mode: impl ToString) -> Entry {
    Entry::new("TLS strict verification disabled")
        .event_code(TLS_VERIFY_STRICT_DISABLED)
        .severity(Severity::Notice)
        .field("mode", mode) // e.g. "compat", "insecure-skip-verify"
}

pub fn tls_certificate_rejected(subject: impl ToString, reason_code: impl ToString) -> Entry {
    Entry::new("Certificate rejected")
        .event_code(TLS_CERTIFICATE_REJECTED)
        .severity(Severity::Error)
        .field("subject", subject)
        .field("reason_code", reason_code) // "missing_san", "eku_missing", ...
}

pub fn tls_no_suitable_certificate(error: impl std::fmt::Display, issues: impl ToString) -> Entry {
    Entry::new("No usable certificate found")
        .event_code(TLS_NO_SUITABLE_CERTIFICATE)
        .severity(Severity::Critical)
        .field("error", format!("{error:#}"))
        .field("issues", issues)
}

pub fn system_cert_selected(thumbprint: impl ToString, subject: impl ToString) -> Entry {
    Entry::new("System certificate selected")
        .event_code(SYSTEM_CERT_SELECTED)
        .severity(Severity::Info)
        .field("thumbprint", thumbprint)
        .field("subject", subject)
}

pub fn tls_key_load_failed(path: impl AsRef<Path>, error: impl std::fmt::Display) -> Entry {
    Entry::new("TLS key/cert load failed")
        .event_code(TLS_KEY_LOAD_FAILED)
        .severity(Severity::Error)
        .field("path", path.as_ref().display())
        .field("error_chain", format!("{error:#}"))
        .field("reason_code", "io_error")
}

pub fn tls_certificate_name_mismatch(hostname: impl ToString, subject: impl ToString) -> Entry {
    Entry::new("TLS certificate name mismatch")
        .event_code(TLS_CERTIFICATE_NAME_MISMATCH)
        .severity(Severity::Notice)
        .field("hostname", hostname)
        .field("subject", subject)
        .field("reason_code", "name_mismatch")
}

// 4000-4099 **Sessions, Tokens & Recording**

pub const SESSION_OPENED: u32 = 4000;
pub const SESSION_CLOSED: u32 = 4001;
pub const TOKEN_PROVISIONED: u32 = 4010;
pub const TOKEN_REUSED: u32 = 4011;
pub const TOKEN_REUSE_LIMIT_EXCEEDED: u32 = 4012;
pub const RECORDING_STARTED: u32 = 4030;
pub const RECORDING_STOPPED: u32 = 4031;
pub const RECORDING_ERROR: u32 = 4032;

pub fn session_opened(
    protocol: impl ToString,
    client_ip: impl ToString,
    target: impl ToString,
    token_id: impl ToString,
) -> Entry {
    Entry::new("Session opened")
        .event_code(SESSION_OPENED)
        .severity(Severity::Info)
        .field("protocol", protocol) // "RDP","SSH","VNC","JMUX",...
        .field("client_ip", client_ip)
        .field("target", target)
        .field("token_id", token_id)
}

pub fn session_closed(
    duration_ms: u64,
    bytes_tx: u64,
    bytes_rx: u64,
    outcome: impl ToString, // "ok","client_disconnect","timeout","denied","error"
) -> Entry {
    Entry::new("Session closed")
        .event_code(SESSION_CLOSED)
        .severity(Severity::Info)
        .field("duration_ms", duration_ms)
        .field("bytes_tx", bytes_tx)
        .field("bytes_rx", bytes_rx)
        .field("outcome", outcome)
}

pub fn token_provisioned(token_id: impl ToString) -> Entry {
    Entry::new("Token provisioned")
        .event_code(TOKEN_PROVISIONED)
        .severity(Severity::Info)
        .field("token_id", token_id)
}

pub fn token_reused(token_id: impl ToString, reuse_count: u32) -> Entry {
    Entry::new("Token reused")
        .event_code(TOKEN_REUSED)
        .severity(Severity::Info)
        .field("token_id", token_id)
        .field("reuse_count", reuse_count)
}

pub fn token_reuse_limit_exceeded(token_id: impl ToString, limit: u32) -> Entry {
    Entry::new("Token reuse limit exceeded")
        .event_code(TOKEN_REUSE_LIMIT_EXCEEDED)
        .severity(Severity::Warning)
        .field("token_id", token_id)
        .field("limit", limit)
        .field("reason_code", "reuse_limit_exceeded")
}

pub fn recording_started(destination: impl ToString) -> Entry {
    Entry::new("Recording started")
        .event_code(RECORDING_STARTED)
        .severity(Severity::Info)
        .field("destination", destination)
}

pub fn recording_stopped(bytes: u64, files: u32) -> Entry {
    Entry::new("Recording stopped")
        .event_code(RECORDING_STOPPED)
        .severity(Severity::Info)
        .field("bytes", bytes)
        .field("files", files)
}

pub fn recording_error(path: impl AsRef<Path>, error: impl std::fmt::Display) -> Entry {
    Entry::new("Recording error")
        .event_code(RECORDING_ERROR)
        .severity(Severity::Error)
        .field("path", path.as_ref().display())
        .field("error_chain", format!("{error:#}"))
}

// 5000-5099 **Authentication / Authorization**

/// Signature/Expiry/Audience failure.
pub const JWT_REJECTED: u32 = 5001;
/// (Warning): unusual but accepted (near-expiry grace, unknown kid with fallback, oversized token).
pub const JWT_ANOMALY: u32 = 5002;
/// Rule evaluation result.
pub const AUTHORIZATION_DENIED: u32 = 5010;
/// (Info): interval_s, jwt_ok, jwt_rejected, denied, by_reason
pub const AUTH_SUMMARY: u32 = 5090;

pub fn jwt_rejected(
    reason_code: impl ToString, // "expired","bad_signature","aud_mismatch","not_before","unknown_kid",...
    reason: impl ToString,      // human-readable reason
) -> Entry {
    Entry::new("JWT rejected")
        .event_code(JWT_REJECTED)
        .severity(Severity::Warning)
        .field("reason_code", reason_code)
        .field("reason", reason)
}

pub fn jwt_anomaly(
    issuer: impl ToString,
    audience: impl ToString,
    kid: impl ToString,
    kind: impl ToString, // "near_expiry_grace","oversized_token","alg_unexpected","clock_skew"
    detail: impl ToString,
) -> Entry {
    Entry::new("JWT anomaly")
        .event_code(JWT_ANOMALY)
        .severity(Severity::Warning)
        .field("issuer", issuer)
        .field("audience", audience)
        .field("kid", kid)
        .field("kind", kind)
        .field("detail", detail)
}

pub fn authorization_denied(
    subject: impl ToString,
    action: impl ToString,
    resource: impl ToString,
    rule: impl ToString,
) -> Entry {
    Entry::new("Authorization denied")
        .event_code(AUTHORIZATION_DENIED)
        .severity(Severity::Warning)
        .field("subject", subject)
        .field("action", action)
        .field("resource", resource)
        .field("rule", rule)
        .field("reason_code", "permission_denied")
}

/// Emit periodically; keep Event Log lightweight but SIEM-friendly.
pub fn auth_summary(
    interval_s: u32,
    jwt_ok: u64,
    jwt_rejected: u64,
    denied: u64,
    by_reason_json: impl ToString, // e.g. compact JSON: {"expired":123,"bad_signature":4}
) -> Entry {
    Entry::new("Auth summary")
        .event_code(AUTH_SUMMARY)
        .severity(Severity::Info)
        .field("interval_s", interval_s)
        .field("jwt_ok", jwt_ok)
        .field("jwt_rejected", jwt_rejected)
        .field("denied", denied)
        .field("by_reason", by_reason_json)
}

// 6000-6099 **Agent Integration**

/// `DevolutionsSession.exe` started in session; include session id & kind (console/remote).
pub const USER_SESSION_PROCESS_STARTED: u32 = 6000;
/// Exit code; who triggered.
pub const USER_SESSION_PROCESS_TERMINATED: u32 = 6001;
pub const UPDATER_TASK_ENABLED: u32 = 6010;
pub const UPDATER_ERROR: u32 = 6011;
pub const PEDM_ENABLED: u32 = 6020;

pub fn user_session_process_started(session_id: u32, kind: impl ToString, exe: impl ToString) -> Entry {
    Entry::new("User session process started")
        .event_code(USER_SESSION_PROCESS_STARTED)
        .severity(Severity::Info)
        .field("session_id", session_id)
        .field("kind", kind) // "console","remote"
        .field("exe", exe)
}

pub fn user_session_process_terminated(session_id: u32, exit_code: i32, by: impl ToString) -> Entry {
    Entry::new("User session process terminated")
        .event_code(USER_SESSION_PROCESS_TERMINATED)
        .severity(Severity::Info)
        .field("session_id", session_id)
        .field("exit_code", exit_code)
        .field("by", by) // "user","service","timeout"
}

pub fn updater_task_enabled() -> Entry {
    Entry::new("Updater task enabled")
        .event_code(UPDATER_TASK_ENABLED)
        .severity(Severity::Info)
}

pub fn updater_error(step: impl ToString, error: impl std::fmt::Display) -> Entry {
    Entry::new("Updater error")
        .event_code(UPDATER_ERROR)
        .severity(Severity::Error)
        .field("step", step) // "download","verify","apply","rollback"
        .field("error_chain", format!("{error:#}"))
}

pub fn pedm_enabled() -> Entry {
    Entry::new("PEDM enabled")
        .event_code(PEDM_ENABLED)
        .severity(Severity::Info)
}

// 7000-7099 **Health**

pub const RECORDING_STORAGE_LOW: u32 = 7010; // (Warning): remaining_bytes, threshold_bytes

pub fn recording_storage_low(remaining_bytes: u64, threshold_bytes: u64) -> Entry {
    Entry::new("Recording storage low")
        .event_code(RECORDING_STORAGE_LOW)
        .severity(Severity::Warning)
        .field("remaining_bytes", remaining_bytes)
        .field("threshold_bytes", threshold_bytes)
}

// 9000-9099 **Diagnostics**

pub const DEBUG_OPTIONS_ENABLED: u32 = 9001;
pub const XMF_NOT_FOUND: u32 = 9002;

pub fn debug_options_enabled(options: impl ToString) -> Entry {
    Entry::new("Debug options enabled")
        .event_code(DEBUG_OPTIONS_ENABLED)
        .severity(Severity::Warning) // policy risk
        .field("options", options) // e.g. "verbose,skip_tls_verify"
}

pub fn xmf_not_found(path: impl AsRef<Path>, error: impl std::fmt::Display) -> Entry {
    Entry::new("XMF not found")
        .event_code(XMF_NOT_FOUND)
        .severity(Severity::Warning)
        .field("path", path.as_ref().display())
        .field("error_chain", format!("{error:#}"))
}
