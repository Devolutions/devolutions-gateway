//! Process-level helpers for RDP credential-injection tests.
//!
//! A real Gateway runs as a child process, and `credential-injection-mock` processes stand in
//! for the RDP client, the destination RDP server and the Kerberos KDC. Tests observe injection
//! from Gateway logs, from the rewritten mstshash cookie arriving at the fake target, and from
//! the Kerberos exchanges recorded by the mock KDC.

pub mod gateway;
pub mod peers;
pub mod preflight;
pub mod tokens;

// The mock binary has the same fixture compiled in; tests provision and assert these values.
pub const CLIENT_COOKIE: &str = "client-cookie-user";
pub const TARGET_USER: &str = "injected-target-user";
pub const PROXY_USER: &str = "injected-proxy-user";
pub const PROXY_PASSWORD: &str = "proxy-secret";
pub const TARGET_PASSWORD: &str = "target-secret";
pub const KERBEROS_TARGET_USER: &str = "administrator@example.invalid";
pub const PROXY_KERBEROS_USER: &str = "injected-proxy-user@example.invalid";

pub const REALM: &str = "EXAMPLE.INVALID";
// sspi-rs downgrades Negotiate to NTLM when the SPN host is an IP address.
pub const SERVICE_HOST: &str = "localhost";

pub const INJECT_LOG: &str = "RDP-TLS forwarding with credential injection";
pub const FORWARD_LOG: &str = "Upstream forwarding";
pub const MISSING_LOG: &str = "missing or expired; re-provision to retry";
pub const PUBLISHED_KDC_LOG: &str = "Published synthetic KDC";
pub const RDCLEANPATH_INJECT_LOG: &str = "Switching to RdpProxy for credential injection (WebSocket)";
pub const RDCLEANPATH_FORWARD_LOG: &str = "RDP-TLS forwarding (RDCleanPath)";
