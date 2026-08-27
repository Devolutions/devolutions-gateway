//! Process-level helpers for RDP credential-injection tests.
//!
//! A real Gateway runs as a child process; loopback peers stand in for the destination RDP
//! server and the Kerberos KDC. Tests observe injection from Gateway logs, from the rewritten
//! mstshash cookie arriving at the fake target, and from the Kerberos exchanges recorded by
//! the mock KDC.

pub mod agent;
pub mod credssp;
pub mod gateway;
pub mod mock_kdc;
pub mod mock_rdp;
pub mod preflight;
pub mod rdp;
pub mod tls;
pub mod tokens;

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
pub const KRBTGT_KEY: [u8; 32] = [0x11; 32];
pub const TERMSRV_KEY: [u8; 32] = [0x22; 32];

pub const INJECT_LOG: &str = "RDP-TLS forwarding with credential injection";
pub const FORWARD_LOG: &str = "Upstream forwarding";
pub const MISSING_LOG: &str = "missing or expired; re-provision to retry";
pub const PUBLISHED_KDC_LOG: &str = "Published synthetic KDC";
pub const REGISTERED_KDC_LOG: &str = "Registered synthetic KDC for credential-injection session";
pub const RDCLEANPATH_INJECT_LOG: &str = "Switching to RdpProxy for credential injection (WebSocket)";
pub const RDCLEANPATH_FORWARD_LOG: &str = "RDP-TLS forwarding (RDCleanPath)";
