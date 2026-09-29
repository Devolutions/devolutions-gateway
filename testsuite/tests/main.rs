#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]
#![allow(clippy::print_stdout, reason = "test code uses print for diagnostics")]
#![allow(clippy::print_stderr, reason = "test code uses print for diagnostics")]

mod agent_tunnel;
mod cli;
mod gateway_ai;
mod mcp_proxy;
mod network_scanner;
#[cfg(windows)]
mod service_accounts;
mod sysevent;
mod timing;
