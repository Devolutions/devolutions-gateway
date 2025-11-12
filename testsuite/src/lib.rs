#![allow(
    clippy::print_stderr,
    reason = "test infrastructure can intentionally use eprintln for debug output"
)]
#![allow(clippy::unwrap_used, reason = "test infrastructure can panic on errors")]

pub mod cli;
pub mod dgw_config;
pub mod mcp_client;
pub mod mcp_server;
