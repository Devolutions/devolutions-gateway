#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]
#![allow(clippy::print_stdout, reason = "test code uses print for diagnostics")]
#![allow(clippy::print_stderr, reason = "test code uses print for diagnostics")]

mod cli;
mod mcp_proxy;
mod sysevent;
