#![expect(clippy::unwrap_used, reason = "test code can panic on errors")]
#![expect(clippy::print_stdout, reason = "test code uses print for diagnostics")]

mod cli;
mod mcp_proxy;
mod sysevent;
