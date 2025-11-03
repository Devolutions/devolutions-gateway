#![expect(clippy::unwrap_used, reason = "Test code can panic on errors")]
#![expect(clippy::print_stdout, reason = "Test code uses print for diagnostics")]
#![expect(clippy::zombie_processes, reason = "Test processes are short-lived")]
#![expect(clippy::clone_on_ref_ptr, reason = "Test code clarity over performance")]
#![expect(clippy::collection_is_never_read, reason = "Test scaffolding may not read all data")]

mod cli;
mod mcp_proxy;
mod sysevent;
