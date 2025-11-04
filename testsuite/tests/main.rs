#![expect(clippy::unwrap_used, reason = "test code can panic on errors")]
#![expect(clippy::print_stdout, reason = "test code uses print for diagnostics")]
#![expect(clippy::zombie_processes, reason = "test processes are short-lived")]
#![expect(clippy::clone_on_ref_ptr, reason = "test code clarity over performance")]
#![expect(clippy::collection_is_never_read, reason = "test scaffolding may not read all data")]

mod cli;
mod mcp_proxy;
mod sysevent;
