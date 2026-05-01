//! All in-tree unit tests for the network-scanner crate.
//!
//! Each submodule mirrors a source module by name. Tests reach into the
//! crate's internals via `crate::{module}::...`. Cross-cutting integration
//! tests live under `crates/network-scanner/tests/` instead.

mod ip_utils;
mod planner;
mod results;
mod sources;
mod task_utils;
