//! Integration tests for the `network-scanner` workspace member.
//!
//! These tests live in the testsuite (not the crate's own `src/`) so the
//! production network-scanner binary contains no test code. Items that the
//! tests need but that aren't part of the scanner's public API are exposed
//! via the crate's `test-utils` feature, which `testsuite/Cargo.toml`
//! enables for this build only.

mod ip_utils;
mod planner;
mod proto_netbios;
mod results;
mod sources;
mod task_utils;
