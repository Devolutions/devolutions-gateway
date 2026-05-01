//! All in-tree unit tests for the `network-scanner-proto` crate.
//!
//! Mirrors the source-module layout: one submodule per protocol module so
//! tests don't get tangled with implementation files.

#![allow(clippy::unwrap_used)] // tests deliberately panic on fixture-parse failure

mod netbios;
