//! Package broker module.
//!
//! Provides policy evaluation and command execution for package operations,
//! communicating over a Windows named pipe using HTTP/1.1.

pub(crate) mod auth;
pub mod command_builder;
pub mod evaluator;
pub mod executor;
pub mod operation_tracker;
pub mod pipe;
pub mod policy_loader;
pub mod policy_watcher;
pub mod server;
pub mod task;

#[cfg(test)]
mod scenario_tests;
