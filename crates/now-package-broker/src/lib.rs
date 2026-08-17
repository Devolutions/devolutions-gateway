//! Package broker for the Devolutions Agent.
//!
//! Provides policy evaluation and command execution for package operations,
//! communicating over a Windows named pipe using HTTP/1.1.
//!
//! The broker is only functional on Windows; on other platforms this crate is empty.

#[cfg(windows)]
mod auth;
#[cfg(windows)]
pub mod command_builder;
#[cfg(windows)]
pub mod evaluator;
#[cfg(windows)]
pub mod event_channel;
#[cfg(windows)]
pub mod executor;
#[cfg(windows)]
pub mod operation_tracker;
#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod policy_loader;
#[cfg(windows)]
mod policy_security;
#[cfg(windows)]
pub mod policy_watcher;
#[cfg(windows)]
pub mod server;
#[cfg(windows)]
pub mod task;

#[cfg(all(test, windows))]
mod scenario_tests;
