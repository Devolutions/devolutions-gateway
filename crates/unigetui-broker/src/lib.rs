//! UniGetUI Package Broker crate.
//!
//! Provides policy evaluation and command execution for UniGetUI package operations,
//! communicating over a Windows named pipe using HTTP/1.1.

pub mod command_builder;
pub mod evaluator;
pub mod executor;
pub mod model;
pub mod pipe;
pub mod policy_loader;
pub mod policy_watcher;
pub mod schema;
pub mod server;
pub mod task;
