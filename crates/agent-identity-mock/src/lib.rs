//! Mock server (conformance oracle) for the Agent Identity V1 contract
//! (`docs/agent-identity/CONTRACT.md`).

mod api_admin;
mod api_agent;
mod api_mock;
mod app;
mod ca;
mod channel;
mod clock;
mod name_eval;
pub(crate) mod oracle;
mod server;
mod state;

pub use app::App;
pub use clock::MockClock;
pub use server::{Dispatcher, serve};
pub use state::State;

#[cfg(test)]
mod vector_tests;
