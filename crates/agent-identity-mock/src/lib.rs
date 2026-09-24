//! Mock server (conformance oracle) for the Agent Identity V1 contract
//! (`docs/agent-identity/CONTRACT.md`).

pub mod api_admin;
pub mod api_agent;
pub mod api_mock;
pub mod app;
pub mod ca;
pub mod channel;
pub mod clock;
pub mod csr;
pub mod httpsig;
pub mod name_eval;
pub mod proof;
pub mod server;
pub mod sfv;
pub mod state;

#[cfg(test)]
mod vector_tests;
