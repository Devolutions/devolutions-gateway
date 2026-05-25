//! Agent-tunnel integration tests.
//!
//! Cover the QUIC tunnel data path end-to-end (`integration`), the registry
//! online/offline accounting (`registry`), the routing decision pipeline
//! (`routing`), and the certificate signing / identity-extraction helpers
//! (`cert`). All exercise the live `agent-tunnel` crate; no mocking of the
//! QUIC layer.

mod cert;
mod common;
mod integration;
mod registry;
mod routing;
