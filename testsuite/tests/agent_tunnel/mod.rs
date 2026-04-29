//! Agent-tunnel integration tests.
//!
//! Cover the QUIC tunnel data path end-to-end (`integration`), the registry
//! online/offline accounting (`registry`), and the routing decision pipeline
//! (`routing`). All three exercise the live `agent-tunnel` crate; no
//! mocking of the QUIC layer.

mod integration;
mod registry;
mod routing;
