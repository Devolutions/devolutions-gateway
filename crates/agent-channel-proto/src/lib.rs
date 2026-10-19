//! Protobuf and gRPC definitions for the agent channel.
//!
//! The schema is `proto/channel.proto`, defined by `docs/agent-identity/CONTRACT.md` §7.1.

#[allow(
    unused_qualifications,
    clippy::clone_on_ref_ptr,
    clippy::pedantic,
    reason = "generated code; the set of triggered lints depends on the proto"
)]
mod generated {
    tonic::include_proto!("devolutions.agent.channel.v1");
}

pub use generated::*;

/// Full gRPC service name of the channel.
pub const SERVICE_NAME: &str = "devolutions.agent.channel.v1.AgentChannel";
