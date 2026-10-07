//! Work the provisioner asks Gateway to do: each request is a Task recorded in `gateway.db`, run as a job on the job
//! queue.

pub mod ai;
pub mod ai_key_store;
pub mod recording_ai_analysis;

/// Why one attempt of a Task failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttemptError {
    /// Worth another attempt later, such as a rate limit or a network error.
    Transient(String),
    /// Another attempt would fail the same way.
    Permanent(String),
    /// The attempt was cancelled before its end, such as when it ran out of time.
    Cancelled,
}
