//! Work the provisioner asks Gateway to do: each request is a Task recorded in `gateway.db`, run as a job on the job
//! queue by the [`runner::ProvisionerTaskRunner`].

pub mod ai;
pub mod recording_ai_analysis;
pub mod runner;

use provisioner_task::DynProvisionerTaskStore;

use self::recording_ai_analysis::RecordingAiAnalysis;
use self::runner::ProvisionerTaskRunner;
use crate::config::ConfHandle;
use crate::job_queue::JobQueueHandle;
use crate::provisioning::ProvisioningStore;
use crate::recording::RecordingMessageSender;

/// The provisioner task runner, with every provisioner task Gateway knows.
pub fn task_runner(
    store: DynProvisionerTaskStore,
    job_queue: JobQueueHandle,
    conf_handle: ConfHandle,
    recordings: RecordingMessageSender,
    provisioning: ProvisioningStore,
) -> ProvisionerTaskRunner {
    ProvisionerTaskRunner::builder(store, job_queue)
        .register(RecordingAiAnalysis::new(conf_handle, recordings, provisioning))
        .build()
}

/// Why one attempt of a Task failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError {
    /// Worth another attempt later, such as a rate limit or a network error.
    Transient(String),
    /// Another attempt would fail the same way.
    Permanent(String),
    /// Fails the Task with a reason of its own, such as `key lost`, instead of `permanent error`.
    Failed { reason: &'static str, details: String },
    /// The attempt was cancelled before its end, such as when it ran out of time.
    Cancelled,
}
