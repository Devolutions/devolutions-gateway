//! Work the provisioner asks Gateway to do: each request is a Task recorded in `gateway.db`, run as a job on the job
//! queue by the [`runner::ProvisionerTaskRunner`].

pub mod ai;
pub mod recording_ai_analysis;
pub mod runner;

use provisioner_task::DynProvisionerTaskStore;

use self::recording_ai_analysis::RecordingAiAnalysis;
use self::runner::{DynProvisionerTaskJobQueue, ProvisionerTaskRunner};
use crate::config::ConfHandle;
use crate::recording::RecordingMessageSender;
use crate::secret_store::SecretStore;

/// The provisioner task runner, with every provisioner task Gateway knows.
pub fn task_runner(
    store: DynProvisionerTaskStore,
    job_queue: DynProvisionerTaskJobQueue,
    conf_handle: ConfHandle,
    recordings: RecordingMessageSender,
    secrets: SecretStore,
) -> ProvisionerTaskRunner {
    ProvisionerTaskRunner::builder(store, job_queue)
        .register(RecordingAiAnalysis::new(conf_handle, recordings, secrets))
        .build()
}

/// Why one attempt of a Task failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError {
    /// Worth another attempt later, such as a rate limit or a network error.
    Recoverable(Recoverable),
    /// Another attempt would fail the same way, so the Task fails at once.
    Permanent(Permanent),
}

/// A failure worth another attempt.
///
/// It reaches the caller only as the `last` failure of [`Permanent::AttemptsExhausted`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Recoverable {
    /// The AI provider could not be reached, or did not answer in time.
    AiUnreachable,
    /// The AI provider is busy or failing for now, such as with a rate limit (429) or a server error (5xx).
    AiBusy { status: u16 },
    /// Gateway could not read its own storage, such as the folder of the session.
    Storage,
}

/// Why a Task failed, as the `error` of its payload: a closed set of kinds without text for people, since the caller
/// words them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Permanent {
    /// The AI provider refused the request for good, such as for a wrong API key (401) or a spent quota.
    AiRejected { status: u16 },
    /// The AI provider answered, but not with something usable.
    AiBadAnswer { why: BadAnswer },
    /// The API key is gone, such as after a Gateway restart.
    KeyLost,
    /// The session has no recording, or it was deleted.
    NoRecording,
    /// The session mixes terminal and video recordings.
    MixedRecording,
    /// A recording file of the session cannot be read.
    UnreadableRecording { file: String },
    /// The Task itself is not valid, such as with parameters this Gateway cannot read.
    InvalidTask,
    /// The attempt panicked.
    Panicked,
    /// Something went wrong inside Gateway, such as a file it could not write.
    Internal,
    /// Every attempt failed with a recoverable failure, the last one being `last`.
    AttemptsExhausted { last: Recoverable },
    /// The Task did not start in time, or went too long without progress.
    DeadlinePassed,
    /// The job of the Task could not be queued.
    NotQueued,
}

/// What was wrong with an answer of the AI provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BadAnswer {
    /// The answer is not in the format of the provider API.
    Invalid,
    /// The answer was cut short by the output token limit or the context window.
    Truncated,
    /// The provider refused to answer, such as when its content filter blocked the request.
    Refused,
    /// The model did not answer in the format it was asked for.
    NotExpectedJson,
}
