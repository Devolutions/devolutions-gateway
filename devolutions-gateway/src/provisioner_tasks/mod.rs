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

/// Why one attempt of a Task failed, with `F` and `R` the failures of its own kind of work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError<F, R> {
    /// Worth another attempt later, such as a rate limit or a network error.
    Recoverable(R),
    /// Another attempt would fail the same way, so the Task fails at once.
    Permanent(Permanent<F, R>),
}

impl<F, R> AttemptError<F, R> {
    /// A permanent failure of the Task's own kind of work.
    pub fn of_kind(failure: F) -> Self {
        Self::Permanent(Permanent::Kind(failure))
    }
}

/// Why a Task failed, as the `error` of its payload: a closed set of kinds without text for people, since the caller
/// words them.
///
/// The kinds below can happen to any Task, while [`Permanent::Kind`] holds those of its own kind of work, so a new kind
/// of Task brings its failures without adding to these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Permanent<F, R> {
    /// The Task itself is not valid, such as with parameters this Gateway cannot read.
    InvalidTask,
    /// The attempt panicked.
    Panicked,
    /// Something went wrong inside Gateway, such as a file it could not write.
    Internal,
    /// Every attempt failed with a recoverable failure, the last one being `last`.
    AttemptsExhausted { last: R },
    /// The Task did not start in time, or went too long without progress.
    DeadlinePassed,
    /// The job of the Task could not be queued.
    NotQueued,
    /// A failure of the Task's own kind of work, which names its own `kind`.
    #[serde(untagged)]
    Kind(F),
}

impl<F, R> Permanent<F, R> {
    /// The same failure, with the failures of its kind converted by `kind` and `last`.
    pub fn try_map<G, S, E>(
        self,
        kind: impl FnOnce(F) -> Result<G, E>,
        last: impl FnOnce(R) -> Result<S, E>,
    ) -> Result<Permanent<G, S>, E> {
        Ok(match self {
            Self::InvalidTask => Permanent::InvalidTask,
            Self::Panicked => Permanent::Panicked,
            Self::Internal => Permanent::Internal,
            Self::AttemptsExhausted { last: failure } => Permanent::AttemptsExhausted { last: last(failure)? },
            Self::DeadlinePassed => Permanent::DeadlinePassed,
            Self::NotQueued => Permanent::NotQueued,
            Self::Kind(failure) => Permanent::Kind(kind(failure)?),
        })
    }
}
