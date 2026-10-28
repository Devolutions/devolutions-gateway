//! Why an AI analysis fails, next to the failures any Task may have.

use devolutions_gateway_ai::Error;
use devolutions_gateway_ai::recording_analysis::RecordingAnalysisError;

use crate::provisioner_tasks::{AttemptError, Permanent};

/// Why one attempt of an AI analysis failed.
pub type AnalysisError = AttemptError<Failure, Recoverable>;

/// Why an AI analysis failed for good, as the `error` of its payload, next to the failures any Task may have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Failure {
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
}

/// A failure of an AI analysis attempt worth another attempt.
///
/// It reaches the caller only as the `last` failure of [`Permanent::AttemptsExhausted`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Recoverable {
    /// The AI provider could not be reached, or did not answer in time.
    AiUnreachable,
    /// The AI provider is busy or failing for now, such as with a rate limit (429) or a server error (5xx).
    AiBusy { status: u16 },
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

/// Retries only the failures that may pass later, such as a rate limit or a network error.
impl From<RecordingAnalysisError> for AnalysisError {
    fn from(error: RecordingAnalysisError) -> Self {
        match error {
            RecordingAnalysisError::Ai(error) => Self::from(error),
            RecordingAnalysisError::NoRecording => Self::of_kind(Failure::NoRecording),
            RecordingAnalysisError::InvalidRecording { file_name, .. } => {
                Self::of_kind(Failure::UnreadableRecording { file: file_name })
            }
            RecordingAnalysisError::Truncated => Self::of_kind(Failure::AiBadAnswer {
                why: BadAnswer::Truncated,
            }),
            // The runner cancels an attempt only once its Task is past its deadline.
            RecordingAnalysisError::Cancelled => Self::Permanent(Permanent::DeadlinePassed),
            _ => Self::Permanent(Permanent::Internal),
        }
    }
}

impl From<Error> for AnalysisError {
    fn from(error: Error) -> Self {
        let bad_answer = |why| Self::of_kind(Failure::AiBadAnswer { why });

        match &error {
            Error::Transport { .. } => Self::Recoverable(Recoverable::AiUnreachable),
            Error::Status { status, .. } if error.is_transient() => {
                Self::Recoverable(Recoverable::AiBusy { status: *status })
            }
            Error::Status { status, .. } => Self::of_kind(Failure::AiRejected { status: *status }),
            Error::InvalidResponse { .. } => bad_answer(BadAnswer::Invalid),
            Error::Truncated { .. } => bad_answer(BadAnswer::Truncated),
            Error::Refused { .. } => bad_answer(BadAnswer::Refused),
            Error::InvalidOutput { .. } => bad_answer(BadAnswer::NotExpectedJson),
            _ => Self::Permanent(Permanent::Internal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // oracle: mutant a failure of the AI analysis takes the name of one any Task may have, so callers mix them up
    #[test]
    fn ai_analysis_failures_have_names_of_their_own() {
        fn kind(failure: impl serde::Serialize) -> serde_json::Value {
            serde_json::to_value(failure).expect("JSON")["kind"].clone()
        }

        let shared = [
            Permanent::<(), ()>::InvalidTask,
            Permanent::Panicked,
            Permanent::Internal,
            Permanent::AttemptsExhausted { last: () },
            Permanent::DeadlinePassed,
            Permanent::NotQueued,
        ]
        .map(kind);

        for failure in [
            Failure::AiRejected { status: 401 },
            Failure::AiBadAnswer {
                why: BadAnswer::Invalid,
            },
            Failure::KeyLost,
            Failure::NoRecording,
            Failure::MixedRecording,
            Failure::UnreadableRecording {
                file: "recording-0.webm".to_owned(),
            },
        ] {
            let name = kind(&failure);
            assert!(!shared.contains(&name), "{name} is also a failure any Task may have");
        }
    }

    // oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
    #[test]
    fn transient_ai_errors_are_recoverable_and_the_others_permanent() {
        let attempt = |error: Error| AnalysisError::from(RecordingAnalysisError::Ai(error));
        let status = |status, code: Option<&str>| Error::Status {
            status,
            message: "failed".to_owned(),
            code: code.map(str::to_owned),
            retry_after: None,
        };

        let network = Error::Transport {
            message: "connection refused".to_owned(),
        };
        assert_eq!(attempt(network), AnalysisError::Recoverable(Recoverable::AiUnreachable));

        for code in [429, 500, 503] {
            assert_eq!(
                attempt(status(code, None)),
                AnalysisError::Recoverable(Recoverable::AiBusy { status: code })
            );
        }

        for code in [400, 401, 403, 404] {
            assert_eq!(
                attempt(status(code, None)),
                AnalysisError::of_kind(Failure::AiRejected { status: code })
            );
        }

        assert_eq!(
            attempt(status(429, Some("insufficient_quota"))),
            AnalysisError::of_kind(Failure::AiRejected { status: 429 }),
            "a spent quota"
        );
        assert_eq!(
            AnalysisError::from(RecordingAnalysisError::Truncated),
            AnalysisError::of_kind(Failure::AiBadAnswer {
                why: BadAnswer::Truncated
            })
        );
        assert_eq!(
            attempt(Error::Refused {
                reason: "content filter".to_owned()
            }),
            AnalysisError::of_kind(Failure::AiBadAnswer {
                why: BadAnswer::Refused
            })
        );
    }
}
