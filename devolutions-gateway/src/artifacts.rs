use serde::{Deserialize, Serialize};

use crate::token::RecordingFileType;

/// Non-recording artifacts, one list per [`ArtifactKind`]. Each list is append-only, like `files`: names
/// are derived from positions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct JrecArtifacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ai_analysis: Vec<JrecArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    events: Vec<JrecArtifact>,
}

impl JrecArtifacts {
    pub(crate) fn is_empty(&self) -> bool {
        let Self { ai_analysis, events } = self;
        ai_analysis.is_empty() && events.is_empty()
    }

    pub(crate) fn into_file_names(self) -> impl IntoIterator<Item = String> {
        let Self { ai_analysis, events } = self;
        ai_analysis.into_iter().chain(events).map(|artifact| artifact.file_name)
    }

    pub(crate) fn of_kind_mut(&mut self, kind: ArtifactKind) -> &mut Vec<JrecArtifact> {
        match kind {
            ArtifactKind::AiAnalysis => &mut self.ai_analysis,
            ArtifactKind::Events => &mut self.events,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JrecArtifact {
    pub(crate) file_name: String,
}

/// Kind of a non-recording artifact, used as its key in the manifest `artifacts` object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    AiAnalysis,
    /// The session events log a recorder pushes next to its recording.
    Events,
}

impl ArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::AiAnalysis => "ai-analysis",
            ArtifactKind::Events => "events",
        }
    }

    pub(crate) const fn file_type(self) -> RecordingFileType {
        match self {
            ArtifactKind::AiAnalysis | ArtifactKind::Events => RecordingFileType::SessionRecordingLog,
        }
    }

    /// Name of the artifact at `index` in its kind's list, such as `ai-analysis-0.slog`.
    pub(crate) fn file_name(self, index: usize) -> String {
        format!("{}-{index}.{}", self.as_str(), self.file_type().extension())
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::ai_analysis(ArtifactKind::AiAnalysis)]
    #[case::events(ArtifactKind::Events)]
    fn manifest_key_is_the_kind_name(#[case] kind: ArtifactKind) {
        let mut artifacts = JrecArtifacts::default();
        artifacts.of_kind_mut(kind).push(JrecArtifact {
            file_name: "file".to_owned(),
        });

        let json = serde_json::to_value(&artifacts).expect("serialize artifacts");
        let keys: Vec<_> = json.as_object().expect("object").keys().collect();
        assert_eq!(keys, [kind.as_str()]);
    }
}
