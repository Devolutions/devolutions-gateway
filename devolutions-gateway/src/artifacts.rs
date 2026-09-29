use serde::{Deserialize, Serialize};

use crate::token::RecordingFileType;

/// Non-recording artifacts, one list per [`ArtifactKind`]. Each list is append-only, like `files`: names
/// are derived from positions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct JrecArtifacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ai_analysis: Vec<JrecArtifact>,
}

impl JrecArtifacts {
    pub(crate) fn is_empty(&self) -> bool {
        let Self { ai_analysis } = self;
        ai_analysis.is_empty()
    }

    pub(crate) fn into_file_names(self) -> Vec<String> {
        let Self { ai_analysis } = self;
        ai_analysis.into_iter().map(|artifact| artifact.file_name).collect()
    }

    pub(crate) fn of_kind_mut(&mut self, kind: ArtifactKind) -> &mut Vec<JrecArtifact> {
        match kind {
            ArtifactKind::AiAnalysis => &mut self.ai_analysis,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JrecArtifact {
    pub(crate) file_name: String,
}

/// Kind of a non-recording artifact, used as its key in the manifest `artifacts` object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    AiAnalysis,
}

impl ArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::AiAnalysis => "ai-analysis",
        }
    }

    pub(crate) const fn file_type(self) -> RecordingFileType {
        match self {
            ArtifactKind::AiAnalysis => RecordingFileType::SessionRecordingLog,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{} artifacts must be {} files", kind.as_str(), kind.file_type().extension())]
pub struct UnsupportedArtifactFileType {
    pub(crate) kind: ArtifactKind,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn artifact_kind_names_match_their_serde_names() {
        let kind = ArtifactKind::AiAnalysis;
        let parsed: ArtifactKind = serde_json::from_value(json!(kind.as_str())).expect("parse kind");
        assert_eq!(parsed, kind);
    }
}
