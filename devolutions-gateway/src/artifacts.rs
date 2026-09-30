use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::{self, AsyncWrite, AsyncWriteExt as _};
use uuid::Uuid;

use crate::recording::RecordingMessageSender;
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

    pub(crate) fn into_file_names(self) -> impl IntoIterator<Item = String> {
        let Self { ai_analysis } = self;
        ai_analysis.into_iter().map(|artifact| artifact.file_name)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Name of the artifact at `index` in its kind's list, such as `ai-analysis-0.slog`.
    pub(crate) fn file_name(self, index: usize) -> String {
        format!("{}-{index}.{}", self.as_str(), self.file_type().extension())
    }
}

/// Streams a new artifact into a session.
///
/// Dropping it without [`ArtifactWriter::finish`] discards what was written.
#[derive(Debug)]
pub struct ArtifactWriter {
    file: Option<fs::File>,
    temp_path: Utf8PathBuf,
    id: Uuid,
    kind: ArtifactKind,
    recordings: RecordingMessageSender,
}

impl ArtifactWriter {
    /// Starts a new artifact of `kind` for the session; it is listed in the manifest only once
    /// [`ArtifactWriter::finish`] succeeds.
    pub async fn create(recordings: &RecordingMessageSender, id: Uuid, kind: ArtifactKind) -> anyhow::Result<Self> {
        let recordings_path = recordings.get_recordings_path().await?;
        let temp_path = temp_path(&recordings_path);

        fs::create_dir_all(&recordings_path)
            .await
            .with_context(|| format!("create {recordings_path}"))?;

        let file = fs::File::create(&temp_path)
            .await
            .with_context(|| format!("create {temp_path}"))?;

        Ok(Self {
            file: Some(file),
            temp_path,
            id,
            kind,
            recordings: recordings.clone(),
        })
    }

    /// Adds the written artifact to the session manifest and returns its file name.
    pub async fn finish(mut self) -> anyhow::Result<String> {
        let mut file = self.file.take().expect("only taken here");
        file.flush().await.context("flush the artifact")?;
        // Closed first: Windows may refuse to move a file that is still open.
        drop(file.into_std().await);

        self.recordings
            .add_artifact(self.id, self.kind, self.temp_path.clone())
            .await
    }

    fn file(&mut self) -> Pin<&mut fs::File> {
        Pin::new(self.file.as_mut().expect("only taken by finish"))
    }
}

impl AsyncWrite for ArtifactWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().file().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().file().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().file().poll_shutdown(cx)
    }
}

impl Drop for ArtifactWriter {
    fn drop(&mut self) {
        // After a successful finish the file was moved away, so there is nothing left to remove.
        let _ = std::fs::remove_file(&self.temp_path);
    }
}

/// Outside every session folder (not a session ID, so never listed as a recording), on the same volume so
/// [`ArtifactWriter::finish`] can move it in atomically.
fn temp_path(recordings_path: &Utf8Path) -> Utf8PathBuf {
    recordings_path.join(format!(".artifact-{}.part", Uuid::new_v4()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_key_is_the_kind_name() {
        let kind = ArtifactKind::AiAnalysis;
        let mut artifacts = JrecArtifacts::default();
        artifacts.of_kind_mut(kind).push(JrecArtifact {
            file_name: "file".to_owned(),
        });

        let json = serde_json::to_value(&artifacts).expect("serialize artifacts");
        let keys: Vec<_> = json.as_object().expect("object").keys().collect();
        assert_eq!(keys, [kind.as_str()]);
    }
}
