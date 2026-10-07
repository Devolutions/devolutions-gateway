//! What the AI answered for one transcript chunk, saved in the working files so analysing again does not ask the AI again.

use std::collections::BTreeMap;
use std::io::{BufReader, BufWriter};
use std::time::Duration;

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::Usage;
use crate::session_actions::Action;

/// Tokens counted by the AI provider, as kept in checkpoints.
///
/// It mirrors [`Usage`], so a change of [`Usage`] never changes the checkpoint format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenUsage {
    input_tokens: u64,
    output_tokens: u64,
}

impl From<Usage> for TokenUsage {
    fn from(usage: Usage) -> Self {
        Self {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
        }
    }
}

impl From<TokenUsage> for Usage {
    fn from(usage: TokenUsage) -> Self {
        Self {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
        }
    }
}

pub(super) fn path(workspace: &Utf8Path, index: usize) -> Utf8PathBuf {
    workspace.join(format!("chunk-{index:04}.json"))
}

/// Actions found in one chunk, with what the AI provider reported for the requests about it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct DescribedChunk {
    pub(super) actions: Vec<Action>,
    /// Model that answered, as reported by the provider.
    pub(super) model: Option<String>,
    /// Tokens of every request about the chunk, answers cut and asked again included; `None` when one was not reported.
    pub(super) usage: Option<Usage>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedChunk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    usage: Option<TokenUsage>,
    actions: Vec<SavedAction>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedAction {
    offset_seconds: f64,
    description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    object: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    parameters: BTreeMap<String, String>,
}

/// Writes the checkpoint through a temporary file, so a crash never leaves a partial one.
pub(super) fn write(path: &Utf8Path, chunk: &DescribedChunk) -> anyhow::Result<()> {
    let partial = path.with_extension("partial");

    let saved = SavedChunk {
        model: chunk.model.clone(),
        usage: chunk.usage.map(TokenUsage::from),
        actions: chunk
            .actions
            .iter()
            .map(|action| SavedAction {
                offset_seconds: action.offset.as_secs_f64(),
                description: action.description.clone(),
                object: action.object.clone(),
                parameters: action.parameters.clone(),
            })
            .collect(),
    };

    let mut out = BufWriter::new(std::fs::File::create(&partial).with_context(|| format!("create {partial}"))?);
    serde_json::to_writer(&mut out, &saved)?;
    out.into_inner()?.sync_all()?;
    std::fs::rename(&partial, path).with_context(|| format!("rename {partial}"))?;

    Ok(())
}

pub(super) fn read(path: &Utf8Path) -> anyhow::Result<DescribedChunk> {
    let file = BufReader::new(std::fs::File::open(path).with_context(|| format!("open {path}"))?);
    let saved: SavedChunk = serde_json::from_reader(file).with_context(|| format!("read {path}"))?;

    let actions = saved
        .actions
        .into_iter()
        .map(|saved| {
            Ok(Action {
                offset: Duration::try_from_secs_f64(saved.offset_seconds)?,
                description: saved.description,
                object: saved.object,
                parameters: saved.parameters,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    Ok(DescribedChunk {
        actions,
        model: saved.model,
        usage: saved.usage.map(Usage::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn described_chunk_round_trips() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = path(Utf8Path::from_path(dir.path()).expect("UTF-8"), 3);
        let chunk = DescribedChunk {
            actions: vec![
                Action {
                    offset: Duration::from_millis(1500),
                    description: "Listed files".to_owned(),
                    object: Some("/var/log".to_owned()),
                    parameters: BTreeMap::from([("Command".to_owned(), "ls".to_owned())]),
                },
                Action {
                    offset: Duration::from_secs(62),
                    description: "Closed the shell".to_owned(),
                    object: None,
                    parameters: BTreeMap::new(),
                },
            ],
            model: Some("gpt-test-2026-09-30".to_owned()),
            usage: Some(Usage {
                input_tokens: 10,
                output_tokens: 20,
            }),
        };

        write(&path, &chunk).expect("written");

        assert!(path.as_str().ends_with("chunk-0003.json"));
        assert_eq!(read(&path).expect("read"), chunk);
        assert!(!path.with_extension("partial").exists());
    }

    #[test]
    fn unreported_model_and_usage_stay_unknown() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = path(Utf8Path::from_path(dir.path()).expect("UTF-8"), 0);
        let chunk = DescribedChunk {
            actions: Vec::new(),
            model: None,
            usage: None,
        };

        write(&path, &chunk).expect("written");

        assert_eq!(std::fs::read_to_string(&path).expect("checkpoint"), r#"{"actions":[]}"#);
        assert_eq!(read(&path).expect("read"), chunk);
    }
}
