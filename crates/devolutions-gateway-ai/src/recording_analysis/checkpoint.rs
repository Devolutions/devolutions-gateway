//! What the AI answered for one transcript chunk, saved in the working files so analysing again does not ask the AI again.

use std::collections::BTreeMap;
use std::io::{BufReader, BufWriter};
use std::time::Duration;

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::Response;
use crate::session_actions::Action;

pub(super) fn path(workspace: &Utf8Path, index: usize) -> Utf8PathBuf {
    workspace.join(format!("chunk-{index:04}.json"))
}

/// Actions found in one chunk, with the model that described them.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct DescribedChunk {
    pub(super) actions: Vec<Action>,
    /// Model that answered, as reported by the provider.
    pub(super) model: Option<String>,
}

impl DescribedChunk {
    /// Adds the answer to one request about the chunk.
    pub(super) fn add(&mut self, response: Response<Vec<Action>>) {
        self.actions.extend(response.output);
        self.model = self.model.take().or(response.model);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedChunk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<String>,
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
        };

        write(&path, &chunk).expect("written");

        assert!(path.as_str().ends_with("chunk-0003.json"));
        assert_eq!(read(&path).expect("read"), chunk);
        assert!(!path.with_extension("partial").exists());
    }

    #[test]
    fn an_unreported_model_stays_unknown() {
        // oracle: property round-trip
        let dir = tempfile::tempdir().expect("temp dir");
        let path = path(Utf8Path::from_path(dir.path()).expect("UTF-8"), 0);
        let chunk = DescribedChunk {
            actions: Vec::new(),
            model: None,
        };

        write(&path, &chunk).expect("written");

        assert_eq!(read(&path).expect("read"), chunk);
    }
}
