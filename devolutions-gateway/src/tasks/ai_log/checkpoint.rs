//! Actions found in one transcript chunk, saved in the task workspace so a retry does not ask the AI again.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, BufWriter, Write as _};
use std::time::Duration;

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_ai::session_actions::Action;

pub(crate) fn path(workspace: &Utf8Path, index: usize) -> Utf8PathBuf {
    workspace.join(format!("chunk-{index:04}.actions.jsonl"))
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
pub(crate) fn write(path: &Utf8Path, actions: &[Action]) -> anyhow::Result<()> {
    let partial = path.with_extension("partial");

    let mut out = BufWriter::new(std::fs::File::create(&partial).with_context(|| format!("create {partial}"))?);

    for action in actions {
        let saved = SavedAction {
            offset_seconds: action.offset.as_secs_f64(),
            description: action.description.clone(),
            object: action.object.clone(),
            parameters: action.parameters.clone(),
        };
        serde_json::to_writer(&mut out, &saved)?;
        out.write_all(b"\n")?;
    }

    out.into_inner()?.sync_all()?;
    std::fs::rename(&partial, path).with_context(|| format!("rename {partial}"))?;

    Ok(())
}

pub(crate) fn read(path: &Utf8Path) -> anyhow::Result<Vec<Action>> {
    let file = BufReader::new(std::fs::File::open(path).with_context(|| format!("open {path}"))?);

    file.lines()
        .map(|line| {
            let saved: SavedAction = serde_json::from_str(&line?)?;
            Ok(Action {
                offset: Duration::try_from_secs_f64(saved.offset_seconds)?,
                description: saved.description,
                object: saved.object,
                parameters: saved.parameters,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_round_trip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = path(Utf8Path::from_path(dir.path()).expect("UTF-8"), 3);
        let actions = vec![
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
        ];

        write(&path, &actions).expect("written");

        assert!(path.as_str().ends_with("chunk-0003.actions.jsonl"));
        assert_eq!(read(&path).expect("read"), actions);
        assert!(!path.with_extension("partial").exists());
    }
}
