use std::fs;
use std::io::ErrorKind;

use anyhow::{Context as _, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::{pending, private_file};

#[derive(Deserialize, Serialize)]
struct Rejection {
    version: u8,
    token_sha256: String,
    code: String,
    at: String,
}

const PERMANENT_CODES: [&str; 7] = [
    "identity_revoked",
    "token_invalid",
    "token_exhausted",
    "token_expired",
    "token_malformed",
    "authority_conflict",
    "authority_url_mismatch",
];

fn directory(data_dir: &Utf8Path) -> Utf8PathBuf {
    // Rejections outlive pending enrollment and are independent of per-authority identities.
    data_dir.join("identity").join("rejected")
}

fn path(data_dir: &Utf8Path, hash_hex: &str) -> anyhow::Result<Utf8PathBuf> {
    ensure!(pending::valid_hash_hex(hash_hex), "invalid enrollment token hash");
    Ok(directory(data_dir).join(format!("{hash_hex}.json")))
}

pub(crate) fn is_rejected(data_dir: &Utf8Path, hash_hex: &str) -> anyhow::Result<bool> {
    let path = path(data_dir, hash_hex)?;
    let file = match private_file::open_read(&path) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == ErrorKind::NotFound) =>
        {
            return Ok(false);
        }
        Err(error) if private_file::is_untrusted(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    ensure!(file.metadata()?.len() <= 1024, "invalid rejected-token marker");
    let marker: Rejection =
        serde_json::from_reader(file).map_err(|_| anyhow::anyhow!("invalid rejected-token marker"))?;
    ensure!(
        marker.version == 1 && PERMANENT_CODES.contains(&marker.code.as_str()) && marker.token_sha256 == hash_hex,
        "invalid rejected-token marker"
    );
    let at =
        OffsetDateTime::parse(&marker.at, &Rfc3339).map_err(|_| anyhow::anyhow!("invalid rejected-token timestamp"))?;
    ensure!(at.offset() == UtcOffset::UTC, "rejected-token timestamp is not UTC");
    Ok(true)
}

pub(crate) fn mark_rejected(
    data_dir: &Utf8Path,
    hash_hex: &str,
    code: &str,
    grant_current_user: bool,
) -> anyhow::Result<()> {
    ensure!(PERMANENT_CODES.contains(&code), "invalid permanent enrollment outcome");
    if is_rejected(data_dir, hash_hex)? {
        return Ok(());
    }
    let marker = Rejection {
        version: 1,
        token_sha256: hash_hex.to_owned(),
        code: code.into(),
        at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("format rejected-token timestamp")?,
    };
    let bytes = serde_json::to_vec(&marker).context("encode rejected-token marker")?;
    private_file::write_atomic(data_dir, &path(data_dir, hash_hex)?, &bytes, grant_current_user)
}

pub(crate) fn list_rejected(data_dir: &Utf8Path) -> anyhow::Result<Vec<String>> {
    let entries = match fs::read_dir(directory(data_dir)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("list rejected-token markers"),
    };
    let mut hashes = Vec::new();
    for entry in entries {
        let entry = entry.context("read rejected-token marker entry")?;
        if let Some(hash_hex) = entry.file_name().to_str().and_then(|name| name.strip_suffix(".json"))
            && pending::valid_hash_hex(hash_hex)
            && is_rejected(data_dir, hash_hex)?
        {
            hashes.push(hash_hex.to_owned());
        }
    }
    hashes.sort_unstable();
    Ok(hashes)
}

pub(crate) fn cleanup_temporary(data_dir: &Utf8Path) -> anyhow::Result<()> {
    private_file::cleanup_temporary_files(
        &directory(data_dir),
        |stem| {
            stem.strip_prefix('.')
                .and_then(|name| name.strip_suffix(".json"))
                .is_some_and(pending::valid_hash_hex)
        },
        |path, _| private_file::remove_file(path),
    )
}
