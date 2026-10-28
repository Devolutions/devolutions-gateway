use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::KeyBackend;
use crate::agent::{DataDir, expected_spki};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Request {
    pub(crate) case_dir: PathBuf,
    pub(crate) agent_bin: PathBuf,
    pub(crate) key_name_prefix: String,
    pub(crate) identity_id: Option<String>,
    pub(crate) token_port: Option<u16>,
    pub(crate) token_nonce: Option<uuid::Uuid>,
    pub(crate) cleanup_only: bool,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ResultFile {
    pub(crate) success: bool,
    pub(crate) error: Option<String>,
}

fn validate_run_key(name: &str, prefix: &str) -> anyhow::Result<()> {
    crate::agent::validate_key_name(prefix, name).context("SYSTEM key name does not belong to this fixture")
}

fn matching_key(identity: &Value, identity_id: &str, prefix: &str) -> anyhow::Result<Option<String>> {
    if identity["identity_id"] != identity_id {
        return Ok(None);
    }
    let name = identity["keys"]["current"]["key_name"]
        .as_str()
        .context("stored identity has no current key name")?;
    validate_run_key(name, prefix)?;
    Ok(Some(name.to_owned()))
}

fn data_dir<'a>(request: &'a Request, tokens: &'a [String]) -> DataDir<'a> {
    DataDir {
        path: &request.case_dir,
        key_backend: KeyBackend::WindowsSoftwareProvider,
        key_name_prefix: &request.key_name_prefix,
        tokens,
        // The SYSTEM agent stores its keys as machine keys, so a run-prefixed file under `identity/keys` is never a key store's leftover copy.
        leftover_key_copies: false,
    }
}

/// The stored identity of the enrolled identity, which must be the only one.
fn enrolled_identity(request: &Request) -> anyhow::Result<Value> {
    let id = request
        .identity_id
        .as_deref()
        .context("SYSTEM probe has no enrolled identity ID")?;
    let authorities = request.case_dir.join("identity").join("authorities");
    let mut identities = Vec::new();
    for entry in std::fs::read_dir(authorities).context("read SYSTEM-only stored identities")? {
        let path = entry?.path().join("identity.json");
        if !path.is_file() {
            continue;
        }
        let identity: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        if matching_key(&identity, id, &request.key_name_prefix)?.is_some() {
            identities.push(identity);
        }
    }
    ensure!(
        identities.len() == 1,
        "expected exactly one SYSTEM stored identity for enrolled identity"
    );
    Ok(identities.remove(0))
}

/// Checks every key that the enrolled identity names, with the suite's per-key checks.
///
/// Unlike the suite's agent cases, which tolerate a renewal retiring a key during the checks, the probe runs once after enrollment settles, so any failed check fails: the current key must exist and be certified, and a key deleted during its checks fails too.
fn check_stored_keys(dir: &DataDir<'_>, identity: &Value) -> anyhow::Result<()> {
    for slot in ["current", "pending", "previous"] {
        let stored = &identity["keys"][slot];
        let Some(name) = stored["key_name"].as_str() else {
            continue;
        };
        validate_run_key(name, dir.key_name_prefix)?;
        let expected = expected_spki(stored)?;
        ensure!(
            expected.is_some() || slot != "current",
            "SYSTEM stored key has no leaf certificate"
        );
        ensure!(
            dir.check_key(slot, name, expected.as_deref())? || slot != "current",
            "settled SYSTEM current machine key is missing"
        );
    }
    Ok(())
}

/// Audits the identity tree, which only SYSTEM can read, including for token fragments.
fn audit_identity_files(dir: &DataDir<'_>) -> anyhow::Result<()> {
    dir.audit_identity_tree()?;
    dir.audit_tokens(&dir.path.join("identity"), None)
}

pub(crate) fn read_token(request: &Request) -> anyhow::Result<String> {
    let port = request.token_port.context("SYSTEM probe has no token channel port")?;
    let nonce = request.token_nonce.context("SYSTEM probe has no token channel nonce")?;
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).context("connect to protected token channel")?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(nonce.as_bytes())?;
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length);
    ensure!(
        (1..=4096).contains(&length),
        "SYSTEM probe received an invalid token length"
    );
    let mut token = vec![0u8; usize::try_from(length)?];
    stream.read_exact(&mut token)?;
    String::from_utf8(token).context("SYSTEM probe received a non-UTF-8 token")
}

fn path_present(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn wait_for_pending_cleanup(request: &Request, token: &str, timeout: Duration) -> anyhow::Result<()> {
    let stem = crate::agent::token_file_id(token);
    let pending_dir = request.case_dir.join("identity").join("pending");
    let pending = pending_dir.join(format!("{stem}.dat"));
    let in_progress = pending_dir.join(format!("{stem}.in-progress.json"));
    let started = Instant::now();
    loop {
        if !path_present(&pending)? && !path_present(&in_progress)? {
            return Ok(());
        }
        ensure!(
            started.elapsed() < timeout,
            "SYSTEM enrollment left pending or in-progress state after success"
        );
        std::thread::sleep(Duration::from_millis(100).min(timeout.saturating_sub(started.elapsed())));
    }
}

pub(crate) fn run(request_path: &Path, result_path: &Path) -> anyhow::Result<()> {
    ensure!(crate::windows::running_as_system()?, "SYSTEM probe must run as SYSTEM");
    let request: Request = serde_json::from_slice(&std::fs::read(request_path)?)?;
    ensure!(
        request.key_name_prefix.starts_with("conformance-") && crate::agent::valid_key_prefix(&request.key_name_prefix),
        "SYSTEM probe received a non-conformance key prefix"
    );
    let mut errors = Vec::new();
    let stopped = if request.cleanup_only {
        match crate::windows::stop_system_agent(&request.agent_bin) {
            Ok(()) => true,
            Err(error) => {
                errors.push(format!("stop SYSTEM agent: {error:#}"));
                false
            }
        }
    } else {
        match read_token(&request).and_then(|token| {
            wait_for_pending_cleanup(&request, &token, Duration::from_secs(20))?;
            let tokens = [token];
            let dir = data_dir(&request, &tokens);
            let identity = enrolled_identity(&request)?;
            check_stored_keys(&dir, &identity)?;
            dir.audit_orphan_keys()?;
            audit_identity_files(&dir)
        }) {
            Ok(()) => {}
            Err(error) => errors.push(format!("inspect SYSTEM-only key: {error:#}")),
        }
        false
    };
    let keys_removed = match crate::windows::cleanup_machine_keys(&request.key_name_prefix) {
        Ok(()) => true,
        Err(error) => {
            errors.push(format!("remove SYSTEM-only machine keys: {error:#}"));
            false
        }
    };
    if request.cleanup_only && stopped && keys_removed {
        let identity_dir = request.case_dir.join("identity");
        if let Err(error) = std::fs::remove_dir_all(identity_dir)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            errors.push(format!("remove SYSTEM-only identity files: {error}"));
        }
    }
    let result = ResultFile {
        success: errors.is_empty(),
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    };
    std::fs::write(result_path, serde_json::to_vec(&result)?).context("write admin-readable SYSTEM probe result")?;
    ensure!(
        result.success,
        "{}",
        result.error.as_deref().unwrap_or("SYSTEM probe failed")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use serde_json::json;

    use super::{Request, audit_identity_files, data_dir, matching_key, wait_for_pending_cleanup};

    #[test]
    fn current_key_is_selected_only_from_the_matching_identity_and_run() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity/INTENT.md §Stored identities
        // oracle: intent crates/device-key/INTENT.md §Key name
        // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
        let prefix = "conformance-4321";
        let name = format!("{prefix}_479e1d51-4038-4d09-b7f8-5bdff4489cad");
        let identity = json!({ "identity_id": "identity-a", "keys": { "current": { "key_name": name } } });
        assert_eq!(matching_key(&identity, "identity-a", prefix)?, Some(name));
        assert_eq!(matching_key(&identity, "identity-b", prefix)?, None);
        assert!(matching_key(&identity, "identity-a", "conformance-432").is_err());
        assert!(
            matching_key(
                &json!({ "identity_id": "identity-a", "keys": { "current": { "key_name": format!("{prefix}bad") } } }),
                "identity-a",
                prefix
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn system_identity_audit_rejects_token_fragments_and_private_key_material() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Coverage
        // oracle: intent crates/agent-identity/INTENT.md §Identities
        // oracle: intent crates/agent-identity/INTENT.md §Stored identities
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-identity-system-probe-tests");
        std::fs::create_dir_all(&scratch)?;
        let dir = tempfile::Builder::new().prefix("identity-").tempdir_in(scratch)?;
        let identity = dir.path().join("identity");
        let authority = identity.join("authorities").join(uuid::Uuid::new_v4().to_string());
        let keys = identity.join("keys");
        std::fs::create_dir_all(&authority)?;
        std::fs::create_dir_all(&keys)?;
        std::fs::write(authority.join("identity.json"), b"{}")?;
        let request = Request {
            case_dir: dir.path().to_path_buf(),
            agent_bin: PathBuf::new(),
            key_name_prefix: "conformance-unit".to_owned(),
            identity_id: None,
            token_port: None,
            token_nonce: None,
            cleanup_only: true,
        };
        let tokens = [format!("dvaet1.bag.{}", "A".repeat(43))];
        let token = &tokens[0];
        let audited = data_dir(&request, &tokens);
        audit_identity_files(&audited)?;
        // A stop can leave the temporary file of a record's atomic write.
        let interrupted = authority.join(format!(".identity.json-{}.tmp", uuid::Uuid::new_v4()));
        std::fs::write(&interrupted, b"{")?;
        audit_identity_files(&audited)?;
        std::fs::remove_file(interrupted)?;
        let leaked = authority.join("debug.log");
        std::fs::write(&leaked, &token.as_bytes()[token.len() - 12..])?;
        assert!(audit_identity_files(&audited).is_err());
        std::fs::remove_file(leaked)?;
        let private = keys.join("extra.p8");
        std::fs::write(&private, b"private key")?;
        assert!(audit_identity_files(&audited).is_err());
        std::fs::remove_file(private)?;
        // The probe's machine-key store keeps no file copies, so an unrecorded run key file is never a leftover copy.
        let run_key_copy = keys.join(format!("conformance-unit_{}.p8.tmp", uuid::Uuid::new_v4()));
        std::fs::write(&run_key_copy, b"-----BEGIN PRIVATE KEY-----")?;
        assert!(audit_identity_files(&audited).is_err());
        std::fs::remove_file(run_key_copy)?;
        std::fs::write(keys.join("extra.bin"), b"-----BEGIN PRIVATE KEY-----")?;
        assert!(audit_identity_files(&audited).is_err());
        Ok(())
    }

    #[test]
    fn system_probe_waits_for_both_successful_pending_records_to_disappear() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-identity-system-probe-tests");
        std::fs::create_dir_all(&scratch)?;
        let dir = tempfile::Builder::new().prefix("pending-").tempdir_in(scratch)?;
        let request = Request {
            case_dir: dir.path().to_path_buf(),
            agent_bin: PathBuf::new(),
            key_name_prefix: String::new(),
            identity_id: None,
            token_port: None,
            token_nonce: None,
            cleanup_only: false,
        };
        let token = format!("dvaet1.bag.{}", "C".repeat(43));
        let stem = crate::agent::token_file_id(&token);
        let pending_dir = dir.path().join("identity").join("pending");
        std::fs::create_dir_all(&pending_dir)?;
        let pending = pending_dir.join(format!("{stem}.dat"));
        let in_progress = pending_dir.join(format!("{stem}.in-progress.json"));
        std::fs::write(&pending, b"pending")?;
        std::fs::write(&in_progress, b"in progress")?;
        assert!(wait_for_pending_cleanup(&request, &token, Duration::from_millis(10)).is_err());
        std::fs::remove_file(pending)?;
        assert!(wait_for_pending_cleanup(&request, &token, Duration::from_millis(10)).is_err());
        let remover = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            std::fs::remove_file(in_progress)
        });
        wait_for_pending_cleanup(&request, &token, Duration::from_secs(1))?;
        remover
            .join()
            .map_err(|_| anyhow::anyhow!("pending cleanup helper panicked"))??;
        Ok(())
    }
}
