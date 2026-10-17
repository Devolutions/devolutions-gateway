use std::collections::HashSet;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use der::{Decode as _, Encode as _};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::EncodePublicKey as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_cert::Certificate;

use crate::client::decoded_certificate;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Request {
    pub(crate) case_dir: PathBuf,
    pub(crate) agent_bin: PathBuf,
    pub(crate) key_name_prefix: String,
    pub(crate) device_id: Option<String>,
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
    let suffix = name
        .strip_prefix(prefix)
        .context("SYSTEM key name does not belong to this fixture")?;
    ensure!(
        uuid::Uuid::parse_str(suffix).is_ok_and(|uuid| uuid.to_string() == suffix),
        "SYSTEM key name has no canonical UUID"
    );
    Ok(())
}

fn matching_key(identity: &Value, device_id: &str, prefix: &str) -> anyhow::Result<Option<String>> {
    if identity["device_id"] != device_id {
        return Ok(None);
    }
    let name = identity["keys"]["current"]["key_name"]
        .as_str()
        .context("stored identity has no current key name")?;
    validate_run_key(name, prefix)?;
    Ok(Some(name.to_owned()))
}

fn stored_keys(request: &Request) -> anyhow::Result<(Value, HashSet<String>)> {
    let id = request
        .device_id
        .as_deref()
        .context("SYSTEM probe has no enrolled device ID")?;
    let authorities = request.case_dir.join("identity").join("authorities");
    let mut identities = Vec::new();
    let mut recorded = HashSet::new();
    for entry in std::fs::read_dir(authorities).context("read SYSTEM-only stored identities")? {
        let path = entry?.path().join("identity.json");
        if !path.is_file() {
            continue;
        }
        let identity: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        for slot in ["current", "pending", "previous"] {
            if let Some(name) = identity["keys"][slot]["key_name"].as_str() {
                validate_run_key(name, &request.key_name_prefix)?;
                recorded.insert(name.to_owned());
            }
        }
        if matching_key(&identity, id, &request.key_name_prefix)?.is_some() {
            identities.push(identity);
        }
    }
    let pending = request.case_dir.join("identity").join("pending");
    if pending.is_dir() {
        for entry in std::fs::read_dir(pending)? {
            let path = entry?.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".in-progress.json"))
            {
                let record: Value = serde_json::from_slice(&std::fs::read(path)?)?;
                let name = record["key_name"]
                    .as_str()
                    .context("in-progress record has no key name")?;
                validate_run_key(name, &request.key_name_prefix)?;
                recorded.insert(name.to_owned());
            }
        }
    }
    ensure!(
        identities.len() == 1,
        "expected exactly one SYSTEM stored identity for enrolled device"
    );
    Ok((identities.remove(0), recorded))
}

fn assert_matching_certificate(name: &str, slot: &Value) -> anyhow::Result<()> {
    let leaf = slot["certificate_chain"]
        .as_array()
        .and_then(|chain| chain.first())
        .and_then(Value::as_str)
        .context("SYSTEM stored key has no leaf certificate")?;
    let certificate = Certificate::from_der(&decoded_certificate(leaf)?)?;
    let expected = certificate.tbs_certificate().subject_public_key_info().to_der()?;
    let actual = VerifyingKey::from_sec1_bytes(&crate::windows::machine_public_key(name)?)?;
    ensure!(
        actual.to_public_key_der()?.as_bytes() == expected,
        "SYSTEM-only machine key does not match its stored certificate"
    );
    Ok(())
}

fn assert_stored_keys(identity: &Value) -> anyhow::Result<()> {
    for slot in ["current", "pending", "previous"] {
        let Some(name) = identity["keys"][slot]["key_name"].as_str() else {
            continue;
        };
        let exists = crate::windows::machine_key_exists(name)?;
        ensure!(
            exists || slot != "current",
            "settled SYSTEM current machine key is missing"
        );
        if exists {
            crate::windows::assert_non_exportable(name)?;
            crate::windows::assert_machine_key_acl(name, false)?;
            if identity["keys"][slot]["certificate_chain"].is_array() || slot == "current" {
                assert_matching_certificate(name, &identity["keys"][slot])?;
            }
        }
    }
    Ok(())
}

fn assert_no_orphan_keys(prefix: &str, recorded: &HashSet<String>) -> anyhow::Result<()> {
    let existing = crate::windows::machine_keys_with_prefix(prefix)?;
    let mut orphaned = existing.difference(recorded).collect::<Vec<_>>();
    orphaned.sort_unstable();
    ensure!(
        orphaned.is_empty(),
        "unrecorded SYSTEM-only machine keys with run prefix: {}",
        orphaned.iter().map(|name| name.as_str()).collect::<Vec<_>>().join(", ")
    );
    Ok(())
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

fn audit_identity_tree(request: &Request, token: &str) -> anyhow::Result<()> {
    let identity = request.case_dir.join("identity");
    let authorities = identity.join("authorities");
    let pending = identity.join("pending");
    let keys = identity.join("keys");
    let pending_file = pending.join(format!("{}.dat", crate::agent::token_file_id(token)));
    let mut documented = HashSet::from([
        pending_file.clone(),
        pending.join(format!("{}.in-progress.json", crate::agent::token_file_id(token))),
    ]);
    if authorities.is_dir() {
        for entry in std::fs::read_dir(&authorities)? {
            let path = entry?.path();
            if path.is_dir() {
                documented.insert(path.join("identity.json"));
            }
        }
    }
    let mut directories = vec![identity];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let known_directory = path == authorities
                || path == pending
                || path == keys
                || path.parent() == Some(authorities.as_path())
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| uuid::Uuid::parse_str(name).is_ok_and(|id| id.to_string() == name));
            if file_type.is_dir() {
                if !known_directory {
                    eprintln!("WARN unknown SYSTEM identity directory");
                }
                directories.push(path);
                continue;
            }
            ensure!(!known_directory, "documented identity directory is not a directory");
            ensure!(
                !path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("p8")),
                "unexpected private key file under SYSTEM identity"
            );
            ensure!(
                !crate::agent::is_temporary_sibling(&path, &documented, &request.key_name_prefix),
                "leftover SYSTEM identity temporary file"
            );
            if file_type.is_file() {
                let contents = std::fs::read(&path)?;
                ensure!(
                    !crate::agent::contains_pkcs8_material(&contents),
                    "unrecorded PKCS#8 private key under SYSTEM identity"
                );
                if path != pending_file {
                    crate::agent::assert_no_token_fragments(&contents, token, Path::new("SYSTEM identity file"))?;
                }
            }
            if documented.contains(&path) {
                ensure!(
                    file_type.is_file(),
                    "documented SYSTEM identity file is not a regular file"
                );
            } else {
                eprintln!("WARN unknown SYSTEM identity file");
            }
        }
    }
    Ok(())
}

pub(crate) fn run(request_path: &Path, result_path: &Path) -> anyhow::Result<()> {
    ensure!(crate::windows::running_as_system()?, "SYSTEM probe must run as SYSTEM");
    let request: Request = serde_json::from_slice(&std::fs::read(request_path)?)?;
    ensure!(
        request
            .key_name_prefix
            .starts_with("DevolutionsAgent-Identity-conformance-"),
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
            let (identity, recorded) = stored_keys(&request)?;
            assert_stored_keys(&identity)?;
            assert_no_orphan_keys(&request.key_name_prefix, &recorded)?;
            audit_identity_tree(&request, &token)
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

    use super::{Request, audit_identity_tree, matching_key, wait_for_pending_cleanup};

    #[test]
    fn current_key_is_selected_only_from_the_matching_device_and_run() -> anyhow::Result<()> {
        let prefix = "DevolutionsAgent-Identity-conformance-4321-";
        let name = format!("{prefix}479e1d51-4038-4d09-b7f8-5bdff4489cad");
        let identity = json!({ "device_id": "device-a", "keys": { "current": { "key_name": name } } });
        assert_eq!(matching_key(&identity, "device-a", prefix)?, Some(name));
        assert_eq!(matching_key(&identity, "device-b", prefix)?, None);
        assert!(matching_key(&identity, "device-a", "other-run-").is_err());
        assert!(
            matching_key(
                &json!({ "device_id": "device-a", "keys": { "current": { "key_name": format!("{prefix}bad") } } }),
                "device-a",
                prefix
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn system_identity_audit_rejects_token_fragments_and_private_key_material() -> anyhow::Result<()> {
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
            key_name_prefix: "DevolutionsAgent-Identity-conformance-unit-".to_owned(),
            device_id: None,
            token_port: None,
            token_nonce: None,
            cleanup_only: true,
        };
        let token = format!("dvaet1.bag.{}", "A".repeat(43));
        audit_identity_tree(&request, &token)?;
        let leaked = authority.join("debug.log");
        std::fs::write(&leaked, &token.as_bytes()[token.len() - 12..])?;
        assert!(audit_identity_tree(&request, &token).is_err());
        std::fs::remove_file(leaked)?;
        let private = keys.join("extra.p8");
        std::fs::write(&private, b"private key")?;
        assert!(audit_identity_tree(&request, &token).is_err());
        std::fs::remove_file(private)?;
        std::fs::write(keys.join("extra.bin"), b"-----BEGIN PRIVATE KEY-----")?;
        assert!(audit_identity_tree(&request, &token).is_err());
        Ok(())
    }

    #[test]
    fn system_probe_waits_for_both_successful_pending_records_to_disappear() -> anyhow::Result<()> {
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
            device_id: None,
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
