use std::fs;
use std::io::{ErrorKind, Read as _};

use anyhow::{Context as _, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::token::{self, Token};
use crate::{private_file, state_lock};

const MAX_PENDING_BYTES: usize = 16 * 1024;
#[cfg(windows)]
const MAX_ENCRYPTED_BYTES: usize = MAX_PENDING_BYTES + 4096;

#[cfg(windows)]
const EXTENSION: &str = "dat";
#[cfg(not(windows))]
const EXTENSION: &str = "json";

#[derive(Debug)]
pub enum PendingRead {
    Ready(Token),
    MalformedToken,
    Unusable,
    #[cfg(windows)]
    Undecryptable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InProgress {
    pub version: u8,
    pub token_sha256: String,
    pub key_name: String,
}

#[derive(Serialize)]
struct PendingBodyRef<'a> {
    version: u8,
    token: &'a str,
}

pub fn directory(data_dir: &Utf8Path) -> Utf8PathBuf {
    data_dir.join("identity").join("pending")
}

pub fn file_path(data_dir: &Utf8Path, hash_hex: &str) -> anyhow::Result<Utf8PathBuf> {
    validate_hash_hex(hash_hex)?;
    Ok(directory(data_dir).join(format!("{hash_hex}.{EXTENSION}")))
}

pub fn in_progress_path(data_dir: &Utf8Path, hash_hex: &str) -> anyhow::Result<Utf8PathBuf> {
    validate_hash_hex(hash_hex)?;
    Ok(directory(data_dir).join(format!("{hash_hex}.in-progress.json")))
}

/// Writes the full token only to its protected pending file.
/// On Windows, SYSTEM must provision the pending drop box before an administrator can submit a token.
pub fn write(data_dir: &Utf8Path, token: &Token, grant_current_user: bool) -> anyhow::Result<Utf8PathBuf> {
    #[cfg(windows)]
    let administrator_writer = crate::windows::is_administrator_writer()?;
    #[cfg(windows)]
    ensure!(
        administrator_writer || grant_current_user || crate::windows::is_system()?,
        "pending enrollment requires SYSTEM or an administrator"
    );
    let hash_hex = token.sha256_hex();
    let path = file_path(data_dir, &hash_hex)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&PendingBodyRef {
            version: 1,
            token: token.as_str(),
        })
        .context("encode pending enrollment")?,
    );
    #[cfg(windows)]
    let contents = crate::windows::protect(&plaintext)?;
    #[cfg(not(windows))]
    let contents = plaintext;
    #[cfg(windows)]
    if administrator_writer && !grant_current_user {
        private_file::submit_pending_as_administrator(data_dir, &path, &contents)?;
        return Ok(path);
    }
    let _lock = state_lock::acquire(data_dir, grant_current_user)?;
    private_file::write_atomic(data_dir, &path, &contents, grant_current_user)?;
    Ok(path)
}

pub fn list(data_dir: &Utf8Path) -> anyhow::Result<Vec<Utf8PathBuf>> {
    let entries = match fs::read_dir(directory(data_dir)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("list pending enrollments"),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.context("read pending enrollment entry")?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if pending_hash_from_name(&name).is_some() {
            let path =
                Utf8PathBuf::from_path_buf(entry.path()).map_err(|_| anyhow::anyhow!("non-UTF-8 pending path"))?;
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

pub(crate) fn pending_hash_from_name(name: &str) -> Option<&str> {
    name.strip_suffix(&format!(".{EXTENSION}"))
        .filter(|hash| valid_hash_hex(hash))
}

/// Only a matching version-one payload can produce a malformed-token outcome.
/// I/O and security-check failures remain retryable errors.
pub fn read(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<PendingRead> {
    #[cfg(not(windows))]
    let _ = grant_current_user;
    let expected_hash = path.file_name().and_then(pending_hash_from_name);
    let file = private_file::open_pending_read(path, grant_current_user)?;
    let mut contents = Zeroizing::new(Vec::new());
    #[cfg(windows)]
    let max_file_bytes = MAX_ENCRYPTED_BYTES;
    #[cfg(not(windows))]
    let max_file_bytes = MAX_PENDING_BYTES;
    file.take(u64::try_from(max_file_bytes + 1)?)
        .read_to_end(&mut contents)?;
    #[cfg(windows)]
    let plaintext = if contents.len() <= MAX_ENCRYPTED_BYTES {
        match crate::windows::unprotect(&contents) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(PendingRead::Undecryptable),
        }
    } else {
        return Ok(PendingRead::Unusable);
    };
    #[cfg(not(windows))]
    let plaintext = contents;
    if plaintext.len() <= MAX_PENDING_BYTES {
        Ok(parse_payload(&plaintext, expected_hash))
    } else {
        Ok(PendingRead::Unusable)
    }
}

fn parse_payload(plaintext: &[u8], expected_hash: Option<&str>) -> PendingRead {
    let Ok(mut payload) = serde_json::from_slice::<Value>(plaintext) else {
        return PendingRead::Unusable;
    };
    let Some(fields) = payload.as_object_mut() else {
        if let Value::String(raw) = payload {
            drop(Zeroizing::new(raw));
        }
        return PendingRead::Unusable;
    };
    let supported_version = fields.get("version").and_then(Value::as_u64) == Some(1);
    let Some(Value::String(raw)) = fields.remove("token") else {
        return PendingRead::Unusable;
    };
    let raw = Zeroizing::new(raw);
    if !supported_version {
        return PendingRead::Unusable;
    }
    if Some(token::sha256_hex(&raw).as_str()) != expected_hash {
        return PendingRead::Unusable;
    }
    match Token::parse(&raw) {
        Ok(token) => PendingRead::Ready(token),
        Err(_) => PendingRead::MalformedToken,
    }
}

pub fn read_in_progress(data_dir: &Utf8Path, hash_hex: &str) -> anyhow::Result<Option<InProgress>> {
    let path = in_progress_path(data_dir, hash_hex)?;
    let file = match private_file::open_read(&path) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) if private_file::is_untrusted(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_PENDING_BYTES + 1)?)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_PENDING_BYTES,
        "pending enrollment record is too large"
    );
    let record: InProgress =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid pending enrollment record"))?;
    ensure!(
        record.version == 1 && record.token_sha256 == hash_hex,
        "invalid pending enrollment record"
    );
    Ok(Some(record))
}

/// The caller must hold the shared identity state lock through the atomic write.
pub(crate) fn write_in_progress(
    data_dir: &Utf8Path,
    hash_hex: &str,
    record: &InProgress,
    grant_current_user: bool,
) -> anyhow::Result<()> {
    ensure!(
        record.version == 1 && record.token_sha256 == hash_hex,
        "invalid pending enrollment record"
    );
    let path = in_progress_path(data_dir, hash_hex)?;
    let bytes = serde_json::to_vec(record).context("encode pending enrollment record")?;
    private_file::write_atomic(data_dir, &path, &bytes, grant_current_user)
}

pub fn list_in_progress(data_dir: &Utf8Path) -> anyhow::Result<Vec<(String, InProgress)>> {
    let entries = match fs::read_dir(directory(data_dir)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("list pending enrollment records"),
    };
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry.context("read pending enrollment record entry")?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(hash) = name
            .strip_suffix(".in-progress.json")
            .filter(|hash| valid_hash_hex(hash))
            && let Some(record) = read_in_progress(data_dir, hash)?
        {
            records.push((hash.to_owned(), record));
        }
    }
    records.sort_by(|first, second| first.0.cmp(&second.0));
    Ok(records)
}

pub fn remove_file(data_dir: &Utf8Path, hash_hex: &str, grant_current_user: bool) -> anyhow::Result<()> {
    private_file::remove_pending_file(&file_path(data_dir, hash_hex)?, grant_current_user)
}

pub fn remove_in_progress(data_dir: &Utf8Path, hash_hex: &str) -> anyhow::Result<()> {
    private_file::remove_file(&in_progress_path(data_dir, hash_hex)?)
}

fn validate_hash_hex(hash_hex: &str) -> anyhow::Result<()> {
    ensure!(valid_hash_hex(hash_hex), "invalid pending enrollment hash");
    Ok(())
}

pub(crate) fn valid_hash_hex(hash_hex: &str) -> bool {
    hash_hex.len() == 64
        && hash_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_owned_temporary_stem(stem: &str) -> bool {
    let Some(name) = stem.strip_prefix('.') else {
        return false;
    };
    let hash = name
        .strip_suffix(".in-progress.json")
        .or_else(|| name.strip_suffix(&format!(".{EXTENSION}")));
    hash.is_some_and(valid_hash_hex)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest as _, Sha256};

    use super::*;

    /// Creates an empty data directory under the system temporary directory, whose directories above pass the checks
    /// of the agent's state, which a workspace `target` directory may not.
    fn test_data_dir() -> anyhow::Result<Utf8PathBuf> {
        let dir = Utf8PathBuf::from_path_buf(std::env::temp_dir())
            .map_err(|_| anyhow::anyhow!("the temporary directory path is not UTF-8"))?
            .join(format!("ai-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn only_matching_version_one_tokens_can_be_malformed() -> anyhow::Result<()> {
        // `crates/agent-identity/INTENT.md` ("Local state") permits markers only for matching hash-named files.
        let token = format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://example.test"}"#),
            "A".repeat(43)
        );
        let token_hash = token::sha256_hex(&token);
        let valid_body = serde_json::to_vec(&serde_json::json!({"version": 1, "token": token}))?;
        assert!(matches!(
            parse_payload(&valid_body, Some(&token_hash)),
            PendingRead::Ready(_)
        ));
        for unusable in [
            serde_json::json!({"version": 2, "token": token}).to_string(),
            serde_json::json!({"token": token}).to_string(),
            serde_json::json!({"version": 1, "token": null}).to_string(),
            serde_json::to_string("bad-token")?,
            "not JSON".to_owned(),
        ] {
            assert!(matches!(
                parse_payload(unusable.as_bytes(), Some(&token_hash)),
                PendingRead::Unusable
            ));
        }
        let wrong_hash = "0".repeat(64);
        assert!(matches!(
            parse_payload(&valid_body, Some(&wrong_hash)),
            PendingRead::Unusable
        ));
        assert!(matches!(parse_payload(&valid_body, None), PendingRead::Unusable));
        let invalid_token = serde_json::json!({"version": 1, "token": "not a token"}).to_string();
        assert!(matches!(
            parse_payload(invalid_token.as_bytes(), Some(&token::sha256_hex("not a token"))),
            PendingRead::MalformedToken
        ));
        assert_eq!(
            pending_hash_from_name(&format!("{token_hash}.{EXTENSION}")),
            Some(token_hash.as_str())
        );
        assert!(pending_hash_from_name(&format!("{token}.{EXTENSION}")).is_none());
        assert!(pending_hash_from_name(&format!("{}.{}", token_hash.to_uppercase(), EXTENSION)).is_none());
        // oracle: intent crates/agent-identity/INTENT.md §Local state
        assert!(is_owned_temporary_stem(&format!(".{token_hash}.{EXTENSION}")));
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn state_paths_take_only_a_lowercase_hex_token_hash() {
        let dir = Utf8Path::new("data");
        let hash = "0123456789abcdef".repeat(4);
        assert!(file_path(dir, &hash).is_ok());
        assert!(in_progress_path(dir, &hash).is_ok());
        for invalid in [hash.to_uppercase(), hash[..63].to_owned(), format!("../{}", &hash[3..])] {
            assert!(file_path(dir, &invalid).is_err(), "{invalid}");
            assert!(in_progress_path(dir, &invalid).is_err(), "{invalid}");
        }
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    #[test]
    fn a_pending_payload_of_exactly_16_kib_is_read() -> anyhow::Result<()> {
        let token = Token::parse(&format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://example.test"}"#),
            "A".repeat(43)
        ))?;
        let dir = test_data_dir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            if fs::metadata(&dir)?.permissions().mode() & 0o022 != 0 {
                fs::remove_dir_all(&dir)?;
                return Ok(());
            }
        }
        private_file::prepare_directories(&dir, true)?;
        let path = file_path(&dir, &token.sha256_hex())?;
        let body = format!(r#"{{"version":1,"token":"{}"}}"#, token.as_str());
        // JSON allows trailing white space, which pads the payload to an exact size.
        for (size, readable) in [(16 * 1024, true), (16 * 1024 + 1, false)] {
            let padded = format!("{body}{}", " ".repeat(size - body.len()));
            #[cfg(windows)]
            let contents = crate::windows::protect(padded.as_bytes())?;
            #[cfg(not(windows))]
            let contents = padded.into_bytes();
            private_file::write_atomic(&dir, &path, &contents, true)?;
            assert_eq!(
                matches!(read(&path, true)?, PendingRead::Ready(found) if found.as_str() == token.as_str()),
                readable,
                "{size}"
            );
        }
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Local state
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn oversized_pending_payload_is_unusable() -> anyhow::Result<()> {
        let token = format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://example.test"}"#),
            "A".repeat(43)
        );
        let dir = test_data_dir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            if fs::metadata(&dir)?.permissions().mode() & 0o022 != 0 {
                fs::remove_dir_all(&dir)?;
                return Ok(());
            }
        }
        let hash = token::sha256_hex(&token);
        let path = file_path(&dir, &hash)?;
        private_file::prepare_directories(&dir, true)?;
        for oversized in [
            format!(
                r#"{{"version":1,"token":"{token}","padding":"{}"}}"#,
                "x".repeat(MAX_PENDING_BYTES)
            ),
            format!(
                r#"{{"version":1,"padding":"{}","token":"{token}"}}"#,
                "x".repeat(MAX_PENDING_BYTES)
            ),
            format!("\"{token}\"{}", " ".repeat(MAX_PENDING_BYTES)),
            "x".repeat(MAX_PENDING_BYTES + 64),
        ] {
            #[cfg(windows)]
            let contents = crate::windows::protect(oversized.as_bytes())?;
            #[cfg(not(windows))]
            let contents = oversized.into_bytes();
            private_file::write_atomic(&dir, &path, &contents, true)?;
            assert!(matches!(read(&path, true)?, PendingRead::Unusable));
        }
        #[cfg(windows)]
        {
            let oversized = format!(
                r#"{{"version":1,"token":"{token}","padding":"{}"}}"#,
                "x".repeat(25 * 1024)
            )
            .into_bytes();
            let ciphertext = crate::windows::protect(&oversized)?;
            assert!(ciphertext.len() > MAX_PENDING_BYTES + 4096);
            private_file::write_atomic(&dir, &path, &ciphertext, true)?;
            assert!(matches!(read(&path, true)?, PendingRead::Unusable));
        }
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    #[test]
    fn derives_pending_names_and_handles_malformed_content() -> anyhow::Result<()> {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let raw = format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://example.test"}"#),
            "A".repeat(43)
        );
        let token = Token::parse(&raw)?;
        let dir = test_data_dir()?;
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));
        assert_eq!(
            file_path(&dir, &hash)?,
            directory(&dir).join(format!("{hash}.{EXTENSION}"))
        );
        let result = write(&dir, &token, true);
        #[cfg(unix)]
        if fs::metadata(&dir)?.permissions().mode() & 0o022 != 0 {
            assert!(
                result.is_err(),
                "pending file written to volume without owner-only permissions"
            );
            assert!(list(&dir)?.is_empty());
            fs::remove_dir_all(&dir)?;
            return Ok(());
        }
        let path = result?;
        assert_eq!(path, file_path(&dir, &hash)?);
        assert!(matches!(read(&path, true)?, PendingRead::Ready(found) if found.as_str() == raw));
        let overwritten = write(&dir, &token, true)?;
        assert_eq!(overwritten, path);
        assert_eq!(list(&dir)?, vec![path.clone()]);
        let token_named = directory(&dir).join(format!("{raw}.{EXTENSION}"));
        fs::write(&token_named, b"not encrypted")?;
        #[cfg(unix)]
        fs::set_permissions(&token_named, fs::Permissions::from_mode(0o644))?;
        assert_eq!(list(&dir)?, vec![path.clone()]);
        let error = read(&token_named, true).expect_err("untrusted token-named file was read");
        assert!(!format!("{error:#}").contains(&raw));
        fs::remove_file(token_named)?;
        private_file::write_atomic(&dir, &path, b"not a token", true)?;
        #[cfg(windows)]
        {
            assert!(matches!(read(&path, true)?, PendingRead::Undecryptable));
            let encrypted = crate::windows::protect(b"not valid JSON")?;
            private_file::write_atomic(&dir, &path, &encrypted, true)?;
            assert!(matches!(read(&path, true)?, PendingRead::Unusable));
        }
        #[cfg(not(windows))]
        assert!(matches!(read(&path, true)?, PendingRead::Unusable));
        #[cfg(unix)]
        {
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        #[cfg(windows)]
        {
            if !crate::windows::is_system()? {
                assert!(
                    read(&path, false).is_err(),
                    "default mode must reject a user-owned pending file"
                );
            }
            let other = Token::parse(&format!(
                "dvaet1.{}.{}",
                URL_SAFE_NO_PAD.encode(r#"{"u":"https://other.test"}"#),
                "A".repeat(43)
            ))?;
            let independent = file_path(&dir, &other.sha256_hex())?;
            fs::write(&independent, b"independently supplied blob")?;
            assert!(
                read(&independent, true).is_err(),
                "files without a protected DACL must not be processed"
            );
            fs::remove_file(&independent)?;
            crate::windows::test::assert_pending_protection(&path, true)?;
            let protected_path = independent;
            if crate::windows::is_system()? {
                assert_eq!(write(&dir, &other, false)?, protected_path);
                assert_eq!(write(&dir, &other, false)?, protected_path);
                crate::windows::test::assert_pending_protection(&protected_path, false)?;
                fs::remove_file(protected_path)?;
            } else {
                assert!(write(&dir, &other, false).is_err());
                assert!(!protected_path.exists());
            }
        }
        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
