#[cfg(windows)]
use std::error::Error;
use std::io::{ErrorKind, Read as _};
use std::{fmt, fs};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use camino::{Utf8Path, Utf8PathBuf};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer as _, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::token::{self, Token};
use crate::{private_file, state_lock};

const MAX_PENDING_BYTES: usize = 16 * 1024;
const MAX_PLAINTEXT_SCAN_BYTES: usize = 64 * 1024;
#[cfg(windows)]
const MAX_ENCRYPTED_BYTES: usize = MAX_PLAINTEXT_SCAN_BYTES + 4096;

#[cfg(windows)]
const EXTENSION: &str = "dat";
#[cfg(not(windows))]
const EXTENSION: &str = "json";

#[derive(Debug)]
pub enum PendingRead {
    Ready(Token),
    Malformed(MalformedPending),
}

#[derive(Debug)]
pub struct MalformedPending {
    rejection_hash_hex: String,
}

impl MalformedPending {
    pub fn rejection_hash_hex(&self) -> &str {
        &self.rejection_hash_hex
    }
}

/// A retryable DPAPI failure, distinguishable by W4's per-file polling loop without inspecting error text.
#[cfg(windows)]
#[derive(Debug)]
pub struct PendingDecryptionFailure(anyhow::Error);

#[cfg(windows)]
impl fmt::Display for PendingDecryptionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("decrypt pending enrollment")
    }
}

#[cfg(windows)]
impl Error for PendingDecryptionFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.root_cause())
    }
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
        crate::windows::submit_pending_as_administrator(data_dir, &path, &contents)?;
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

fn pending_hash_from_name(name: &str) -> Option<&str> {
    name.strip_suffix(&format!(".{EXTENSION}"))
        .filter(|hash| valid_hash_hex(hash))
}

/// A malformed result carries the token hash when extractable, otherwise the plaintext hash (bounded for oversized payloads).
/// I/O, security-check and DPAPI failures remain retryable errors.
pub fn read(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<PendingRead> {
    #[cfg(not(windows))]
    let _ = grant_current_user;
    let expected_hash = path.file_name().and_then(pending_hash_from_name);
    let file = private_file::open_pending_read(path, grant_current_user)?;
    #[cfg(windows)]
    ensure!(
        file.metadata()?.len() <= u64::try_from(MAX_ENCRYPTED_BYTES)?,
        "encrypted pending enrollment is too large"
    );
    let mut contents = Zeroizing::new(Vec::new());
    #[cfg(windows)]
    let max_file_bytes = MAX_ENCRYPTED_BYTES;
    #[cfg(not(windows))]
    let max_file_bytes = MAX_PLAINTEXT_SCAN_BYTES;
    file.take(u64::try_from(max_file_bytes + 1)?)
        .read_to_end(&mut contents)?;
    #[cfg(windows)]
    ensure!(
        contents.len() <= MAX_ENCRYPTED_BYTES,
        "encrypted pending enrollment is too large"
    );
    #[cfg(windows)]
    let plaintext = crate::windows::unprotect(&contents).map_err(PendingDecryptionFailure)?;
    #[cfg(not(windows))]
    let plaintext = contents;
    if plaintext.len() > MAX_PENDING_BYTES {
        return Ok(oversized_payload(
            &plaintext[..plaintext.len().min(MAX_PLAINTEXT_SCAN_BYTES)],
        ));
    }
    Ok(parse_payload(&plaintext, expected_hash))
}

struct TokenHashVisitor<'a>(&'a mut Option<String>);

impl<'de> Visitor<'de> for TokenHashVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a pending enrollment object")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "token" {
                if let Some(raw) = map.next_value::<Value>()?.as_str() {
                    *self.0 = Some(token::sha256_hex(raw));
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }

    fn visit_str<E: serde::de::Error>(self, raw: &str) -> Result<(), E> {
        *self.0 = Some(token::sha256_hex(raw));
        Ok(())
    }

    fn visit_string<E: serde::de::Error>(self, raw: String) -> Result<(), E> {
        *self.0 = Some(token::sha256_hex(&Zeroizing::new(raw)));
        Ok(())
    }
}

fn oversized_payload(plaintext_prefix: &[u8]) -> PendingRead {
    let mut token_hash = None;
    let mut decoder = serde_json::Deserializer::from_slice(plaintext_prefix);
    let _ = decoder.deserialize_any(TokenHashVisitor(&mut token_hash));
    PendingRead::Malformed(MalformedPending {
        rejection_hash_hex: token_hash
            .unwrap_or_else(|| hex::encode(Sha256::digest(&plaintext_prefix[..MAX_PENDING_BYTES]))),
    })
}

fn parse_payload(plaintext: &[u8], expected_hash: Option<&str>) -> PendingRead {
    let Ok(mut payload) = serde_json::from_slice::<Value>(plaintext) else {
        return malformed(plaintext);
    };
    if let Value::String(raw) = payload {
        return PendingRead::Malformed(MalformedPending {
            rejection_hash_hex: token::sha256_hex(&Zeroizing::new(raw)),
        });
    }
    let Some(fields) = payload.as_object_mut() else {
        return malformed(plaintext);
    };
    let supported_version = fields.get("version").and_then(Value::as_u64) == Some(1);
    let Some(Value::String(raw)) = fields.remove("token") else {
        return malformed(plaintext);
    };
    let raw = Zeroizing::new(raw);
    let token_hash_hex = token::sha256_hex(&raw);
    if !supported_version {
        return PendingRead::Malformed(MalformedPending {
            rejection_hash_hex: token_hash_hex,
        });
    }
    let Ok(token) = Token::parse(&raw) else {
        return PendingRead::Malformed(MalformedPending {
            rejection_hash_hex: token_hash_hex,
        });
    };
    if Some(token_hash_hex.as_str()) != expected_hash {
        return PendingRead::Malformed(MalformedPending {
            rejection_hash_hex: token_hash_hex,
        });
    }
    PendingRead::Ready(token)
}

fn malformed(plaintext: &[u8]) -> PendingRead {
    PendingRead::Malformed(MalformedPending {
        rejection_hash_hex: hex::encode(Sha256::digest(plaintext)),
    })
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
        record.version == 1 && record.token_sha256 == base64_hash(hash_hex)?,
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
        record.version == 1 && record.token_sha256 == base64_hash(hash_hex)?,
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

fn base64_hash(hash_hex: &str) -> anyhow::Result<String> {
    validate_hash_hex(hash_hex)?;
    Ok(URL_SAFE_NO_PAD.encode(hex::decode(hash_hex)?))
}

fn validate_hash_hex(hash_hex: &str) -> anyhow::Result<()> {
    ensure!(valid_hash_hex(hash_hex), "invalid pending enrollment hash");
    Ok(())
}

fn valid_hash_hex(hash_hex: &str) -> bool {
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest as _, Sha256};

    use super::*;

    #[test]
    fn malformed_payload_uses_token_hash_or_raw_payload_hash() -> anyhow::Result<()> {
        let token = format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://example.test"}"#),
            "A".repeat(43)
        );
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
        let wrong_version = serde_json::to_vec(&serde_json::json!({"version": 2, "token": token}))?;
        let PendingRead::Malformed(malformed) = parse_payload(&wrong_version, Some(&token_hash)) else {
            anyhow::bail!("unsupported pending version was accepted")
        };
        assert_eq!(malformed.rejection_hash_hex(), token_hash);

        let no_token_string = br#"{"version":1,"token":null}"#;
        let PendingRead::Malformed(malformed) = parse_payload(no_token_string, Some(&token_hash)) else {
            anyhow::bail!("non-string pending token was accepted")
        };
        assert_eq!(
            malformed.rejection_hash_hex(),
            hex::encode(Sha256::digest(no_token_string))
        );

        let json_string = serde_json::to_vec("bad-token")?;
        let PendingRead::Malformed(malformed) = parse_payload(&json_string, Some(&token_hash)) else {
            anyhow::bail!("wrong pending payload shape was accepted")
        };
        assert_eq!(malformed.rejection_hash_hex(), token::sha256_hex("bad-token"));

        let invalid_token = serde_json::json!({"version": 1, "token": "not a token"}).to_string();
        let PendingRead::Malformed(malformed) = parse_payload(invalid_token.as_bytes(), Some(&token_hash)) else {
            anyhow::bail!("invalid pending token was accepted")
        };
        assert_eq!(malformed.rejection_hash_hex(), token::sha256_hex("not a token"));

        let invalid_json = b"not JSON";
        let PendingRead::Malformed(malformed) = parse_payload(invalid_json, Some(&token_hash)) else {
            anyhow::bail!("malformed pending JSON was accepted")
        };
        assert_eq!(
            malformed.rejection_hash_hex(),
            hex::encode(Sha256::digest(invalid_json))
        );

        let valid_body = serde_json::to_vec(&serde_json::json!({"version": 1, "token": token}))?;
        let wrong_hash = "0".repeat(64);
        let PendingRead::Malformed(malformed) = parse_payload(&valid_body, Some(&wrong_hash)) else {
            anyhow::bail!("wrong-filename pending token was accepted")
        };
        assert_eq!(malformed.rejection_hash_hex(), token_hash);
        assert_eq!(
            pending_hash_from_name(&format!("{token_hash}.{EXTENSION}")),
            Some(token_hash.as_str())
        );
        assert!(pending_hash_from_name(&format!("{token}.{EXTENSION}")).is_none());
        assert!(pending_hash_from_name(&format!("{}.{}", token_hash.to_uppercase(), EXTENSION)).is_none());
        assert!(is_owned_temporary_stem(&format!(".{token_hash}.{EXTENSION}")));
        Ok(())
    }

    #[test]
    fn oversized_plaintext_uses_token_hash_or_bounded_plaintext_hash() -> anyhow::Result<()> {
        let token = format!(
            "dvaet1.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"u":"https://example.test"}"#),
            "A".repeat(43)
        );
        let dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("pending-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&dir)?;
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
        let oversized = format!(
            r#"{{"version":1,"token":"{token}","padding":"{}"}}"#,
            "x".repeat(MAX_PENDING_BYTES)
        )
        .into_bytes();
        #[cfg(windows)]
        let contents = crate::windows::protect(&oversized)?;
        #[cfg(not(windows))]
        let contents = oversized;
        private_file::write_atomic(&dir, &path, &contents, true)?;
        let PendingRead::Malformed(malformed) = read(&path, true)? else {
            anyhow::bail!("oversized pending plaintext was not classified as malformed")
        };
        assert_eq!(malformed.rejection_hash_hex(), hash);

        let oversized = format!(
            r#"{{"version":1,"padding":"{}","token":"{token}"}}"#,
            "x".repeat(MAX_PENDING_BYTES)
        )
        .into_bytes();
        #[cfg(windows)]
        let contents = crate::windows::protect(&oversized)?;
        #[cfg(not(windows))]
        let contents = oversized;
        private_file::write_atomic(&dir, &path, &contents, true)?;
        let PendingRead::Malformed(malformed) = read(&path, true)? else {
            anyhow::bail!("oversized token after padding was not classified as malformed")
        };
        assert_eq!(malformed.rejection_hash_hex(), hash);

        let oversized = format!("\"{token}\"{}", " ".repeat(MAX_PENDING_BYTES)).into_bytes();
        #[cfg(windows)]
        let contents = crate::windows::protect(&oversized)?;
        #[cfg(not(windows))]
        let contents = oversized;
        private_file::write_atomic(&dir, &path, &contents, true)?;
        let PendingRead::Malformed(malformed) = read(&path, true)? else {
            anyhow::bail!("oversized JSON string was not classified as malformed")
        };
        assert_eq!(malformed.rejection_hash_hex(), hash);

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
            let PendingRead::Malformed(malformed) = read(&path, true)? else {
                anyhow::bail!("decryptable oversized Windows plaintext was not malformed")
            };
            assert_eq!(malformed.rejection_hash_hex(), hash);
        }

        let oversized = vec![b'x'; MAX_PENDING_BYTES + 64];
        #[cfg(windows)]
        let contents = crate::windows::protect(&oversized)?;
        #[cfg(not(windows))]
        let contents = oversized.clone();
        private_file::write_atomic(&dir, &path, &contents, true)?;
        let PendingRead::Malformed(malformed) = read(&path, true)? else {
            anyhow::bail!("oversized malformed plaintext was not classified as malformed")
        };
        assert_eq!(
            malformed.rejection_hash_hex(),
            hex::encode(Sha256::digest(&oversized[..MAX_PENDING_BYTES]))
        );
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

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
        let dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("pending-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&dir)?;
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
            let error = read(&path, true).expect_err("opaque DPAPI failure was not transient");
            assert!(error.downcast_ref::<PendingDecryptionFailure>().is_some());
            let encrypted = crate::windows::protect(b"not valid JSON")?;
            private_file::write_atomic(&dir, &path, &encrypted, true)?;
            assert!(matches!(read(&path, true)?, PendingRead::Malformed(_)));
        }
        #[cfg(not(windows))]
        assert!(matches!(read(&path, true)?, PendingRead::Malformed(_)));
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
            crate::windows::assert_pending_protection(&path, true)?;
            let protected_path = independent;
            if crate::windows::is_system()? {
                assert_eq!(write(&dir, &other, false)?, protected_path);
                assert_eq!(write(&dir, &other, false)?, protected_path);
                crate::windows::assert_pending_protection(&protected_path, false)?;
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
