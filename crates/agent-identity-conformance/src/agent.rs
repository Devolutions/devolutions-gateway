use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use der::{Decode as _, Encode as _, Reader as _};
#[cfg(any(unix, windows))]
use p256::ecdsa::SigningKey;
#[cfg(windows)]
use p256::ecdsa::VerifyingKey;
#[cfg(any(unix, windows))]
use p256::pkcs8::DecodePrivateKey as _;
use p256::pkcs8::EncodePublicKey as _;
use rand::RngExt as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncWriteExt as _;
use tokio::process::{Child, Command};
use x509_cert::Certificate;

use crate::client::{Target, Token, count, decoded_certificate, expect_status, field};
use crate::dvls::{CertificateStatus, IdentityQuery, IdentityRecord, IdentityStatus, RotationDeadline};
use crate::{Context, KeyBackend};

#[cfg(windows)]
#[path = "system_fixture.rs"]
mod system_fixture;

type CaseFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
const WAIT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(100);
const KNOWN_METADATA_KEYS: [&str; 8] = [
    "hostname",
    "fqdn",
    "domain",
    "os_name",
    "os_version",
    "arch",
    "agent_version",
    "machine_id",
];
const REQUIRED_METADATA_KEYS: [&str; 5] = ["hostname", "os_name", "os_version", "arch", "agent_version"];

pub(crate) fn token_file_id(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn valid_key_prefix(prefix: &str) -> bool {
    (1..=64).contains(&prefix.len())
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn key_belongs_to_run(name: &str, prefix: &str) -> bool {
    name.split_once('_').is_some_and(|(candidate, _)| candidate == prefix)
}

pub(crate) fn validate_key_name(prefix: &str, name: &str) -> anyhow::Result<()> {
    ensure!(valid_key_prefix(prefix), "invalid device-key run prefix");
    let (_, key_uuid) = name.split_once('_').context("key name has no prefix separator")?;
    ensure!(
        key_belongs_to_run(name, prefix),
        "key name {name} does not belong to run prefix {prefix}"
    );
    let parsed = uuid::Uuid::parse_str(key_uuid).context("key name does not end with a UUID")?;
    ensure!(
        parsed.to_string() == key_uuid,
        "key name does not end with a lowercase hyphenated UUID"
    );
    Ok(())
}

/// The run's key name that a file name embeds, such as the name of a key-store file holding a copy of that key.
fn embedded_key_name<'a>(file_name: &'a str, prefix: &str) -> Option<&'a str> {
    let start = file_name.find(&format!("{prefix}_"))?;
    let name = file_name.get(start..start + prefix.len() + 1 + uuid::fmt::Hyphenated::LENGTH)?;
    validate_key_name(prefix, name).is_ok().then_some(name)
}

fn canonical_authority_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| uuid::Uuid::parse_str(name).ok().map(|id| id.to_string() == name))
        == Some(true)
}

pub(crate) fn contains_pkcs8_material(contents: &[u8]) -> bool {
    const PEM_MARKERS: [&[u8]; 2] = [b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN ENCRYPTED PRIVATE KEY-----"];
    PEM_MARKERS
        .iter()
        .any(|marker| contents.windows(marker.len()).any(|window| window == *marker))
        || p256::pkcs8::PrivateKeyInfoRef::try_from(contents).is_ok()
        || encrypted_pkcs8_der(contents).unwrap_or(false)
}

fn encrypted_pkcs8_der(contents: &[u8]) -> der::Result<bool> {
    let outer = <&der::asn1::SequenceRef>::from_der(contents)?;
    let mut fields = der::SliceReader::new(outer.as_bytes())?;
    let algorithm: &der::asn1::SequenceRef = fields.decode()?;
    let encrypted: &der::asn1::OctetStringRef = fields.decode()?;
    fields.finish()?;
    let mut algorithm_fields = der::SliceReader::new(algorithm.as_bytes())?;
    let oid: der::asn1::ObjectIdentifier = algorithm_fields.decode()?;
    let oid = oid.to_string();
    Ok(!encrypted.as_bytes().is_empty()
        && (oid.starts_with("1.2.840.113549.1.5.") || oid.starts_with("1.2.840.113549.1.12.1.")))
}

fn temporary_name(name: &str, expected: &str) -> bool {
    let name = name.strip_prefix('.').unwrap_or(name);
    let Some(suffix) = name
        .strip_prefix(expected)
        .and_then(|tail| tail.strip_prefix('.').or_else(|| tail.strip_prefix('-')))
    else {
        return false;
    };
    suffix.starts_with("tmp")
        || ["temp", "part", "new"].iter().any(|marker| {
            suffix.strip_prefix(marker).is_some_and(|rest| {
                rest.is_empty()
                    || rest.starts_with('.')
                    || rest.starts_with('-')
                    || rest.starts_with('_')
                    || rest.as_bytes().first().is_some_and(|byte| byte.is_ascii_digit())
            })
        })
        || [".tmp", ".temp", ".part", ".new"]
            .iter()
            .any(|extension| suffix.ends_with(extension))
}

pub(crate) fn is_temporary_sibling(path: &Path, documented: &HashSet<PathBuf>, key_prefix: &str) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if documented.iter().any(|file| {
        path.parent() == file.parent()
            && file
                .file_name()
                .and_then(|expected| expected.to_str())
                .is_some_and(|expected| temporary_name(name, expected))
    }) {
        return true;
    }
    let candidate = name.strip_prefix('.').unwrap_or(name);
    match path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|parent| parent.to_str())
    {
        Some("keys") => candidate
            .split_once(".p8.")
            .or_else(|| candidate.split_once(".p8-"))
            .is_some_and(|(key, _)| {
                validate_key_name(key_prefix, key).is_ok() && temporary_name(name, &format!("{key}.p8"))
            }),
        Some("pending") if candidate.len() >= 64 => {
            let (hash, _) = candidate.split_at(64);
            hash.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && [".json", ".dat", ".in-progress.json"]
                    .iter()
                    .any(|suffix| temporary_name(name, &format!("{hash}{suffix}")))
        }
        _ => false,
    }
}

fn validate_agent_metadata(metadata: &Value, agent_version: Option<&str>) -> anyhow::Result<()> {
    let values = metadata.as_object().context("agent metadata is not an object")?;
    let mut total_bytes = 0;
    for (key, value) in values {
        ensure!(
            KNOWN_METADATA_KEYS.contains(&key.as_str()),
            "agent sent unknown metadata key {key}"
        );
        let value = value
            .as_str()
            .with_context(|| format!("agent metadata {key} is not a string"))?;
        ensure!(!value.is_empty(), "agent metadata {key} is empty");
        ensure!(value.len() <= 1024, "agent metadata {key} exceeds 1024 UTF-8 bytes");
        ensure!(
            value
                .chars()
                .all(|character| character >= '\u{20}' && !('\u{7f}'..='\u{9f}').contains(&character)),
            "agent metadata {key} contains a C0/C1 control character"
        );
        total_bytes += key.len() + value.len();
    }
    ensure!(total_bytes <= 16 * 1024, "agent metadata exceeds 16 KiB");
    for key in REQUIRED_METADATA_KEYS {
        ensure!(
            values
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty()),
            "agent metadata is missing required {key}"
        );
    }
    ensure!(
        metadata["arch"] == std::env::consts::ARCH,
        "agent metadata arch differs from the test platform"
    );
    if let Some(expected) = agent_version {
        ensure!(
            metadata["agent_version"] == expected,
            "agent metadata version differs from --agent-version"
        );
    }
    #[cfg(target_os = "linux")]
    if Path::new("/etc/machine-id").exists() {
        let expected = std::fs::read_to_string("/etc/machine-id").context("read Linux machine ID")?;
        ensure!(
            metadata["machine_id"] == expected.trim(),
            "agent metadata machine_id differs from /etc/machine-id"
        );
    }
    Ok(())
}

pub(crate) fn assert_no_token_fragments(contents: &[u8], token: &str, path: &Path) -> anyhow::Result<()> {
    let mut parts = token.split('.');
    let _ = parts.next();
    let bag = parts.next().context("registered token has no bag")?;
    let secret = parts.next().context("registered token has no secret")?;
    for fragment in [token.as_bytes(), bag.as_bytes(), secret.as_bytes()] {
        if fragment.is_empty() {
            continue;
        }
        ensure!(
            !contents.windows(fragment.len()).any(|chunk| chunk == fragment),
            "enrollment token leaked into {}",
            path.display()
        );
    }
    for fragment in secret.as_bytes().windows(12) {
        ensure!(
            !contents.windows(12).any(|chunk| chunk == fragment),
            "twelve-character enrollment secret fragment leaked into {}",
            path.display()
        );
    }
    Ok(())
}

struct AgentCase {
    ctx: Context,
    dir: tempfile::TempDir,
    child: Option<Child>,
    #[cfg(windows)]
    job: Option<crate::windows::AgentJob>,
    #[cfg(unix)]
    process_group: Option<i32>,
    tokens: Vec<String>,
    metadata_hostname: String,
    cleaned: bool,
}

impl AgentCase {
    async fn new(ctx: Context, renewal_after_secs: Option<u64>, run: bool) -> anyhow::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("identity-agent-")
            .tempdir_in(&ctx.work_dir)
            .context("create agent data dir")?;
        let metadata_hostname = "conformance-initial".to_owned();
        let metadata_override_path = dir.path().join("identity-metadata-override.json");
        std::fs::write(
            &metadata_override_path,
            serde_json::to_vec(&json!({ "hostname": metadata_hostname }))?,
        )?;
        let mut identity_debug = json!({
            "disable_jitter": true,
            "backoff_max_secs": 2,
            "pending_poll_interval_ms": 200,
            "check_in_interval_secs": 5,
            "channel_failure_check_in_after_secs": 3,
            "key_name_prefix": &ctx.key_name_prefix,
            "metadata_override_path": metadata_override_path
        });
        if let Some(seconds) = renewal_after_secs {
            identity_debug["renewal_after_secs"] = json!(seconds);
        }
        let first_root = ctx.target.ca_path.as_deref();
        let second_root = ctx.second.as_ref().and_then(|target| target.ca_path.as_deref());
        match (first_root, second_root) {
            (Some(first), Some(second)) => {
                let mut roots = std::fs::read(first)?;
                roots.push(b'\n');
                roots.extend_from_slice(&std::fs::read(second)?);
                let combined = dir.path().join("trusted-roots.pem");
                std::fs::write(&combined, roots)?;
                identity_debug["extra_trusted_root"] = json!(combined);
            }
            (Some(path), None) | (None, Some(path)) => {
                identity_debug["extra_trusted_root"] = json!(path);
            }
            (None, None) => {}
        }
        #[cfg(windows)]
        {
            identity_debug["acl_grant_current_user"] = json!(true);
        }
        let config = json!({
            "Identity": { "Enabled": true, "KeyBackend": ctx.key_backend.name() },
            "__debug__": {
                "log_directives": "debug,h2=info,hyper=info,rustls=info",
                "identity": identity_debug
            }
        });
        std::fs::write(dir.path().join("agent.json"), serde_json::to_vec_pretty(&config)?)?;
        let mut case = Self {
            ctx,
            dir,
            child: None,
            #[cfg(windows)]
            job: None,
            #[cfg(unix)]
            process_group: None,
            tokens: Vec::new(),
            metadata_hostname,
            cleaned: false,
        };
        if run {
            case.start().await?;
        }
        Ok(case)
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn pending_path_for(&self, token: &str) -> PathBuf {
        #[cfg(windows)]
        let extension = "dat";
        #[cfg(not(windows))]
        let extension = "json";
        self.path()
            .join("identity")
            .join("pending")
            .join(format!("{}.{extension}", token_file_id(token)))
    }

    fn pending_path(&self) -> PathBuf {
        self.pending_path_for(self.tokens.last().expect("pending token is tracked"))
    }

    fn identity_path(&self, authority_id: &str) -> PathBuf {
        self.path()
            .join("identity")
            .join("authorities")
            .join(authority_id)
            .join("identity.json")
    }

    fn in_progress_path_for(&self, token: &str) -> PathBuf {
        self.path()
            .join("identity")
            .join("pending")
            .join(format!("{}.in-progress.json", token_file_id(token)))
    }

    fn in_progress_path(&self) -> PathBuf {
        self.in_progress_path_for(self.tokens.last().expect("pending token is tracked"))
    }

    fn rejection_path_for(&self, token: &str) -> PathBuf {
        self.path()
            .join("identity")
            .join("rejected")
            .join(format!("{}.json", token_file_id(token)))
    }

    fn metadata_override_path(&self) -> PathBuf {
        self.path().join("identity-metadata-override.json")
    }

    fn set_metadata_hostname(&mut self, hostname: &str) -> anyhow::Result<()> {
        let replacement = self.path().join("identity-metadata-override-next.json");
        std::fs::write(&replacement, serde_json::to_vec(&json!({ "hostname": hostname }))?)?;
        std::fs::rename(&replacement, self.metadata_override_path())?;
        self.metadata_hostname = hostname.to_owned();
        Ok(())
    }

    #[cfg(windows)]
    fn set_acl_grant_current_user(&mut self, allowed: bool) -> anyhow::Result<()> {
        ensure!(
            self.child.is_none(),
            "key ACL setting must be set before starting the agent"
        );
        let path = self.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        config["__debug__"]["identity"]["acl_grant_current_user"] = json!(allowed);
        std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
        Ok(())
    }

    /// Raises the agent's maximum retry delay, which also caps how long it honors `Retry-After`
    /// (CONTRACT.agent-identity.md §5.4).
    fn set_backoff_max_secs(&mut self, secs: u64) -> anyhow::Result<()> {
        ensure!(
            self.child.is_none(),
            "the retry cap must be set before starting the agent"
        );
        let path = self.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        config["__debug__"]["identity"]["backoff_max_secs"] = json!(secs);
        std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
        Ok(())
    }

    /// Removes the renewal schedule override, so the agent renews at its scheduled time again.
    fn clear_renewal_after_secs(&mut self) -> anyhow::Result<()> {
        ensure!(
            self.child.is_none(),
            "the renewal schedule must be set before starting the agent"
        );
        let path = self.path().join("agent.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        config["__debug__"]["identity"]
            .as_object_mut()
            .context("agent configuration has no identity debug settings")?
            .remove("renewal_after_secs");
        std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
        Ok(())
    }

    fn key_file_path(&self, name: &str) -> PathBuf {
        self.path().join("identity").join("keys").join(format!("{name}.p8"))
    }

    fn in_progress(&self) -> anyhow::Result<Option<Value>> {
        self.in_progress_for(self.tokens.last().expect("pending token is tracked"))
    }

    fn in_progress_for(&self, token: &str) -> anyhow::Result<Option<Value>> {
        let path = self.in_progress_path_for(token);
        if !path.exists() {
            return Ok(None);
        }
        let record: Value = serde_json::from_slice(&std::fs::read(path)?).context("read pending in-progress record")?;
        ensure!(record["version"] == 1, "in-progress enrollment has wrong version");
        ensure!(
            record["token_sha256"] == token_file_id(token),
            "in-progress record does not belong to its pending token"
        );
        validate_key_name(&self.ctx.key_name_prefix, field(&record, "key_name")?)?;
        Ok(Some(record))
    }

    fn state(&self, authority_id: &str) -> anyhow::Result<Value> {
        serde_json::from_slice(&std::fs::read(self.identity_path(authority_id))?).context("read stored identity")
    }

    fn has_stored_identity(&self) -> anyhow::Result<bool> {
        let authorities = self.path().join("identity").join("authorities");
        if !authorities.exists() {
            return Ok(false);
        }
        for entry in std::fs::read_dir(authorities)? {
            if entry?.path().join("identity.json").exists() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn add_token(&mut self, token: &str) {
        self.tokens.push(token.to_owned());
    }

    fn observe_agent_metadata(&self, record: &IdentityRecord) -> anyhow::Result<()> {
        validate_agent_metadata(
            &serde_json::to_value(&record.metadata)?,
            self.ctx.agent_version.as_deref(),
        )
    }

    /// The identity's full management API record, after checking the agent metadata it reports.
    async fn identity_record(&mut self, target: &Target, identity_id: &str) -> anyhow::Result<IdentityRecord> {
        let record = target.management().identity(identity_id).await?;
        self.observe_agent_metadata(&record)?;
        Ok(record)
    }

    /// Like [`Self::identity_record`], but `None` once the identity no longer exists.
    async fn find_identity_record(
        &mut self,
        target: &Target,
        identity_id: &str,
    ) -> anyhow::Result<Option<IdentityRecord>> {
        let record = target.management().find_identity(identity_id).await?;
        if let Some(record) = &record {
            self.observe_agent_metadata(record)?;
        }
        Ok(record)
    }

    fn write_pending(&mut self, token: &str) -> anyhow::Result<()> {
        self.add_token(token);
        let path = self.pending_path();
        std::fs::create_dir_all(path.parent().context("pending parent")?)?;
        let contents = serde_json::to_vec(&json!({ "version": 1, "token": token }))?;
        #[cfg(windows)]
        {
            crate::windows::write_pending(&path, &contents)?;
            crate::windows::pending_acl_is_protected(&path)?;
        }
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&contents)?;
        }
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        ensure!(self.child.is_none(), "agent is already running");
        let stdout = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path().join("agent-stdout.log"))?;
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path().join("agent-stderr.log"))?;
        let mut command = Command::new(&self.ctx.agent_bin);
        command
            .arg("run")
            .env("DAGENT_CONFIG_PATH", self.path())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.as_std_mut().process_group(0);
        }
        let process = command.spawn().context("spawn devolutions-agent run")?;
        #[cfg(windows)]
        let mut process = process;
        #[cfg(windows)]
        {
            let pid = process.id().context("agent has no process ID")?;
            match crate::windows::AgentJob::attach(pid) {
                Ok(job) => self.job = Some(job),
                Err(error) => {
                    let _ = process.kill().await;
                    let _ = process.wait().await;
                    return Err(error.context("attach agent to kill-on-close job"));
                }
            }
        }
        #[cfg(unix)]
        {
            self.process_group = Some(i32::try_from(process.id().context("agent has no process ID")?)?);
        }
        self.child = Some(process);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        self.kill_process_tree();
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill().await.context("stop agent")?;
            }
            let _ = child.wait().await;
        }
        Ok(())
    }

    fn kill_process_tree(&mut self) {
        #[cfg(windows)]
        drop(self.job.take());
        #[cfg(unix)]
        if let Some(group) = self.process_group.take() {
            // SAFETY: The agent was spawned as the leader of this new process group.
            let _ = unsafe { libc::kill(-group, libc::SIGKILL) };
        }
    }

    fn check_running(&mut self) -> anyhow::Result<()> {
        if let Some(child) = self.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            anyhow::bail!("agent exited before observing identity state ({status})");
        }
        Ok(())
    }

    async fn enrolled(&mut self, target: &Target, token: &Token) -> anyhow::Result<(String, Value)> {
        let start = Instant::now();
        loop {
            let listing = target
                .management()
                .identities(&IdentityQuery::enrolled_with(token).full())
                .await?;
            if let [record] = listing.items.as_slice() {
                let id = record.id.clone();
                let identity_dir = self.path().join("identity").join("authorities");
                if identity_dir.exists() {
                    for path in std::fs::read_dir(identity_dir)? {
                        let authority = path?;
                        let json_path = authority.path().join("identity.json");
                        if json_path.exists() {
                            let state: Value = serde_json::from_slice(&std::fs::read(json_path)?)?;
                            if state["identity_id"] == id && !self.pending_path_for(&token.text).exists() {
                                ensure!(
                                    key_exists(self, key_name(&state, "current")?)?,
                                    "settled enrollment has no current identity key"
                                );
                                self.observe_agent_metadata(record)?;
                                if let Some(known) = target.authority_id {
                                    ensure!(
                                        state["authority_id"] == known.to_string(),
                                        "agent stored an unexpected authority ID"
                                    );
                                }
                                return Ok((id, state));
                            }
                        }
                    }
                }
            }
            self.check_running()?;
            ensure!(
                start.elapsed() < WAIT,
                "agent did not enroll and persist an identity within 20 seconds"
            );
            tokio::time::sleep(POLL).await;
        }
    }

    async fn until_identity<F>(
        &mut self,
        target: &Target,
        identity_id: &str,
        what: &str,
        check: F,
    ) -> anyhow::Result<IdentityRecord>
    where
        F: Fn(&IdentityRecord) -> bool,
    {
        let start = Instant::now();
        loop {
            if let Some(record) = self.find_identity_record(target, identity_id).await?
                && check(&record)
            {
                return Ok(record);
            }
            self.check_running()?;
            ensure!(start.elapsed() < WAIT, "agent did not reach {what} within 20 seconds");
            tokio::time::sleep(POLL).await;
        }
    }

    async fn until_pending_deleted(
        &mut self,
        target: &Target,
        pending: &str,
        attempted: &Token,
        expected_identities: u64,
        expected_uses: u64,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        loop {
            ensure!(
                target.management().identity_count(attempted).await? == expected_identities,
                "permanently invalid pending token changed its identity count"
            );
            ensure!(
                target.management().token(&attempted.id).await?.used_count == expected_uses,
                "permanently invalid pending token consumed a use"
            );
            #[cfg(windows)]
            let machine_keys_gone = crate::windows::machine_keys_with_prefix(&self.ctx.key_name_prefix)?.is_empty();
            #[cfg(not(windows))]
            let machine_keys_gone = true;
            if !self.pending_path_for(pending).exists()
                && !self.in_progress_path_for(pending).exists()
                && self.rejection_path_for(pending).exists()
                && !self.has_stored_identity()?
                && self.file_keys_with_prefix()?.is_empty()
                && machine_keys_gone
            {
                let marker: Value = serde_json::from_slice(&std::fs::read(self.rejection_path_for(pending))?)?;
                ensure!(
                    marker["version"] == 1 && marker["token_sha256"] == token_file_id(pending),
                    "rejection marker has an invalid version or full-token hex hash"
                );
                time::OffsetDateTime::parse(field(&marker, "at")?, &Rfc3339)?;
                return Ok(());
            }
            self.check_running()?;
            ensure!(
                start.elapsed() < WAIT,
                "agent kept a permanently invalid pending token, in-progress record, key or identity"
            );
            tokio::time::sleep(POLL).await;
        }
    }

    async fn until_rejected(
        &mut self,
        target: &Target,
        authority_id: &str,
        identity_id: &str,
        error: &str,
    ) -> anyhow::Result<Value> {
        let start = Instant::now();
        loop {
            let _ = self.find_identity_record(target, identity_id).await?;
            let state = self.state(authority_id)?;
            if state["rejected"]["code"] == error {
                return Ok(state);
            }
            self.check_running()?;
            ensure!(
                start.elapsed() < WAIT,
                "agent did not persist rejected identity {error}"
            );
            tokio::time::sleep(POLL).await;
        }
    }

    async fn until_state<F>(
        &mut self,
        target: &Target,
        authority_id: &str,
        identity_id: &str,
        what: &str,
        check: F,
    ) -> anyhow::Result<Value>
    where
        F: Fn(&Value) -> bool,
    {
        let start = Instant::now();
        loop {
            let _ = self.find_identity_record(target, identity_id).await?;
            if let Ok(state) = self.state(authority_id)
                && check(&state)
            {
                return Ok(state);
            }
            self.check_running()?;
            ensure!(start.elapsed() < WAIT, "agent did not persist {what} within 20 seconds");
            tokio::time::sleep(POLL).await;
        }
    }

    /// Waits until `done` holds for the agent's files, which the agent may still be changing after the authority answered.
    async fn until_files(&mut self, what: &str, done: impl Fn() -> bool) -> anyhow::Result<()> {
        let start = Instant::now();
        while !done() {
            self.check_running()?;
            ensure!(
                start.elapsed() < WAIT,
                "agent did not complete {what} within 20 seconds"
            );
            tokio::time::sleep(POLL).await;
        }
        Ok(())
    }

    /// Waits until the agent has deleted each token's pending file and in-progress record.
    ///
    /// On success the agent deletes both ([agent intent], "Pending-enrollment files"), but nothing orders their deletion before it stores the identity.
    ///
    /// [agent intent]: ../../agent-identity/INTENT.md#pending-enrollment-files
    async fn until_pending_consumed(&mut self, tokens: &[&Token]) -> anyhow::Result<()> {
        let paths = tokens
            .iter()
            .flat_map(|token| {
                [
                    self.pending_path_for(&token.text),
                    self.in_progress_path_for(&token.text),
                ]
            })
            .collect::<Vec<_>>();
        self.until_files("the deletion of the pending files and in-progress records", || {
            paths.iter().all(|path| !path.exists())
        })
        .await
    }

    async fn finish(&mut self) -> anyhow::Result<()> {
        let stopped = self.stop().await;
        let layout = self.audit_identity_tree();
        let protected = self.audit_stored_keys();
        let orphaned = self.audit_orphan_keys();
        let tokens = self.audit_tokens();
        let cleaned = self.cleanup_run_keys();
        self.cleaned = cleaned.is_ok();
        stopped?;
        layout?;
        protected?;
        orphaned?;
        tokens?;
        cleaned
    }

    fn audit_identity_tree(&self) -> anyhow::Result<()> {
        let identity = self.path().join("identity");
        let metadata = match std::fs::symlink_metadata(&identity) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            metadata.file_type().is_dir(),
            "identity directory is not a real directory"
        );
        let authorities = identity.join("authorities");
        let keys = identity.join("keys");
        let pending = identity.join("pending");
        let recorded_keys = self.recorded_key_names()?;
        let recorded_files = if self.ctx.key_backend == KeyBackend::File {
            recorded_keys
                .iter()
                .map(|name| self.key_file_path(name))
                .collect::<HashSet<_>>()
        } else {
            HashSet::new()
        };
        let mut documented = recorded_files.clone();
        for token in &self.tokens {
            documented.insert(self.pending_path_for(token));
            documented.insert(self.in_progress_path_for(token));
        }
        if authorities.exists() {
            for entry in std::fs::read_dir(&authorities)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() && canonical_authority_dir(&entry.path()) {
                    documented.insert(entry.path().join("identity.json"));
                }
            }
        }

        let mut directories = vec![identity];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;
                let known_directory = path == pending
                    || path == keys
                    || path == authorities
                    || path.parent() == Some(authorities.as_path()) && canonical_authority_dir(&path);
                if file_type.is_dir() {
                    if !known_directory {
                        eprintln!("WARN unknown identity directory {}", path.display());
                    }
                    directories.push(path);
                    continue;
                }
                ensure!(
                    !known_directory,
                    "documented identity directory {} is not a directory",
                    path.display()
                );
                let recorded = recorded_files.contains(&path);
                ensure!(
                    !path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("p8"))
                        || recorded,
                    "unrecorded private key file {}",
                    path.display()
                );
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy();
                if path.parent() == Some(keys.as_path())
                    && let Some(key) = embedded_key_name(&file_name, &self.ctx.key_name_prefix)
                    && !recorded_keys.contains(key)
                {
                    // A leftover copy of a deleted key survives only until a later operation in its key store (`crates/device-key/INTENT.md`, "Operations"), and the agent's last operation may have left it.
                    eprintln!("WARN leftover copy of deleted key {key}: {}", path.display());
                    continue;
                }
                ensure!(
                    !is_temporary_sibling(&path, &documented, &self.ctx.key_name_prefix),
                    "leftover identity temporary file {}",
                    path.display()
                );
                if file_type.is_file() && !recorded {
                    ensure!(
                        !contains_pkcs8_material(&std::fs::read(&path)?),
                        "unrecorded PKCS#8 private key in {}",
                        path.display()
                    );
                }
                if documented.contains(&path) {
                    ensure!(
                        file_type.is_file(),
                        "documented identity file {} is not a file",
                        path.display()
                    );
                } else {
                    eprintln!("WARN unknown identity file {}", path.display());
                }
            }
        }
        Ok(())
    }

    fn file_keys_with_prefix(&self) -> anyhow::Result<HashSet<String>> {
        let dir = self.path().join("identity").join("keys");
        let mut keys = HashSet::new();
        if dir.exists() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str().and_then(|name| name.strip_suffix(".p8")) else {
                    continue;
                };
                if key_belongs_to_run(name, &self.ctx.key_name_prefix) {
                    ensure!(
                        entry.file_type()?.is_file(),
                        "key file {} is not a regular file",
                        entry.path().display()
                    );
                    keys.insert(name.to_owned());
                }
            }
        }
        Ok(keys)
    }

    fn recorded_key_names(&self) -> anyhow::Result<HashSet<String>> {
        let mut recorded = HashSet::new();
        let authorities = self.path().join("identity").join("authorities");
        if authorities.exists() {
            for authority in std::fs::read_dir(authorities)? {
                let authority = authority?;
                if !authority.file_type()?.is_dir() || !canonical_authority_dir(&authority.path()) {
                    continue;
                }
                let path = authority.path().join("identity.json");
                if path.exists() {
                    let state: Value = serde_json::from_slice(&std::fs::read(&path)?)
                        .with_context(|| format!("read {}", path.display()))?;
                    for slot in ["current", "pending", "previous"] {
                        if let Some(name) = state["keys"][slot]["key_name"].as_str() {
                            validate_key_name(&self.ctx.key_name_prefix, name)?;
                            recorded.insert(name.to_owned());
                        }
                    }
                }
            }
        }
        for token in &self.tokens {
            if let Some(progress) = self.in_progress_for(token)? {
                recorded.insert(field(&progress, "key_name")?.to_owned());
            }
        }
        Ok(recorded)
    }

    fn audit_orphan_keys(&self) -> anyhow::Result<()> {
        let recorded = self.recorded_key_names()?;
        let existing = self.file_keys_with_prefix()?;
        #[cfg(windows)]
        let existing = {
            let mut existing = existing;
            existing.extend(crate::windows::machine_keys_with_prefix(&self.ctx.key_name_prefix)?);
            existing
        };
        let mut orphaned = existing.difference(&recorded).cloned().collect::<Vec<_>>();
        orphaned.sort_unstable();
        ensure!(
            orphaned.is_empty(),
            "unrecorded identity keys with run prefix: {}",
            orphaned.join(", ")
        );
        Ok(())
    }

    fn cleanup_run_keys(&self) -> anyhow::Result<()> {
        let files = self.file_keys_with_prefix();
        #[cfg(windows)]
        let machine_cleanup = crate::windows::cleanup_machine_keys(&self.ctx.key_name_prefix);
        for name in files? {
            std::fs::remove_file(self.key_file_path(&name))
                .with_context(|| format!("delete run-owned file key {name}"))?;
        }
        #[cfg(windows)]
        machine_cleanup?;
        Ok(())
    }

    fn audit_stored_keys(&self) -> anyhow::Result<()> {
        let authorities = self.path().join("identity").join("authorities");
        if !authorities.exists() {
            return Ok(());
        }
        for authority in std::fs::read_dir(authorities)? {
            let authority = authority?;
            if !authority.file_type()?.is_dir() || !canonical_authority_dir(&authority.path()) {
                continue;
            }
            let path = authority.path().join("identity.json");
            if path.exists() {
                let state: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                let id = field(&state, "authority_id")?;
                self.check_key_protection_inner(id, &state, false)?;
            }
        }
        Ok(())
    }

    fn check_key_protection(&self, authority_id: &str, state: &Value) -> anyhow::Result<()> {
        self.check_key_protection_inner(authority_id, state, true)
    }

    fn check_key_protection_inner(
        &self,
        _authority_id: &str,
        state: &Value,
        require_current: bool,
    ) -> anyhow::Result<()> {
        if require_current {
            ensure!(
                state["keys"]["current"]["key_name"].is_string(),
                "settled identity has no current key name"
            );
        }
        for slot in ["current", "pending", "previous"] {
            let Some(name) = state["keys"][slot]["key_name"].as_str() else {
                continue;
            };
            validate_key_name(&self.ctx.key_name_prefix, name)?;
            let expected_spki = state["keys"][slot]["certificate_chain"]
                .as_array()
                .map(|chain| -> anyhow::Result<Vec<u8>> {
                    let leaf = chain
                        .first()
                        .and_then(Value::as_str)
                        .context("stored certificate chain is empty")?;
                    let certificate = Certificate::from_der(&decoded_certificate(leaf)?)?;
                    Ok(certificate.tbs_certificate().subject_public_key_info().to_der()?)
                })
                .transpose()?;
            // A record can briefly name a key that has not been created yet or was already deleted (C15).
            #[cfg(windows)]
            if self.ctx.key_backend == KeyBackend::WindowsSoftwareProvider {
                let exists = crate::windows::machine_key_exists(name)?;
                ensure!(
                    exists || !require_current || slot != "current",
                    "settled current machine key is missing"
                );
                if exists {
                    crate::windows::assert_non_exportable(name)?;
                    crate::windows::assert_machine_key_acl(name)?;
                    if let Some(expected) = &expected_spki {
                        let key = VerifyingKey::from_sec1_bytes(&crate::windows::machine_public_key(name)?)?;
                        ensure!(
                            key.to_public_key_der()?.as_bytes() == expected,
                            "{slot} machine key does not match its leaf SPKI"
                        );
                    }
                }
            }
            #[cfg(any(unix, windows))]
            if self.ctx.key_backend == KeyBackend::File {
                let path = self.key_file_path(name);
                ensure!(
                    path.exists() || !require_current || slot != "current",
                    "settled current file-backed key is missing"
                );
                if path.exists() {
                    #[cfg(unix)]
                    assert_file_key_access(&path)?;
                    if let Some(expected) = &expected_spki {
                        let key = SigningKey::from_pkcs8_der(&std::fs::read(&path)?)?;
                        ensure!(
                            key.verifying_key().to_public_key_der()?.as_bytes() == expected,
                            "{slot} file key does not match its leaf SPKI"
                        );
                    }
                }
            }
            #[cfg(not(any(unix, windows)))]
            let _ = expected_spki;
        }
        Ok(())
    }

    fn audit_tokens(&self) -> anyhow::Result<()> {
        self.audit_tokens_excluding(None)
    }

    fn audit_tokens_excluding(&self, excluded: Option<&Path>) -> anyhow::Result<()> {
        let mut stack = vec![self.path().to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if excluded == Some(path.as_path())
                    || self.tokens.iter().any(|token| path == self.pending_path_for(token))
                {
                    continue;
                }
                let contents = std::fs::read(&path)?;
                for token in &self.tokens {
                    assert_no_token_fragments(&contents, token, &path)?;
                }
            }
        }
        Ok(())
    }
}

impl Drop for AgentCase {
    fn drop(&mut self) {
        self.kill_process_tree();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            for _ in 0..100 {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        if !self.cleaned {
            if let Err(error) = self.audit_identity_tree() {
                eprintln!("agent-case identity tree audit failed: {error:#}");
            }
            if let Err(error) = self.audit_orphan_keys() {
                eprintln!("agent-case orphan audit failed: {error:#}");
            }
            if let Err(error) = self.audit_tokens() {
                eprintln!("agent-case cleanup audit failed: {error:#}");
            }
            if let Err(error) = self.cleanup_run_keys() {
                eprintln!("agent-case key cleanup failed: {error:#}");
            }
        }
    }
}

/// Runs `work` as one agent sub-case, with a new agent data directory that is audited once the agent stops.
///
/// On the mock, every sub-case starts from reset authorities, so it inherits no fault, setting, clock offset, barrier, token or identity from an earlier sub-case of the same test.
/// A sub-case therefore sets only the faults it needs and relies on the reset for every default.
/// DVLS has no reset, so an agent sub-case that runs on it changes no settings.
async fn with_agent<F>(ctx: Context, renewal_after_secs: Option<u64>, run: bool, work: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(&'a mut AgentCase) -> CaseFuture<'a>,
{
    reset_mocks(&ctx).await?;
    let mut case = AgentCase::new(ctx, renewal_after_secs, run).await?;
    let result = work(&mut case).await;
    let audit = case.finish().await;
    match (result, audit) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(audit)) => anyhow::bail!("{error:#}; cleanup/audit: {audit:#}"),
    }
}

/// Resets each mock authority, the second one included, as `__mock__/reset` describes.
async fn reset_mocks(ctx: &Context) -> anyhow::Result<()> {
    if ctx.mock() {
        ctx.target.reset().await?;
        if let Some(second) = &ctx.second {
            second.reset().await?;
        }
    }
    Ok(())
}

async fn new_token(case: &AgentCase, uses: u64) -> anyhow::Result<Token> {
    case.ctx
        .target
        .management()
        .create_token(uses, Duration::from_secs(3600), None)
        .await
}

async fn dropped_enrollment(case: &mut AgentCase, token: &Token) -> anyhow::Result<(String, String)> {
    let target = case.ctx.target.clone();
    let before = count(&target.requests(Some(token)).await?, "enroll")?;
    expect_status(
        &target
            .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": true }))
            .await?,
        200,
    )?;
    target.faults(&json!({ "drop_next_response": "enroll" })).await?;
    case.write_pending(&token.text)?;
    let started = Instant::now();
    let mut unsettled = "agent did not commit a dropped-response enrollment and persist its key within 20 seconds";
    loop {
        let requests = target.requests(Some(token)).await?;
        let attempts = count(&requests, "enroll")?;
        ensure!(
            attempts <= before + 1 + count(&requests, "enroll_retry_503")?,
            "agent retried enrollment successfully while the retry barrier was held"
        );
        let listing = target
            .management()
            .identities(&IdentityQuery::enrolled_with(token))
            .await?;
        let record = target.management().token(&token.id).await?;
        if listing.total_count == 1
            && record.used_count == 1
            && let Some(progress) = case.in_progress()?
        {
            ensure!(
                case.pending_path().exists(),
                "agent deleted the pending file before receiving a response"
            );
            ensure!(
                !case.has_stored_identity()?,
                "agent stored an identity before receiving a response"
            );
            ensure!(
                progress["token_sha256"] == token_file_id(&token.text),
                "in-progress enrollment has the wrong full-token hash"
            );
            let key = field(&progress, "key_name")?.to_owned();
            ensure!(key_exists(case, &key)?, "committed enrollment key is missing");
            // The enrollment can commit between the counter and listing reads, and the mock's README orders neither its counters nor the fault's consumption before the commit, so wait for both.
            let consumed = target.control("faults", &json!({})).await?.body["drop_next_response"].is_null();
            if before < attempts && consumed {
                let id = listing
                    .items
                    .first()
                    .context("listing omitted the identity")?
                    .id
                    .clone();
                return Ok((id, key));
            }
            unsettled = if before < attempts {
                "the dropped enroll response fault was not consumed"
            } else {
                "enrollment committed without a recorded request"
            };
        }
        case.check_running()?;
        ensure!(started.elapsed() < WAIT, "{unsettled}");
        tokio::time::sleep(POLL).await;
    }
}

async fn assert_terminal_stops(
    case: &mut AgentCase,
    target: &Target,
    authority: &str,
    identity_id: Option<&str>,
    error: &str,
    since: time::OffsetDateTime,
) -> anyhow::Result<()> {
    let first = case.state(authority)?;
    let at = field(&first["rejected"], "at")?.to_owned();
    let timestamp = time::OffsetDateTime::parse(&at, &Rfc3339)?;
    ensure!(
        timestamp >= since - time::Duration::seconds(2) && timestamp <= time::OffsetDateTime::now_utc(),
        "rejected.at was not newly set by this terminal error"
    );
    let counters = if case.ctx.mock() {
        Some(target.requests(None).await?)
    } else {
        None
    };
    let before_record = if let Some(id) = identity_id {
        Some(case.identity_record(target, id).await?)
    } else {
        None
    };
    for phase in 0..2 {
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            case.check_running()?;
            let state = case.state(authority)?;
            ensure!(
                state["rejected"]["code"] == error && state["rejected"]["at"] == at,
                "terminal rejection changed during backoff observation"
            );
            if let Some(before) = &counters {
                let after = target.requests(None).await?;
                ensure!(
                    after["renew"] == before["renew"]
                        && after["confirm"] == before["confirm"]
                        && after["check_in"] == before["check_in"]
                        && after["connect"] == before["connect"],
                    "rejected identity sent another signed request during backoff cycles"
                );
            }
            if let Some(id) = identity_id {
                let now = case.identity_record(target, id).await?;
                ensure!(
                    !now.connected
                        && before_record
                            .as_ref()
                            .is_some_and(|before| now.certificates == before.certificates),
                    "rejected identity reconnected or issued another certificate"
                );
            }
        }
        if phase == 0 {
            case.stop().await?;
            case.start().await?;
        }
    }
    Ok(())
}

fn assert_stored_identity(
    case: &AgentCase,
    token: &Token,
    state: &Value,
    record: &IdentityRecord,
) -> anyhow::Result<()> {
    ensure!(state["version"] == 1, "stored identity has wrong version");
    ensure!(
        state["identity_id"] == record.id,
        "stored identity has wrong identity ID"
    );
    let authority = field(state, "authority_id")?;
    ensure!(
        uuid::Uuid::parse_str(authority).is_ok(),
        "stored identity authority is not a UUID"
    );
    if let Some(known) = case.ctx.target.authority_id {
        ensure!(authority == known.to_string(), "stored identity has wrong authority ID");
    }
    ensure!(
        field(state, "base_url")? == case.ctx.target.base_url,
        "stored identity has wrong base URL"
    );
    let config = state["config"].as_object().context("stored identity config missing")?;
    ensure!(
        config.get("version") == Some(&json!(1)),
        "stored identity has wrong config version"
    );
    ensure!(
        config.get("revision").and_then(Value::as_u64).is_some(),
        "stored identity lacks config.revision"
    );
    if case.ctx.channel_available {
        let channel_url = field(&state["config"], "agent_channel_url")?;
        ensure!(
            reqwest::Url::parse(channel_url)?.scheme() == "https",
            "stored identity has an invalid config.agent_channel_url"
        );
        if case.ctx.mock() {
            ensure!(
                channel_url == case.ctx.target.base_url,
                "stored mock config.agent_channel_url does not match enrollment"
            );
        }
    } else {
        ensure!(
            config.get("agent_channel_url").is_none(),
            "unavailable config.agent_channel_url was stored"
        );
    }
    if case.ctx.mock() {
        let mut expected = json!({ "version": 1, "revision": config["revision"] });
        if case.ctx.channel_available {
            expected["agent_channel_url"] = json!(case.ctx.target.base_url);
        }
        ensure!(
            state["config"] == expected,
            "agent did not store the mock's enrollment config exactly"
        );
    }
    ensure!(state.get("rejected").is_none(), "new identity is already rejected");
    ensure!(
        state["token_sha256"] == token_file_id(&token.text),
        "stored identity has wrong full-token hash"
    );
    ensure!(
        record.metadata_value("hostname") == Some(&*case.metadata_hostname),
        "enrollment ignored the configured metadata hostname"
    );
    ensure!(
        state["keys"]["current"]["certificate_chain"]
            .as_array()
            .is_some_and(|chain| !chain.is_empty()),
        "stored identity has an empty current certificate chain"
    );
    ensure!(
        key_exists(case, key_name(state, "current")?)?,
        "enrolled identity's current key is missing"
    );
    let mut names = HashSet::new();
    for slot in ["current", "pending", "previous"] {
        if let Some(name) = state["keys"][slot]["key_name"].as_str() {
            validate_key_name(&case.ctx.key_name_prefix, name)
                .with_context(|| format!("stored {slot} key name is invalid"))?;
            ensure!(names.insert(name), "stored key slots refer to the same key");
            if let Some(chain) = state["keys"][slot]["certificate_chain"].as_array() {
                ensure!(!chain.is_empty(), "{slot} certificate chain is empty");
                ensure!(
                    chain.iter().all(|cert| cert.as_str().is_some()),
                    "{slot} certificate chain contains non-string entries"
                );
            }
        }
    }
    Ok(())
}

fn current_thumbprint(record: &IdentityRecord) -> anyhow::Result<&str> {
    record
        .certificate_with(CertificateStatus::Current)
        .map(|cert| cert.thumbprint.as_str())
        .context("no current certificate")
}

fn assert_check_in_triggers_renewal(requests: &Value, start: usize) -> anyhow::Result<()> {
    let sequence = requests["request_sequence"]
        .as_array()
        .context("mock request sequence missing")?;
    let steps = sequence
        .iter()
        .skip(start)
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let position = |name: &str| steps.iter().position(|step| *step == name);
    let (Some(check_in), Some(renew), Some(confirm)) = (position("check-in"), position("renew"), position("confirm"))
    else {
        anyhow::bail!("channelless request sequence omitted check-in, renew or confirm");
    };
    ensure!(
        check_in < renew && renew < confirm,
        "channelless renewal did not follow check-in → renew → confirm"
    );
    Ok(())
}

fn key_name<'a>(state: &'a Value, slot: &str) -> anyhow::Result<&'a str> {
    field(&state["keys"][slot], "key_name")
}

/// The thumbprint of the leaf stored on a key slot, or `None` while the slot holds no chain.
fn stored_leaf_thumbprint(state: &Value, slot: &str) -> anyhow::Result<Option<String>> {
    state["keys"][slot]["certificate_chain"][0]
        .as_str()
        .map(crate::signer::thumbprint)
        .transpose()
}

fn request_sequence(requests: &Value) -> anyhow::Result<&[Value]> {
    requests["request_sequence"]
        .as_array()
        .map(Vec::as_slice)
        .context("mock request sequence missing")
}

/// The renew and confirm attempts, with the mock's `confirm_204` markers, recorded after `earlier`.
///
/// Check-ins are left out: once a `confirm` has been answered, the contract does not order them against a renewal.
fn renew_and_confirm_steps_since<'a>(requests: &'a Value, earlier: &Value) -> anyhow::Result<Vec<&'a str>> {
    Ok(request_sequence(requests)?
        .iter()
        .skip(request_sequence(earlier)?.len())
        .filter_map(Value::as_str)
        .filter(|step| matches!(*step, "renew" | "confirm" | "confirm_204"))
        .collect())
}

fn renew_keyids(requests: &Value) -> anyhow::Result<&[Value]> {
    requests["renew_attempt_keyids"]
        .as_array()
        .map(Vec::as_slice)
        .context("mock renew signing-key trace missing")
}

/// The thumbprints that signed the renew attempts recorded after `earlier`, in order.
fn renew_keyids_since<'a>(requests: &'a Value, earlier: &Value) -> anyhow::Result<&'a [Value]> {
    Ok(renew_keyids(requests)?
        .get(renew_keyids(earlier)?.len()..)
        .unwrap_or_default())
}

fn key_exists(case: &AgentCase, name: &str) -> anyhow::Result<bool> {
    validate_key_name(&case.ctx.key_name_prefix, name)?;
    #[cfg(windows)]
    if case.ctx.key_backend == KeyBackend::WindowsSoftwareProvider {
        return crate::windows::machine_key_exists(name);
    }
    Ok(case.key_file_path(name).exists())
}

#[cfg(unix)]
fn assert_file_key_access(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    ensure!(mode == 0o600, "{} has mode {mode:o}, expected 0600", path.display());
    // SAFETY: Calling geteuid reads the tester's effective uid, which the spawned agent inherits.
    let agent_uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.uid() == agent_uid,
        "{} is owned by uid {}, expected agent uid {agent_uid}",
        path.display(),
        metadata.uid()
    );
    Ok(())
}

async fn wait_key_deleted(case: &mut AgentCase, name: &str) -> anyhow::Result<()> {
    let started = Instant::now();
    while key_exists(case, name)? {
        case.check_running()?;
        ensure!(
            started.elapsed() < WAIT,
            "old key survived successful identity replacement"
        );
        tokio::time::sleep(POLL).await;
    }
    Ok(())
}

/// Waits until the agent has stored a renewal that replaced `old_key`, holds no pending or previous key, and has deleted `old_key`.
///
/// The authority answers `confirm` before the agent stores its outcome and deletes the old key (`crates/agent-identity/INTENT.md`, "Stored identities"), so stopping the agent right after the `204` could interrupt those writes.
async fn until_renewal_settled(
    case: &mut AgentCase,
    target: &Target,
    authority: &str,
    identity_id: &str,
    old_key: &str,
) -> anyhow::Result<Value> {
    let state = case
        .until_state(target, authority, identity_id, "a settled renewal", |state| {
            key_name(state, "current").is_ok_and(|name| name != old_key)
                && state["keys"].get("pending").is_none()
                && state["keys"].get("previous").is_none()
        })
        .await?;
    wait_key_deleted(case, old_key).await?;
    Ok(state)
}

/// Fails if a file in the key store still holds a copy of the deleted key `name`.
///
/// No leftover copy of a private key survives a later operation in the same key store (`crates/device-key/INTENT.md`, "Operations"), so call this only after one.
fn assert_no_copy_of_deleted_key(case: &AgentCase, name: &str) -> anyhow::Result<()> {
    let keys = case.path().join("identity").join("keys");
    if !keys.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(keys)? {
        let file_name = entry?.file_name();
        ensure!(
            embedded_key_name(&file_name.to_string_lossy(), &case.ctx.key_name_prefix) != Some(name),
            "{} still holds a copy of deleted key {name} after a later key-store operation",
            file_name.to_string_lossy()
        );
    }
    Ok(())
}

async fn assert_new_auth_precedes_old_close(
    target: &Target,
    identity_id: &str,
    old_thumb: &str,
    new_thumb: &str,
) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        let events = target.events(identity_id).await?;
        let confirmed = events.iter().find(|event| {
            event["type"] == "cert_status_changed" && event["cert_thumbprint"] == new_thumb && event["to"] == "current"
        });
        let new_auth = events
            .iter()
            .find(|event| event["type"] == "stream_authenticated" && event["cert_thumbprint"] == new_thumb);
        let old_close = events
            .iter()
            .find(|event| event["type"] == "stream_closed" && event["cert_thumbprint"] == old_thumb);
        if let (Some(confirmed), Some(new_auth), Some(old_close)) = (confirmed, new_auth, old_close) {
            ensure!(
                old_close["status"] == "OK"
                    && count(confirmed, "seq")? < count(new_auth, "seq")?
                    && count(new_auth, "seq")? < count(old_close, "seq")?,
                "confirm, new channel authentication and old stream close occurred out of order"
            );
            return Ok(());
        }
        ensure!(
            started.elapsed() < WAIT,
            "confirm, new authentication or old stream-closed event missing"
        );
        tokio::time::sleep(POLL).await;
    }
}

pub(crate) async fn a_pending_file_enroll_success(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 2).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            ensure!(
                !case.pending_path().exists(),
                "pending file not deleted after enrollment"
            );
            let record = case.identity_record(&target, &id).await?;
            ensure!(record.id == id, "enrolled identity absent from the management API");
            assert_stored_identity(case, &token, &state, &record)?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_bad_pending_files_do_not_reject_valid_tokens(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let probe = new_token(case, 1).await?;
            case.write_pending(&probe.text)?;
            let _ = case.enrolled(&target, &probe).await?;
            let token_a = new_token(case, 1).await?;
            let token_b = new_token(case, 1).await?;
            let token_c = new_token(case, 1).await?;
            case.add_token(&token_a.text);
            for (file_token, contents) in [
                (&token_b.text, json!({ "version": 1, "token": token_a.text })),
                (&token_c.text, json!({ "version": 2, "token": token_c.text })),
            ] {
                case.add_token(file_token);
                let path = case.pending_path_for(file_token);
                std::fs::create_dir_all(path.parent().context("pending directory")?)?;
                // Stage outside the watched directory so only the complete malformed record is observed.
                let staged = case
                    .path()
                    .join(format!("pending-fixture-{}.staged", uuid::Uuid::new_v4()));
                let encoded = serde_json::to_vec(&contents)?;
                #[cfg(windows)]
                crate::windows::write_pending(&staged, &encoded)?;
                #[cfg(unix)]
                {
                    use std::io::Write as _;
                    use std::os::unix::fs::OpenOptionsExt as _;
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&staged)?;
                    file.write_all(&encoded)?;
                }
                std::fs::rename(staged, &path)?;
                #[cfg(windows)]
                crate::windows::pending_acl_is_protected(&path)?;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            case.check_running()?;
            for (name, token) in [("A", &token_a), ("B", &token_b), ("C", &token_c)] {
                ensure!(
                    !case.rejection_path_for(&token.text).exists(),
                    "malformed pending file wrote a rejection marker for valid token {name}"
                );
            }
            case.stop().await?;
            for token in [&token_a, &token_b, &token_c] {
                case.write_pending(&token.text)?;
            }
            case.start().await?;
            let started = Instant::now();
            loop {
                let mut all_enrolled = true;
                for (name, token) in [("A", &token_a), ("B", &token_b), ("C", &token_c)] {
                    ensure!(
                        !case.rejection_path_for(&token.text).exists(),
                        "pending file wrote a rejection marker for valid token {name}"
                    );
                    let identities = target.management().identity_count(token).await?;
                    let uses = target.management().token(&token.id).await?.used_count;
                    ensure!(
                        identities <= 1 && uses <= 1,
                        "correct pending token {name} created more than one identity"
                    );
                    all_enrolled &= identities == 1
                        && uses == 1
                        && !case.pending_path_for(&token.text).exists()
                        && !case.in_progress_path_for(&token.text).exists();
                }
                if all_enrolled {
                    break;
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "correct pending files did not each enroll within 20 seconds"
                );
                tokio::time::sleep(POLL).await;
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_undecryptable_pending_file_does_not_reject_token(ctx: Context) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        return with_agent(ctx, None, false, |case| {
            Box::pin(async move {
                let target = case.ctx.target.clone();
                let token = new_token(case, 1).await?;
                let before = count(&target.requests(None).await?, "enroll_total")?;
                case.write_pending(&token.text)?;
                let pending = case.pending_path_for(&token.text);
                std::fs::write(&pending, b"not a DPAPI blob")?;
                crate::windows::pending_acl_is_protected(&pending)?;
                case.start().await?;
                let started = Instant::now();
                loop {
                    ensure!(
                        count(&target.requests(None).await?, "enroll_total")? == before,
                        "undecryptable pending file sent an enrollment request"
                    );
                    if !pending.exists() {
                        break;
                    }
                    case.check_running()?;
                    ensure!(
                        started.elapsed() < WAIT,
                        "agent did not delete the undecryptable pending file"
                    );
                    tokio::time::sleep(POLL).await;
                }
                ensure!(
                    !case.rejection_path_for(&token.text).exists(),
                    "undecryptable pending file wrote a rejection marker"
                );
                case.write_pending(&token.text)?;
                let _ = case.enrolled(&target, &token).await?;
                ensure!(
                    !case.rejection_path_for(&token.text).exists()
                        && count(&target.requests(None).await?, "enroll_total")? == before + 1,
                    "valid token did not enroll once after an undecryptable pending file"
                );
                Ok(())
            })
        })
        .await;
    }
    #[cfg(not(windows))]
    {
        let _ = ctx;
        Err(crate::NotApplicable("DPAPI pending files require Windows").into())
    }
}

pub(crate) async fn a_untrusted_tls_server_keeps_pending_token(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, false, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let second = case.ctx.second.as_ref().context("second mock authority required")?;
            let root = second.ca_path.as_ref().context("second mock TLS CA required")?;
            let path = case.path().join("agent.json");
            let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            config["__debug__"]["identity"]["extra_trusted_root"] = json!(root);
            std::fs::write(path, serde_json::to_vec_pretty(&config)?)?;
            let token = new_token(case, 1).await?;
            let before = count(&target.requests(None).await?, "enroll_total")?;
            case.start().await?;
            case.write_pending(&token.text)?;
            let started = Instant::now();
            loop {
                if case.in_progress_for(&token.text)?.is_some() {
                    break;
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not process the pending token for TLS validation"
                );
                tokio::time::sleep(POLL).await;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            case.check_running()?;
            ensure!(
                count(&target.requests(None).await?, "enroll_total")? == before
                    && case.pending_path_for(&token.text).exists()
                    && !case.rejection_path_for(&token.text).exists(),
                "untrusted TLS did not preserve the processed pending token"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_enroll_lost_response_retried_across_restart(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            let (id, key) = dropped_enrollment(case, &token).await?;
            case.stop().await?;
            let requests = target.requests(Some(&token)).await?;
            ensure!(
                count(&requests, "enroll")? == 1 + count(&requests, "enroll_retry_503")?,
                "agent received an enrollment retry before it could be restarted"
            );
            ensure!(
                case.in_progress()?
                    .as_ref()
                    .and_then(|record| record["key_name"].as_str())
                    == Some(key.as_str())
                    && case.pending_path().exists(),
                "pending enrollment key was not persisted across agent stop"
            );
            let before_restart = count(&requests, "enroll")?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": false }))
                    .await?,
                200,
            )?;
            case.start().await?;
            let (recovered_id, state) = case.enrolled(&target, &token).await?;
            ensure!(recovered_id == id, "retry created a second identity");
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll")? > before_restart,
                "agent did not retry enrollment after restart"
            );
            ensure!(
                target.management().token(&token.id).await?.used_count == 1,
                "retry consumed a second token use"
            );
            ensure!(
                key_name(&state, "current")? == key,
                "agent did not reuse the in-progress key"
            );
            case.until_pending_consumed(&[&token]).await?;
            let record = case.identity_record(&target, &id).await?;
            assert_stored_identity(case, &token, &state, &record)?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_two_pending_tokens_same_authority_last_wins(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, false, |case| {
        Box::pin(async move {
            // The first token's retry must wait out the second token's enrollment.
            case.set_backoff_max_secs(10)?;
            case.start().await?;
            let target = case.ctx.target.clone();
            let original_token = new_token(case, 1).await?;
            let replacement = new_token(case, 1).await?;
            target
                .faults(&json!({
                    "fail_next_response": {
                        "endpoint": "enroll",
                        "status": 503,
                        "retry_after_secs": 8
                    }
                }))
                .await?;
            case.write_pending(&original_token.text)?;
            let started = Instant::now();
            let original_key = loop {
                if count(&target.requests(Some(&original_token)).await?, "enroll")? >= 1
                    && target.control("faults", &json!({})).await?.body["fail_next_response"].is_null()
                    && let Some(progress) = case.in_progress_for(&original_token.text)?
                {
                    let name = field(&progress, "key_name")?;
                    if key_exists(case, name)? {
                        break name.to_owned();
                    }
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not persist its first pending enrollment during transient backoff"
                );
                tokio::time::sleep(POLL).await;
            };
            ensure!(
                case.pending_path_for(&original_token.text).exists(),
                "first pending file vanished during transient backoff"
            );
            case.write_pending(&replacement.text)?;
            let (replacement_id, replacement_state) = case.enrolled(&target, &replacement).await?;
            let replacement_key = key_name(&replacement_state, "current")?.to_owned();
            ensure!(
                replacement_key != original_key
                    && replacement_state["token_sha256"] == token_file_id(&replacement.text)
                    && case.pending_path_for(&original_token.text).exists()
                    && case.in_progress_for(&original_token.text)?.is_some()
                    && key_exists(case, &original_key)?,
                "second token displaced the first pending file or in-progress key"
            );
            let (original_id, state) = case.enrolled(&target, &original_token).await?;
            ensure!(
                original_id != replacement_id
                    && state["token_sha256"] == token_file_id(&original_token.text)
                    && key_name(&state, "current")? == original_key,
                "last completing token did not become the stored identity for its authority"
            );
            wait_key_deleted(case, &replacement_key).await?;
            case.until_pending_consumed(&[&original_token, &replacement]).await?;
            ensure!(
                target.management().identity_count(&original_token).await? == 1
                    && target.management().identity_count(&replacement).await? == 1
                    && target.management().token(&original_token.id).await?.used_count == 1
                    && target.management().token(&replacement.id).await?.used_count == 1,
                "independent pending tokens were not both consumed"
            );
            let record = case.identity_record(&target, &original_id).await?;
            assert_stored_identity(case, &original_token, &state, &record)?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_two_pending_tokens_different_authorities_progress_independently(
    ctx: Context,
) -> anyhow::Result<()> {
    with_agent(ctx, None, false, |case| {
        Box::pin(async move {
            // The first authority's retry must wait out the second authority's enrollment.
            case.set_backoff_max_secs(10)?;
            case.start().await?;
            let first = case.ctx.target.clone();
            let second = case.ctx.second.clone().context("second authority required")?;
            let first_token = first
                .management()
                .create_token(1, Duration::from_secs(3600), None)
                .await?;
            let second_token = second
                .management()
                .create_token(1, Duration::from_secs(3600), None)
                .await?;
            first
                .faults(&json!({
                    "fail_next_response": {
                        "endpoint": "enroll",
                        "status": 503,
                        "retry_after_secs": 8
                    }
                }))
                .await?;
            case.write_pending(&first_token.text)?;
            let started = Instant::now();
            let first_key = loop {
                if count(&first.requests(Some(&first_token)).await?, "enroll")? >= 1
                    && first.control("faults", &json!({})).await?.body["fail_next_response"].is_null()
                    && let Some(progress) = case.in_progress_for(&first_token.text)?
                {
                    let name = field(&progress, "key_name")?;
                    if key_exists(case, name)? {
                        break name.to_owned();
                    }
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "first authority did not persist a pending key during transient backoff"
                );
                tokio::time::sleep(POLL).await;
            };
            case.write_pending(&second_token.text)?;
            let (second_id, second_state) = case.enrolled(&second, &second_token).await?;
            ensure!(
                case.pending_path_for(&first_token.text).exists()
                    && case.in_progress_for(&first_token.text)?.is_some()
                    && key_exists(case, &first_key)?
                    && key_name(&second_state, "current")? != first_key,
                "first authority backoff blocked or displaced the second pending token"
            );
            let (first_id, first_state) = case.enrolled(&first, &first_token).await?;
            case.until_pending_consumed(&[&first_token, &second_token]).await?;
            let first_authority = field(&first_state, "authority_id")?;
            let second_authority = field(&second_state, "authority_id")?;
            ensure!(
                first_authority != second_authority
                    && first_state["identity_id"] == first_id
                    && second_state["identity_id"] == second_id
                    && case.state(first_authority)?["identity_id"] == first_id
                    && case.state(second_authority)?["identity_id"] == second_id
                    && first.management().token(&first_token.id).await?.used_count == 1
                    && second.management().token(&second_token.id).await?.used_count == 1,
                "independent authorities did not both enroll and retain their keys"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_enroll_revoked_before_response_is_permanent(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            let (id, key) = dropped_enrollment(case, &token).await?;
            target.management().revoke(&id).await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": false }))
                    .await?,
                200,
            )?;
            let started = Instant::now();
            let attempts = loop {
                let requests = target.requests(Some(&token)).await?;
                let attempts = count(&requests, "enroll")?;
                let rejections = count(&requests, "enroll_identity_revoked")?;
                ensure!(
                    rejections <= 1,
                    "agent retried enrollment again after receiving identity_revoked"
                );
                let conditions = [
                    (rejections == 1, "identity_revoked recorded"),
                    (!case.pending_path().exists(), "pending file deleted"),
                    (!case.in_progress_path().exists(), "in-progress record deleted"),
                    (!key_exists(case, &key)?, "enrollment key deleted"),
                    (!case.has_stored_identity()?, "no identity stored"),
                ];
                if conditions.iter().all(|(met, _)| *met) {
                    break attempts;
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not remove the revoked enrollment, in-progress record and key within 20 seconds (unmet: {})",
                    conditions
                        .iter()
                        .filter_map(|(met, name)| (!met).then_some(*name))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                tokio::time::sleep(POLL).await;
            };
            ensure!(attempts >= 2, "agent did not retry the revoked enrollment");
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                case.check_running()?;
                ensure!(
                    count(&target.requests(Some(&token)).await?, "enroll")? == attempts,
                    "agent sent another enrollment request after identity_revoked"
                );
            }
            case.stop().await?;
            case.start().await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            case.check_running()?;
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll")? == attempts
                    && !case.pending_path().exists()
                    && !case.in_progress_path().exists()
                    && !key_exists(case, &key)?
                    && !case.has_stored_identity()?,
                "permanently revoked enrollment resumed after restart"
            );
            ensure!(
                target.management().token(&token.id).await?.used_count == 1
                    && target.management().identity_count(&token).await? == 1,
                "revoked enrollment created another identity or consumed another use"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_pending_file_deleted_on_permanent_error(ctx: Context) -> anyhow::Result<()> {
    for reason in ["token_invalid", "token_exhausted", "token_expired", "token_malformed"] {
        if reason == "token_expired" && !ctx.mock() {
            continue;
        }
        with_agent(ctx.clone(), None, true, |case| {
            Box::pin(async move {
                let target = case.ctx.target.clone();
                let token = new_token(case, 2).await?;
                let (pending, attempted, identities, used) = match reason {
                    "token_invalid" => {
                        let (prefix, _) = token.text.rsplit_once('.').context("token structure")?;
                        (format!("{prefix}.{}", URL_SAFE_NO_PAD.encode([0x49; 32])), token, 0, 0)
                    }
                    "token_exhausted" => {
                        let once = target
                            .management()
                            .create_token(1, Duration::from_secs(3600), None)
                            .await?;
                        let key = crate::signer::KeyPair::generate()?;
                        expect_status(&target.enroll(&once.text, &key, &json!({})).await?, 200)?;
                        (once.text.clone(), once, 1, 1)
                    }
                    "token_expired" => {
                        let expiring = target
                            .management()
                            .create_token(1, Duration::from_secs(2), None)
                            .await?;
                        target.advance(4).await?;
                        (expiring.text.clone(), expiring, 0, 0)
                    }
                    "token_malformed" => {
                        let mut secret = [0u8; 32];
                        rand::rng().fill(&mut secret[..]);
                        (
                            format!("dvaet1.not-base64!.{}", URL_SAFE_NO_PAD.encode(secret)),
                            token,
                            0,
                            0,
                        )
                    }
                    _ => anyhow::bail!("unknown permanent error"),
                };
                let ingress = if reason == "token_malformed" && case.ctx.mock() {
                    Some(count(&target.requests(None).await?, "enroll_total")?)
                } else {
                    None
                };
                case.write_pending(&pending)?;
                case.until_pending_deleted(&target, &pending, &attempted, identities, used)
                    .await?;
                if let Some(before) = ingress {
                    ensure!(
                        count(&target.requests(None).await?, "enroll_total")? == before,
                        "malformed token was sent to the server instead of rejected locally"
                    );
                }
                Ok(())
            })
        })
        .await
        .with_context(|| format!("permanent error {reason}"))?;
    }
    Ok(())
}

pub(crate) async fn a_pending_file_kept_on_transient_error(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx.clone(), None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            drop(listener);
            let (prefix, secret) = token.text.rsplit_once('.').context("token structure")?;
            let (_, bag) = prefix.rsplit_once('.').context("token bag")?;
            let mut route: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(bag)?)?;
            route["u"] = json!(format!("https://127.0.0.1:{port}/mock"));
            let offline = format!(
                "dvaet1.{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&route)?),
                secret
            );
            case.write_pending(&offline)?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            ensure!(
                target.management().identity_count(&token).await? == 0,
                "unreachable enrollment created an identity"
            );
            ensure!(
                case.pending_path().exists(),
                "unreachable enrollment deleted the pending file"
            );
            case.check_running()?;
            Ok(())
        })
    })
    .await?;
    if ctx.mock() {
        with_agent(ctx, None, true, |case| {
            Box::pin(async move {
                let target = case.ctx.target.clone();
                let token = new_token(case, 1).await?;
                let initial = count(&target.requests(Some(&token)).await?, "enroll")?;
                for (index, response) in [
                    json!({ "endpoint": "enroll", "status": 503 }),
                    json!({ "endpoint": "enroll", "status": 400, "error": "invalid_request" }),
                    json!({ "endpoint": "enroll", "status": 429, "retry_after_secs": 3 }),
                    json!({ "endpoint": "enroll", "status": 302 }),
                    json!({ "endpoint": "enroll", "status": 503 }),
                ]
                .into_iter()
                .enumerate()
                {
                    target.faults(&json!({ "fail_next_response": response })).await?;
                    if index == 0 {
                        case.write_pending(&token.text)?;
                    }
                    let start = Instant::now();
                    loop {
                        let attempts = count(&target.requests(Some(&token)).await?, "enroll")?;
                        ensure!(
                            attempts <= initial + index as u64 + 1,
                            "agent retried before the next transient response was configured"
                        );
                        if attempts == initial + index as u64 + 1
                            && target.control("faults", &json!({})).await?.body["fail_next_response"].is_null()
                        {
                            break;
                        }
                        case.check_running()?;
                        ensure!(
                            start.elapsed() < WAIT,
                            "agent did not retry the transient enrollment error"
                        );
                        tokio::time::sleep(POLL).await;
                    }
                    let observed_failure = Instant::now();
                    ensure!(
                        case.pending_path().exists(),
                        "transient HTTP error deleted the pending file"
                    );
                    ensure!(
                        target.management().identity_count(&token).await? == 0
                            && target.management().token(&token.id).await?.used_count == 0,
                        "transient HTTP error created an identity or consumed a token use"
                    );
                    if response["retry_after_secs"] == 3 {
                        // Probe near the two-second cap without racing the next retry.
                        tokio::time::sleep_until((observed_failure + Duration::from_millis(1_700)).into()).await;
                        ensure!(
                            count(&target.requests(Some(&token)).await?, "enroll")? == initial + index as u64 + 1,
                            "agent retried before the capped Retry-After delay"
                        );
                    }
                    if response["status"] == 302 {
                        tokio::time::sleep(POLL).await;
                        ensure!(
                            count(&target.requests(None).await?, "redirect_hits")? == 0,
                            "agent followed the injected redirect"
                        );
                    }
                    case.check_running()?;
                }
                let _ = case.enrolled(&target, &token).await?;
                ensure!(
                    target.management().token(&token.id).await?.used_count == 1,
                    "retry consumed an additional token use"
                );
                ensure!(
                    count(&target.requests(Some(&token)).await?, "enroll")? >= initial + 6,
                    "agent did not survive five transient failures and retry successfully"
                );
                Ok(())
            })
        })
        .await?;
    }
    Ok(())
}

/// Removes the ANSI escape sequences that colour the agent's console log, which it writes even when its output is a file.
#[cfg(unix)]
fn without_ansi_escapes(line: &str) -> String {
    let mut plain = String::with_capacity(line.len());
    let mut characters = line.chars();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            plain.push(character);
            continue;
        }
        // A control sequence ends at its first byte in `@`..=`~` (ECMA-48 §5.4).
        if characters.next() == Some('[') {
            characters
                .by_ref()
                .find(|final_character| ('@'..='~').contains(final_character));
        }
    }
    plain
}

#[cfg(unix)]
fn is_error_level_log_line(line: &str) -> bool {
    let line = without_ansi_escapes(line);
    if let Ok(entry) = serde_json::from_str::<Value>(&line) {
        return entry["level"]
            .as_str()
            .is_some_and(|level| level.eq_ignore_ascii_case("error"));
    }
    let levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
    line.split_whitespace()
        .take(3)
        .map(|field| field.trim_matches(&['[', ']', ':'][..]))
        .find(|field| levels.contains(field))
        == Some("ERROR")
}

pub(crate) async fn a_unavailable_key_backend_stops_identity(ctx: Context) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut ctx = ctx;
        ctx.key_backend = KeyBackend::WindowsSoftwareProvider;
        return with_agent(ctx, None, false, |case| {
            Box::pin(async move {
                let target = case.ctx.target.clone();
                let token = new_token(case, 1).await?;
                let token_record = target.management().token(&token.id).await?;
                let used_before = token_record.used_count;
                ensure!(used_before == 0, "new enrollment token was already used");
                let requests_before = if case.ctx.mock() {
                    Some(count(&target.requests(None).await?, "enroll_total")?)
                } else {
                    None
                };
                case.write_pending(&token.text)?;
                let pending = case.pending_path();
                let pending_contents = std::fs::read(&pending)?;
                case.start().await?;
                let check_unchanged = |case: &mut AgentCase| -> anyhow::Result<()> {
                    case.check_running()?;
                    ensure!(
                        std::fs::read(&pending)? == pending_contents,
                        "unavailable backend changed or deleted the pending file"
                    );
                    ensure!(
                        !case.in_progress_path().exists() && !case.rejection_path_for(&token.text).exists(),
                        "unavailable backend processed the pending token"
                    );
                    ensure!(
                        case.file_keys_with_prefix()?.is_empty() && !case.has_stored_identity()?,
                        "unavailable backend created a key or identity"
                    );
                    Ok(())
                };
                let started = Instant::now();
                loop {
                    check_unchanged(case)?;
                    let mut logged_error = false;
                    for name in ["agent-stdout.log", "agent-stderr.log"] {
                        let contents = std::fs::read_to_string(case.path().join(name))?;
                        logged_error |= contents.lines().any(is_error_level_log_line);
                    }
                    if logged_error {
                        break;
                    }
                    ensure!(
                        started.elapsed() < WAIT,
                        "unavailable backend emitted no error-level log line within 20 seconds"
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                for _ in 0..6 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    check_unchanged(case)?;
                }
                if let Some(before) = requests_before {
                    ensure!(
                        count(&target.requests(None).await?, "enroll_total")? == before,
                        "unavailable backend sent an enroll request"
                    );
                }
                ensure!(
                    target.management().identity_count(&token).await? == 0,
                    "unavailable backend created an identity"
                );
                let record = target.management().token(&token.id).await?;
                ensure!(
                    record.used_count == used_before,
                    "unavailable backend consumed a token use"
                );
                check_unchanged(case)?;
                Ok(())
            })
        })
        .await;
    }
    #[cfg(not(unix))]
    {
        let _ = ctx;
        Err(crate::NotApplicable("Windows software provider is available on Windows").into())
    }
}

async fn wait_for_injected_attempt(
    case: &mut AgentCase,
    target: &Target,
    counter: &str,
    before: u64,
) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        let attempts = count(&target.requests(None).await?, counter)?;
        ensure!(
            attempts <= before + 1,
            "{counter} retried before the injected error was observed"
        );
        if attempts == before + 1 && target.control("faults", &json!({})).await?.body["fail_next_response"].is_null() {
            return Ok(());
        }
        case.check_running()?;
        ensure!(started.elapsed() < WAIT, "{counter} did not receive the injected error");
        tokio::time::sleep(POLL).await;
    }
}

pub(crate) async fn a_renew_transient_failures_retry_without_state_change(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, initial) = case.enrolled(&target, &token).await?;
            let authority = field(&initial, "authority_id")?.to_owned();
            case.until_identity(&target, &id, "working channel for renewal faults", |record| {
                record.connected
            })
            .await?;
            for status in [302, 429, 503] {
                let before = target.requests(None).await?;
                let record_before = case.identity_record(&target, &id).await?;
                let stored_before = case.state(&authority)?;
                let old_thumb = current_thumbprint(&record_before)?.to_owned();
                let old_key = key_name(&stored_before, "current")?.to_owned();
                let attempts = count(&before, "renew")?;
                let mut fault = json!({ "endpoint": "renew", "status": status });
                if status == 429 {
                    fault["retry_after_secs"] = json!(3);
                }
                target.faults(&json!({ "fail_next_response": fault })).await?;
                target.management().request_renewal(&id).await?;
                wait_for_injected_attempt(case, &target, "renew", attempts).await?;
                let failed_at = Instant::now();
                let failed = case.identity_record(&target, &id).await?;
                let stored = case.state(&authority)?;
                ensure!(
                    failed.certificates == record_before.certificates
                        && failed.metadata == record_before.metadata
                        && failed.last_seen_at == record_before.last_seen_at
                        && stored["config"] == stored_before["config"]
                        && key_name(&stored, "current")? == old_key
                        && stored["keys"]["pending"]["certificate_chain"].is_null()
                        && stored.get("rejected").is_none(),
                    "injected renew {status} changed server or committed identity state"
                );
                if status == 429 {
                    // The agent waits for `Retry-After` up to its maximum retry delay (CONTRACT.agent-identity.md §5.4), which `backoff_max_secs: 2` caps, so the retry comes after about two seconds.
                    tokio::time::sleep_until((failed_at + Duration::from_millis(1_500)).into()).await;
                    ensure!(
                        count(&target.requests(None).await?, "renew")? == attempts + 1,
                        "renew retried before the Retry-After delay capped at two seconds"
                    );
                }
                let renewed = case
                    .until_identity(&target, &id, "renew retry confirmed", |record| {
                        current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb) && record.connected
                    })
                    .await?;
                let settled = until_renewal_settled(case, &target, &authority, &id, &old_key).await?;
                ensure!(
                    count(&target.requests(None).await?, "renew")? >= attempts + 2
                        && count(&target.requests(None).await?, "redirect_hits")? == count(&before, "redirect_hits")?
                        && !renewed.renewal_requested
                        && settled.get("rejected").is_none(),
                    "renew {status} was followed as a redirect or not retried to completion"
                );
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_check_in_transient_failures_retry_without_state_change(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, false, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_available": false })).await?;
            let config_path = case.path().join("agent.json");
            let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path)?)?;
            config["__debug__"]["identity"]["check_in_interval_secs"] = json!(60);
            std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
            case.start().await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, initial) = case.enrolled(&target, &token).await?;
            let authority = field(&initial, "authority_id")?.to_owned();
            let started = Instant::now();
            loop {
                if target
                    .events(&id)
                    .await?
                    .iter()
                    .any(|event| event["type"] == "check_in_received")
                {
                    break;
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "initial check-in never completed");
                tokio::time::sleep(POLL).await;
            }
            for status in [302, 429, 503] {
                case.stop().await?;
                let before = target.requests(None).await?;
                let record_before = case.identity_record(&target, &id).await?;
                let stored_before = case.state(&authority)?;
                let completed_before = target
                    .events(&id)
                    .await?
                    .iter()
                    .filter(|event| event["type"] == "check_in_received")
                    .count();
                let hostname = format!("check-in-after-{status}");
                case.set_metadata_hostname(&hostname)?;
                let attempts = count(&before, "check_in")?;
                let mut fault = json!({ "endpoint": "check-in", "status": status });
                if status == 429 {
                    fault["retry_after_secs"] = json!(3);
                }
                target.faults(&json!({ "fail_next_response": fault })).await?;
                case.start().await?;
                wait_for_injected_attempt(case, &target, "check_in", attempts).await?;
                let failed_at = Instant::now();
                let failed = case.identity_record(&target, &id).await?;
                let stored = case.state(&authority)?;
                ensure!(
                    failed.certificates == record_before.certificates
                        && failed.metadata == record_before.metadata
                        && failed.last_seen_at == record_before.last_seen_at
                        && stored["config"] == stored_before["config"]
                        && stored["keys"] == stored_before["keys"]
                        && stored.get("rejected").is_none(),
                    "injected check-in {status} changed server or committed identity state"
                );
                if status == 429 {
                    // The agent waits for `Retry-After` up to its maximum retry delay (CONTRACT.agent-identity.md §5.4), which `backoff_max_secs: 2` caps, so the retry comes after about two seconds.
                    tokio::time::sleep_until((failed_at + Duration::from_millis(1_500)).into()).await;
                    ensure!(
                        count(&target.requests(None).await?, "check_in")? == attempts + 1,
                        "check-in retried before the Retry-After delay capped at two seconds"
                    );
                }
                let retry_started = Instant::now();
                loop {
                    let current = count(&target.requests(None).await?, "check_in")?;
                    ensure!(
                        current <= attempts + 2,
                        "check-in sent extra requests before the retry was observed"
                    );
                    if current == attempts + 2
                        && case.identity_record(&target, &id).await?.metadata_value("hostname") == Some(&*hostname)
                    {
                        break;
                    }
                    case.check_running()?;
                    ensure!(
                        retry_started.elapsed() < Duration::from_secs(10),
                        "check-in {status} was not retried before the next 60-second periodic send"
                    );
                    tokio::time::sleep(POLL).await;
                }
                ensure!(
                    target
                        .events(&id)
                        .await?
                        .iter()
                        .filter(|event| event["type"] == "check_in_received")
                        .count()
                        == completed_before + 1
                        && count(&target.requests(None).await?, "redirect_hits")? == count(&before, "redirect_hits")?,
                    "check-in {status} was followed as a redirect or not retried to completion"
                );
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_token_never_logged(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let _ = case.enrolled(&target, &token).await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_same_token_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 2).await?;
            case.write_pending(&token.text)?;
            let (id, old) = case.enrolled(&target, &token).await?;
            ensure!(!case.pending_path().exists(), "initial pending file still exists");
            let uses = target.management().token(&token.id).await?.used_count;
            let attempts = if case.ctx.mock() {
                Some(count(&target.requests(Some(&token)).await?, "enroll")?)
            } else {
                None
            };
            case.write_pending(&token.text)?;
            let start = Instant::now();
            while case.pending_path().exists() {
                ensure!(
                    target.management().identity_count(&token).await? == 1,
                    "duplicate token enrolled another identity"
                );
                case.check_running()?;
                ensure!(start.elapsed() < WAIT, "same token pending file was not discarded");
                tokio::time::sleep(POLL).await;
            }
            ensure!(
                case.state(field(&old, "authority_id")?)?["identity_id"] == id,
                "same token replaced identity"
            );
            ensure!(
                target.management().token(&token.id).await?.used_count == uses,
                "same token used again"
            );
            let final_identities = target
                .management()
                .identities(&IdentityQuery::enrolled_with(&token))
                .await?;
            ensure!(
                final_identities.total_count == 1 && final_identities.items.first().is_some_and(|row| row.id == id),
                "same token created a new identity"
            );
            if let Some(attempts) = attempts {
                ensure!(
                    count(&target.requests(Some(&token)).await?, "enroll")? == attempts,
                    "same token caused another enrollment request"
                );
            }
            Ok(())
        })
    })
    .await
}

#[derive(Clone, Copy)]
enum PermanentTokenOutcome {
    Exhausted,
    Invalid,
    Malformed,
}

async fn same_token_after_permanent_outcome(ctx: Context, outcome: PermanentTokenOutcome) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            let (pending, expected_identities, expected_uses) = match outcome {
                PermanentTokenOutcome::Exhausted => {
                    let key = crate::signer::KeyPair::generate()?;
                    expect_status(&target.enroll(&token.text, &key, &json!({})).await?, 200)?;
                    (token.text.clone(), 1, 1)
                }
                PermanentTokenOutcome::Invalid => {
                    let (prefix, secret) = token.text.rsplit_once('.').context("token structure")?;
                    let mut bytes = URL_SAFE_NO_PAD.decode(secret)?;
                    bytes[0] ^= 1;
                    (format!("{prefix}.{}", URL_SAFE_NO_PAD.encode(bytes)), 0, 0)
                }
                PermanentTokenOutcome::Malformed => {
                    let (_, secret) = token.text.rsplit_once('.').context("token structure")?;
                    (format!("dvaet1.not-base64!.{secret}"), 0, 0)
                }
            };
            let before = if case.ctx.mock() {
                Some(count(&target.requests(None).await?, "enroll_total")?)
            } else {
                None
            };
            case.write_pending(&pending)?;
            case.until_pending_deleted(&target, &pending, &token, expected_identities, expected_uses)
                .await?;
            if let Some(before) = before {
                let expected = before + u64::from(!matches!(outcome, PermanentTokenOutcome::Malformed));
                ensure!(
                    count(&target.requests(None).await?, "enroll_total")? == expected,
                    "initial permanent outcome sent the wrong number of enrollment requests"
                );
            }
            assert_same_token_replay_dropped(case, &target, &token, &pending, expected_identities, expected_uses).await
        })
    })
    .await
}

async fn assert_same_token_replay_dropped(
    case: &mut AgentCase,
    target: &Target,
    token: &Token,
    pending: &str,
    expected_identities: u64,
    expected_uses: u64,
) -> anyhow::Result<()> {
    let attempts = if case.ctx.mock() {
        Some(count(&target.requests(None).await?, "enroll_total")?)
    } else {
        None
    };
    case.write_pending(pending)?;
    let started = Instant::now();
    loop {
        assert_replay_unchanged(target, token, expected_identities, expected_uses, attempts).await?;
        if !case.pending_path_for(pending).exists() && !case.in_progress_path_for(pending).exists() {
            break;
        }
        case.check_running()?;
        ensure!(
            started.elapsed() < WAIT,
            "agent did not discard the rewritten permanently failed token within 20 seconds"
        );
        tokio::time::sleep(POLL).await;
    }
    let settled = Instant::now();
    while settled.elapsed() < Duration::from_secs(3) {
        assert_replay_unchanged(target, token, expected_identities, expected_uses, attempts).await?;
        ensure!(
            !case.pending_path_for(pending).exists() && !case.in_progress_path_for(pending).exists(),
            "rewritten permanently failed token reappeared"
        );
        case.check_running()?;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

async fn assert_replay_unchanged(
    target: &Target,
    token: &Token,
    expected_identities: u64,
    expected_uses: u64,
    attempts: Option<u64>,
) -> anyhow::Result<()> {
    ensure!(
        target.management().identity_count(token).await? == expected_identities,
        "rewritten permanently failed token created another identity"
    );
    let record = target.management().token(&token.id).await?;
    ensure!(
        record.used_count == expected_uses,
        "rewritten permanently failed token consumed another use"
    );
    if let Some(attempts) = attempts {
        ensure!(
            count(&target.requests(None).await?, "enroll_total")? == attempts,
            "rewritten permanently failed token sent an enrollment request"
        );
    }
    Ok(())
}

pub(crate) async fn a_same_token_after_token_exhausted_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    same_token_after_permanent_outcome(ctx, PermanentTokenOutcome::Exhausted).await
}

pub(crate) async fn a_same_token_after_token_invalid_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    same_token_after_permanent_outcome(ctx, PermanentTokenOutcome::Invalid).await
}

pub(crate) async fn a_same_token_after_token_malformed_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    same_token_after_permanent_outcome(ctx, PermanentTokenOutcome::Malformed).await
}

pub(crate) async fn a_same_token_after_identity_revoked_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            let (id, key) = dropped_enrollment(case, &token).await?;
            target.management().revoke(&id).await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": false }))
                    .await?,
                200,
            )?;
            case.until_pending_deleted(&target, &token.text, &token, 1, 1).await?;
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll_identity_revoked")? == 1
                    && !key_exists(case, &key)?
                    && target.management().identity(&id).await?.status == IdentityStatus::Revoked,
                "lost response was not followed by a permanent identity_revoked outcome"
            );
            assert_same_token_replay_dropped(case, &target, &token, &token.text, 1, 1).await
        })
    })
    .await
}

pub(crate) async fn a_same_token_rejected_identity_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 3).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            case.until_identity(&target, &id, "connected", |record| record.connected)
                .await?;
            target.management().revoke(&id).await?;
            case.until_rejected(&target, &authority, &id, "identity_revoked")
                .await?;
            let attempts = if case.ctx.mock() {
                Some(count(&target.requests(Some(&token)).await?, "enroll")?)
            } else {
                None
            };
            case.write_pending(&token.text)?;
            let start = Instant::now();
            while case.pending_path().exists() {
                let _ = target.management().identity_count(&token).await?;
                case.check_running()?;
                ensure!(start.elapsed() < WAIT, "same token was not discarded after rejection");
                tokio::time::sleep(POLL).await;
            }
            ensure!(
                target.management().token(&token.id).await?.used_count == 1,
                "rejected identity consumed another token use"
            );
            let final_identities = target
                .management()
                .identities(&IdentityQuery::enrolled_with(&token))
                .await?;
            ensure!(
                final_identities.total_count == 1 && final_identities.items.first().is_some_and(|row| row.id == id),
                "same token created a new identity after rejection"
            );
            ensure!(
                case.state(&authority)?["rejected"]["code"] == "identity_revoked",
                "rejection was cleared"
            );
            if let Some(attempts) = attempts {
                ensure!(
                    count(&target.requests(Some(&token)).await?, "enroll")? == attempts,
                    "rejected identity sent another enrollment request"
                );
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_different_token_replaces_identity(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let first_token = new_token(case, 1).await?;
            case.write_pending(&first_token.text)?;
            let (first_id, first_state) = case.enrolled(&target, &first_token).await?;
            let authority = field(&first_state, "authority_id")?.to_owned();
            let original_key = key_name(&first_state, "current")?.to_owned();
            let next_token = new_token(case, 1).await?;
            case.write_pending(&next_token.text)?;
            let (next_id, next_state) = case.enrolled(&target, &next_token).await?;
            ensure!(first_id != next_id, "different token did not replace the identity");
            ensure!(
                next_state["authority_id"] == authority,
                "same mock changed authority on re-enrollment"
            );
            ensure!(
                next_state["token_sha256"] == token_file_id(&next_token.text)
                    && next_state["token_sha256"] != first_state["token_sha256"],
                "replacement did not store the new token hash"
            );
            wait_key_deleted(case, &original_key).await?;
            ensure!(
                case.state(&authority)?["identity_id"] == next_id,
                "stored identity not replaced"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_rejected_identity_replaced(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let original_token = new_token(case, 1).await?;
            case.write_pending(&original_token.text)?;
            let (old_id, old_state) = case.enrolled(&target, &original_token).await?;
            let authority = field(&old_state, "authority_id")?.to_owned();
            let old_key = key_name(&old_state, "current")?.to_owned();
            case.until_identity(&target, &old_id, "old connection", |record| record.connected)
                .await?;
            target.management().revoke(&old_id).await?;
            case.until_rejected(&target, &authority, &old_id, "identity_revoked")
                .await?;
            let replacement = new_token(case, 1).await?;
            case.write_pending(&replacement.text)?;
            let (new_id, new_state) = case.enrolled(&target, &replacement).await?;
            ensure!(new_id != old_id, "new token reused the revoked identity ID");
            ensure!(
                new_state["authority_id"] == authority,
                "replacement changed authorities"
            );
            ensure!(
                new_state.get("rejected").is_none(),
                "new token retained the old rejection"
            );
            ensure!(
                new_state["token_sha256"] == token_file_id(&replacement.text)
                    && new_state["token_sha256"] != old_state["token_sha256"],
                "rejected identity replacement did not store the new token hash"
            );
            wait_key_deleted(case, &old_key).await?;
            case.until_identity(&target, &new_id, "replacement connection", |record| record.connected)
                .await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_cli_identity_enroll_writes_pending_file(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, false, |case| {
        Box::pin(async move {
            let token = new_token(case, 1).await?;
            case.add_token(&token.text);
            let output = Command::new(&case.ctx.agent_bin)
                .args(["identity", "enroll", &token.text])
                .env("DAGENT_CONFIG_PATH", case.path())
                .kill_on_drop(true)
                .output()
                .await
                .context("run identity enroll CLI")?;
            std::fs::write(case.path().join("cli-stdout.log"), &output.stdout)?;
            std::fs::write(case.path().join("cli-stderr.log"), &output.stderr)?;
            ensure!(output.status.success(), "identity enroll CLI rejected a valid token");
            ensure!(
                case.pending_path().exists(),
                "identity enroll CLI did not write the pending file"
            );
            #[cfg(windows)]
            crate::windows::pending_acl_is_protected(&case.pending_path())?;
            ensure!(
                String::from_utf8_lossy(&output.stdout).contains(&case.pending_path().to_string_lossy().to_string()),
                "identity enroll CLI did not print the pending file path"
            );
            #[cfg(windows)]
            let data = {
                let encrypted = std::fs::read(case.pending_path())?;
                crate::windows::assert_machine_scope(&encrypted)?;
                crate::windows::unprotect_pending(&encrypted)?
            };
            #[cfg(unix)]
            let data = std::fs::read(case.pending_path())?;
            let contents: Value = serde_json::from_slice(&data)?;
            ensure!(
                contents["version"] == 1 && contents["token"] == token.text,
                "CLI pending file malformed"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(case.pending_path())?.permissions().mode() & 0o777;
                ensure!(mode == 0o600, "CLI pending file is not mode 0600");
            }
            std::fs::remove_file(case.pending_path())?;
            let (prefix, secret) = token.text.rsplit_once('.').context("token secret")?;
            let bag = prefix.rsplit_once('.').context("token bag")?.1;
            let invalid = [
                ("wrong prefix", format!("dvaet2.{bag}.{secret}")),
                ("missing secret", format!("dvaet1.{bag}")),
                ("invalid bag", format!("dvaet1.!invalid.{secret}")),
                (
                    "invalid JSON bag",
                    format!("dvaet1.{}.{secret}", URL_SAFE_NO_PAD.encode("not-json")),
                ),
                (
                    "bag without URL",
                    format!("dvaet1.{}.{secret}", URL_SAFE_NO_PAD.encode("{}")),
                ),
                (
                    "HTTP URL",
                    format!(
                        "dvaet1.{}.{secret}",
                        URL_SAFE_NO_PAD.encode(r#"{"u":"http://localhost/mock"}"#)
                    ),
                ),
                (
                    "URL with query",
                    format!(
                        "dvaet1.{}.{secret}",
                        URL_SAFE_NO_PAD.encode(r#"{"u":"https://localhost/mock?q=1"}"#)
                    ),
                ),
                (
                    "URL with fragment",
                    format!(
                        "dvaet1.{}.{secret}",
                        URL_SAFE_NO_PAD.encode(r##"{"u":"https://localhost/mock#frag"}"##)
                    ),
                ),
                ("short secret", format!("dvaet1.{bag}.{}", &secret[..secret.len() - 1])),
                ("padded secret", format!("dvaet1.{bag}.{secret}=")),
                (
                    "overlong token",
                    format!(
                        "dvaet1.{}.{secret}",
                        URL_SAFE_NO_PAD.encode(serde_json::to_vec(
                            &json!({ "u": format!("https://localhost/{}", "a".repeat(5000)) })
                        )?)
                    ),
                ),
            ];
            for (reason, candidate) in invalid {
                let result = tokio::time::timeout(
                    Duration::from_secs(10),
                    Command::new(&case.ctx.agent_bin)
                        .args(["identity", "enroll", &candidate])
                        .env("DAGENT_CONFIG_PATH", case.path())
                        .kill_on_drop(true)
                        .output(),
                )
                .await
                .with_context(|| format!("identity enroll CLI hung for {reason}"))??;
                use std::io::Write as _;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(case.path().join("cli-stdout.log"))?
                    .write_all(&result.stdout)?;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(case.path().join("cli-stderr.log"))?
                    .write_all(&result.stderr)?;
                ensure!(!result.status.success(), "identity enroll CLI accepted {reason}");
                ensure!(
                    !case.pending_path_for(&candidate).exists() && !case.in_progress_path_for(&candidate).exists(),
                    "{reason} wrote pending enrollment state"
                );
            }
            Ok(())
        })
    })
    .await
}

async fn enroll_cli_from_stdin(case: &AgentCase, input: &[u8]) -> anyhow::Result<std::process::Output> {
    let output = tokio::time::timeout(Duration::from_secs(10), async {
        let mut child = Command::new(&case.ctx.agent_bin)
            .args(["identity", "enroll", "-"])
            .env("DAGENT_CONFIG_PATH", case.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("start identity enroll CLI with stdin")?;
        let mut stdin = child.stdin.take().context("identity enroll CLI has no stdin")?;
        if let Err(error) = stdin.write_all(input).await {
            ensure!(
                error.kind() == std::io::ErrorKind::BrokenPipe,
                "write token to identity enroll CLI stdin: {error}"
            );
        }
        drop(stdin);
        child.wait_with_output().await.context("wait for identity enroll CLI")
    })
    .await
    .context("identity enroll CLI with stdin timed out")??;
    use std::io::Write as _;
    for (name, contents) in [("cli-stdout.log", &output.stdout), ("cli-stderr.log", &output.stderr)] {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(case.path().join(name))?
            .write_all(contents)?;
    }
    Ok(output)
}

fn assert_no_pending_files(case: &AgentCase) -> anyhow::Result<()> {
    let dir = case.path().join("identity").join("pending");
    if dir.exists() {
        ensure!(
            std::fs::read_dir(dir)?.next().is_none(),
            "identity enroll CLI created pending or in-progress state for invalid stdin"
        );
    }
    Ok(())
}

pub(crate) async fn a_cli_identity_enroll_stdin(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, false, |case| {
        Box::pin(async move {
            let token = new_token(case, 1).await?;
            case.add_token(&token.text);
            let output = enroll_cli_from_stdin(case, format!(" \t{} \r\n", token.text).as_bytes()).await?;
            ensure!(
                output.status.success(),
                "identity enroll CLI rejected a valid token on stdin"
            );
            let pending = case.pending_path();
            ensure!(
                pending.exists(),
                "identity enroll CLI did not write stdin token's pending file"
            );
            ensure!(
                String::from_utf8_lossy(&output.stdout).contains(&pending.to_string_lossy().to_string()),
                "identity enroll CLI did not print the stdin token's pending path"
            );
            #[cfg(windows)]
            crate::windows::pending_acl_is_protected(&pending)?;
            #[cfg(windows)]
            let data = crate::windows::unprotect_pending(&std::fs::read(&pending)?)?;
            #[cfg(unix)]
            let data = std::fs::read(&pending)?;
            let contents: Value = serde_json::from_slice(&data)?;
            ensure!(
                contents["version"] == 1 && contents["token"] == token.text,
                "CLI did not trim stdin to exactly the enrollment token"
            );
            std::fs::remove_file(pending)?;
            let (prefix, secret) = token.text.rsplit_once('.').context("token structure")?;
            let bag = prefix.rsplit_once('.').context("token bag")?.1;
            let invalid = format!("dvaet2.{bag}.{secret}");
            for (name, input) in [
                ("invalid token", format!("{invalid}\r\n").into_bytes()),
                ("immediate EOF", Vec::new()),
                ("whitespace-only line", b" \t \r\n".to_vec()),
            ] {
                let output = enroll_cli_from_stdin(case, &input).await?;
                ensure!(!output.status.success(), "identity enroll CLI accepted {name} on stdin");
                assert_no_pending_files(case)?;
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_renewal_happy_path(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, Some(2), true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, initial) = case.enrolled(&target, &token).await?;
            let authority = field(&initial, "authority_id")?.to_owned();
            let old_key = key_name(&initial, "current")?.to_owned();
            let before = case.identity_record(&target, &id).await?;
            let old_thumb = current_thumbprint(&before)?.to_owned();
            let name = before.friendly_name.as_str().to_owned();
            let start = Instant::now();
            let renewed = loop {
                let record = case.identity_record(&target, &id).await?;
                if current_thumbprint(&record).is_ok_and(|thumb| thumb != old_thumb) {
                    break record;
                }
                if let Ok(state) = case.state(&authority) {
                    case.check_key_protection_inner(&authority, &state, false)?;
                }
                if !key_exists(case, &old_key)? {
                    let confirmed = current_thumbprint(&case.identity_record(&target, &id).await?)
                        .is_ok_and(|thumb| thumb != old_thumb);
                    ensure!(
                        confirmed,
                        "old key was deleted before the server confirmed its replacement"
                    );
                }
                case.check_running()?;
                ensure!(
                    start.elapsed() < WAIT,
                    "agent did not confirm a new current certificate"
                );
                tokio::time::sleep(POLL).await;
            };
            ensure!(renewed.friendly_name == name, "friendly name changed on renewal");
            ensure!(
                renewed.certificates.as_ref().is_some_and(|items| items
                    .iter()
                    .any(|cert| cert.thumbprint == old_thumb && cert.status == CertificateStatus::Retired)),
                "old certificate not retired"
            );
            let final_state = case
                .until_state(
                    &target,
                    &authority,
                    &id,
                    "settled new stored current certificate",
                    |state| {
                        key_name(state, "current").is_ok_and(|name| name != old_key)
                            && state["keys"].get("pending").is_none()
                            && state["keys"].get("previous").is_none()
                    },
                )
                .await?;
            ensure!(
                key_name(&final_state, "current")? != old_key,
                "old key remained current"
            );
            ensure!(
                final_state["keys"].get("pending").is_none() && final_state["keys"].get("previous").is_none(),
                "renewal left pending or previous key slots after confirm"
            );
            let current_chain = final_state["keys"]["current"]["certificate_chain"]
                .as_array()
                .context("renewed current certificate chain missing")?;
            ensure!(
                !current_chain.is_empty()
                    && crate::signer::thumbprint(current_chain[0].as_str().context("renewed leaf")?)?
                        == current_thumbprint(&renewed)?,
                "stored current certificate does not match the authenticated new leaf"
            );
            case.check_key_protection(&authority, &final_state)?;
            wait_key_deleted(case, &old_key).await?;
            let new_thumb = current_thumbprint(&renewed)?.to_owned();
            if case.ctx.mock() {
                ensure!(
                    target.events(&id).await?.iter().any(|event| {
                        event["type"] == "cert_status_changed"
                            && event["cert_thumbprint"] == new_thumb
                            && event["to"] == "current"
                    }),
                    "old key was deleted without a server-side confirm event"
                );
                assert_new_auth_precedes_old_close(&target, &id, &old_thumb, &new_thumb).await?;
            }
            case.stop().await?;
            case.until_identity(&target, &id, "offline channel after restart", |record| {
                !record.connected
            })
            .await?;
            // The restarted agent would renew at once, since its certificate is older than `renewal_after_secs`.
            case.clear_renewal_after_secs()?;
            case.start().await?;
            let resumed = case
                .until_identity(&target, &id, "reconnected with persisted key", |record| {
                    record.connected && current_thumbprint(record).is_ok_and(|thumb| thumb == new_thumb)
                })
                .await?;
            ensure!(
                resumed.issuer() == renewed.issuer(),
                "agent changed issuer while loading the persisted key"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_renewal_lost_response_retried(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let old_key = key_name(&state, "current")?.to_owned();
            let before = case.identity_record(&target, &id).await?;
            let old_thumb = current_thumbprint(&before)?.to_owned();
            case.until_identity(&target, &id, "channel before requested renewal", |record| {
                record.connected
            })
            .await?;
            let counters = target.requests(None).await?;
            let attempts = count(&counters, "renew")?;
            let confirmed_before = count(&counters, "confirm")?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "renew", "pause": true }))
                    .await?,
                200,
            )?;
            target.faults(&json!({ "drop_next_response": "renew" })).await?;
            target.management().request_renewal(&id).await?;
            let started = Instant::now();
            let mut unsettled = "agent did not persist the first pending renewal";
            let (pending_thumb, pending_key) = loop {
                let record = case.identity_record(&target, &id).await?;
                let state = case.state(&authority)?;
                let requests = target.requests(None).await?;
                let renew_count = count(&requests, "renew")?;
                ensure!(
                    renew_count <= attempts + 1 + count(&requests, "renew_retry_503")?,
                    "renewal retry succeeded while the retry barrier was held"
                );
                let pending = record
                    .certificates
                    .as_ref()
                    .context("missing certificates")?
                    .iter()
                    .find(|cert| cert.status == CertificateStatus::Pending);
                if renew_count > attempts
                    && let Some(pending) = pending
                    && let Ok(key) = key_name(&state, "pending")
                {
                    // The mock's README does not order the fault's consumption before the renewal it commits.
                    if target.control("faults", &json!({})).await?.body["drop_next_response"].is_null() {
                        break (pending.thumbprint.clone(), key.to_owned());
                    }
                    unsettled = "drop-next-renew fault was not consumed";
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "{unsettled}");
                tokio::time::sleep(POLL).await;
            };
            case.stop().await?;
            let requests = target.requests(None).await?;
            ensure!(
                count(&requests, "renew")? == attempts + 1 + count(&requests, "renew_retry_503")?,
                "renewal retry succeeded before the agent was stopped"
            );
            ensure!(
                key_name(&case.state(&authority)?, "pending")? == pending_key,
                "pending CSR key was not persisted across stop"
            );
            let before_restart = count(&requests, "renew")?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "renew", "pause": false }))
                    .await?,
                200,
            )?;
            case.start().await?;
            let renewed = case
                .until_identity(&target, &id, "retried renewal after restart", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb == pending_thumb) && !record.renewal_requested
                })
                .await?;
            ensure!(
                renewed.certificates.as_ref().is_some_and(|certs| certs.len() == 2) && old_thumb != pending_thumb,
                "lost renewal response created multiple new certificates"
            );
            ensure!(
                count(&target.requests(None).await?, "renew")? > before_restart,
                "lost renewal response was not retried after restart"
            );
            ensure!(
                count(&target.requests(None).await?, "confirm")? > confirmed_before,
                "retried renewal was not confirmed with the new key"
            );
            let state = case
                .until_state(
                    &target,
                    &authority,
                    &id,
                    "the retried renewal's key as current",
                    |state| {
                        key_name(state, "current").is_ok_and(|name| name == pending_key)
                            && state["keys"].get("pending").is_none()
                            && state["keys"].get("previous").is_none()
                    },
                )
                .await?;
            wait_key_deleted(case, &old_key).await?;
            case.check_key_protection(&authority, &state)?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_renewal_lost_confirm_response_retried(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let old_key = key_name(&state, "current")?.to_owned();
            let old = case
                .until_identity(&target, &id, "old-key channel", |record| record.connected)
                .await?;
            let old_thumb = current_thumbprint(&old)?.to_owned();
            let before = target.requests(None).await?;
            let renew_before = count(&before, "renew")?;
            let connect_before = count(&before, "connect")?;
            let confirm_before = count(&before, "confirm")?;
            let sequence_before = before["request_sequence"]
                .as_array()
                .context("mock request sequence missing")?
                .len();
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                    .await?,
                200,
            )?;
            target.faults(&json!({ "drop_next_response": "confirm" })).await?;
            target.management().request_renewal(&id).await?;
            let started = Instant::now();
            let (new_thumb, pending_key) = loop {
                let record = case.identity_record(&target, &id).await?;
                let stored = case.state(&authority)?;
                let requests = target.requests(None).await?;
                if count(&requests, "confirm")? > confirm_before
                    && count(&requests, "confirm_retry_503")? >= 2
                    && let Ok(thumb) = current_thumbprint(&record)
                    && thumb != old_thumb
                    && let Ok(pending_key) = key_name(&stored, "pending")
                {
                    ensure!(
                        key_name(&stored, "current")? == old_key && key_exists(case, &old_key)?,
                        "agent discarded the old key before receiving confirm 204"
                    );
                    break (thumb.to_owned(), pending_key.to_owned());
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "agent did not retry the dropped confirm");
                tokio::time::sleep(POLL).await;
            };
            ensure!(
                target.control("faults", &json!({})).await?.body["drop_next_response"].is_null(),
                "drop-next-confirm fault was not consumed"
            );
            let blocked = target.requests(None).await?;
            ensure!(
                count(&blocked, "renew")? == renew_before + 1 && count(&blocked, "connect")? == connect_before,
                "agent renewed again or opened a stream while confirm outcome was unknown"
            );
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                    .await?,
                200,
            )?;
            let settled = case
                .until_state(
                    &target,
                    &authority,
                    &id,
                    "confirmed new key after dropped response",
                    |state| {
                        key_name(state, "current").is_ok_and(|name| name == pending_key)
                            && state["keys"].get("pending").is_none()
                            && state["keys"].get("previous").is_none()
                    },
                )
                .await?;
            ensure!(
                key_name(&settled, "current")? == pending_key,
                "agent used a different key for its confirm retry"
            );
            wait_key_deleted(case, &old_key).await?;
            case.until_identity(&target, &id, "new channel after confirm retry", |record| {
                record.connected && current_thumbprint(record).is_ok_and(|thumb| thumb == new_thumb)
            })
            .await?;
            let requests = target.requests(None).await?;
            let sequence = requests["request_sequence"]
                .as_array()
                .context("mock request sequence missing")?;
            let completed = sequence
                .iter()
                .enumerate()
                .skip(sequence_before)
                .filter_map(|(idx, value)| (value == "confirm_204").then_some(idx))
                .take(2)
                .collect::<Vec<_>>();
            ensure!(
                completed.len() == 2,
                "dropped confirm or successful retry was not processed"
            );
            ensure!(
                completed[1] > completed[0] + 1
                    && sequence[completed[0] + 1..completed[1]]
                        .iter()
                        .all(|entry| entry == "confirm")
                    && count(&requests, "renew")? == renew_before + 1,
                "agent sent renew or connect between the dropped confirm and its successful retry"
            );
            let events = target.events(&id).await?;
            ensure!(
                events
                    .iter()
                    .filter(|event| {
                        event["type"] == "cert_status_changed"
                            && event["cert_thumbprint"] == new_thumb
                            && event["to"] == "current"
                    })
                    .count()
                    == 1,
                "lost confirm response promoted the pending certificate more than once"
            );
            assert_new_auth_precedes_old_close(&target, &id, &old_thumb, &new_thumb).await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_confirm_barrier_blocks_channelless_traffic(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_available": false })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, initial) = case.enrolled(&target, &token).await?;
            let authority = field(&initial, "authority_id")?.to_owned();
            let original = case.identity_record(&target, &id).await?;
            let old_thumb = current_thumbprint(&original)?.to_owned();
            let started = Instant::now();
            loop {
                if count(&target.requests(None).await?, "check_in")? > 0 {
                    break;
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "initial channelless check-in did not run");
                tokio::time::sleep(POLL).await;
            }
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                    .await?,
                200,
            )?;
            target
                .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
                .await?;
            target.management().request_renewal(&id).await?;
            let started = Instant::now();
            let blocked = loop {
                let requests = target.requests(None).await?;
                let state = case.state(&authority)?;
                if count(&requests, "confirm_retry_503")? > 0 && state["keys"]["pending"]["key_name"].is_string() {
                    break requests;
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "confirm retry never reached the channelless barrier"
                );
                tokio::time::sleep(POLL).await;
            };
            let sequence_start = blocked["request_sequence"]
                .as_array()
                .context("mock request sequence missing")?
                .iter()
                .position(|entry| entry == "confirm")
                .context("confirm barrier observed no confirm attempt")?;
            let blocked_certificates = case.identity_record(&target, &id).await?.certificates.clone();
            tokio::time::sleep(Duration::from_secs(11)).await;
            case.check_running()?;
            let after = target.requests(None).await?;
            ensure!(
                count(&after, "confirm")? > count(&blocked, "confirm")?
                    && count(&after, "renew")? == count(&blocked, "renew")?
                    && count(&after, "check_in")? == count(&blocked, "check_in")?
                    && count(&after, "connect")? == count(&blocked, "connect")?
                    && after["request_sequence"]
                        .as_array()
                        .context("mock request sequence missing")?
                        .iter()
                        .skip(sequence_start)
                        .all(|entry| entry == "confirm")
                    && case.identity_record(&target, &id).await?.certificates == blocked_certificates,
                "unknown confirm outcome permitted check-in, renew, connect or certificate promotion"
            );
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                    .await?,
                200,
            )?;
            case.until_identity(&target, &id, "channelless confirm resolved", |record| {
                current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb) && !record.renewal_requested
            })
            .await?;
            let settled = until_renewal_settled(case, &target, &authority, &id, key_name(&initial, "current")?).await?;
            ensure!(
                settled.get("rejected").is_none(),
                "an unknown confirm outcome rejected the identity"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_confirm_expired_pending_renews_with_fresh_key(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx.clone(), Some(3), true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target
                .faults(&json!({ "channel_available": false, "leaf_lifetime_secs": 30 }))
                .await?;
            let token = new_token(case, 1).await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                    .await?,
                200,
            )?;
            target.faults(&json!({ "drop_next_response": "confirm" })).await?;
            let before = target.requests(None).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let old_key = key_name(&state, "current")?.to_owned();
            let old_thumb = crate::signer::thumbprint(
                state["keys"]["current"]["certificate_chain"][0]
                    .as_str()
                    .context("original enrolled leaf missing")?,
            )?;
            let started = Instant::now();
            let (first_thumb, first_key) = loop {
                let record = case.identity_record(&target, &id).await?;
                let stored = case.state(&authority)?;
                let requests = target.requests(None).await?;
                if count(&requests, "confirm_retry_503")? > count(&before, "confirm_retry_503")?
                    && let Ok(thumb) = current_thumbprint(&record)
                    && thumb != old_thumb
                    && let Ok(pending_key) = key_name(&stored, "pending")
                    && stored_leaf_thumbprint(&stored, "pending")?.as_deref() == Some(thumb)
                {
                    ensure!(
                        key_exists(case, &old_key)? && key_name(&stored, "current")? == old_key,
                        "lost confirm response already discarded the old local current key"
                    );
                    break (thumb.to_owned(), pending_key.to_owned());
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not retain its key after a dropped confirm"
                );
                tokio::time::sleep(POLL).await;
            };
            case.stop().await?;
            ensure!(
                target.control("faults", &json!({})).await?.body["drop_next_response"].is_null()
                    && case
                        .identity_record(&target, &id)
                        .await?
                        .has_certificate(&first_thumb, CertificateStatus::Current),
                "dropped confirm did not promote the pending certificate server-side"
            );
            let expiry = case
                .identity_record(&target, &id)
                .await?
                .not_after()
                .context("identity has no current certificate")?
                .unix_timestamp();
            let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
                .as_i64()
                .context("mock time missing")?;
            let secs = expiry - now + 1;
            ensure!(
                secs > 0 && secs < 60,
                "pending key did not approach expiry before retry"
            );
            target.advance(secs).await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                    .await?,
                200,
            )?;
            let restart = target.requests(None).await?;
            case.start().await?;
            let confirmed_record = case
                .until_identity(&target, &id, "fresh-key renewal after rejected confirm", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb && thumb != first_thumb)
                        && record.has_certificate(&first_thumb, CertificateStatus::Retired)
                        && !record.renewal_requested
                })
                .await?;
            let new_thumb = current_thumbprint(&confirmed_record)?.to_owned();
            let settled = case
                .until_state(&target, &authority, &id, "settled fresh confirmed key", |state| {
                    key_name(state, "current").is_ok_and(|name| name != old_key && name != first_key)
                        && state["keys"].get("pending").is_none()
                        && state["keys"].get("previous").is_none()
                })
                .await?;
            ensure!(
                key_name(&settled, "current")? != first_key,
                "agent reused the expired pending key after confirm rejected it"
            );
            wait_key_deleted(case, &first_key).await?;
            wait_key_deleted(case, &old_key).await?;
            // `renewal_after_secs` starts the next renewal three seconds after this one, so stop at the settled state.
            case.stop().await?;
            let requests = target.requests(None).await?;
            ensure!(
                renew_and_confirm_steps_since(&requests, &restart)?.starts_with(&[
                    "confirm",
                    "renew",
                    "confirm",
                    "confirm_204"
                ]) && renew_keyids_since(&requests, &restart)?.starts_with(&[json!(first_thumb)]),
                "agent did not retry confirm, renew signed with the expired pending key, then confirm a fresh CSR"
            );
            let events = target.events(&id).await?;
            ensure!(
                events
                    .iter()
                    .any(|event| { event["type"] == "renew_received" && event["cert_thumbprint"] == first_thumb })
                    && events.iter().any(|event| {
                        event["type"] == "cert_status_changed"
                            && event["cert_thumbprint"] == first_thumb
                            && event["from"] == "current"
                            && event["to"] == "retired"
                    })
                    && events.iter().any(|event| {
                        event["type"] == "cert_status_changed"
                            && event["cert_thumbprint"] == new_thumb
                            && event["to"] == "current"
                    }),
                "the failed pending certificate was not retired before confirming the new key"
            );
            Ok(())
        })
    })
    .await?;

    with_agent(ctx, Some(3), true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target
                .faults(&json!({ "channel_available": false, "leaf_lifetime_secs": 30 }))
                .await?;
            let token = new_token(case, 1).await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                    .await?,
                200,
            )?;
            target
                .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
                .await?;
            let before = target.requests(None).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let old_key = key_name(&state, "current")?.to_owned();
            let old_thumb = crate::signer::thumbprint(
                state["keys"]["current"]["certificate_chain"][0]
                    .as_str()
                    .context("original enrolled leaf missing")?,
            )?;
            let started = Instant::now();
            let (first_thumb, first_key) = loop {
                let record = case.identity_record(&target, &id).await?;
                let stored = case.state(&authority)?;
                let requests = target.requests(None).await?;
                if count(&requests, "confirm_retry_503")? > count(&before, "confirm_retry_503")?
                    && let Some(pending) = record
                        .certificates
                        .as_ref()
                        .and_then(|certs| certs.iter().find(|cert| cert.status == CertificateStatus::Pending))
                    && let Ok(key) = key_name(&stored, "pending")
                    && stored_leaf_thumbprint(&stored, "pending")?.as_deref() == Some(pending.thumbprint.as_str())
                {
                    ensure!(
                        current_thumbprint(&record)? == old_thumb,
                        "injected confirm failure promoted the pending certificate"
                    );
                    break (pending.thumbprint.clone(), key.to_owned());
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not persist a pending key after confirm 503"
                );
                tokio::time::sleep(POLL).await;
            };
            case.stop().await?;
            let pending = case.identity_record(&target, &id).await?;
            let certificate = pending
                .certificates
                .as_ref()
                .context("identity certificates missing")?
                .iter()
                .find(|cert| cert.thumbprint == first_thumb)
                .context("pending certificate missing")?;
            let expiry = certificate.not_after.unix_timestamp();
            let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
                .as_i64()
                .context("mock time missing")?;
            let secs = expiry - now + 1;
            ensure!(
                secs > 0 && secs < 60,
                "pending key did not approach expiry before retry"
            );
            target.advance(secs).await?;
            target
                .faults(&json!({
                    "fail_next_response": {
                        "endpoint": "renew",
                        "status": 401,
                        "error": "identity_unknown"
                    }
                }))
                .await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                    .await?,
                200,
            )?;
            let restart = target.requests(None).await?;
            case.start().await?;
            let renewed = case
                .until_identity(
                    &target,
                    &id,
                    "fallback renewal after pending-key identity_unknown",
                    |record| {
                        current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb && thumb != first_thumb)
                            && record.has_certificate(&first_thumb, CertificateStatus::Retired)
                    },
                )
                .await?;
            let settled = case
                .until_state(&target, &authority, &id, "confirmed fallback key", |state| {
                    key_name(state, "current").is_ok_and(|name| name != old_key && name != first_key)
                        && state["keys"].get("pending").is_none()
                        && state["keys"].get("previous").is_none()
                        && state.get("rejected").is_none()
                })
                .await?;
            ensure!(
                stored_leaf_thumbprint(&settled, "current")?.as_deref() == Some(current_thumbprint(&renewed)?),
                "agent did not persist the fallback-renewed certificate"
            );
            wait_key_deleted(case, &first_key).await?;
            wait_key_deleted(case, &old_key).await?;
            // `renewal_after_secs` starts the next renewal three seconds after this one, so stop at the settled state.
            case.stop().await?;
            let requests = target.requests(None).await?;
            ensure!(
                renew_and_confirm_steps_since(&requests, &restart)?.starts_with(&[
                    "confirm",
                    "renew",
                    "renew",
                    "confirm",
                    "confirm_204"
                ]) && renew_keyids_since(&requests, &restart)?.starts_with(&[json!(first_thumb), json!(old_thumb)])
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| { event["type"] == "renew_received" && event["cert_thumbprint"] == old_thumb }),
                "identity_unknown on pending-key renew did not fall back to the old current key"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_confirm_expired_pending_beyond_grace_rejects(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, Some(3), true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target
                .faults(&json!({ "channel_available": false, "leaf_lifetime_secs": 30 }))
                .await?;
            let token = new_token(case, 1).await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                    .await?,
                200,
            )?;
            target
                .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
                .await?;
            case.write_pending(&token.text)?;
            let (id, initial) = case.enrolled(&target, &token).await?;
            let authority = field(&initial, "authority_id")?.to_owned();
            let old_key = key_name(&initial, "current")?.to_owned();
            let started = Instant::now();
            let (pending_thumb, pending_certificate) = loop {
                let record = case.identity_record(&target, &id).await?;
                let stored = case.state(&authority)?;
                if count(&target.requests(None).await?, "confirm_retry_503")? > 0
                    && let Some(pending) = record
                        .certificates
                        .as_ref()
                        .and_then(|certs| certs.iter().find(|cert| cert.status == CertificateStatus::Pending))
                    && stored["keys"]["pending"]["key_name"].is_string()
                {
                    break (pending.thumbprint.clone(), pending.clone());
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "pending certificate was not held at confirm");
                tokio::time::sleep(POLL).await;
            };
            case.stop().await?;
            let before = target.requests(None).await?;
            let certificates = case.identity_record(&target, &id).await?.certificates.clone();
            let not_before = pending_certificate.not_before.unix_timestamp();
            let not_after = pending_certificate.not_after.unix_timestamp();
            let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
                .as_i64()
                .context("mock time missing")?;
            let secs = not_after + (not_after - not_before) + 1 - now;
            ensure!(
                secs > 0 && secs < 120,
                "pending certificate did not approach its grace limit"
            );
            target.advance(secs).await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                    .await?,
                200,
            )?;
            let since = time::OffsetDateTime::now_utc();
            case.start().await?;
            let rejected = case
                .until_rejected(&target, &authority, &id, "certificate_expired")
                .await?;
            let after = target.requests(None).await?;
            let renew_index = usize::try_from(count(&before, "renew")?)?;
            ensure!(
                rejected["rejected"]["code"] == "certificate_expired"
                    && key_name(&rejected, "current")? == old_key
                    && after["renew_attempt_keyids"][renew_index] == pending_thumb
                    && count(&after, "renew")? == count(&before, "renew")? + 1
                    && count(&after, "confirm")? > count(&before, "confirm")?
                    && case.identity_record(&target, &id).await?.certificates == certificates,
                "beyond-grace pending-key renew did not reject without issuing or promoting a certificate"
            );
            assert_terminal_stops(case, &target, &authority, Some(&id), "certificate_expired", since).await
        })
    })
    .await
}

pub(crate) async fn a_expired_current_renews_in_grace_or_rejects_beyond(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx.clone(), None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "leaf_lifetime_secs": 30 })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let old_key = key_name(&state, "current")?.to_owned();
            let original = case
                .until_identity(&target, &id, "old certificate channel", |record| record.connected)
                .await?;
            let old_thumb = current_thumbprint(&original)?.to_owned();
            let expiry = original
                .not_after()
                .context("identity has no current certificate")?
                .unix_timestamp();
            let before = target.requests(None).await?;
            case.stop().await?;
            case.until_identity(&target, &id, "offline expired channel", |record| !record.connected)
                .await?;
            let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
                .as_i64()
                .context("mock time missing")?;
            let secs = expiry - now + 1;
            ensure!(secs > 0 && secs < 60, "old certificate is not approaching expiry");
            target.advance(secs).await?;
            case.start().await?;
            let renewed = case
                .until_identity(&target, &id, "within-grace renewal and reconnect", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb) && record.connected
                })
                .await?;
            ensure!(
                renewed.issuer() == original.issuer()
                    && count(&target.requests(None).await?, "renew")? > count(&before, "renew")?
                    && count(&target.requests(None).await?, "confirm")? > count(&before, "confirm")?
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| { event["type"] == "renew_received" && event["cert_thumbprint"] == old_thumb })
                    && case.state(&authority)?["rejected"].is_null(),
                "expired-within-grace certificate did not sign renew and confirm before reconnecting"
            );
            until_renewal_settled(case, &target, &authority, &id, &old_key).await?;
            Ok(())
        })
    })
    .await?;

    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "leaf_lifetime_secs": 30 })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            case.until_identity(&target, &id, "old certificate channel", |record| record.connected)
                .await?;
            let before = count(&target.requests(None).await?, "renew")?;
            case.stop().await?;
            target.advance(61).await?;
            let since = time::OffsetDateTime::now_utc();
            case.start().await?;
            let rejected = case
                .until_rejected(&target, &authority, &id, "certificate_expired")
                .await?;
            ensure!(
                rejected["rejected"]["code"] == "certificate_expired"
                    && count(&target.requests(None).await?, "renew")? > before,
                "agent did not mark an expired-beyond-grace identity rejected"
            );
            assert_terminal_stops(case, &target, &authority, Some(&id), "certificate_expired", since).await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_channel_connected_and_metadata(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            if case.ctx.mock() {
                expect_status(&target.control("handshake", &json!({ "pause": true })).await?, 200)?;
            }
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, initial_state) = case.enrolled(&target, &token).await?;
            let authority = field(&initial_state, "authority_id")?.to_owned();
            let enrolled = case.identity_record(&target, &id).await?;
            ensure!(
                enrolled.metadata_value("hostname") == Some(&*case.metadata_hostname),
                "enrollment ignored the metadata override"
            );
            let connected = if case.ctx.mock() {
                ensure!(
                    !enrolled.connected,
                    "Hello authenticated before enrollment metadata was observed"
                );
                let start = Instant::now();
                loop {
                    if count(&target.requests(None).await?, "paused_hellos")? > 0 {
                        break;
                    }
                    case.check_running()?;
                    ensure!(start.elapsed() < WAIT, "agent did not reach the held Hello proof");
                    tokio::time::sleep(POLL).await;
                }
                let held = case.identity_record(&target, &id).await?;
                ensure!(
                    !held.connected && held.metadata == enrolled.metadata,
                    "enrollment metadata changed before Hello authenticated"
                );
                target.advance(2).await?;
                expect_status(&target.control("handshake", &json!({ "pause": false })).await?, 200)?;
                let connected = case
                    .until_identity(&target, &id, "authenticated Hello", |record| record.connected)
                    .await?;
                ensure!(
                    count(&target.requests(None).await?, "authenticated_connects")? > 0,
                    "released Hello did not authenticate"
                );
                connected
            } else {
                case.until_identity(&target, &id, "connected channel", |record| record.connected)
                    .await?
            };
            ensure!(
                connected.last_seen_at.is_some(),
                "channel did not update the last-seen time"
            );
            ensure!(
                connected.metadata_value("hostname") == Some(&*case.metadata_hostname),
                "initial Hello ignored the metadata override"
            );
            for key in REQUIRED_METADATA_KEYS {
                ensure!(
                    connected.metadata_value(key).is_some_and(|value| !value.is_empty()),
                    "Hello omitted required {key} metadata"
                );
            }
            ensure!(
                case.state(&authority)?.get("rejected").is_none(),
                "successful Hello rejected the stored identity"
            );
            if case.ctx.mock() {
                ensure!(
                    connected.last_seen_at.is_some() && connected.last_seen_at != enrolled.last_seen_at,
                    "authenticated Hello did not refresh the last-seen time"
                );
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_make_before_break_on_renewal(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, Some(2), true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let old_key = key_name(&state, "current")?.to_owned();
            let connected = case
                .until_identity(&target, &id, "first connection", |record| record.connected)
                .await?;
            let old_thumb = current_thumbprint(&connected)?.to_owned();
            let start = Instant::now();
            let new_thumb = loop {
                let record = case.identity_record(&target, &id).await?;
                ensure!(record.connected, "agent disconnected during make-before-break");
                if let Ok(thumb) = current_thumbprint(&record)
                    && thumb != old_thumb
                {
                    ensure!(
                        record.certificates.as_ref().is_some_and(|certs| certs
                            .iter()
                            .any(|cert| cert.thumbprint == old_thumb && cert.status == CertificateStatus::Retired)),
                        "old certificate not retired after new one connected"
                    );
                    break thumb.to_owned();
                }
                case.check_running()?;
                ensure!(start.elapsed() < WAIT, "agent did not renew over a live channel");
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            if case.ctx.mock() {
                assert_new_auth_precedes_old_close(&target, &id, &old_thumb, &new_thumb).await?;
            }
            until_renewal_settled(case, &target, &authority, &id, &old_key).await?;
            // `renewal_after_secs` starts the next renewal two seconds after this one, so stop at the settled state.
            case.stop().await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_old_key_deleted_after_confirm_without_channel(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, Some(8), true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let old_key = key_name(&state, "current")?.to_owned();
            let enrolled_revision = count(&state["config"], "revision")?;
            let first = case
                .until_identity(&target, &id, "old-root channel", |record| record.connected)
                .await?;
            ensure!(
                first.metadata_value("hostname") == Some(&*case.metadata_hostname),
                "initial Hello ignored the metadata override"
            );
            let old_thumb = current_thumbprint(&first)?.to_owned();
            let renewed_hostname = "conformance-renew";
            case.set_metadata_hostname(renewed_hostname)?;
            target.faults(&json!({ "channel_available": false })).await?;
            case.until_state(&target, &authority, &id, "removed channel URL", |state| {
                state["config"]["revision"]
                    .as_u64()
                    .is_some_and(|revision| revision > enrolled_revision)
                    && state["config"].get("agent_channel_url").is_none()
            })
            .await?;
            case.until_identity(&target, &id, "closed old channel before offline renewal", |record| {
                !record.connected
            })
            .await?;
            target.management().request_renewal(&id).await?;
            let start = Instant::now();
            let confirmed = loop {
                let record = case.identity_record(&target, &id).await?;
                if current_thumbprint(&record).is_ok_and(|thumb| thumb != old_thumb) {
                    break record;
                }
                if !key_exists(case, &old_key)? {
                    let refreshed = case.identity_record(&target, &id).await?;
                    ensure!(
                        current_thumbprint(&refreshed).is_ok_and(|thumb| thumb != old_thumb),
                        "old key was deleted before confirm while the channel was unavailable"
                    );
                }
                case.check_running()?;
                ensure!(
                    start.elapsed() < WAIT,
                    "agent did not confirm renewal without the channel"
                );
                tokio::time::sleep(POLL).await;
            };
            let new_thumb = current_thumbprint(&confirmed)?.to_owned();
            ensure!(
                confirmed.metadata_value("hostname") == Some(renewed_hostname)
                    && !confirmed.renewal_requested
                    && confirmed.certificates.as_ref().is_some_and(|certs| {
                        certs
                            .iter()
                            .any(|cert| cert.thumbprint == old_thumb && cert.status == CertificateStatus::Retired)
                    }),
                "HTTP renewal did not finish through confirm while the channel was unavailable"
            );
            let events = target.events(&id).await?;
            ensure!(
                events.iter().any(|event| {
                    event["type"] == "cert_status_changed"
                        && event["cert_thumbprint"] == new_thumb
                        && event["to"] == "current"
                }) && events
                    .iter()
                    .all(|event| { event["type"] != "stream_authenticated" || event["cert_thumbprint"] != new_thumb }),
                "new key was promoted by the channel instead of confirm"
            );
            let requests = target.requests(None).await?;
            ensure!(
                count(&requests, "renew")? >= 1 && count(&requests, "confirm")? >= 1,
                "agent did not send both renew and confirm while the channel was unavailable"
            );
            wait_key_deleted(case, &old_key).await?;
            let stored = case
                .until_state(&target, &authority, &id, "settled confirmed key", |state| {
                    key_name(state, "current").is_ok_and(|name| name != old_key)
                        && state["keys"].get("pending").is_none()
                        && state["keys"].get("previous").is_none()
                })
                .await?;
            ensure!(
                crate::signer::thumbprint(
                    stored["keys"]["current"]["certificate_chain"][0]
                        .as_str()
                        .context("confirmed leaf missing")?
                )? == new_thumb,
                "agent stored a different key after confirm"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_request_renewal_connected(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let record = case
                .until_identity(&target, &id, "connected channel", |record| record.connected)
                .await?;
            let original = current_thumbprint(&record)?.to_owned();
            let acknowledgments = if case.ctx.mock() {
                Some(count(&target.requests(None).await?, "correlated_acks")?)
            } else {
                None
            };
            target.management().request_renewal(&id).await?;
            let renewed = case
                .until_identity(&target, &id, "requested renewal", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != original) && !record.renewal_requested
                })
                .await?;
            ensure!(renewed.connected, "requested renewal broke the channel");
            if let Some(before) = acknowledgments {
                let start = Instant::now();
                loop {
                    if count(&target.requests(None).await?, "correlated_acks")? > before {
                        break;
                    }
                    ensure!(
                        start.elapsed() < Duration::from_secs(2),
                        "agent did not Ack RenewRequested"
                    );
                    tokio::time::sleep(POLL).await;
                }
            }
            until_renewal_settled(
                case,
                &target,
                field(&state, "authority_id")?,
                &id,
                key_name(&state, "current")?,
            )
            .await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_request_renewal_while_offline(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let first = case
                .until_identity(&target, &id, "initial connection", |record| record.connected)
                .await?;
            let original = current_thumbprint(&first)?.to_owned();
            case.stop().await?;
            let _ = case
                .until_identity(&target, &id, "offline channel", |record| !record.connected)
                .await?;
            target.management().request_renewal(&id).await?;
            ensure!(
                case.identity_record(&target, &id).await?.renewal_requested,
                "offline renewal flag missing"
            );
            case.start().await?;
            let renewed = case
                .until_identity(&target, &id, "renewal after reconnect", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != original) && !record.renewal_requested
                })
                .await?;
            ensure!(renewed.connected, "agent did not reconnect after offline request");
            until_renewal_settled(
                case,
                &target,
                field(&state, "authority_id")?,
                &id,
                key_name(&state, "current")?,
            )
            .await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_request_renewal_without_channel(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            if case.ctx.mock() {
                target.faults(&json!({ "channel_available": false })).await?;
            } else {
                ensure!(!case.ctx.channel_available, "DVLS target offers an agent channel");
            }
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let initial = case.identity_record(&target, &id).await?;
            ensure!(
                state["config"].get("agent_channel_url").is_none() && !initial.connected,
                "no-channel renewal fixture unexpectedly offers a channel"
            );
            let original = current_thumbprint(&initial)?.to_owned();
            let before = if case.ctx.mock() {
                Some(target.requests(None).await?)
            } else {
                None
            };
            target.management().request_renewal(&id).await?;
            ensure!(
                case.identity_record(&target, &id).await?.renewal_requested,
                "channelless renewal flag was not persisted"
            );
            case.until_identity(&target, &id, "check-in-triggered channelless renewal", |record| {
                current_thumbprint(record).is_ok_and(|thumb| thumb != original)
                    && !record.renewal_requested
                    && !record.connected
            })
            .await?;
            if let Some(before) = before {
                let sequence_start = before["request_sequence"]
                    .as_array()
                    .context("mock request sequence missing")?
                    .len();
                let requests = target.requests(None).await?;
                ensure!(
                    count(&requests, "check_in")? > count(&before, "check_in")?
                        && count(&requests, "renew")? >= 1
                        && count(&requests, "confirm")? >= 1
                        && count(&requests, "connect")? == 0
                        && count(&requests, "channel_attempts")? == 0
                        && target.events(&id).await?.iter().any(|event| {
                            event["type"] == "check_in_received" && event["renewal_requested"] == true
                        }),
                    "channelless renewal did not start at check-in and finish with confirm"
                );
                assert_check_in_triggers_renewal(&requests, sequence_start)?;
            }
            let authority = field(&state, "authority_id")?;
            let old_key = key_name(&state, "current")?;
            until_renewal_settled(case, &target, authority, &id, old_key).await?;
            if case.ctx.mock() {
                let check_ins = count(&target.requests(None).await?, "check_in")?;
                case.stop().await?;
                case.start().await?;
                // Signing the check-in opens the current key, an operation in the key store later than the old key's deletion.
                let started = Instant::now();
                while count(&target.requests(None).await?, "check_in")? == check_ins {
                    case.check_running()?;
                    ensure!(started.elapsed() < WAIT, "restarted agent did not check in");
                    tokio::time::sleep(POLL).await;
                }
                assert_no_copy_of_deleted_key(case, old_key)?;
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_reconnect_make_before_break(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, _) = case.enrolled(&target, &token).await?;
            case.until_identity(&target, &id, "first channel", |record| record.connected)
                .await?;
            ensure!(
                case.identity_record(&target, &id).await?.metadata_value("hostname") == Some(&*case.metadata_hostname),
                "first Hello did not send the current metadata override"
            );
            case.set_metadata_hostname("reconnected-host")?;
            let before = target.requests(None).await?;
            expect_status(&target.control("reconnect", &json!({ "identity_id": id })).await?, 202)?;
            let started = Instant::now();
            loop {
                let current = case.identity_record(&target, &id).await?;
                ensure!(current.connected, "agent disconnected before replacement stream opened");
                let observed = target.requests(None).await?;
                if count(&observed, "connect")? > count(&before, "connect")?
                    && count(&observed, "overlap_open")? > count(&before, "overlap_open")?
                    && count(&observed, "authenticated_connects")? > count(&before, "authenticated_connects")?
                    && count(&observed, "active_streams")? == 1
                {
                    break;
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "agent did not make-before-break on Reconnect");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let events = target.events(&id).await?;
            let authenticated = events
                .iter()
                .filter(|event| event["type"] == "stream_authenticated")
                .collect::<Vec<_>>();
            ensure!(
                authenticated.len() >= 2,
                "Reconnect never authenticated a replacement stream"
            );
            ensure!(
                case.identity_record(&target, &id).await?.metadata_value("hostname") == Some("reconnected-host"),
                "replacement Hello reused the previous metadata override"
            );
            let old_stream = field(authenticated[0], "stream_id")?;
            let new_seq = count(authenticated[1], "seq")?;
            ensure!(
                events.iter().any(|event| {
                    event["type"] == "stream_closed"
                        && event["stream_id"] == old_stream
                        && event["status"] == "OK"
                        && event["seq"].as_u64().is_some_and(|seq| seq > new_seq)
                }),
                "Reconnect closed the old stream before the replacement authenticated"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_revocation_stops_agent(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, Some(2), true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            case.until_identity(&target, &id, "initial connection", |record| record.connected)
                .await?;
            ensure!(
                state.get("rejected").is_none(),
                "identity was rejected before revocation"
            );
            let before = time::OffsetDateTime::now_utc();
            target.management().revoke(&id).await?;
            let _ = case
                .until_rejected(&target, &authority, &id, "identity_revoked")
                .await?;
            let revoked = case.identity_record(&target, &id).await?;
            ensure!(!revoked.connected, "revoked agent remains connected");
            assert_terminal_stops(case, &target, &authority, Some(&id), "identity_revoked", before).await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_identity_unknown_recorded(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            case.until_identity(&target, &id, "connection before reset", |record| record.connected)
                .await?;
            ensure!(state.get("rejected").is_none(), "identity was rejected before reset");
            let before = time::OffsetDateTime::now_utc();
            target.reset().await?;
            ensure!(
                case.find_identity_record(&target, &id).await?.is_none(),
                "identity still exists"
            );
            let rejected = case
                .until_rejected(&target, &authority, &id, "identity_unknown")
                .await?;
            ensure!(rejected["rejected"]["at"].as_str().is_some(), "rejection time missing");
            assert_terminal_stops(case, &target, &authority, None, "identity_unknown", before).await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_signed_rejection_without_live_stream(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx.clone(), None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_available": false })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            ensure!(
                !case.identity_record(&target, &id).await?.connected,
                "signed-request rejection fixture unexpectedly opened a channel"
            );
            let before = target.requests(None).await?;
            ensure!(
                count(&before, "renew")? == 0,
                "check-in rejection fixture renewed before revocation"
            );
            let since = time::OffsetDateTime::now_utc();
            target.management().revoke(&id).await?;
            case.until_rejected(&target, &authority, &id, "identity_revoked")
                .await?;
            let after = target.requests(None).await?;
            ensure!(
                count(&after, "check_in")? > count(&before, "check_in")?
                    && count(&after, "renew")? == count(&before, "renew")?,
                "agent did not record identity_revoked from check-in before any renewal"
            );
            assert_terminal_stops(case, &target, &authority, Some(&id), "identity_revoked", since).await?;
            Ok(())
        })
    })
    .await?;
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_broken": true })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            ensure!(
                state["config"]["agent_channel_url"] == target.base_url,
                "channel-open rejection fixture offers no channel"
            );
            ensure!(
                !case.identity_record(&target, &id).await?.connected,
                "channel-open rejection fixture authenticated prematurely"
            );
            let since = time::OffsetDateTime::now_utc();
            target.reset().await?;
            let rejected = case
                .until_rejected(&target, &authority, &id, "identity_unknown")
                .await?;
            ensure!(
                rejected["rejected"]["code"] == "identity_unknown"
                    && count(&target.requests(None).await?, "connect")? > 0,
                "agent did not record identity_unknown from a channel-open rejection"
            );
            assert_terminal_stops(case, &target, &authority, None, "identity_unknown", since).await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_no_channel_when_absent(ctx: Context) -> anyhow::Result<()> {
    let invalid_url_case = ctx.clone();
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_available": false })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            ensure!(
                state["config"].get("agent_channel_url").is_none(),
                "agent stored config.agent_channel_url despite its absence from enrollment"
            );
            let started = Instant::now();
            let first_check_in = loop {
                let requests = target.requests(None).await?;
                if count(&requests, "check_in")? > 0
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| event["type"] == "check_in_received")
                {
                    break count(&requests, "check_in")?;
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "first channelless check-in did not complete");
                tokio::time::sleep(POLL).await;
            };
            ensure!(
                case.identity_record(&target, &id).await?.metadata_value("hostname") == Some(&*case.metadata_hostname),
                "first check-in did not send the current metadata override"
            );
            let first_completed = target
                .events(&id)
                .await?
                .iter()
                .filter(|event| event["type"] == "check_in_received")
                .count();
            case.set_metadata_hostname("second-check-in-host")?;
            let started = Instant::now();
            loop {
                let attempts = count(&target.requests(None).await?, "check_in")?;
                let completed = target
                    .events(&id)
                    .await?
                    .iter()
                    .filter(|event| event["type"] == "check_in_received")
                    .count();
                ensure!(
                    attempts <= first_check_in + 1 && completed <= first_completed + 1,
                    "multiple check-ins occurred before the first post-change send was observed"
                );
                if completed == first_completed + 1 {
                    ensure!(
                        attempts == first_check_in + 1
                            && case.identity_record(&target, &id).await?.metadata["hostname"] == "second-check-in-host",
                        "the first post-change check-in used stale metadata"
                    );
                    break;
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not complete a check-in after the metadata override changed"
                );
                tokio::time::sleep(POLL).await;
            }
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                case.check_running()?;
                ensure!(
                    !case.identity_record(&target, &id).await?.connected,
                    "agent opened an unavailable channel"
                );
                let requests = target.requests(None).await?;
                ensure!(
                    count(&requests, "connect")? == 0 && count(&requests, "channel_attempts")? == 0,
                    "agent attempted a channel despite absent config.agent_channel_url"
                );
            }
            Ok(())
        })
    })
    .await?;
    let insecure_url = invalid_url_case.target.base_url.replacen("https://", "http://", 1);
    no_channel_for_malformed_url(invalid_url_case, "HTTP scheme", json!(true), insecure_url).await
}

async fn no_channel_for_malformed_url(
    ctx: Context,
    variant: &'static str,
    fault: Value,
    expected_url: String,
) -> anyhow::Result<()> {
    with_agent(ctx, None, false, move |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "malformed_channel_url": fault })).await?;
            let config_path = case.path().join("agent.json");
            let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path)?)?;
            config["__debug__"]["identity"]["channel_failure_check_in_after_secs"] = json!(120);
            std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
            case.start().await?;
            let before = target.requests(None).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            ensure!(
                state["config"]["agent_channel_url"] == expected_url,
                "mock did not inject config.agent_channel_url with {variant}"
            );
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                case.check_running()?;
                let requests = target.requests(None).await?;
                ensure!(
                    count(&requests, "connect")? == count(&before, "connect")?
                        && count(&requests, "channel_attempts")? == count(&before, "channel_attempts")?,
                    "agent attempted a channel with {variant} in config.agent_channel_url"
                );
                ensure!(
                    !case.identity_record(&target, &id).await?.connected,
                    "agent authenticated a channel with {variant} in config.agent_channel_url"
                );
            }
            ensure!(
                count(&target.requests(None).await?, "check_in")? > count(&before, "check_in")?
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| event["type"] == "check_in_received"),
                "agent did not check in for {variant} before the delayed broken-channel fallback"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_no_channel_url_with_query(ctx: Context) -> anyhow::Result<()> {
    let expected_url = format!("{}?identity_probe=1", ctx.target.base_url);
    no_channel_for_malformed_url(ctx, "query", json!("query"), expected_url).await
}

pub(crate) async fn a_no_channel_url_with_fragment(ctx: Context) -> anyhow::Result<()> {
    let expected_url = format!("{}#identity_probe", ctx.target.base_url);
    no_channel_for_malformed_url(ctx, "fragment", json!("fragment"), expected_url).await
}

pub(crate) async fn a_config_update_disables_channel(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            case.until_identity(&target, &id, "initial channel", |record| record.connected)
                .await?;
            let before = target.requests(None).await?;
            ensure!(
                count(&before, "check_in")? == 0,
                "agent checked in over HTTP while its channel was working"
            );
            let initial_revision = count(&state["config"], "revision")?;
            target.faults(&json!({ "channel_available": false })).await?;
            let stored = case
                .until_state(&target, &authority, &id, "disabled channel config", |state| {
                    state["config"]["revision"]
                        .as_u64()
                        .is_some_and(|revision| revision > initial_revision)
                        && state["config"].get("agent_channel_url").is_none()
                })
                .await?;
            let disabled_revision = count(&stored["config"], "revision")?;
            case.until_identity(&target, &id, "closed channel after config update", |record| {
                !record.connected
            })
            .await?;
            let events = target.events(&id).await?;
            ensure!(
                events
                    .iter()
                    .any(|event| { event["type"] == "config_update_sent" && event["revision"] == disabled_revision })
                    && events
                        .iter()
                        .any(|event| event["type"] == "stream_closed" && event["status"] == "OK"),
                "channel was not cleanly closed after the higher config revision"
            );
            let connects = count(&target.requests(None).await?, "connect")?;
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                case.check_running()?;
                ensure!(
                    count(&target.requests(None).await?, "connect")? == connects
                        && !case.identity_record(&target, &id).await?.connected
                        && count(&case.state(&authority)?["config"], "revision")? == disabled_revision,
                    "agent retried the channel after its URL was removed"
                );
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_check_in_enables_channel(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_available": false })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let enrolled_revision = count(&state["config"], "revision")?;
            ensure!(
                state["config"].get("agent_channel_url").is_none()
                    && !case.identity_record(&target, &id).await?.connected,
                "agent was enrolled with a channel URL despite disabled availability"
            );
            let start = Instant::now();
            loop {
                if count(&target.requests(None).await?, "check_in")? >= 1 {
                    break;
                }
                case.check_running()?;
                ensure!(start.elapsed() < WAIT, "agent did not check in without a channel URL");
                tokio::time::sleep(POLL).await;
            }
            let before = count(&target.requests(None).await?, "check_in")?;
            target.faults(&json!({ "channel_available": true })).await?;
            let stored = case
                .until_state(
                    &target,
                    &authority,
                    &id,
                    "enabled channel config from check-in",
                    |state| {
                        state["config"]["revision"]
                            .as_u64()
                            .is_some_and(|revision| revision > enrolled_revision)
                            && state["config"]["agent_channel_url"] == target.base_url
                    },
                )
                .await?;
            ensure!(
                count(&target.requests(None).await?, "check_in")? > before,
                "agent did not learn the enabled URL through check-in"
            );
            case.until_identity(&target, &id, "channel opened from check-in config", |record| {
                record.connected
            })
            .await?;
            ensure!(
                stored["config"]["agent_channel_url"] == target.base_url
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| event["type"] == "check_in_received"),
                "agent did not persist the check-in revision before opening a channel"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_check_in_recovers_broken_channel(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_broken": true })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let enrolled_revision = count(&state["config"], "revision")?;
            ensure!(
                state["config"]["agent_channel_url"] == target.base_url,
                "broken transport incorrectly changed the effective config"
            );
            let start = Instant::now();
            loop {
                let requests = target.requests(None).await?;
                if count(&requests, "connect")? >= 1 && count(&requests, "check_in")? >= 1 {
                    break;
                }
                case.check_running()?;
                ensure!(
                    start.elapsed() < WAIT,
                    "agent did not check in after its channel remained broken"
                );
                tokio::time::sleep(POLL).await;
            }
            ensure!(
                !case.identity_record(&target, &id).await?.connected
                    && count(&case.state(&authority)?["config"], "revision")? == enrolled_revision,
                "broken channel was treated as an effective config change"
            );
            let before = count(&target.requests(None).await?, "check_in")?;
            target.faults(&json!({ "channel_available": false })).await?;
            let stored = case
                .until_state(
                    &target,
                    &authority,
                    &id,
                    "disabled config after broken-channel check-in",
                    |state| {
                        state["config"]["revision"]
                            .as_u64()
                            .is_some_and(|revision| revision > enrolled_revision)
                            && state["config"].get("agent_channel_url").is_none()
                    },
                )
                .await?;
            ensure!(
                count(&target.requests(None).await?, "check_in")? > before
                    && stored["config"].get("agent_channel_url").is_none(),
                "agent did not learn the disabled URL through check-in"
            );
            let connects = count(&target.requests(None).await?, "connect")?;
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                case.check_running()?;
                ensure!(
                    count(&target.requests(None).await?, "connect")? == connects
                        && !case.identity_record(&target, &id).await?.connected,
                    "agent kept reconnecting after check-in removed its channel URL"
                );
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_config_unknown_fields_and_hello_revision(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            case.until_identity(&target, &id, "initial channel", |record| record.connected)
                .await?;
            let initial_revision = count(&state["config"], "revision")?;
            let before = target.events(&id).await?;
            let authenticated_before = before
                .iter()
                .filter(|event| event["type"] == "stream_authenticated")
                .collect::<Vec<_>>();
            ensure!(
                authenticated_before
                    .iter()
                    .any(|event| { event["applied_config_revision"] == initial_revision })
                    && count(&target.requests(None).await?, "check_in")? == 0,
                "working channel did not report its stored revision or checked in over HTTP"
            );
            let acks_before = count(&target.requests(None).await?, "correlated_acks")?;
            expect_status(
                &target
                    .control(
                        "config",
                        &json!({ "fields": { "product_hint": { "mode": "preserved" } } }),
                    )
                    .await?,
                200,
            )?;
            let stored = case
                .until_state(&target, &authority, &id, "unknown pushed config field", |state| {
                    state["config"]["revision"]
                        .as_u64()
                        .is_some_and(|revision| revision > initial_revision)
                        && state["config"]["product_hint"] == json!({ "mode": "preserved" })
                })
                .await?;
            let revision = count(&stored["config"], "revision")?;
            let started = Instant::now();
            loop {
                if count(&target.requests(None).await?, "correlated_acks")? > acks_before {
                    break;
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "agent did not acknowledge ConfigUpdate");
                tokio::time::sleep(POLL).await;
            }
            ensure!(
                count(&target.requests(None).await?, "check_in")? == 0
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| { event["type"] == "config_update_sent" && event["revision"] == revision }),
                "agent polled HTTP despite a working channel config update"
            );
            let acks_before_stale = count(&target.requests(None).await?, "correlated_acks")?;
            let injected_reply = target
                .control(
                    "config/stale",
                    &json!({ "identity_id": id, "revision": initial_revision }),
                )
                .await?;
            expect_status(&injected_reply, 200)?;
            ensure!(injected_reply.body["sent"] == 1, "stale ConfigUpdate was not delivered");
            let started = Instant::now();
            loop {
                if count(&target.requests(None).await?, "correlated_acks")? > acks_before_stale {
                    break;
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not acknowledge the stale ConfigUpdate"
                );
                tokio::time::sleep(POLL).await;
            }
            let after_stale = case.state(&authority)?;
            ensure!(
                after_stale["config"] == stored["config"]
                    && after_stale["config"].get("mock_stale_marker").is_none()
                    && target.events(&id).await?.iter().any(|event| {
                        event["type"] == "stale_config_update_sent" && event["revision"] == initial_revision
                    }),
                "agent applied a decreasing config revision"
            );
            expect_status(&target.control("reconnect", &json!({ "identity_id": id })).await?, 202)?;
            let started = Instant::now();
            loop {
                let events = target.events(&id).await?;
                let authenticated = events
                    .iter()
                    .filter(|event| event["type"] == "stream_authenticated")
                    .collect::<Vec<_>>();
                if authenticated.len() > authenticated_before.len() {
                    ensure!(
                        authenticated
                            .last()
                            .is_some_and(|event| event["applied_config_revision"] == revision),
                        "reconnected Hello did not report the stored config revision"
                    );
                    break;
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "agent did not reconnect after mock push");
                tokio::time::sleep(POLL).await;
            }
            ensure!(
                count(&target.requests(None).await?, "check_in")? == 0
                    && case.state(&authority)?["config"]["product_hint"] == json!({ "mode": "preserved" }),
                "agent lost the unknown config field or checked in with a working channel"
            );
            // Hold the healthy channel beyond two five-second check-in intervals.
            tokio::time::sleep(Duration::from_secs(12)).await;
            case.check_running()?;
            ensure!(
                count(&target.requests(None).await?, "check_in")? == 0
                    && case.identity_record(&target, &id).await?.connected,
                "agent checked in periodically despite a working channel"
            );
            Ok(())
        })
    })
    .await
}

fn completed_check_ins(events: &[Value]) -> usize {
    events
        .iter()
        .filter(|event| event["type"] == "check_in_received")
        .count()
}

pub(crate) async fn a_config_unsupported_version_keeps_stored_config(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_available": false })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let stored = state["config"].clone();
            let stored_revision = count(&stored, "revision")?;
            ensure!(
                stored["version"] == 1,
                "agent stored an enrollment config whose version is not 1"
            );
            let started = Instant::now();
            while completed_check_ins(&target.events(&id).await?) == 0 {
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "agent did not check in without a channel");
                tokio::time::sleep(POLL).await;
            }
            target.faults(&json!({ "config_version": 2 })).await?;
            let baseline = completed_check_ins(&target.events(&id).await?);
            let started = Instant::now();
            while completed_check_ins(&target.events(&id).await?) < baseline + 2 {
                let current = case.state(&authority)?;
                ensure!(
                    current["config"] == stored && current.get("rejected").is_none(),
                    "agent replaced its stored config with an unsupported config version"
                );
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent stopped checking in after receiving an unsupported config version"
                );
                tokio::time::sleep(POLL).await;
            }
            ensure!(
                case.state(&authority)?["config"] == stored,
                "agent replaced its stored config with an unsupported config version"
            );
            target.faults(&json!({ "config_version": null })).await?;
            let updated = case
                .until_state(&target, &authority, &id, "the supported config version", |state| {
                    state["config"]["version"] == 1
                        && state["config"]["revision"]
                            .as_u64()
                            .is_some_and(|revision| revision > stored_revision)
                })
                .await?;
            ensure!(
                updated.get("rejected").is_none(),
                "agent recorded a rejection after an unsupported config version"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_config_unsupported_version_on_enroll_keeps_pending(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target
                .faults(&json!({ "channel_available": false, "config_version": 2 }))
                .await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let started = Instant::now();
            while count(&target.requests(Some(&token)).await?, "enroll")? < 2 {
                ensure!(
                    case.pending_path().exists() && !case.has_stored_identity()?,
                    "agent stored an identity or dropped its pending file for an unsupported config version"
                );
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not retry an enrollment answered with an unsupported config version"
                );
                tokio::time::sleep(POLL).await;
            }
            ensure!(
                case.pending_path().exists()
                    && !case.has_stored_identity()?
                    && !case.rejection_path_for(&token.text).exists(),
                "agent treated an unsupported config version on enrollment as final"
            );
            target.faults(&json!({ "config_version": null })).await?;
            let (_, state) = case.enrolled(&target, &token).await?;
            ensure!(
                state["config"]["version"] == 1,
                "agent stored an enrollment config whose version is not 1"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_multi_authority(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let first = case.ctx.target.clone();
            let second = case.ctx.second.clone().context("second authority required")?;
            let first_token = first
                .management()
                .create_token(1, Duration::from_secs(3600), None)
                .await?;
            case.write_pending(&first_token.text)?;
            let (first_id, first_state) = case.enrolled(&first, &first_token).await?;
            let first_authority = field(&first_state, "authority_id")?.to_owned();
            case.until_identity(&first, &first_id, "first connection", |record| record.connected)
                .await?;
            let second_token = second
                .management()
                .create_token(1, Duration::from_secs(3600), None)
                .await?;
            case.write_pending(&second_token.text)?;
            let (second_id, second_state) = case.enrolled(&second, &second_token).await?;
            let second_authority = field(&second_state, "authority_id")?.to_owned();
            ensure!(
                first_authority != second_authority,
                "two mocks returned the same authority ID"
            );
            case.until_identity(&second, &second_id, "second connection", |record| record.connected)
                .await?;
            ensure!(
                case.identity_record(&first, &first_id).await?.connected,
                "first authority was disconnected"
            );
            ensure!(
                case.identity_path(&first_authority).exists(),
                "first identity not stored"
            );
            ensure!(
                case.identity_path(&second_authority).exists(),
                "second identity not stored"
            );
            ensure!(
                first_state["token_sha256"] == token_file_id(&first_token.text)
                    && second_state["token_sha256"] == token_file_id(&second_token.text),
                "multi-authority token hashes are incorrect"
            );
            case.stop().await?;
            case.until_identity(&first, &first_id, "first authority offline", |record| !record.connected)
                .await?;
            case.until_identity(&second, &second_id, "second authority offline", |record| {
                !record.connected
            })
            .await?;
            case.start().await?;
            case.until_identity(&first, &first_id, "first authority reconnected", |record| {
                record.connected
            })
            .await?;
            case.until_identity(&second, &second_id, "second authority reconnected", |record| {
                record.connected
            })
            .await?;
            ensure!(
                case.state(&first_authority)?["token_sha256"] == first_state["token_sha256"]
                    && case.state(&second_authority)?["token_sha256"] == second_state["token_sha256"],
                "multi-authority identities changed across restart"
            );
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_key_non_exportable(ctx: Context) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        ensure!(
            ctx.key_backend == KeyBackend::WindowsSoftwareProvider,
            "Windows non-exportability requires Windows software provider backend"
        );
        with_agent(ctx.clone(), None, true, |case| {
            Box::pin(async move {
                let target = case.ctx.target.clone();
                let token = new_token(case, 1).await?;
                case.write_pending(&token.text)?;
                let (id, state) = case.enrolled(&target, &token).await?;
                crate::windows::assert_non_exportable(key_name(&state, "current")?)?;
                crate::windows::assert_machine_key_acl(key_name(&state, "current")?)?;
                case.check_key_protection(field(&state, "authority_id")?, &state)?;
                if case.ctx.channel_available {
                    case.until_identity(&target, &id, "signed channel Hello", |record| record.connected)
                        .await?;
                } else {
                    case.set_metadata_hostname("acl-signing-probe")?;
                    case.until_identity(&target, &id, "signed check-in", |record| {
                        record.metadata_value("hostname") == Some("acl-signing-probe")
                    })
                    .await?;
                }
                Ok(())
            })
        })
        .await?;
        if !crate::windows::running_as_system()? {
            if !crate::windows::running_as_elevated_administrator()? {
                return Err(crate::Incomplete("requires an elevated administrator for the SYSTEM fixture").into());
            }
            return system_fixture::run(ctx).await;
        }
        return with_agent(ctx, None, false, |case| {
            Box::pin(async move {
                case.set_acl_grant_current_user(false)?;
                case.start().await?;
                let target = case.ctx.target.clone();
                let token = new_token(case, 1).await?;
                case.write_pending(&token.text)?;
                let (id, state) = case.enrolled(&target, &token).await?;
                let key = key_name(&state, "current")?;
                crate::windows::assert_non_exportable(key)?;
                crate::windows::assert_machine_key_acl(key)?;
                case.check_key_protection(field(&state, "authority_id")?, &state)?;
                if case.ctx.channel_available {
                    case.until_identity(&target, &id, "SYSTEM-only key signed channel Hello", |record| {
                        record.connected
                    })
                    .await?;
                } else {
                    case.set_metadata_hostname("system-acl-signing-probe")?;
                    case.until_identity(&target, &id, "SYSTEM-only key signed check-in", |record| {
                        record.metadata_value("hostname") == Some("system-acl-signing-probe")
                    })
                    .await?;
                }
                Ok(())
            })
        })
        .await;
    }
    #[cfg(not(windows))]
    {
        let _ = ctx;
        anyhow::bail!("non-exportable key test is Windows-only")
    }
}

pub(crate) async fn a_file_backend_permissions(ctx: Context) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        ensure!(
            ctx.key_backend == KeyBackend::File,
            "Unix permission test requires file backend"
        );
        return with_agent(ctx, None, true, |case| {
            Box::pin(async move {
                let target = case.ctx.target.clone();
                let token = new_token(case, 1).await?;
                case.write_pending(&token.text)?;
                let (_, state) = case.enrolled(&target, &token).await?;
                let name = key_name(&state, "current")?;
                let key_file = case.key_file_path(name);
                assert_file_key_access(&key_file)?;
                Ok(())
            })
        })
        .await;
    }
    #[cfg(not(unix))]
    {
        let _ = ctx;
        anyhow::bail!("file permission test is Unix-only")
    }
}

pub(crate) async fn a_rotation_migrates_connected_agent(ctx: Context) -> anyhow::Result<()> {
    ensure!(
        ctx.mock() || ctx.disposable_dvls_target,
        "DVLS rotation requires --disposable-dvls-target"
    );
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, initial_state) = case.enrolled(&target, &token).await?;
            let authority = field(&initial_state, "authority_id")?.to_owned();
            let old = case
                .until_identity(&target, &id, "old-root connection", |record| record.connected)
                .await?;
            let old_root = old.issuer().context("identity has no current certificate")?.to_owned();
            let started = if case.ctx.mock() {
                target.management().rotate(RotationDeadline::Default).await?
            } else {
                crate::protocol::wait_rotation_idle(&target, case.ctx.dvls_rotation_window_secs).await?;
                let deadline = time::OffsetDateTime::now_utc()
                    + time::Duration::seconds(i64::try_from(case.ctx.dvls_rotation_window_secs)?);
                target.management().rotate(RotationDeadline::At(deadline)).await?
            };
            let initial = started.active_identities_on_old_root;
            ensure!(initial >= 1, "the agent's old-root identity was not counted");
            let new = case
                .until_identity(&target, &id, "connected new-root certificate", |record| {
                    record.issuer() != Some(&*old_root)
                        && record.connected
                        && record
                            .certificates
                            .as_ref()
                            .is_some_and(|items| items.iter().any(|cert| cert.status == CertificateStatus::Retired))
                })
                .await?;
            ensure!(new.issuer() != Some(&*old_root), "agent did not migrate roots");
            let new_root = new.issuer().context("identity has no current certificate")?.to_owned();
            let stored = case
                .until_state(&target, &authority, &id, "stored new-root chain", |state| {
                    state["keys"]["current"]["certificate_chain"]
                        .as_array()
                        .and_then(|chain| chain.last())
                        .and_then(Value::as_str)
                        .and_then(|root| crate::signer::thumbprint(root).ok())
                        .is_some_and(|issuer| issuer == new_root)
                        && state["keys"].get("pending").is_none()
                        && state["keys"].get("previous").is_none()
                })
                .await?;
            ensure!(
                stored["keys"]["current"]["certificate_chain"]
                    .as_array()
                    .is_some_and(|chain| chain.len() >= 2),
                "migrated agent did not persist the new-root chain"
            );
            case.stop().await?;
            case.until_identity(&target, &id, "offline new-root channel", |record| !record.connected)
                .await?;
            let authenticated_before = if case.ctx.mock() {
                Some(count(&target.requests(None).await?, "authenticated_connects")?)
            } else {
                None
            };
            case.start().await?;
            case.until_identity(&target, &id, "new-root channel after restart", |record| {
                record.connected && record.issuer() == Some(&*new_root)
            })
            .await?;
            if let Some(before) = authenticated_before {
                ensure!(
                    count(&target.requests(None).await?, "authenticated_connects")? > before,
                    "restarted agent did not authenticate its new-root channel"
                );
            }
            let rotation = target.management().rotation().await?;
            if rotation.rotating() {
                ensure!(
                    rotation.active_identities_on_old_root < initial,
                    "agent migration did not reduce the old-root count"
                );
            }
            if !case.ctx.mock() {
                crate::protocol::wait_rotation_idle(&target, case.ctx.dvls_rotation_window_secs).await?;
            }
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_rotation_migrates_through_check_in(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_available": false })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, initial_state) = case.enrolled(&target, &token).await?;
            let authority = field(&initial_state, "authority_id")?.to_owned();
            let before = case.identity_record(&target, &id).await?;
            ensure!(!before.connected, "channel unavailable but agent connected");
            let old_root = before
                .issuer()
                .context("identity has no current certificate")?
                .to_owned();
            let before_requests = target.requests(None).await?;
            let confirms_before = count(&before_requests, "confirm")?;
            let blocked_before = count(&before_requests, "confirm_retry_503")?;
            let check_ins_before = count(&before_requests, "check_in")?;
            let rotation_sequence_start = before_requests["request_sequence"]
                .as_array()
                .context("mock request sequence missing")?
                .len();
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                    .await?,
                200,
            )?;
            target
                .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
                .await?;
            target.management().rotate(RotationDeadline::Default).await?;
            let new = case
                .until_identity(&target, &id, "check-in-triggered new-root renewal", |record| {
                    record.certificates.as_ref().is_some_and(|certs| {
                        certs
                            .iter()
                            .any(|cert| cert.issuer != old_root && cert.status == CertificateStatus::Pending)
                    })
                })
                .await?;
            ensure!(
                count(&target.requests(None).await?, "check_in")? > check_ins_before
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| { event["type"] == "check_in_received" && event["renewal_requested"] == true }),
                "channelless rotation did not request renewal through check-in"
            );
            ensure!(!new.connected, "scheduled renewal unexpectedly required a channel");
            let pending = new
                .certificates
                .as_ref()
                .context("scheduled certificates missing")?
                .iter()
                .find(|cert| cert.issuer != old_root && cert.status == CertificateStatus::Pending)
                .context("new-root pending certificate missing")?;
            let new_root = pending.issuer.clone();
            let pending_thumb = pending.thumbprint.clone();
            let stored = case
                .until_state(&target, &authority, &id, "stored pending new-root chain", |state| {
                    state["keys"]["pending"]["certificate_chain"]
                        .as_array()
                        .and_then(|chain| chain.last())
                        .and_then(Value::as_str)
                        .and_then(|root| crate::signer::thumbprint(root).ok())
                        .is_some_and(|issuer| issuer == new_root)
                })
                .await?;
            let pending_key = key_name(&stored, "pending")?.to_owned();
            let started = Instant::now();
            loop {
                let requests = target.requests(None).await?;
                if count(&requests, "confirm")? > confirms_before
                    && count(&requests, "confirm_retry_503")? > blocked_before
                    && target.control("faults", &json!({})).await?.body["fail_next_response"].is_null()
                {
                    break;
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not retry confirm after new-root renewal"
                );
                tokio::time::sleep(POLL).await;
            }
            case.stop().await?;
            ensure!(
                key_name(&case.state(&authority)?, "pending")? == pending_key
                    && case
                        .identity_record(&target, &id)
                        .await?
                        .has_certificate(&pending_thumb, CertificateStatus::Pending),
                "new-root pending key was not persisted across restart"
            );
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                    .await?,
                200,
            )?;
            let before_restart = target.requests(None).await?;
            let restart_sequence_start = before_restart["request_sequence"]
                .as_array()
                .context("mock request sequence missing")?
                .len();
            let confirms = count(&before_restart, "confirm")?;
            case.start().await?;
            case.until_identity(&target, &id, "confirmed new-root key after restart", |record| {
                record.issuer() == Some(&*new_root)
                    && current_thumbprint(record).is_ok_and(|thumb| thumb == pending_thumb)
            })
            .await?;
            let requests = target.requests(None).await?;
            ensure!(
                count(&requests, "confirm")? > confirms
                    && requests["request_sequence"]
                        .as_array()
                        .and_then(|sequence| sequence.get(restart_sequence_start))
                        .is_some_and(|entry| entry == "confirm"),
                "agent did not retry confirm first with its persisted pending key"
            );
            assert_check_in_triggers_renewal(&requests, rotation_sequence_start)?;
            case.until_state(
                &target,
                &authority,
                &id,
                "the confirmed new-root chain after restart",
                |state| {
                    key_name(state, "current").is_ok_and(|name| name == pending_key)
                        && state["keys"]["current"]["certificate_chain"]
                            .as_array()
                            .and_then(|chain| chain.last())
                            .and_then(Value::as_str)
                            .is_some_and(|root| crate::signer::thumbprint(root).is_ok_and(|issuer| issuer == new_root))
                        && state["keys"].get("pending").is_none()
                        && state["keys"].get("previous").is_none()
                },
            )
            .await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_rotation_migrates_on_schedule(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, Some(50), false, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_available": false })).await?;
            let config_path = case.path().join("agent.json");
            let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path)?)?;
            // Keep the next check-in later than scheduled renewal so it cannot deliver the rotation request.
            config["__debug__"]["identity"]["check_in_interval_secs"] = json!(120);
            std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;

            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            case.start().await?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            ensure!(
                state["config"].get("agent_channel_url").is_none(),
                "scheduled-rotation fixture unexpectedly offers a channel"
            );
            let old = case.identity_record(&target, &id).await?;
            ensure!(!old.connected, "scheduled-rotation fixture connected");
            let old_root = old.issuer().context("identity has no current certificate")?.to_owned();
            let old_thumb = current_thumbprint(&old)?.to_owned();
            let started = Instant::now();
            loop {
                if count(&target.requests(None).await?, "check_in")? > 0 {
                    break;
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not check in before scheduled rotation"
                );
                tokio::time::sleep(POLL).await;
            }
            let before = target.requests(None).await?;
            ensure!(
                count(&before, "renew")? == 0 && count(&before, "confirm")? == 0,
                "agent renewed before rotation began"
            );
            target.management().rotate(RotationDeadline::Default).await?;
            let wait = Instant::now();
            let migrated = loop {
                let record = case.identity_record(&target, &id).await?;
                if record.issuer() != Some(&*old_root) && !record.renewal_requested && !record.connected {
                    break record;
                }
                case.check_running()?;
                ensure!(
                    wait.elapsed() < Duration::from_secs(70),
                    "agent did not migrate roots on schedule before the next check-in"
                );
                tokio::time::sleep(POLL).await;
            };
            let new_root = migrated
                .issuer()
                .context("identity has no current certificate")?
                .to_owned();
            let after = target.requests(None).await?;
            ensure!(
                count(&after, "check_in")? == count(&before, "check_in")?
                    && count(&after, "renew")? > count(&before, "renew")?
                    && count(&after, "confirm")? > count(&before, "confirm")?
                    && count(&after, "channel_attempts")? == 0
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| { event["type"] == "renew_received" && event["cert_thumbprint"] == old_thumb }),
                "agent did not renew under the new root on schedule before another check-in"
            );
            case.until_state(&target, &authority, &id, "stored scheduled new-root chain", |state| {
                state["keys"]["current"]["certificate_chain"]
                    .as_array()
                    .and_then(|chain| chain.last())
                    .and_then(Value::as_str)
                    .and_then(|root| crate::signer::thumbprint(root).ok())
                    .is_some_and(|issuer| issuer == new_root)
                    && state["keys"].get("pending").is_none()
                    && state["keys"].get("previous").is_none()
            })
            .await?;
            Ok(())
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::EncodePrivateKey as _;

    use super::*;

    #[test]
    fn key_names_require_this_runs_prefix_and_a_canonical_uuid() -> anyhow::Result<()> {
        let prefix = format!("conformance-{}", uuid::Uuid::new_v4().simple());
        let key_uuid = uuid::Uuid::new_v4();
        let name = format!("{prefix}_{key_uuid}");
        validate_key_name(&prefix, &name)?;
        validate_key_name(
            "devolutions-agent-identity",
            &format!("devolutions-agent-identity_{key_uuid}"),
        )?;
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}_{}", key_uuid.to_string().to_uppercase())).is_err(),
            "uppercase UUID was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("devolutions-agent-identity_{key_uuid}")).is_err(),
            "a key without the run prefix was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}_{key_uuid}.p8")).is_err(),
            "a key name with a file extension was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}{key_uuid}")).is_err(),
            "a key name without the underscore separator was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}-other_{key_uuid}")).is_err()
                && !key_belongs_to_run(&format!("{prefix}-other_{key_uuid}"), &prefix),
            "a longer prefix was treated as this run's prefix"
        );
        for invalid in ["", "Conformance", "conformance_", "conformance.dot"] {
            ensure!(
                validate_key_name(invalid, &format!("{invalid}_{key_uuid}")).is_err(),
                "invalid device-key prefix {invalid:?} was accepted"
            );
        }
        let too_long = "a".repeat(65);
        let max_length = "a".repeat(64);
        validate_key_name(&max_length, &format!("{max_length}_{key_uuid}"))?;
        ensure!(
            validate_key_name(&too_long, &format!("{too_long}_{key_uuid}")).is_err(),
            "a device-key prefix longer than 64 characters was accepted"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn error_log_level_is_distinct_from_message_text() {
        assert!(is_error_level_log_line(
            "2026-10-19T00:00:00Z ERROR devolutions_agent: unavailable backend"
        ));
        assert!(is_error_level_log_line(
            r#"{"level":"error","fields":{"message":"unavailable backend"}}"#
        ));
        assert!(!is_error_level_log_line(
            "2026-10-19T00:00:00Z INFO devolutions_agent: ERROR was returned"
        ));
        assert!(is_error_level_log_line(
            "\u{1b}[2m2026-10-19T00:00:00Z\u{1b}[0m \u{1b}[31mERROR\u{1b}[0m \u{1b}[2mdevolutions_agent\u{1b}[0m\u{1b}[2m:\u{1b}[0m unavailable backend"
        ));
        assert!(!is_error_level_log_line(
            "\u{1b}[2m2026-10-19T00:00:00Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mdevolutions_agent\u{1b}[0m\u{1b}[2m:\u{1b}[0m ERROR was returned"
        ));
    }

    #[tokio::test]
    async fn orphan_audit_accepts_both_records_and_cleanup_is_prefix_scoped() -> anyhow::Result<()> {
        let work_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-identity-conformance-tests");
        std::fs::create_dir_all(&work_dir)?;
        let prefix = format!("conformance-{}", uuid::Uuid::new_v4().simple());
        let target = Target::new(
            "https://localhost/mock".to_owned(),
            crate::dvls::AppCredential::new("test".to_owned(), "test".to_owned()),
            None,
            None,
        )?;
        let mut case = AgentCase::new(
            Context {
                target,
                second: None,
                target_kind: crate::TargetKind::Mock,
                disposable_dvls_target: false,
                dvls_rotation_window_secs: 60,
                leaf_lifetime_secs: 90 * 24 * 3600,
                expect_channel: true,
                channel_available: true,
                key_name_prefix: prefix.clone(),
                agent_version: None,
                unprivileged: None,
                agent_bin: PathBuf::new(),
                key_backend: KeyBackend::File,
                work_dir,
            },
            None,
            false,
        )
        .await?;
        let fixture_token = "dvaet1.fixturebag.fixturesecret";
        let fixture_hash = token_file_id(fixture_token);
        case.add_token(fixture_token);
        let pending_name = case
            .pending_path()
            .file_name()
            .context("pending filename")?
            .to_string_lossy()
            .to_string();
        ensure!(
            pending_name.starts_with(&token_file_id(fixture_token)) && token_file_id(fixture_token).len() == 64,
            "pending filename is not keyed by the full token SHA-256"
        );
        let config: Value = serde_json::from_slice(&std::fs::read(case.path().join("agent.json"))?)?;
        ensure!(
            config["__debug__"]["identity"]["key_name_prefix"] == prefix,
            "agent.json omitted the run prefix"
        );
        ensure!(
            config["__debug__"]["identity"]["metadata_override_path"]
                == case.metadata_override_path().to_string_lossy().as_ref(),
            "agent.json omitted the metadata override path"
        );
        case.set_metadata_hostname("refreshed-host")?;
        ensure!(
            serde_json::from_slice::<Value>(&std::fs::read(case.metadata_override_path())?)?["hostname"]
                == "refreshed-host",
            "metadata override was not refreshed"
        );
        let name = format!("{prefix}_{}", uuid::Uuid::new_v4());
        let foreign = format!("devolutions-agent-identity_{}", uuid::Uuid::new_v4());
        let overlapping = format!("{prefix}-other_{}", uuid::Uuid::new_v4());
        std::fs::create_dir_all(case.key_file_path(&name).parent().context("key directory")?)?;
        let write_run_key = |path: &Path| -> anyhow::Result<()> {
            #[cfg(unix)]
            {
                use std::io::Write as _;
                use std::os::unix::fs::OpenOptionsExt as _;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)?;
                file.write_all(b"run-owned-key")?;
            }
            #[cfg(not(unix))]
            std::fs::write(path, b"run-owned-key")?;
            Ok(())
        };
        write_run_key(&case.key_file_path(&name))?;
        std::fs::write(case.key_file_path(&foreign), b"foreign-key")?;
        std::fs::write(case.key_file_path(&overlapping), b"other-run-key")?;
        ensure!(
            case.audit_identity_tree().is_err(),
            "an unexpected key file in the identity tree was accepted"
        );
        ensure!(
            case.audit_orphan_keys().is_err(),
            "an unrecorded file-backed key was accepted"
        );
        std::fs::create_dir_all(case.in_progress_path().parent().context("pending directory")?)?;
        std::fs::write(
            case.in_progress_path(),
            serde_json::to_vec(&json!({ "version": 1, "token_sha256": fixture_hash, "key_name": name }))?,
        )?;
        case.audit_orphan_keys()?;
        std::fs::remove_file(case.key_file_path(&foreign))?;
        std::fs::remove_file(case.key_file_path(&overlapping))?;
        case.audit_identity_tree()?;
        case.ctx.key_backend = KeyBackend::WindowsSoftwareProvider;
        ensure!(
            case.audit_identity_tree().is_err(),
            "Windows software provider backend accepted a file-backed key"
        );
        case.ctx.key_backend = KeyBackend::File;
        write_run_key(&case.key_file_path(&foreign))?;
        write_run_key(&case.key_file_path(&overlapping))?;
        std::fs::remove_file(case.in_progress_path())?;
        let identity = case.identity_path(&uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(identity.parent().context("authority directory")?)?;
        std::fs::write(
            &identity,
            serde_json::to_vec(&json!({ "keys": { "current": { "key_name": name } } }))?,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600))?;
        }
        let stored: Value = serde_json::from_slice(&std::fs::read(&identity)?)?;
        let authority = identity
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .context("fixture authority")?;
        case.check_key_protection(authority, &stored)?;
        std::fs::remove_file(case.key_file_path(&name))?;
        ensure!(
            case.check_key_protection(authority, &stored).is_err(),
            "settled identity accepted a missing current key"
        );
        write_run_key(&case.key_file_path(&name))?;
        case.audit_orphan_keys()?;
        std::fs::remove_file(&identity)?;
        std::fs::write(
            case.in_progress_path(),
            serde_json::to_vec(&json!({ "version": 1, "token_sha256": fixture_hash, "key_name": name }))?,
        )?;
        case.cleanup_run_keys()?;
        ensure!(!case.key_file_path(&name).exists(), "run-owned key survived cleanup");
        ensure!(
            case.key_file_path(&foreign).exists(),
            "cleanup deleted a key outside the run prefix"
        );
        ensure!(
            case.key_file_path(&overlapping).exists(),
            "cleanup deleted a key with a longer prefix"
        );
        std::fs::remove_file(case.key_file_path(&foreign))?;
        std::fs::remove_file(case.key_file_path(&overlapping))?;
        case.audit_identity_tree()?;
        let unknown = case.path().join("identity").join("notes").join("unknown.bin");
        std::fs::create_dir_all(unknown.parent().context("unknown entry parent")?)?;
        std::fs::write(&unknown, b"non-key data")?;
        case.audit_identity_tree()?;
        let unexpected_key = unknown.with_file_name("other.p8");
        std::fs::write(&unexpected_key, b"not even a PKCS#8 key")?;
        ensure!(
            case.audit_identity_tree().is_err(),
            "nested unrecorded .p8 file was accepted"
        );
        std::fs::remove_file(unexpected_key)?;
        let pkcs8 = p256::SecretKey::generate_from_rng(&mut rand::rng()).to_pkcs8_der()?;
        std::fs::write(&unknown, pkcs8.as_bytes())?;
        ensure!(
            case.audit_identity_tree().is_err(),
            "unrecorded PKCS#8 DER was accepted"
        );
        std::fs::write(
            &unknown,
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(pkcs8.as_bytes())
            ),
        )?;
        ensure!(
            case.audit_identity_tree().is_err(),
            "unrecorded PKCS#8 PEM was accepted"
        );
        let encrypted_pkcs8 = base64::engine::general_purpose::STANDARD.decode(
            "MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBDtKK//RHOS2x0YBSFGGtPAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQKvLa4jZ8A4WkKva7UtVXYQSBkEduwKFQc7aMPm4ZYJQGbaBB72cZ+GZ3lsNoaJaVZcwLNBLXwUgfQEnx6o5L7LAa8/L2G+6X6uJxnxyQzH4yhvW7RqambZYzGluT8kf3uxdu/TBlAfjKRZQht0Q5niBAmut2MbKgfAk4JryXi/mKvQ0QAMDN6grm1Nlq2xa5ZgCILNnfErEQbRexpKQiSLSW9w==",
        )?;
        std::fs::write(&unknown, encrypted_pkcs8)?;
        ensure!(
            case.audit_identity_tree().is_err(),
            "unrecorded encrypted PKCS#8 DER was accepted"
        );
        std::fs::remove_file(unknown)?;
        let unrelated = identity.with_file_name(".identity.json.notes");
        std::fs::write(&unrelated, b"not a temporary file")?;
        case.audit_identity_tree()?;
        std::fs::remove_file(unrelated)?;
        let template = identity.with_file_name(".identity.json.template");
        std::fs::write(&template, b"also not a temporary file")?;
        case.audit_identity_tree()?;
        std::fs::remove_file(template)?;
        let leftover = identity.with_file_name("identity.json.tmp");
        std::fs::write(&leftover, b"temp")?;
        ensure!(
            case.audit_identity_tree().is_err(),
            "leftover identity.json sibling was accepted"
        );
        std::fs::remove_file(leftover)?;
        for leftover in [
            case.pending_path()
                .with_extension(if cfg!(windows) { "dat.tmp" } else { "json.tmp" }),
            case.key_file_path(&name).with_extension("p8.tmp"),
        ] {
            std::fs::write(&leftover, b"temp")?;
            ensure!(
                case.audit_identity_tree().is_err(),
                "leftover pending or key-file sibling was accepted"
            );
            std::fs::remove_file(leftover)?;
        }
        std::fs::remove_file(case.in_progress_path())?;
        ensure!(
            case.recorded_key_names()?.is_empty(),
            "the removed key is still recorded"
        );
        let untracked_pending = case
            .path()
            .join("identity")
            .join("pending")
            .join(format!("{}.json.tmp", token_file_id("untracked-token")));
        std::fs::write(&untracked_pending, b"partial temporary file")?;
        ensure!(
            case.audit_identity_tree().is_err(),
            "temporary sibling survived after its record was removed"
        );
        std::fs::remove_file(untracked_pending)?;
        for copy in [
            case.key_file_path(&name).with_extension("p8.tmp"),
            case.key_file_path(&name)
                .with_file_name(format!(".{name}-{}.deleted", uuid::Uuid::new_v4())),
        ] {
            std::fs::write(&copy, pkcs8.as_bytes())?;
            case.audit_identity_tree()
                .context("a leftover copy of a deleted key before a later key-store operation was rejected")?;
            ensure!(
                assert_no_copy_of_deleted_key(&case, &name).is_err(),
                "a leftover copy of a deleted key was not reported"
            );
            std::fs::remove_file(copy)?;
        }
        case.audit_identity_tree()?;
        let unknown_authority = case
            .path()
            .join("identity")
            .join("authorities")
            .join("not-an-authority");
        std::fs::create_dir_all(&unknown_authority)?;
        std::fs::write(unknown_authority.join("identity.json"), b"not an identity")?;
        case.audit_identity_tree()?;
        case.audit_stored_keys()?;
        case.audit_orphan_keys()?;
        std::fs::remove_dir_all(unknown_authority)?;
        case.finish().await?;
        Ok(())
    }

    #[test]
    fn agent_metadata_requires_c14_fields_and_stable_platform_values() -> anyhow::Result<()> {
        let mut metadata = json!({
            "hostname": "test-host",
            "os_name": "Windows",
            "os_version": "11",
            "arch": std::env::consts::ARCH,
            "agent_version": "2026.3.0"
        });
        #[cfg(target_os = "linux")]
        if Path::new("/etc/machine-id").exists() {
            metadata["machine_id"] = json!(std::fs::read_to_string("/etc/machine-id")?.trim());
        }
        validate_agent_metadata(&metadata, Some("2026.3.0"))?;
        for key in REQUIRED_METADATA_KEYS {
            let mut missing = metadata.clone();
            missing.as_object_mut().context("fixture metadata")?.remove(key);
            ensure!(
                validate_agent_metadata(&missing, Some("2026.3.0")).is_err(),
                "missing {key} was accepted"
            );
        }
        let mut unknown = metadata.clone();
        unknown["custom"] = json!("value");
        ensure!(
            validate_agent_metadata(&unknown, None).is_err(),
            "unknown metadata key was accepted"
        );
        metadata["arch"] = json!("wrong-platform");
        ensure!(
            validate_agent_metadata(&metadata, None).is_err(),
            "wrong architecture was accepted"
        );
        metadata["arch"] = json!(std::env::consts::ARCH);
        ensure!(
            validate_agent_metadata(&metadata, Some("different-version")).is_err(),
            "wrong agent version was accepted"
        );
        Ok(())
    }
}
