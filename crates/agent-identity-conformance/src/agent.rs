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
use http::Method;
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
use crate::protocol::has_certificate;
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

fn validate_key_name(prefix: &str, name: &str) -> anyhow::Result<()> {
    let key_uuid = name
        .strip_prefix(prefix)
        .with_context(|| format!("key name {name} does not start with run prefix {prefix}"))?;
    let parsed = uuid::Uuid::parse_str(key_uuid).context("key name does not end with a UUID")?;
    ensure!(
        parsed.to_string() == key_uuid,
        "key name does not end with a lowercase hyphenated UUID"
    );
    Ok(())
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
    #[cfg(windows)]
    acl_grant_current_user: bool,
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
                // Interpret CONTRACT.md §10.1's extra_trusted_root path as a PEM bundle containing both mock CAs.
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
        #[cfg(windows)]
        let acl_grant_current_user = identity_debug["acl_grant_current_user"].as_bool().unwrap_or(false);
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
            #[cfg(windows)]
            acl_grant_current_user,
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
        self.acl_grant_current_user = allowed;
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
            record["token_sha256"] == URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),
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

    fn observe_agent_metadata(&self, device: &Value) -> anyhow::Result<()> {
        let metadata = device
            .get("metadata")
            .context("admin full view omitted agent metadata")?;
        validate_agent_metadata(metadata, self.ctx.agent_version.as_deref())
    }

    async fn device(&mut self, target: &Target, device_id: &str) -> anyhow::Result<crate::client::Reply> {
        let response = target.device(device_id).await?;
        if response.status == 200 {
            self.observe_agent_metadata(&response.body)?;
        }
        Ok(response)
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
            let listing = target.devices_for(token, "&view=full").await?;
            expect_status(&listing, 200)?;
            if count(&listing.body, "totalCount")? == 1 {
                let device = &listing.body["data"][0];
                let id = field(device, "id")?.to_owned();
                let identity_dir = self.path().join("identity").join("authorities");
                if identity_dir.exists() {
                    for path in std::fs::read_dir(identity_dir)? {
                        let authority = path?;
                        let json_path = authority.path().join("identity.json");
                        if json_path.exists() {
                            let state: Value = serde_json::from_slice(&std::fs::read(json_path)?)?;
                            if state["device_id"] == id && !self.pending_path_for(&token.text).exists() {
                                ensure!(
                                    key_exists(self, key_name(&state, "current")?)?,
                                    "settled enrollment has no current identity key"
                                );
                                self.observe_agent_metadata(device)?;
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

    async fn until_device<F>(&mut self, target: &Target, device_id: &str, what: &str, check: F) -> anyhow::Result<Value>
    where
        F: Fn(&Value) -> bool,
    {
        let start = Instant::now();
        loop {
            let response = self.device(target, device_id).await?;
            if response.status == 200 && check(&response.body) {
                return Ok(response.body);
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
        expected_devices: u64,
        expected_uses: u64,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        loop {
            let listing = target.devices_for(attempted, "").await?;
            expect_status(&listing, 200)?;
            ensure!(
                count(&listing.body, "totalCount")? == expected_devices,
                "permanently invalid pending token changed its device count"
            );
            ensure!(
                count(&target.token_record(&attempted.id).await?.body, "usedCount")? == expected_uses,
                "permanently invalid pending token consumed a use"
            );
            #[cfg(windows)]
            let machine_keys_gone = crate::windows::machine_keys_with_prefix(&self.ctx.key_name_prefix)?.is_empty();
            #[cfg(not(windows))]
            let machine_keys_gone = true;
            if !self.pending_path_for(pending).exists()
                && !self.in_progress_path_for(pending).exists()
                && !self.has_stored_identity()?
                && self.file_keys_with_prefix()?.is_empty()
                && machine_keys_gone
            {
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
        device_id: &str,
        error: &str,
    ) -> anyhow::Result<Value> {
        let start = Instant::now();
        loop {
            let _ = self.device(target, device_id).await?;
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
        device_id: &str,
        what: &str,
        check: F,
    ) -> anyhow::Result<Value>
    where
        F: Fn(&Value) -> bool,
    {
        let start = Instant::now();
        loop {
            let _ = self.device(target, device_id).await?;
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
                if name.starts_with(&self.ctx.key_name_prefix) {
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
            if self.ctx.key_backend == KeyBackend::KeyStore {
                let exists = crate::windows::machine_key_exists(name)?;
                ensure!(
                    exists || !require_current || slot != "current",
                    "settled current machine key is missing"
                );
                if exists {
                    crate::windows::assert_non_exportable(name)?;
                    crate::windows::assert_machine_key_acl(name, self.acl_grant_current_user)?;
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
                    use std::os::unix::fs::PermissionsExt as _;
                    #[cfg(unix)]
                    ensure!(
                        std::fs::metadata(&path)?.permissions().mode() & 0o777 == 0o600,
                        "{} is not mode 0600",
                        path.display()
                    );
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

async fn with_agent<F>(ctx: Context, renewal_after_secs: Option<u64>, run: bool, work: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(&'a mut AgentCase) -> CaseFuture<'a>,
{
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

async fn new_token(case: &AgentCase, uses: u32) -> anyhow::Result<Token> {
    case.ctx
        .target
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
    loop {
        let requests = target.requests(Some(token)).await?;
        let attempts = count(&requests, "enroll")?;
        ensure!(
            attempts <= before + 1 + count(&requests, "enroll_retry_503")?,
            "agent retried enrollment successfully while the retry barrier was held"
        );
        let listing = target.devices_for(token, "").await?;
        expect_status(&listing, 200)?;
        let record = target.token_record(&token.id).await?;
        expect_status(&record, 200)?;
        if count(&listing.body, "totalCount")? == 1
            && count(&record.body, "usedCount")? == 1
            && let Some(progress) = case.in_progress()?
        {
            ensure!(attempts > before, "enrollment committed without a recorded request");
            ensure!(
                case.pending_path().exists(),
                "agent deleted the pending file before receiving a response"
            );
            ensure!(
                !case.has_stored_identity()?,
                "agent stored an identity before receiving a response"
            );
            ensure!(
                progress["token_sha256"] == URL_SAFE_NO_PAD.encode(Sha256::digest(token.text.as_bytes())),
                "in-progress enrollment has the wrong full-token hash"
            );
            let key = field(&progress, "key_name")?.to_owned();
            ensure!(key_exists(case, &key)?, "committed enrollment key is missing");
            ensure!(
                target.control("faults", &json!({})).await?.body["drop_next_response"].is_null(),
                "the dropped enroll response fault was not consumed"
            );
            let id = field(&listing.body["data"][0], "id")?.to_owned();
            return Ok((id, key));
        }
        case.check_running()?;
        ensure!(
            started.elapsed() < WAIT,
            "agent did not commit a dropped-response enrollment and persist its key within 20 seconds"
        );
        tokio::time::sleep(POLL).await;
    }
}

async fn assert_terminal_stops(
    case: &mut AgentCase,
    target: &Target,
    authority: &str,
    device_id: Option<&str>,
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
    let before_device = if let Some(id) = device_id {
        Some(case.device(target, id).await?)
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
            if let Some(id) = device_id {
                let now = case.device(target, id).await?;
                ensure!(
                    now.body["connected"] == false
                        && before_device
                            .as_ref()
                            .is_some_and(|before| now.body["certificates"] == before.body["certificates"]),
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

fn assert_stored_identity(case: &AgentCase, token: &Token, state: &Value, device: &Value) -> anyhow::Result<()> {
    ensure!(state["version"] == 1, "stored identity has wrong version");
    ensure!(
        state["device_id"] == field(device, "id")?,
        "stored identity has wrong device ID"
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
        let mut expected = json!({ "version": 1, "revision": 1 });
        if case.ctx.channel_available {
            expected["agent_channel_url"] = json!(case.ctx.target.base_url);
        }
        ensure!(
            state["config"] == expected,
            "agent did not store the initial mock config and revision exactly"
        );
    }
    ensure!(state.get("rejected").is_none(), "new identity is already rejected");
    ensure!(
        state["token_sha256"] == URL_SAFE_NO_PAD.encode(Sha256::digest(token.text.as_bytes())),
        "stored identity has wrong full-token hash"
    );
    ensure!(
        device["metadata"]["hostname"] == case.metadata_hostname,
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

fn current_thumbprint(record: &Value) -> anyhow::Result<&str> {
    record["certificates"]
        .as_array()
        .context("no admin certificates")?
        .iter()
        .find(|cert| cert["status"] == "current")
        .and_then(|cert| cert["thumbprint"].as_str())
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

fn key_exists(case: &AgentCase, name: &str) -> anyhow::Result<bool> {
    validate_key_name(&case.ctx.key_name_prefix, name)?;
    #[cfg(windows)]
    if case.ctx.key_backend == KeyBackend::KeyStore {
        return crate::windows::machine_key_exists(name);
    }
    Ok(case.key_file_path(name).exists())
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

async fn assert_new_auth_precedes_old_close(
    target: &Target,
    device_id: &str,
    old_thumb: &str,
    new_thumb: &str,
) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        let events = target.events(device_id).await?;
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
            let admin = case.device(&target, &id).await?;
            expect_status(&admin, 200)?;
            ensure!(admin.body["id"] == id, "enrolled device absent from admin API");
            assert_stored_identity(case, &token, &state, &admin.body)?;
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
            ensure!(recovered_id == id, "retry created a second device");
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll")? > before_restart,
                "agent did not retry enrollment after restart"
            );
            ensure!(
                count(&target.token_record(&token.id).await?.body, "usedCount")? == 1,
                "retry consumed a second token use"
            );
            ensure!(
                key_name(&state, "current")? == key,
                "agent did not reuse the in-progress key"
            );
            ensure!(
                !case.in_progress_path().exists(),
                "in-progress enrollment record survived success"
            );
            let admin = case.device(&target, &id).await?;
            expect_status(&admin, 200)?;
            assert_stored_identity(case, &token, &state, &admin.body)?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_two_pending_tokens_same_authority_last_wins(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let original_token = new_token(case, 1).await?;
            let replacement = new_token(case, 1).await?;
            target
                .faults(&json!({
                    "fail_next_response": {
                        "endpoint": "enroll",
                        "status": 503,
                        "retry_after_secs": 15
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
                    && replacement_state["token_sha256"]
                        == URL_SAFE_NO_PAD.encode(Sha256::digest(replacement.text.as_bytes()))
                    && case.pending_path_for(&original_token.text).exists()
                    && case.in_progress_for(&original_token.text)?.is_some()
                    && key_exists(case, &original_key)?,
                "second token displaced the first pending file or in-progress key"
            );
            let (original_id, state) = case.enrolled(&target, &original_token).await?;
            ensure!(
                original_id != replacement_id
                    && state["token_sha256"] == URL_SAFE_NO_PAD.encode(Sha256::digest(original_token.text.as_bytes()))
                    && key_name(&state, "current")? == original_key,
                "last completing token did not become the stored identity for its authority"
            );
            wait_key_deleted(case, &replacement_key).await?;
            ensure!(
                count(&target.devices_for(&original_token, "").await?.body, "totalCount")? == 1
                    && count(&target.devices_for(&replacement, "").await?.body, "totalCount")? == 1
                    && count(&target.token_record(&original_token.id).await?.body, "usedCount")? == 1
                    && count(&target.token_record(&replacement.id).await?.body, "usedCount")? == 1
                    && !case.pending_path_for(&original_token.text).exists()
                    && !case.pending_path_for(&replacement.text).exists()
                    && !case.in_progress_path_for(&original_token.text).exists()
                    && !case.in_progress_path_for(&replacement.text).exists(),
                "independent pending tokens were not both consumed and cleaned up"
            );
            let admin = case.device(&target, &original_id).await?;
            expect_status(&admin, 200)?;
            assert_stored_identity(case, &original_token, &state, &admin.body)?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_two_pending_tokens_different_authorities_progress_independently(
    ctx: Context,
) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let first = case.ctx.target.clone();
            let second = case.ctx.second.clone().context("second authority required")?;
            let first_token = first.create_token(1, Duration::from_secs(3600), None).await?;
            let second_token = second.create_token(1, Duration::from_secs(3600), None).await?;
            first
                .faults(&json!({
                    "fail_next_response": {
                        "endpoint": "enroll",
                        "status": 503,
                        "retry_after_secs": 15
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
            let first_authority = field(&first_state, "authority_id")?;
            let second_authority = field(&second_state, "authority_id")?;
            ensure!(
                first_authority != second_authority
                    && first_state["device_id"] == first_id
                    && second_state["device_id"] == second_id
                    && case.state(first_authority)?["device_id"] == first_id
                    && case.state(second_authority)?["device_id"] == second_id
                    && !case.pending_path_for(&first_token.text).exists()
                    && !case.pending_path_for(&second_token.text).exists()
                    && !case.in_progress_path_for(&first_token.text).exists()
                    && !case.in_progress_path_for(&second_token.text).exists()
                    && count(&first.token_record(&first_token.id).await?.body, "usedCount")? == 1
                    && count(&second.token_record(&second_token.id).await?.body, "usedCount")? == 1,
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
            target.revoke(&id).await?;
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
                ensure!(
                    count(&requests, "enroll_device_revoked")? <= 1,
                    "agent retried enrollment again after receiving device_revoked"
                );
                if count(&requests, "enroll_device_revoked")? == 1
                    && !case.pending_path().exists()
                    && !case.in_progress_path().exists()
                    && !key_exists(case, &key)?
                    && !case.has_stored_identity()?
                {
                    break attempts;
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not remove the revoked enrollment, in-progress record and key within 20 seconds"
                );
                tokio::time::sleep(POLL).await;
            };
            ensure!(attempts >= 2, "agent did not retry the revoked enrollment");
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                case.check_running()?;
                ensure!(
                    count(&target.requests(Some(&token)).await?, "enroll")? == attempts,
                    "agent sent another enrollment request after device_revoked"
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
                count(&target.token_record(&token.id).await?.body, "usedCount")? == 1
                    && count(&target.devices_for(&token, "").await?.body, "totalCount")? == 1,
                "revoked enrollment created another device or consumed another use"
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
                let (pending, attempted, devices, used) = match reason {
                    "token_invalid" => {
                        let (prefix, _) = token.text.rsplit_once('.').context("token structure")?;
                        (format!("{prefix}.{}", URL_SAFE_NO_PAD.encode([0x49; 32])), token, 0, 0)
                    }
                    "token_exhausted" => {
                        let once = target.create_token(1, Duration::from_secs(3600), None).await?;
                        let key = crate::signer::KeyPair::generate()?;
                        expect_status(&target.enroll(&once.text, &key, &json!({})).await?, 200)?;
                        (once.text.clone(), once, 1, 1)
                    }
                    "token_expired" => {
                        let expiring = target.create_token(1, Duration::from_secs(2), None).await?;
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
                case.until_pending_deleted(&target, &pending, &attempted, devices, used)
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
            let devices = target.devices_for(&token, "").await?;
            ensure!(
                count(&devices.body, "totalCount")? == 0,
                "unreachable enrollment created a device"
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
                    ensure!(
                        case.pending_path().exists(),
                        "transient HTTP error deleted the pending file"
                    );
                    ensure!(
                        count(&target.devices_for(&token, "").await?.body, "totalCount")? == 0
                            && count(&target.token_record(&token.id).await?.body, "usedCount")? == 0,
                        "transient HTTP error created a device or consumed a token use"
                    );
                    if response["retry_after_secs"] == 3 {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        ensure!(
                            count(&target.requests(Some(&token)).await?, "enroll")? == initial + index as u64 + 1,
                            "agent ignored the Retry-After delay"
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
                    count(&target.token_record(&token.id).await?.body, "usedCount")? == 1,
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
            case.until_device(&target, &id, "working channel for renewal faults", |device| {
                device["connected"] == true
            })
            .await?;
            for status in [302, 429, 503] {
                let before = target.requests(None).await?;
                let device_before = case.device(&target, &id).await?.body;
                let stored_before = case.state(&authority)?;
                let old_thumb = current_thumbprint(&device_before)?.to_owned();
                let old_key = key_name(&stored_before, "current")?.to_owned();
                let attempts = count(&before, "renew")?;
                let mut fault = json!({ "endpoint": "renew", "status": status });
                if status == 429 {
                    fault["retry_after_secs"] = json!(3);
                }
                target.faults(&json!({ "fail_next_response": fault })).await?;
                expect_status(
                    &target
                        .admin(Method::POST, &format!("/devices/{id}/request-renewal"), None)
                        .await?,
                    202,
                )?;
                wait_for_injected_attempt(case, &target, "renew", attempts).await?;
                let failed = case.device(&target, &id).await?.body;
                let stored = case.state(&authority)?;
                ensure!(
                    failed["certificates"] == device_before["certificates"]
                        && failed["metadata"] == device_before["metadata"]
                        && failed["lastSeenAt"] == device_before["lastSeenAt"]
                        && stored["config"] == stored_before["config"]
                        && key_name(&stored, "current")? == old_key
                        && stored["keys"]["pending"]["certificate_chain"].is_null()
                        && stored.get("rejected").is_none(),
                    "injected renew {status} changed server or committed identity state"
                );
                if status == 429 {
                    tokio::time::sleep(Duration::from_millis(2600)).await;
                    ensure!(
                        count(&target.requests(None).await?, "renew")? == attempts + 1,
                        "renew retry ignored Retry-After: 3 seconds"
                    );
                }
                let renewed = case
                    .until_device(&target, &id, "renew retry confirmed", |device| {
                        current_thumbprint(device).is_ok_and(|thumb| thumb != old_thumb) && device["connected"] == true
                    })
                    .await?;
                case.until_state(&target, &authority, &id, "renew retry persisted", |state| {
                    key_name(state, "current").is_ok_and(|name| name != old_key)
                        && state["keys"].get("pending").is_none()
                        && state.get("rejected").is_none()
                })
                .await?;
                ensure!(
                    count(&target.requests(None).await?, "renew")? >= attempts + 2
                        && count(&target.requests(None).await?, "redirect_hits")? == count(&before, "redirect_hits")?
                        && renewed["renewalRequested"] == false,
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
                let device_before = case.device(&target, &id).await?.body;
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
                let failed = case.device(&target, &id).await?.body;
                let stored = case.state(&authority)?;
                ensure!(
                    failed["certificates"] == device_before["certificates"]
                        && failed["metadata"] == device_before["metadata"]
                        && failed["lastSeenAt"] == device_before["lastSeenAt"]
                        && stored["config"] == stored_before["config"]
                        && stored["keys"] == stored_before["keys"]
                        && stored.get("rejected").is_none(),
                    "injected check-in {status} changed server or committed identity state"
                );
                if status == 429 {
                    tokio::time::sleep(Duration::from_millis(2600)).await;
                    ensure!(
                        count(&target.requests(None).await?, "check_in")? == attempts + 1,
                        "check-in retry ignored Retry-After: 3 seconds"
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
                        && case.device(&target, &id).await?.body["metadata"]["hostname"] == hostname
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
            let uses = count(&target.token_record(&token.id).await?.body, "usedCount")?;
            let attempts = if case.ctx.mock() {
                Some(count(&target.requests(Some(&token)).await?, "enroll")?)
            } else {
                None
            };
            case.write_pending(&token.text)?;
            let start = Instant::now();
            while case.pending_path().exists() {
                let listing = target.devices_for(&token, "").await?;
                ensure!(
                    count(&listing.body, "totalCount")? == 1,
                    "duplicate token enrolled another device"
                );
                case.check_running()?;
                ensure!(start.elapsed() < WAIT, "same token pending file was not discarded");
                tokio::time::sleep(POLL).await;
            }
            ensure!(
                case.state(field(&old, "authority_id")?)?["device_id"] == id,
                "same token replaced identity"
            );
            ensure!(
                count(&target.token_record(&token.id).await?.body, "usedCount")? == uses,
                "same token used again"
            );
            let final_devices = target.devices_for(&token, "").await?;
            expect_status(&final_devices, 200)?;
            ensure!(
                count(&final_devices.body, "totalCount")? == 1 && final_devices.body["data"][0]["id"] == id,
                "same token created a new device"
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
            let (pending, expected_devices, expected_uses) = match outcome {
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
            case.until_pending_deleted(&target, &pending, &token, expected_devices, expected_uses)
                .await?;
            if let Some(before) = before {
                let expected = before + u64::from(!matches!(outcome, PermanentTokenOutcome::Malformed));
                ensure!(
                    count(&target.requests(None).await?, "enroll_total")? == expected,
                    "initial permanent outcome sent the wrong number of enrollment requests"
                );
            }
            assert_same_token_replay_dropped(case, &target, &token, &pending, expected_devices, expected_uses).await
        })
    })
    .await
}

async fn assert_same_token_replay_dropped(
    case: &mut AgentCase,
    target: &Target,
    token: &Token,
    pending: &str,
    expected_devices: u64,
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
        assert_replay_unchanged(target, token, expected_devices, expected_uses, attempts).await?;
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
        assert_replay_unchanged(target, token, expected_devices, expected_uses, attempts).await?;
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
    expected_devices: u64,
    expected_uses: u64,
    attempts: Option<u64>,
) -> anyhow::Result<()> {
    let listing = target.devices_for(token, "").await?;
    expect_status(&listing, 200)?;
    ensure!(
        count(&listing.body, "totalCount")? == expected_devices,
        "rewritten permanently failed token created another device"
    );
    let record = target.token_record(&token.id).await?;
    expect_status(&record, 200)?;
    ensure!(
        count(&record.body, "usedCount")? == expected_uses,
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

pub(crate) async fn a_same_token_after_device_revoked_no_enrollment(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            let (id, key) = dropped_enrollment(case, &token).await?;
            target.revoke(&id).await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": false }))
                    .await?,
                200,
            )?;
            case.until_pending_deleted(&target, &token.text, &token, 1, 1).await?;
            ensure!(
                count(&target.requests(Some(&token)).await?, "enroll_device_revoked")? == 1
                    && !key_exists(case, &key)?
                    && target.device(&id).await?.body["status"] == "revoked",
                "lost response was not followed by a permanent device_revoked outcome"
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
            case.until_device(&target, &id, "connected", |device| device["connected"] == true)
                .await?;
            target.revoke(&id).await?;
            case.until_rejected(&target, &authority, &id, "device_revoked").await?;
            let attempts = if case.ctx.mock() {
                Some(count(&target.requests(Some(&token)).await?, "enroll")?)
            } else {
                None
            };
            case.write_pending(&token.text)?;
            let start = Instant::now();
            while case.pending_path().exists() {
                let _ = target.devices_for(&token, "").await?;
                case.check_running()?;
                ensure!(start.elapsed() < WAIT, "same token was not discarded after rejection");
                tokio::time::sleep(POLL).await;
            }
            ensure!(
                count(&target.token_record(&token.id).await?.body, "usedCount")? == 1,
                "rejected identity consumed another token use"
            );
            let final_devices = target.devices_for(&token, "").await?;
            expect_status(&final_devices, 200)?;
            ensure!(
                count(&final_devices.body, "totalCount")? == 1 && final_devices.body["data"][0]["id"] == id,
                "same token created a new device after rejection"
            );
            ensure!(
                case.state(&authority)?["rejected"]["code"] == "device_revoked",
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
            ensure!(first_id != next_id, "different token did not replace the device");
            ensure!(
                next_state["authority_id"] == authority,
                "same mock changed authority on re-enrollment"
            );
            ensure!(
                next_state["token_sha256"] == URL_SAFE_NO_PAD.encode(Sha256::digest(next_token.text.as_bytes()))
                    && next_state["token_sha256"] != first_state["token_sha256"],
                "replacement did not store the new token hash"
            );
            wait_key_deleted(case, &original_key).await?;
            ensure!(
                case.state(&authority)?["device_id"] == next_id,
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
            case.until_device(&target, &old_id, "old connection", |record| record["connected"] == true)
                .await?;
            target.revoke(&old_id).await?;
            case.until_rejected(&target, &authority, &old_id, "device_revoked")
                .await?;
            let replacement = new_token(case, 1).await?;
            case.write_pending(&replacement.text)?;
            let (new_id, new_state) = case.enrolled(&target, &replacement).await?;
            ensure!(new_id != old_id, "new token reused the revoked device ID");
            ensure!(
                new_state["authority_id"] == authority,
                "replacement changed authorities"
            );
            ensure!(
                new_state.get("rejected").is_none(),
                "new token retained the old rejection"
            );
            ensure!(
                new_state["token_sha256"] == URL_SAFE_NO_PAD.encode(Sha256::digest(replacement.text.as_bytes()))
                    && new_state["token_sha256"] != old_state["token_sha256"],
                "rejected identity replacement did not store the new token hash"
            );
            wait_key_deleted(case, &old_key).await?;
            case.until_device(&target, &new_id, "replacement connection", |record| {
                record["connected"] == true
            })
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
            let before = case.device(&target, &id).await?;
            let old_thumb = current_thumbprint(&before.body)?.to_owned();
            let name = field(&before.body, "friendlyName")?.to_owned();
            let start = Instant::now();
            let renewed = loop {
                let record = case.device(&target, &id).await?;
                expect_status(&record, 200)?;
                if current_thumbprint(&record.body).is_ok_and(|thumb| thumb != old_thumb) {
                    break record.body;
                }
                if let Ok(state) = case.state(&authority) {
                    case.check_key_protection_inner(&authority, &state, false)?;
                }
                if !key_exists(case, &old_key)? {
                    let confirmed = current_thumbprint(&case.device(&target, &id).await?.body)
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
            ensure!(renewed["friendlyName"] == name, "friendly name changed on renewal");
            ensure!(
                renewed["certificates"].as_array().is_some_and(|items| items
                    .iter()
                    .any(|cert| cert["thumbprint"] == old_thumb && cert["status"] == "retired")),
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
            case.until_device(&target, &id, "offline channel after restart", |device| {
                device["connected"] == false
            })
            .await?;
            case.start().await?;
            let resumed = case
                .until_device(&target, &id, "reconnected with persisted key", |device| {
                    device["connected"] == true && current_thumbprint(device).is_ok_and(|thumb| thumb == new_thumb)
                })
                .await?;
            ensure!(
                resumed["certificate"]["issuer"] == renewed["certificate"]["issuer"],
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
            let before = case.device(&target, &id).await?;
            let old_thumb = current_thumbprint(&before.body)?.to_owned();
            case.until_device(&target, &id, "channel before requested renewal", |device| {
                device["connected"] == true
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
            expect_status(
                &target
                    .admin(Method::POST, &format!("/devices/{id}/request-renewal"), None)
                    .await?,
                202,
            )?;
            let started = Instant::now();
            let (pending_thumb, pending_key) = loop {
                let record = case.device(&target, &id).await?;
                expect_status(&record, 200)?;
                let state = case.state(&authority)?;
                let requests = target.requests(None).await?;
                let renew_count = count(&requests, "renew")?;
                ensure!(
                    renew_count <= attempts + 1 + count(&requests, "renew_retry_503")?,
                    "renewal retry succeeded while the retry barrier was held"
                );
                let pending = record.body["certificates"]
                    .as_array()
                    .context("missing certificates")?
                    .iter()
                    .find(|cert| cert["status"] == "pending");
                if renew_count > attempts
                    && let Some(pending) = pending
                    && let Ok(key) = key_name(&state, "pending")
                {
                    break (field(pending, "thumbprint")?.to_owned(), key.to_owned());
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not persist the first pending renewal"
                );
                tokio::time::sleep(POLL).await;
            };
            ensure!(
                target.control("faults", &json!({})).await?.body["drop_next_response"].is_null(),
                "drop-next-renew fault was not consumed"
            );
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
                .until_device(&target, &id, "retried renewal after restart", |device| {
                    current_thumbprint(device).is_ok_and(|thumb| thumb == pending_thumb)
                        && device["renewalRequested"] == false
                })
                .await?;
            ensure!(
                renewed["certificates"].as_array().is_some_and(|certs| certs.len() == 2) && old_thumb != pending_thumb,
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
            let state = case.state(&authority)?;
            ensure!(
                key_name(&state, "current")? == pending_key,
                "agent did not reuse its persisted CSR key after restart"
            );
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
                .until_device(&target, &id, "old-key channel", |record| record["connected"] == true)
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
            expect_status(
                &target
                    .admin(Method::POST, &format!("/devices/{id}/request-renewal"), None)
                    .await?,
                202,
            )?;
            let started = Instant::now();
            let (new_thumb, pending_key) = loop {
                let record = case.device(&target, &id).await?;
                let stored = case.state(&authority)?;
                let requests = target.requests(None).await?;
                if count(&requests, "confirm")? > confirm_before
                    && count(&requests, "confirm_retry_503")? >= 2
                    && let Ok(thumb) = current_thumbprint(&record.body)
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
            case.until_device(&target, &id, "new channel after confirm retry", |record| {
                record["connected"] == true && current_thumbprint(record).is_ok_and(|thumb| thumb == new_thumb)
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
            let original = case.device(&target, &id).await?.body;
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
            expect_status(
                &target
                    .admin(Method::POST, &format!("/devices/{id}/request-renewal"), None)
                    .await?,
                202,
            )?;
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
            let blocked_certificates = case.device(&target, &id).await?.body["certificates"].clone();
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
                    && case.device(&target, &id).await?.body["certificates"] == blocked_certificates,
                "unknown confirm outcome permitted check-in, renew, connect or certificate promotion"
            );
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                    .await?,
                200,
            )?;
            case.until_device(&target, &id, "channelless confirm resolved", |record| {
                current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb) && record["renewalRequested"] == false
            })
            .await?;
            case.until_state(&target, &authority, &id, "confirmed key stored", |state| {
                state["keys"].get("pending").is_none() && state.get("rejected").is_none()
            })
            .await?;
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
                let record = case.device(&target, &id).await?;
                let stored = case.state(&authority)?;
                let requests = target.requests(None).await?;
                if count(&requests, "confirm")? > count(&before, "confirm")?
                    && count(&requests, "confirm_retry_503")? >= 1
                    && let Ok(thumb) = current_thumbprint(&record.body)
                    && thumb != old_thumb
                    && let Ok(pending_key) = key_name(&stored, "pending")
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
                    && has_certificate(&case.device(&target, &id).await?.body, &first_thumb, "current"),
                "dropped confirm did not promote the pending certificate server-side"
            );
            let expiry = time::OffsetDateTime::parse(
                field(&case.device(&target, &id).await?.body["certificate"], "notAfter")?,
                &Rfc3339,
            )?
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
            case.start().await?;
            let confirmed_device = case
                .until_device(&target, &id, "fresh-key renewal after rejected confirm", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb && thumb != first_thumb)
                        && has_certificate(record, &first_thumb, "retired")
                        && record["renewalRequested"] == false
                })
                .await?;
            let new_thumb = current_thumbprint(&confirmed_device)?.to_owned();
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
            let requests = target.requests(None).await?;
            ensure!(
                count(&requests, "renew")? >= count(&before, "renew")? + 2
                    && count(&requests, "confirm")? >= count(&before, "confirm")? + 4,
                "agent did not renew with the expired pending key and confirm a fresh CSR"
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
                let record = case.device(&target, &id).await?;
                let stored = case.state(&authority)?;
                let requests = target.requests(None).await?;
                if count(&requests, "confirm_retry_503")? >= 1
                    && let Some(pending) = record.body["certificates"]
                        .as_array()
                        .and_then(|certs| certs.iter().find(|cert| cert["status"] == "pending"))
                    && let Ok(key) = key_name(&stored, "pending")
                {
                    ensure!(
                        current_thumbprint(&record.body)? == old_thumb,
                        "injected confirm failure promoted the pending certificate"
                    );
                    break (field(pending, "thumbprint")?.to_owned(), key.to_owned());
                }
                case.check_running()?;
                ensure!(
                    started.elapsed() < WAIT,
                    "agent did not persist a pending key after confirm 503"
                );
                tokio::time::sleep(POLL).await;
            };
            case.stop().await?;
            let pending = case.device(&target, &id).await?;
            let certificate = pending.body["certificates"]
                .as_array()
                .context("device certificates missing")?
                .iter()
                .find(|cert| cert["thumbprint"] == first_thumb)
                .context("pending certificate missing")?;
            let expiry = time::OffsetDateTime::parse(field(certificate, "notAfter")?, &Rfc3339)?.unix_timestamp();
            let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
                .as_i64()
                .context("mock time missing")?;
            let secs = expiry - now + 1;
            ensure!(
                secs > 0 && secs < 60,
                "pending key did not approach expiry before retry"
            );
            target.advance(secs).await?;
            let renew_before_restart = count(&target.requests(None).await?, "renew")?;
            target
                .faults(&json!({
                    "fail_next_response": {
                        "endpoint": "renew",
                        "status": 401,
                        "error": "device_unknown"
                    }
                }))
                .await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                    .await?,
                200,
            )?;
            case.start().await?;
            let renewed = case
                .until_device(
                    &target,
                    &id,
                    "fallback renewal after pending-key device_unknown",
                    |record| {
                        current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb && thumb != first_thumb)
                            && has_certificate(record, &first_thumb, "retired")
                    },
                )
                .await?;
            let settled = case
                .until_state(&target, &authority, &id, "confirmed fallback key", |state| {
                    key_name(state, "current").is_ok_and(|name| name != old_key && name != first_key)
                        && state["keys"].get("pending").is_none()
                        && state.get("rejected").is_none()
                })
                .await?;
            ensure!(
                crate::signer::thumbprint(
                    settled["keys"]["current"]["certificate_chain"][0]
                        .as_str()
                        .context("fallback certificate missing")?
                )? == current_thumbprint(&renewed)?,
                "agent did not persist the fallback-renewed certificate"
            );
            wait_key_deleted(case, &first_key).await?;
            wait_key_deleted(case, &old_key).await?;
            let requests = target.requests(None).await?;
            let keyids = requests["renew_attempt_keyids"]
                .as_array()
                .context("mock renew signing-key trace missing")?;
            let index = usize::try_from(renew_before_restart)?;
            ensure!(
                keyids.get(index) == Some(&json!(first_thumb))
                    && keyids.get(index + 1) == Some(&json!(old_thumb))
                    && count(&requests, "renew")? >= count(&before, "renew")? + 3
                    && count(&requests, "confirm")? >= count(&before, "confirm")? + 4
                    && target
                        .events(&id)
                        .await?
                        .iter()
                        .any(|event| { event["type"] == "renew_received" && event["cert_thumbprint"] == old_thumb }),
                "device_unknown on pending-key renew did not fall back to the old current key"
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
                let record = case.device(&target, &id).await?.body;
                let stored = case.state(&authority)?;
                if count(&target.requests(None).await?, "confirm_retry_503")? > 0
                    && let Some(pending) = record["certificates"]
                        .as_array()
                        .and_then(|certs| certs.iter().find(|cert| cert["status"] == "pending"))
                    && stored["keys"]["pending"]["key_name"].is_string()
                {
                    break (field(pending, "thumbprint")?.to_owned(), pending.clone());
                }
                case.check_running()?;
                ensure!(started.elapsed() < WAIT, "pending certificate was not held at confirm");
                tokio::time::sleep(POLL).await;
            };
            case.stop().await?;
            let before = target.requests(None).await?;
            let certificates = case.device(&target, &id).await?.body["certificates"].clone();
            let not_before =
                time::OffsetDateTime::parse(field(&pending_certificate, "notBefore")?, &Rfc3339)?.unix_timestamp();
            let not_after =
                time::OffsetDateTime::parse(field(&pending_certificate, "notAfter")?, &Rfc3339)?.unix_timestamp();
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
                    && case.device(&target, &id).await?.body["certificates"] == certificates,
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
            let original = case
                .until_device(&target, &id, "old certificate channel", |record| {
                    record["connected"] == true
                })
                .await?;
            let old_thumb = current_thumbprint(&original)?.to_owned();
            let expiry =
                time::OffsetDateTime::parse(field(&original["certificate"], "notAfter")?, &Rfc3339)?.unix_timestamp();
            let before = target.requests(None).await?;
            case.stop().await?;
            case.until_device(&target, &id, "offline expired channel", |record| {
                record["connected"] == false
            })
            .await?;
            let now = target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
                .as_i64()
                .context("mock time missing")?;
            let secs = expiry - now + 1;
            ensure!(secs > 0 && secs < 60, "old certificate is not approaching expiry");
            target.advance(secs).await?;
            case.start().await?;
            let renewed = case
                .until_device(&target, &id, "within-grace renewal and reconnect", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != old_thumb) && record["connected"] == true
                })
                .await?;
            ensure!(
                renewed["certificate"]["issuer"] == original["certificate"]["issuer"]
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
            case.until_device(&target, &id, "old certificate channel", |record| {
                record["connected"] == true
            })
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
            let enrolled = case.device(&target, &id).await?;
            expect_status(&enrolled, 200)?;
            ensure!(
                enrolled.body["metadata"].is_object(),
                "enrollment metadata was not an object"
            );
            ensure!(
                enrolled.body["metadata"]["hostname"] == case.metadata_hostname,
                "enrollment ignored the metadata override"
            );
            let connected = if case.ctx.mock() {
                ensure!(
                    enrolled.body["connected"] == false,
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
                let held = case.device(&target, &id).await?;
                ensure!(
                    held.body["connected"] == false && held.body["metadata"] == enrolled.body["metadata"],
                    "enrollment metadata changed before Hello authenticated"
                );
                target.advance(2).await?;
                expect_status(&target.control("handshake", &json!({ "pause": false })).await?, 200)?;
                let connected = case
                    .until_device(&target, &id, "authenticated Hello", |device| {
                        device["connected"] == true
                    })
                    .await?;
                ensure!(
                    count(&target.requests(None).await?, "authenticated_connects")? > 0,
                    "released Hello did not authenticate"
                );
                connected
            } else {
                case.until_device(&target, &id, "connected channel", |device| device["connected"] == true)
                    .await?
            };
            ensure!(
                connected["lastSeenAt"].as_str().is_some(),
                "channel did not update lastSeenAt"
            );
            ensure!(connected["metadata"].is_object(), "Hello metadata not stored");
            ensure!(
                connected["metadata"]["hostname"] == case.metadata_hostname,
                "initial Hello ignored the metadata override"
            );
            for key in REQUIRED_METADATA_KEYS {
                ensure!(
                    !field(&connected["metadata"], key)?.is_empty(),
                    "Hello omitted required {key} metadata"
                );
            }
            ensure!(
                case.state(&authority)?.get("rejected").is_none(),
                "successful Hello rejected the stored identity"
            );
            if case.ctx.mock() {
                ensure!(
                    field(&connected, "lastSeenAt")? != field(&enrolled.body, "lastSeenAt")?,
                    "authenticated Hello did not refresh lastSeenAt"
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
            let (id, _) = case.enrolled(&target, &token).await?;
            let connected = case
                .until_device(&target, &id, "first connection", |device| device["connected"] == true)
                .await?;
            let old_thumb = current_thumbprint(&connected)?.to_owned();
            let start = Instant::now();
            let new_thumb = loop {
                let record = case.device(&target, &id).await?;
                expect_status(&record, 200)?;
                ensure!(
                    record.body["connected"] == true,
                    "agent disconnected during make-before-break"
                );
                if let Ok(thumb) = current_thumbprint(&record.body)
                    && thumb != old_thumb
                {
                    ensure!(
                        record.body["certificates"].as_array().is_some_and(|certs| certs
                            .iter()
                            .any(|cert| cert["thumbprint"] == old_thumb && cert["status"] == "retired")),
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
            let first = case
                .until_device(&target, &id, "old-root channel", |record| record["connected"] == true)
                .await?;
            ensure!(
                first["metadata"]["hostname"] == case.metadata_hostname,
                "initial Hello ignored the metadata override"
            );
            let old_thumb = current_thumbprint(&first)?.to_owned();
            let renewed_hostname = "conformance-renew";
            case.set_metadata_hostname(renewed_hostname)?;
            target.faults(&json!({ "channel_available": false })).await?;
            case.until_state(&target, &authority, &id, "removed channel URL", |state| {
                state["config"]["revision"]
                    .as_u64()
                    .is_some_and(|revision| revision > 1)
                    && state["config"].get("agent_channel_url").is_none()
            })
            .await?;
            case.until_device(&target, &id, "closed old channel before offline renewal", |record| {
                record["connected"] == false
            })
            .await?;
            expect_status(
                &target
                    .admin(Method::POST, &format!("/devices/{id}/request-renewal"), None)
                    .await?,
                202,
            )?;
            let start = Instant::now();
            let confirmed = loop {
                let record = case.device(&target, &id).await?;
                expect_status(&record, 200)?;
                if current_thumbprint(&record.body).is_ok_and(|thumb| thumb != old_thumb) {
                    break record.body;
                }
                if !key_exists(case, &old_key)? {
                    let refreshed = case.device(&target, &id).await?;
                    ensure!(
                        current_thumbprint(&refreshed.body).is_ok_and(|thumb| thumb != old_thumb),
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
                confirmed["metadata"]["hostname"] == renewed_hostname
                    && confirmed["renewalRequested"] == false
                    && confirmed["certificates"].as_array().is_some_and(|certs| {
                        certs
                            .iter()
                            .any(|cert| cert["thumbprint"] == old_thumb && cert["status"] == "retired")
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
            let (id, _) = case.enrolled(&target, &token).await?;
            let record = case
                .until_device(&target, &id, "connected channel", |record| record["connected"] == true)
                .await?;
            let original = current_thumbprint(&record)?.to_owned();
            let acknowledgments = if case.ctx.mock() {
                Some(count(&target.requests(None).await?, "correlated_acks")?)
            } else {
                None
            };
            expect_status(
                &target
                    .admin(Method::POST, &format!("/devices/{id}/request-renewal"), None)
                    .await?,
                202,
            )?;
            let renewed = case
                .until_device(&target, &id, "requested renewal", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != original)
                        && record["renewalRequested"] == false
                })
                .await?;
            ensure!(renewed["connected"] == true, "requested renewal broke the channel");
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
            let (id, _) = case.enrolled(&target, &token).await?;
            let first = case
                .until_device(&target, &id, "initial connection", |record| record["connected"] == true)
                .await?;
            let original = current_thumbprint(&first)?.to_owned();
            case.stop().await?;
            let _ = case
                .until_device(&target, &id, "offline channel", |record| record["connected"] == false)
                .await?;
            expect_status(
                &target
                    .admin(Method::POST, &format!("/devices/{id}/request-renewal"), None)
                    .await?,
                202,
            )?;
            ensure!(
                case.device(&target, &id).await?.body["renewalRequested"] == true,
                "offline renewal flag missing"
            );
            case.start().await?;
            let renewed = case
                .until_device(&target, &id, "renewal after reconnect", |record| {
                    current_thumbprint(record).is_ok_and(|thumb| thumb != original)
                        && record["renewalRequested"] == false
                })
                .await?;
            ensure!(
                renewed["connected"] == true,
                "agent did not reconnect after offline request"
            );
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
            let initial = case.device(&target, &id).await?;
            ensure!(
                state["config"].get("agent_channel_url").is_none() && initial.body["connected"] == false,
                "no-channel renewal fixture unexpectedly offers a channel"
            );
            let original = current_thumbprint(&initial.body)?.to_owned();
            let before = if case.ctx.mock() {
                Some(target.requests(None).await?)
            } else {
                None
            };
            expect_status(
                &target
                    .admin(Method::POST, &format!("/devices/{id}/request-renewal"), None)
                    .await?,
                202,
            )?;
            ensure!(
                case.device(&target, &id).await?.body["renewalRequested"] == true,
                "channelless renewal flag was not persisted"
            );
            case.until_device(&target, &id, "check-in-triggered channelless renewal", |record| {
                current_thumbprint(record).is_ok_and(|thumb| thumb != original)
                    && record["renewalRequested"] == false
                    && record["connected"] == false
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
            case.until_device(&target, &id, "first channel", |record| record["connected"] == true)
                .await?;
            ensure!(
                case.device(&target, &id).await?.body["metadata"]["hostname"] == case.metadata_hostname,
                "first Hello did not send the current metadata override"
            );
            case.set_metadata_hostname("reconnected-host")?;
            let before = target.requests(None).await?;
            expect_status(&target.control("reconnect", &json!({ "device_id": id })).await?, 202)?;
            let started = Instant::now();
            loop {
                let current = case.device(&target, &id).await?;
                ensure!(
                    current.body["connected"] == true,
                    "agent disconnected before replacement stream opened"
                );
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
                case.device(&target, &id).await?.body["metadata"]["hostname"] == "reconnected-host",
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
            case.until_device(&target, &id, "initial connection", |record| record["connected"] == true)
                .await?;
            ensure!(
                state.get("rejected").is_none(),
                "identity was rejected before revocation"
            );
            let before = time::OffsetDateTime::now_utc();
            target.revoke(&id).await?;
            let _ = case.until_rejected(&target, &authority, &id, "device_revoked").await?;
            let revoked = case.device(&target, &id).await?;
            ensure!(revoked.body["connected"] == false, "revoked agent remains connected");
            assert_terminal_stops(case, &target, &authority, Some(&id), "device_revoked", before).await?;
            Ok(())
        })
    })
    .await
}

pub(crate) async fn a_device_unknown_recorded(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            case.until_device(&target, &id, "connection before reset", |record| {
                record["connected"] == true
            })
            .await?;
            ensure!(state.get("rejected").is_none(), "identity was rejected before reset");
            let before = time::OffsetDateTime::now_utc();
            target.reset().await?;
            expect_status(&case.device(&target, &id).await?, 404)?;
            let rejected = case.until_rejected(&target, &authority, &id, "device_unknown").await?;
            ensure!(rejected["rejected"]["at"].as_str().is_some(), "rejection time missing");
            assert_terminal_stops(case, &target, &authority, None, "device_unknown", before).await?;
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
                case.device(&target, &id).await?.body["connected"] == false,
                "signed-request rejection fixture unexpectedly opened a channel"
            );
            let before = target.requests(None).await?;
            ensure!(
                count(&before, "renew")? == 0,
                "check-in rejection fixture renewed before revocation"
            );
            let since = time::OffsetDateTime::now_utc();
            target.revoke(&id).await?;
            case.until_rejected(&target, &authority, &id, "device_revoked").await?;
            let after = target.requests(None).await?;
            ensure!(
                count(&after, "check_in")? > count(&before, "check_in")?
                    && count(&after, "renew")? == count(&before, "renew")?,
                "agent did not record device_revoked from check-in before any renewal"
            );
            assert_terminal_stops(case, &target, &authority, Some(&id), "device_revoked", since).await?;
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
                case.device(&target, &id).await?.body["connected"] == false,
                "channel-open rejection fixture authenticated prematurely"
            );
            let since = time::OffsetDateTime::now_utc();
            target.reset().await?;
            let rejected = case.until_rejected(&target, &authority, &id, "device_unknown").await?;
            ensure!(
                rejected["rejected"]["code"] == "device_unknown"
                    && count(&target.requests(None).await?, "connect")? > 0,
                "agent did not record device_unknown from a channel-open rejection"
            );
            assert_terminal_stops(case, &target, &authority, None, "device_unknown", since).await?;
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
                case.device(&target, &id).await?.body["metadata"]["hostname"] == case.metadata_hostname,
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
                            && case.device(&target, &id).await?.body["metadata"]["hostname"] == "second-check-in-host",
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
                    case.device(&target, &id).await?.body["connected"] == false,
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
            target
                .faults(&json!({ "channel_available": true, "malformed_channel_url": fault }))
                .await?;
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
                    case.device(&target, &id).await?.body["connected"] == false,
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
            case.until_device(&target, &id, "initial channel", |record| record["connected"] == true)
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
            case.until_device(&target, &id, "closed channel after config update", |record| {
                record["connected"] == false
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
                        && case.device(&target, &id).await?.body["connected"] == false
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
            ensure!(
                state["config"].get("agent_channel_url").is_none()
                    && case.device(&target, &id).await?.body["connected"] == false,
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
                            .is_some_and(|revision| revision > 1)
                            && state["config"]["agent_channel_url"] == target.base_url
                    },
                )
                .await?;
            ensure!(
                count(&target.requests(None).await?, "check_in")? > before,
                "agent did not learn the enabled URL through check-in"
            );
            case.until_device(&target, &id, "channel opened from check-in config", |record| {
                record["connected"] == true
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
            ensure!(
                state["config"]["agent_channel_url"] == target.base_url && count(&state["config"], "revision")? == 1,
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
                case.device(&target, &id).await?.body["connected"] == false
                    && count(&case.state(&authority)?["config"], "revision")? == 1,
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
                            .is_some_and(|revision| revision > 1)
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
                        && case.device(&target, &id).await?.body["connected"] == false,
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
            case.until_device(&target, &id, "initial channel", |record| record["connected"] == true)
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
                    &json!({ "device_id": id, "revision": initial_revision }),
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
            expect_status(&target.control("reconnect", &json!({ "device_id": id })).await?, 202)?;
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
                    && case.device(&target, &id).await?.body["connected"] == true,
                "agent checked in periodically despite a working channel"
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
            let first_token = first.create_token(1, Duration::from_secs(3600), None).await?;
            case.write_pending(&first_token.text)?;
            let (first_id, first_state) = case.enrolled(&first, &first_token).await?;
            let first_authority = field(&first_state, "authority_id")?.to_owned();
            case.until_device(&first, &first_id, "first connection", |record| {
                record["connected"] == true
            })
            .await?;
            let second_token = second.create_token(1, Duration::from_secs(3600), None).await?;
            case.write_pending(&second_token.text)?;
            let (second_id, second_state) = case.enrolled(&second, &second_token).await?;
            let second_authority = field(&second_state, "authority_id")?.to_owned();
            ensure!(
                first_authority != second_authority,
                "two mocks returned the same authority ID"
            );
            case.until_device(&second, &second_id, "second connection", |record| {
                record["connected"] == true
            })
            .await?;
            ensure!(
                case.device(&first, &first_id).await?.body["connected"] == true,
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
                first_state["token_sha256"] == URL_SAFE_NO_PAD.encode(Sha256::digest(first_token.text.as_bytes()))
                    && second_state["token_sha256"]
                        == URL_SAFE_NO_PAD.encode(Sha256::digest(second_token.text.as_bytes())),
                "multi-authority token hashes are incorrect"
            );
            case.stop().await?;
            case.until_device(&first, &first_id, "first authority offline", |record| {
                record["connected"] == false
            })
            .await?;
            case.until_device(&second, &second_id, "second authority offline", |record| {
                record["connected"] == false
            })
            .await?;
            case.start().await?;
            case.until_device(&first, &first_id, "first authority reconnected", |record| {
                record["connected"] == true
            })
            .await?;
            case.until_device(&second, &second_id, "second authority reconnected", |record| {
                record["connected"] == true
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
            ctx.key_backend == KeyBackend::KeyStore,
            "Windows non-exportability requires key-store backend"
        );
        with_agent(ctx.clone(), None, true, |case| {
            Box::pin(async move {
                let target = case.ctx.target.clone();
                let token = new_token(case, 1).await?;
                case.write_pending(&token.text)?;
                let (id, state) = case.enrolled(&target, &token).await?;
                crate::windows::assert_non_exportable(key_name(&state, "current")?)?;
                crate::windows::assert_machine_key_acl(key_name(&state, "current")?, case.acl_grant_current_user)?;
                case.check_key_protection(field(&state, "authority_id")?, &state)?;
                if case.ctx.channel_available {
                    case.until_device(&target, &id, "signed channel Hello", |device| {
                        device["connected"] == true
                    })
                    .await?;
                } else {
                    case.set_metadata_hostname("acl-signing-probe")?;
                    case.until_device(&target, &id, "signed check-in", |device| {
                        device["metadata"]["hostname"] == "acl-signing-probe"
                    })
                    .await?;
                }
                Ok(())
            })
        })
        .await?;
        if !crate::windows::running_as_system()? {
            if !crate::windows::running_as_elevated_administrator()? {
                return Err(crate::NotApplicable("requires an elevated administrator for the SYSTEM fixture").into());
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
                crate::windows::assert_machine_key_acl(key, false)?;
                case.check_key_protection(field(&state, "authority_id")?, &state)?;
                if case.ctx.channel_available {
                    case.until_device(&target, &id, "SYSTEM-only key signed channel Hello", |device| {
                        device["connected"] == true
                    })
                    .await?;
                } else {
                    case.set_metadata_hostname("system-acl-signing-probe")?;
                    case.until_device(&target, &id, "SYSTEM-only key signed check-in", |device| {
                        device["metadata"]["hostname"] == "system-acl-signing-probe"
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
        use std::os::unix::fs::PermissionsExt as _;
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
                let mode = std::fs::metadata(&key_file)?.permissions().mode() & 0o777;
                ensure!(mode == 0o600, "{} has mode {mode:o}, expected 0600", key_file.display());
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
                .until_device(&target, &id, "old-root connection", |record| {
                    record["connected"] == true
                })
                .await?;
            let old_root = field(&old["certificate"], "issuer")?.to_owned();
            let started = if case.ctx.mock() {
                target.rotate(None).await?
            } else {
                crate::protocol::wait_rotation_idle(&target, case.ctx.dvls_rotation_window_secs).await?;
                let deadline = (time::OffsetDateTime::now_utc()
                    + time::Duration::seconds(i64::try_from(case.ctx.dvls_rotation_window_secs)?))
                .format(&Rfc3339)?;
                target.rotate(Some(&deadline)).await?
            };
            expect_status(&started, 202)?;
            let initial = count(&started.body, "activeDevicesOnOldRoot")?;
            ensure!(initial >= 1, "the agent's old-root device was not counted");
            let new = case
                .until_device(&target, &id, "connected new-root certificate", |record| {
                    record["certificate"]["issuer"] != old_root
                        && record["connected"] == true
                        && record["certificates"]
                            .as_array()
                            .is_some_and(|items| items.iter().any(|cert| cert["status"] == "retired"))
                })
                .await?;
            ensure!(new["certificate"]["issuer"] != old_root, "agent did not migrate roots");
            let new_root = field(&new["certificate"], "issuer")?.to_owned();
            let stored = case
                .until_state(&target, &authority, &id, "stored new-root chain", |state| {
                    state["keys"]["current"]["certificate_chain"]
                        .as_array()
                        .and_then(|chain| chain.last())
                        .and_then(Value::as_str)
                        .and_then(|root| crate::signer::thumbprint(root).ok())
                        .is_some_and(|issuer| issuer == new_root)
                })
                .await?;
            ensure!(
                stored["keys"]["current"]["certificate_chain"]
                    .as_array()
                    .is_some_and(|chain| chain.len() >= 2),
                "migrated agent did not persist the new-root chain"
            );
            case.stop().await?;
            case.until_device(&target, &id, "offline new-root channel", |record| {
                record["connected"] == false
            })
            .await?;
            let authenticated_before = if case.ctx.mock() {
                Some(count(&target.requests(None).await?, "authenticated_connects")?)
            } else {
                None
            };
            case.start().await?;
            case.until_device(&target, &id, "new-root channel after restart", |record| {
                record["connected"] == true && record["certificate"]["issuer"] == new_root
            })
            .await?;
            if let Some(before) = authenticated_before {
                ensure!(
                    count(&target.requests(None).await?, "authenticated_connects")? > before,
                    "restarted agent did not authenticate its new-root channel"
                );
            }
            let rotation = target.admin(Method::GET, "/ca/rotation", None).await?;
            if rotation.body["phase"] == "rotating" {
                ensure!(
                    count(&rotation.body, "activeDevicesOnOldRoot")? < initial,
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
            let before = case.device(&target, &id).await?;
            ensure!(
                before.body["connected"] == false,
                "channel unavailable but agent connected"
            );
            let old_root = field(&before.body["certificate"], "issuer")?.to_owned();
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
            expect_status(&target.rotate(None).await?, 202)?;
            let new = case
                .until_device(&target, &id, "check-in-triggered new-root renewal", |record| {
                    record["certificates"].as_array().is_some_and(|certs| {
                        certs
                            .iter()
                            .any(|cert| cert["issuer"] != old_root && cert["status"] == "pending")
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
            ensure!(
                new["connected"] == false,
                "scheduled renewal unexpectedly required a channel"
            );
            let pending = new["certificates"]
                .as_array()
                .context("scheduled certificates missing")?
                .iter()
                .find(|cert| cert["issuer"] != old_root && cert["status"] == "pending")
                .context("new-root pending certificate missing")?;
            let new_root = field(pending, "issuer")?.to_owned();
            let pending_thumb = field(pending, "thumbprint")?.to_owned();
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
                    && has_certificate(&case.device(&target, &id).await?.body, &pending_thumb, "pending"),
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
            case.until_device(&target, &id, "confirmed new-root key after restart", |record| {
                record["certificate"]["issuer"] == new_root
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
            let final_state = case.state(&authority)?;
            ensure!(
                key_name(&final_state, "current")? == pending_key
                    && final_state["keys"]["current"]["certificate_chain"]
                        .as_array()
                        .and_then(|chain| chain.last())
                        .and_then(Value::as_str)
                        .is_some_and(|root| crate::signer::thumbprint(root).is_ok_and(|issuer| issuer == new_root)),
                "restarted agent did not keep the confirmed new-root chain"
            );
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
            let old = case.device(&target, &id).await?;
            ensure!(old.body["connected"] == false, "scheduled-rotation fixture connected");
            let old_root = field(&old.body["certificate"], "issuer")?.to_owned();
            let old_thumb = current_thumbprint(&old.body)?.to_owned();
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
            expect_status(&target.rotate(None).await?, 202)?;
            let wait = Instant::now();
            let migrated = loop {
                let record = case.device(&target, &id).await?.body;
                if record["certificate"]["issuer"] != old_root
                    && record["renewalRequested"] == false
                    && record["connected"] == false
                {
                    break record;
                }
                case.check_running()?;
                ensure!(
                    wait.elapsed() < Duration::from_secs(70),
                    "agent did not migrate roots on schedule before the next check-in"
                );
                tokio::time::sleep(POLL).await;
            };
            let new_root = field(&migrated["certificate"], "issuer")?.to_owned();
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
        let prefix = format!("DevolutionsAgent-Identity-conformance-{}-", uuid::Uuid::new_v4());
        let key_uuid = uuid::Uuid::new_v4();
        validate_key_name(&prefix, &format!("{prefix}{key_uuid}"))?;
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}{}", key_uuid.to_string().to_uppercase())).is_err(),
            "uppercase UUID was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("DevolutionsAgent-Identity-{key_uuid}")).is_err(),
            "a key without the run prefix was accepted"
        );
        ensure!(
            validate_key_name(&prefix, &format!("{prefix}{key_uuid}.p8")).is_err(),
            "a key name with a file extension was accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn orphan_audit_accepts_both_records_and_cleanup_is_prefix_scoped() -> anyhow::Result<()> {
        let work_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-identity-conformance-tests");
        std::fs::create_dir_all(&work_dir)?;
        let prefix = format!("DevolutionsAgent-Identity-conformance-{}-", uuid::Uuid::new_v4());
        let target = Target::new("https://localhost/mock".to_owned(), "test".to_owned(), None, None)?;
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
                unprivileged_admin_token: None,
                agent_bin: PathBuf::new(),
                key_backend: KeyBackend::File,
                work_dir,
            },
            None,
            false,
        )
        .await?;
        let fixture_token = "dvaet1.fixturebag.fixturesecret";
        let fixture_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(fixture_token.as_bytes()));
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
        let name = format!("{prefix}{}", uuid::Uuid::new_v4());
        let foreign = format!("DevolutionsAgent-Identity-{}", uuid::Uuid::new_v4());
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
        case.audit_identity_tree()?;
        case.ctx.key_backend = KeyBackend::KeyStore;
        ensure!(
            case.audit_identity_tree().is_err(),
            "key-store backend accepted a file-backed key"
        );
        case.ctx.key_backend = KeyBackend::File;
        write_run_key(&case.key_file_path(&foreign))?;
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
        std::fs::remove_file(case.key_file_path(&foreign))?;
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
        for leftover in [
            case.key_file_path(&name).with_extension("p8.tmp"),
            case.path()
                .join("identity")
                .join("pending")
                .join(format!("{}.json.tmp", token_file_id("untracked-token"))),
        ] {
            std::fs::write(&leftover, b"partial temporary file")?;
            ensure!(
                case.audit_identity_tree().is_err(),
                "temporary sibling survived after its record was removed"
            );
            std::fs::remove_file(leftover)?;
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
