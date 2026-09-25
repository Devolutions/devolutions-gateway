use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use der::{Decode as _, Encode as _};
use http::Method;
#[cfg(unix)]
use p256::ecdsa::SigningKey;
#[cfg(windows)]
use p256::ecdsa::VerifyingKey;
#[cfg(unix)]
use p256::pkcs8::DecodePrivateKey as _;
use p256::pkcs8::EncodePublicKey as _;
use rand::RngExt as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;
use tokio::process::{Child, Command};
use x509_cert::Certificate;

use crate::client::{Target, Token, count, decoded_certificate, expect_status, field};
use crate::{Context, KeyBackend};

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
    ensure!(total_bytes <= 8 * 1024, "agent metadata exceeds 8 KiB");
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

struct AgentCase {
    ctx: Context,
    dir: tempfile::TempDir,
    child: Option<Child>,
    #[cfg(windows)]
    job: Option<crate::windows::AgentJob>,
    #[cfg(unix)]
    process_group: Option<i32>,
    tokens: Vec<String>,
    metadata_baseline: Option<Value>,
    cleaned: bool,
    #[cfg(windows)]
    machine_keys: Vec<String>,
    #[cfg(windows)]
    preexisting_keys: std::collections::HashSet<String>,
    #[cfg(windows)]
    known_authorities: std::collections::HashSet<uuid::Uuid>,
}

impl AgentCase {
    async fn new(ctx: Context, renewal_after_secs: Option<u64>, run: bool) -> anyhow::Result<Self> {
        #[cfg(windows)]
        let preexisting_keys =
            crate::windows::snapshot_machine_identity_keys().context("snapshot existing machine identity keys")?;
        #[cfg(windows)]
        let known_authorities = [
            ctx.target.authority_id,
            ctx.second.as_ref().and_then(|target| target.authority_id),
        ]
        .into_iter()
        .flatten()
        .collect();
        let dir = tempfile::Builder::new()
            .prefix("identity-agent-")
            .tempdir_in(&ctx.work_dir)
            .context("create agent data dir")?;
        let mut identity_debug = json!({
            "disable_jitter": true,
            "backoff_max_secs": 2,
            "pending_poll_interval_ms": 200
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
            metadata_baseline: None,
            cleaned: false,
            #[cfg(windows)]
            machine_keys: Vec::new(),
            #[cfg(windows)]
            preexisting_keys,
            #[cfg(windows)]
            known_authorities,
        };
        if run {
            case.start().await?;
        }
        Ok(case)
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn pending_path(&self) -> PathBuf {
        #[cfg(windows)]
        let name = "pending-enrollment.dat";
        #[cfg(not(windows))]
        let name = "pending-enrollment.json";
        self.path().join("identity").join(name)
    }

    fn identity_path(&self, authority_id: &str) -> PathBuf {
        self.path()
            .join("identity")
            .join("authorities")
            .join(authority_id)
            .join("identity.json")
    }

    fn state(&self, authority_id: &str) -> anyhow::Result<Value> {
        serde_json::from_slice(&std::fs::read(self.identity_path(authority_id))?).context("read stored identity")
    }

    fn add_token(&mut self, token: &str) {
        self.tokens.push(token.to_owned());
    }

    fn observe_agent_metadata(&mut self, device: &Value) -> anyhow::Result<()> {
        let metadata = device
            .get("metadata")
            .context("admin full view omitted agent metadata")?;
        validate_agent_metadata(metadata, self.ctx.agent_version.as_deref())?;
        if let Some(baseline) = &self.metadata_baseline {
            ensure!(
                metadata == baseline,
                "agent metadata changed between enroll, renew or Hello"
            );
        } else {
            self.metadata_baseline = Some(metadata.clone());
        }
        Ok(())
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
                .create_new(true)
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
        let mut process = command.spawn().context("spawn devolutions-agent run")?;
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
                            if state["device_id"] == id && !self.pending_path().exists() {
                                self.observe_agent_metadata(device)?;
                                if let Some(known) = target.authority_id {
                                    ensure!(
                                        state["authority_id"] == known.to_string(),
                                        "agent stored an unexpected authority ID"
                                    );
                                }
                                #[cfg(windows)]
                                for slot in ["current", "pending", "previous"] {
                                    if let Some(name) = state["keys"][slot]["key_name"].as_str() {
                                        self.machine_keys.push(name.to_owned());
                                    }
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
        token: &Token,
        expected_devices: u64,
        expected_uses: u64,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        loop {
            let listing = target.devices_for(token, "").await?;
            expect_status(&listing, 200)?;
            ensure!(
                count(&listing.body, "totalCount")? == expected_devices,
                "permanently invalid pending token changed its device count"
            );
            ensure!(
                count(&target.token_record(&token.id).await?.body, "usedCount")? == expected_uses,
                "permanently invalid pending token consumed a use"
            );
            if !self.pending_path().exists() {
                return Ok(());
            }
            self.check_running()?;
            ensure!(start.elapsed() < WAIT, "agent kept a permanently invalid pending token");
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
        let protected = self.audit_stored_keys();
        #[cfg(windows)]
        crate::windows::cleanup_machine_keys(
            self.path(),
            &self.machine_keys,
            &self.preexisting_keys,
            &self.known_authorities,
            self.ctx.mock() || self.ctx.cleanup_machine_keys,
        );
        let audited = self.audit_tokens();
        self.cleaned = true;
        stopped?;
        protected?;
        audited
    }

    fn audit_stored_keys(&self) -> anyhow::Result<()> {
        let authorities = self.path().join("identity").join("authorities");
        if !authorities.exists() {
            return Ok(());
        }
        for authority in std::fs::read_dir(authorities)? {
            let authority = authority?;
            let path = authority.path().join("identity.json");
            if path.exists() {
                let state: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                let id = field(&state, "authority_id")?;
                self.check_key_protection(id, &state)?;
            }
        }
        Ok(())
    }

    fn check_key_protection(&self, authority_id: &str, state: &Value) -> anyhow::Result<()> {
        #[cfg(windows)]
        let _ = authority_id;
        #[cfg(unix)]
        if self.ctx.key_backend == KeyBackend::File {
            use std::os::unix::fs::PermissionsExt as _;
            let path = self.identity_path(authority_id);
            ensure!(
                std::fs::metadata(path)?.permissions().mode() & 0o777 == 0o600,
                "identity.json is not mode 0600"
            );
        }
        for slot in ["current", "pending", "previous"] {
            let Some(name) = state["keys"][slot]["key_name"].as_str() else {
                continue;
            };
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
            #[cfg(windows)]
            if self.ctx.key_backend == KeyBackend::KeyStore {
                if crate::windows::machine_key_exists(name)? {
                    crate::windows::assert_non_exportable(name)?;
                    crate::windows::assert_machine_key_acl(name)?;
                    if let Some(expected) = &expected_spki {
                        let key = VerifyingKey::from_sec1_bytes(&crate::windows::machine_public_key(name)?)?;
                        ensure!(
                            key.to_public_key_der()?.as_bytes() == expected,
                            "{slot} machine key does not match its leaf SPKI"
                        );
                    }
                } else {
                    ensure!(slot == "previous", "{slot} machine key is missing");
                }
            }
            #[cfg(unix)]
            if self.ctx.key_backend == KeyBackend::File {
                use std::os::unix::fs::PermissionsExt as _;
                let path = self
                    .path()
                    .join("identity")
                    .join("authorities")
                    .join(authority_id)
                    .join("keys")
                    .join(format!("{name}.p8"));
                if path.exists() {
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
                } else {
                    ensure!(slot == "previous", "{slot} file key is missing");
                }
            }
            #[cfg(not(any(unix, windows)))]
            let _ = (name, expected_spki);
        }
        #[cfg(unix)]
        if self.ctx.key_backend == KeyBackend::File {
            let keys_dir = self
                .path()
                .join("identity")
                .join("authorities")
                .join(authority_id)
                .join("keys");
            if keys_dir.exists() {
                for entry in std::fs::read_dir(keys_dir)? {
                    let path = entry?.path();
                    ensure!(
                        path.is_file() && path.extension().is_some_and(|ext| ext == "p8"),
                        "leftover key-store temp file {}",
                        path.display()
                    );
                }
            }
        }
        Ok(())
    }

    fn audit_tokens(&self) -> anyhow::Result<()> {
        let mut stack = vec![self.path().to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path == self.pending_path() && path.exists() {
                    continue;
                }
                let contents = std::fs::read(&path)?;
                for token in &self.tokens {
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
            for _ in 0..20 {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        if !self.cleaned {
            #[cfg(windows)]
            crate::windows::cleanup_machine_keys(
                self.path(),
                &self.machine_keys,
                &self.preexisting_keys,
                &self.known_authorities,
                self.ctx.mock() || self.ctx.cleanup_machine_keys,
            );
            if let Err(error) = self.audit_tokens() {
                eprintln!("agent-case cleanup audit failed: {error:#}");
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
                    after["renew"] == before["renew"] && after["connect"] == before["connect"],
                    "rejected identity sent a renew or Connect during backoff cycles"
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
    ensure!(
        state["friendly_name"] == device["friendlyName"],
        "stored identity has the wrong friendly name"
    );
    if case.ctx.channel_available {
        let channel_url = field(state, "channel_url")?;
        ensure!(
            reqwest::Url::parse(channel_url)?.scheme() == "https",
            "stored identity has an invalid channel URL"
        );
        if case.ctx.mock() {
            ensure!(
                channel_url == case.ctx.target.base_url,
                "stored mock channel URL does not match enrollment"
            );
        }
    } else {
        ensure!(state.get("channel_url").is_none(), "unavailable channel URL was stored");
    }
    ensure!(state.get("rejected").is_none(), "new identity is already rejected");
    ensure!(
        state["token_sha256"] == URL_SAFE_NO_PAD.encode(Sha256::digest(token.text.as_bytes())),
        "stored identity has wrong full-token hash"
    );
    ensure!(
        state["keys"]["current"]["certificate_chain"]
            .as_array()
            .is_some_and(|chain| !chain.is_empty()),
        "stored identity has an empty current certificate chain"
    );
    let mut names = std::collections::HashSet::new();
    for slot in ["current", "pending", "previous"] {
        if let Some(name) = state["keys"][slot]["key_name"].as_str() {
            let generation = name
                .strip_prefix(&format!("DevolutionsAgent-Identity-{authority}-"))
                .context("stored key name has the wrong authority prefix")?;
            ensure!(
                !generation.is_empty()
                    && generation.len() <= 64
                    && generation
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-'),
                "stored {slot} key name has an invalid generation"
            );
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
    ensure!(
        state["config"]["version"] == 1,
        "stored identity has wrong config version"
    );
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

fn key_name<'a>(state: &'a Value, slot: &str) -> anyhow::Result<&'a str> {
    field(&state["keys"][slot], "key_name")
}

fn key_exists(case: &AgentCase, authority_id: &str, name: &str) -> anyhow::Result<bool> {
    #[cfg(windows)]
    if case.ctx.key_backend == KeyBackend::KeyStore {
        return crate::windows::machine_key_exists(name);
    }
    Ok(case
        .path()
        .join("identity")
        .join("authorities")
        .join(authority_id)
        .join("keys")
        .join(format!("{name}.p8"))
        .exists())
}

async fn wait_key_deleted(case: &mut AgentCase, authority_id: &str, name: &str) -> anyhow::Result<()> {
    let started = Instant::now();
    while key_exists(case, authority_id, name)? {
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
        let new_auth = events
            .iter()
            .find(|event| event["type"] == "stream_authenticated" && event["cert_thumbprint"] == new_thumb);
        let old_close = events
            .iter()
            .find(|event| event["type"] == "stream_closed" && event["cert_thumbprint"] == old_thumb);
        if let (Some(new_auth), Some(old_close)) = (new_auth, old_close) {
            ensure!(
                old_close["status"] == "OK" && count(new_auth, "seq")? < count(old_close, "seq")?,
                "old stream closed before the new channel proof authenticated"
            );
            return Ok(());
        }
        ensure!(
            started.elapsed() < WAIT,
            "new authentication or old stream-closed event missing"
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
                case.until_pending_deleted(&target, &attempted, devices, used).await?;
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
                    case.check_running()?;
                }
                let _ = case.enrolled(&target, &token).await?;
                ensure!(
                    count(&target.token_record(&token.id).await?.body, "usedCount")? == 1,
                    "retry consumed an additional token use"
                );
                ensure!(
                    count(&target.requests(Some(&token)).await?, "enroll")? >= initial + 4,
                    "agent did not survive three transient failures and retry successfully"
                );
                Ok(())
            })
        })
        .await?;
    }
    Ok(())
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
            wait_key_deleted(case, &authority, &original_key).await?;
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
            wait_key_deleted(case, &authority, &old_key).await?;
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
                ensure!(!case.pending_path().exists(), "{reason} wrote a pending file");
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
                    case.check_key_protection(&authority, &state)?;
                }
                ensure!(
                    key_exists(case, &authority, &old_key)?,
                    "old key was deleted before a replacement certificate authenticated"
                );
                case.check_running()?;
                ensure!(
                    start.elapsed() < WAIT,
                    "agent did not authenticate a new current certificate"
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
                "renewal left pending or previous key slots after new-key authentication"
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
            wait_key_deleted(case, &authority, &old_key).await?;
            let new_thumb = current_thumbprint(&renewed)?.to_owned();
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
            let attempts = count(&target.requests(None).await?, "renew")?;
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
                let renew_count = count(&target.requests(None).await?, "renew")?;
                ensure!(
                    renew_count <= attempts + 1,
                    "lost-response retry happened before the restart fixture could stop the agent"
                );
                let pending = record.body["certificates"]
                    .as_array()
                    .context("missing certificates")?
                    .iter()
                    .find(|cert| cert["status"] == "pending");
                if renew_count == attempts + 1
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
            ensure!(
                count(&target.requests(None).await?, "renew")? == attempts + 1,
                "agent retried before it was stopped"
            );
            ensure!(
                key_name(&case.state(&authority)?, "pending")? == pending_key,
                "pending CSR key was not persisted across stop"
            );
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
                count(&target.requests(None).await?, "renew")? >= attempts + 2,
                "lost renewal response was not retried"
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
            for key in REQUIRED_METADATA_KEYS {
                let value = field(&enrolled.body["metadata"], key)?;
                ensure!(
                    !value.is_empty() && connected["metadata"][key] == value,
                    "Hello did not refresh the required {key} metadata value"
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

pub(crate) async fn a_old_key_survives_unavailable_channel(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let old_key = key_name(&state, "current")?.to_owned();
            let old_thumb = current_thumbprint(
                &case
                    .until_device(&target, &id, "old-root channel", |record| record["connected"] == true)
                    .await?,
            )?
            .to_owned();
            target.faults(&json!({ "channel_available": false })).await?;
            expect_status(
                &target
                    .admin(Method::POST, &format!("/devices/{id}/request-renewal"), None)
                    .await?,
                202,
            )?;
            let pending = case
                .until_device(&target, &id, "pending renewal without channel", |record| {
                    record["certificates"].as_array().is_some_and(|certs| {
                        certs
                            .iter()
                            .any(|cert| cert["status"] == "pending" && cert["thumbprint"] != old_thumb)
                    })
                })
                .await?;
            let new_thumb = pending["certificates"]
                .as_array()
                .context("pending certificates missing")?
                .iter()
                .find(|cert| cert["status"] == "pending")
                .and_then(|cert| cert["thumbprint"].as_str())
                .context("pending certificate lacks a thumbprint")?
                .to_owned();
            for _ in 0..3 {
                ensure!(
                    key_exists(case, &authority, &old_key)?
                        && current_thumbprint(&case.device(&target, &id).await?.body)? == old_thumb,
                    "old key was deleted before the pending key authenticated"
                );
                case.check_running()?;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            ensure!(
                target
                    .events(&id)
                    .await?
                    .iter()
                    .all(|event| { event["type"] != "stream_authenticated" || event["cert_thumbprint"] != new_thumb }),
                "new channel authenticated while the channel was unavailable"
            );
            expect_status(&target.control("handshake", &json!({ "pause": true })).await?, 200)?;
            target.faults(&json!({ "channel_available": true })).await?;
            let start = Instant::now();
            loop {
                let events = target.events(&id).await?;
                let opened_new = events
                    .iter()
                    .any(|event| event["type"] == "stream_opened" && event["cert_thumbprint"] == new_thumb);
                if opened_new && count(&target.requests(None).await?, "paused_hellos")? > 0 {
                    break;
                }
                ensure!(
                    key_exists(case, &authority, &old_key)?,
                    "old key was deleted while the new channel was still opening"
                );
                case.check_running()?;
                ensure!(
                    start.elapsed() < WAIT,
                    "agent did not reach the new-key handshake barrier"
                );
                tokio::time::sleep(POLL).await;
            }
            for _ in 0..5 {
                ensure!(
                    key_exists(case, &authority, &old_key)?
                        && target.events(&id).await?.iter().all(|event| {
                            event["type"] != "stream_authenticated" || event["cert_thumbprint"] != new_thumb
                        }),
                    "agent deleted the previous key before the new Hello authenticated"
                );
                case.check_running()?;
                tokio::time::sleep(POLL).await;
            }
            expect_status(&target.control("handshake", &json!({ "pause": false })).await?, 200)?;
            let start = Instant::now();
            loop {
                let exists = key_exists(case, &authority, &old_key)?;
                let authenticated = target
                    .events(&id)
                    .await?
                    .iter()
                    .any(|event| event["type"] == "stream_authenticated" && event["cert_thumbprint"] == new_thumb);
                ensure!(
                    exists || authenticated,
                    "previous key was deleted before stream_authenticated"
                );
                if !exists && authenticated {
                    break;
                }
                case.check_running()?;
                ensure!(start.elapsed() < WAIT, "old key survived new channel authentication");
                tokio::time::sleep(POLL).await;
            }
            case.until_device(&target, &id, "new authenticated channel", |record| {
                current_thumbprint(record).is_ok_and(|thumb| thumb == new_thumb) && record["connected"] == true
            })
            .await?;
            assert_new_auth_precedes_old_close(&target, &id, &old_thumb, &new_thumb).await?;
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

pub(crate) async fn a_reconnect_make_before_break(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, _) = case.enrolled(&target, &token).await?;
            case.until_device(&target, &id, "first channel", |record| record["connected"] == true)
                .await?;
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

pub(crate) async fn a_no_channel_when_absent(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            target.faults(&json!({ "channel_available": false })).await?;
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            ensure!(
                state.get("channel_url").is_none(),
                "agent stored channel_url despite the field being absent from enrollment"
            );
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                case.check_running()?;
                ensure!(
                    case.device(&target, &id).await?.body["connected"] == false,
                    "agent opened an unavailable channel"
                );
                ensure!(
                    count(&target.requests(None).await?, "connect")? == 0,
                    "agent attempted Connect despite absent channel_url"
                );
            }
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
        return with_agent(ctx, None, true, |case| {
            Box::pin(async move {
                let target = case.ctx.target.clone();
                let token = new_token(case, 1).await?;
                case.write_pending(&token.text)?;
                let (_, state) = case.enrolled(&target, &token).await?;
                crate::windows::assert_non_exportable(key_name(&state, "current")?)?;
                crate::windows::assert_machine_key_acl(key_name(&state, "current")?)?;
                case.check_key_protection(field(&state, "authority_id")?, &state)?;
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
                let authority = field(&state, "authority_id")?;
                let name = key_name(&state, "current")?;
                let key_file = case
                    .path()
                    .join("identity")
                    .join("authorities")
                    .join(authority)
                    .join("keys")
                    .join(format!("{name}.p8"));
                for path in [key_file, case.identity_path(authority)] {
                    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
                    ensure!(mode == 0o600, "{} has mode {mode:o}, expected 0600", path.display());
                }
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

pub(crate) async fn a_rotation_migrates_on_schedule(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, Some(2), true, |case| {
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
            expect_status(&target.rotate(None).await?, 202)?;
            let new = case
                .until_device(&target, &id, "scheduled new-root renewal", |record| {
                    record["certificates"].as_array().is_some_and(|certs| {
                        certs
                            .iter()
                            .any(|cert| cert["issuer"] != old_root && cert["status"] == "pending")
                    })
                })
                .await?;
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
            case.stop().await?;
            ensure!(
                key_name(&case.state(&authority)?, "pending")? == pending_key,
                "new-root pending key was not persisted across restart"
            );
            let attempts = count(&target.requests(None).await?, "renew")?;
            case.start().await?;
            case.until_device(&target, &id, "authenticated new-root key after restart", |record| {
                record["certificate"]["issuer"] == new_root
                    && current_thumbprint(record).is_ok_and(|thumb| thumb == pending_thumb)
            })
            .await?;
            ensure!(
                count(&target.requests(None).await?, "renew")? > attempts,
                "agent did not authenticate the stored new-root key through renew"
            );
            let final_state = case.state(&authority)?;
            ensure!(
                key_name(&final_state, "current")? == pending_key
                    && final_state["keys"]["current"]["certificate_chain"]
                        .as_array()
                        .and_then(|chain| chain.last())
                        .and_then(Value::as_str)
                        .is_some_and(|root| crate::signer::thumbprint(root).is_ok_and(|issuer| issuer == new_root)),
                "restarted agent did not keep the authenticated new-root chain"
            );
            Ok(())
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

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
