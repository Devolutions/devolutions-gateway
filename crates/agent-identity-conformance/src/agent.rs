use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Method;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;
use tokio::process::{Child, Command};

use crate::client::{Target, Token, count, expect_status, field};
use crate::{Context, KeyBackend};

type CaseFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
const WAIT: Duration = Duration::from_secs(6);
const POLL: Duration = Duration::from_millis(100);

struct AgentCase {
    ctx: Context,
    dir: tempfile::TempDir,
    child: Option<Child>,
    tokens: Vec<String>,
    cleaned: bool,
    #[cfg(windows)]
    machine_keys: Vec<String>,
    #[cfg(windows)]
    preexisting_keys: std::collections::HashSet<String>,
}

impl AgentCase {
    async fn new(ctx: Context, renewal_after_secs: Option<u64>, run: bool) -> anyhow::Result<Self> {
        #[cfg(windows)]
        let preexisting_keys =
            crate::windows::snapshot_machine_identity_keys().context("snapshot existing machine identity keys")?;
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
            tokens: Vec::new(),
            cleaned: false,
            #[cfg(windows)]
            machine_keys: Vec::new(),
            #[cfg(windows)]
            preexisting_keys,
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
        let process = Command::new(&self.ctx.agent_bin)
            .arg("run")
            .env("DAGENT_CONFIG_PATH", self.path())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .context("spawn devolutions-agent run")?;
        self.child = Some(process);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill().await.context("stop agent")?;
            }
            let _ = child.wait().await;
        }
        Ok(())
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
                "agent did not enroll and persist an identity within six seconds"
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
            let response = target.device(device_id).await?;
            if response.status == 200 && check(&response.body) {
                return Ok(response.body);
            }
            self.check_running()?;
            ensure!(start.elapsed() < WAIT, "agent did not reach {what} within six seconds");
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
            let _ = target.device(device_id).await?;
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
            let _ = target.device(device_id).await?;
            if let Ok(state) = self.state(authority_id)
                && check(&state)
            {
                return Ok(state);
            }
            self.check_running()?;
            ensure!(
                start.elapsed() < WAIT,
                "agent did not persist {what} within six seconds"
            );
            tokio::time::sleep(POLL).await;
        }
    }

    async fn finish(&mut self) -> anyhow::Result<()> {
        let stopped = self.stop().await;
        let protected = self.audit_stored_keys();
        #[cfg(windows)]
        crate::windows::cleanup_machine_keys(self.path(), &self.machine_keys, &self.preexisting_keys);
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
            #[cfg(windows)]
            if self.ctx.key_backend == KeyBackend::KeyStore {
                if crate::windows::machine_key_exists(name)? {
                    crate::windows::assert_non_exportable(name)?;
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
                } else {
                    ensure!(slot == "previous", "{slot} file key is missing");
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
                        ensure!(
                            !contents.windows(fragment.len()).any(|chunk| chunk == fragment),
                            "enrollment token leaked into {}",
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
            crate::windows::cleanup_machine_keys(self.path(), &self.machine_keys, &self.preexisting_keys);
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

fn assert_stored_identity(case: &AgentCase, token: &Token, state: &Value, device_id: &str) -> anyhow::Result<()> {
    ensure!(state["version"] == 1, "stored identity has wrong version");
    ensure!(state["device_id"] == device_id, "stored identity has wrong device ID");
    let authority = field(state, "authority_id")?;
    ensure!(
        uuid::Uuid::parse_str(authority).is_ok(),
        "stored identity authority is not a UUID"
    );
    ensure!(
        field(state, "base_url")? == case.ctx.target.base_url,
        "stored identity has wrong base URL"
    );
    ensure!(
        state["token_sha256"] == URL_SAFE_NO_PAD.encode(Sha256::digest(token.text.as_bytes())),
        "stored identity has wrong full-token hash"
    );
    ensure!(
        state["keys"]["current"]["certificate_chain"].is_array(),
        "stored identity has no current certificate"
    );
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

pub(crate) async fn a_pending_file_enroll_success(ctx: Context) -> anyhow::Result<()> {
    with_agent(ctx, None, true, |case| {
        Box::pin(async move {
            let target = case.ctx.target.clone();
            let token = new_token(case, 2).await?;
            case.write_pending(&token.text)?;
            let (id, state) = case.enrolled(&target, &token).await?;
            assert_stored_identity(case, &token, &state, &id)?;
            ensure!(
                !case.pending_path().exists(),
                "pending file not deleted after enrollment"
            );
            let admin = target.device(&id).await?;
            expect_status(&admin, 200)?;
            ensure!(admin.body["id"] == id, "enrolled device absent from admin API");
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
                    "token_malformed" => ("dvaet1.not-base64.short".to_owned(), token, 0, 0),
                    _ => anyhow::bail!("unknown permanent error"),
                };
                let ingress = if reason == "token_malformed" {
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
                target.faults(&json!({ "drop_next_response": "enroll" })).await?;
                case.write_pending(&token.text)?;
                let start = Instant::now();
                let mut observed = false;
                while start.elapsed() < WAIT {
                    let listing = target.devices_for(&token, "").await?;
                    if count(&listing.body, "totalCount")? == 1 && case.pending_path().exists() {
                        observed = true;
                        break;
                    }
                    case.check_running()?;
                    tokio::time::sleep(POLL).await;
                }
                ensure!(observed, "dropped response did not leave pending enrollment for retry");
                let _ = case.enrolled(&target, &token).await?;
                ensure!(
                    count(&target.token_record(&token.id).await?.body, "usedCount")? == 1,
                    "retry consumed an additional token use"
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
                !key_exists(case, &authority, &original_key)?,
                "old private key survived replacement"
            );
            ensure!(
                case.state(&authority)?["device_id"] == next_id,
                "stored identity not replaced"
            );
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
            let invalid = Command::new(&case.ctx.agent_bin)
                .args(["identity", "enroll", "dvaet1.bad.short"])
                .env("DAGENT_CONFIG_PATH", case.path())
                .output()
                .await?;
            ensure!(
                !invalid.status.success(),
                "identity enroll CLI accepted a malformed token"
            );
            ensure!(
                !case.pending_path().exists(),
                "malformed CLI token wrote a pending file"
            );
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
            let before = target.device(&id).await?;
            let old_thumb = current_thumbprint(&before.body)?.to_owned();
            let name = field(&before.body, "friendlyName")?.to_owned();
            let start = Instant::now();
            let renewed = loop {
                let record = target.device(&id).await?;
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
                .until_state(&target, &authority, &id, "new stored current certificate", |state| {
                    key_name(state, "current").is_ok_and(|name| name != old_key)
                })
                .await?;
            ensure!(
                key_name(&final_state, "current")? != old_key,
                "old key remained current"
            );
            case.check_key_protection(&authority, &final_state)?;
            ensure!(
                !key_exists(case, &authority, &old_key)?,
                "old key survived successful renewal"
            );
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
            let before = target.device(&id).await?;
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
            let renewed = case
                .until_device(&target, &id, "retried renewal", |device| {
                    current_thumbprint(device).is_ok_and(|thumb| thumb != old_thumb)
                        && device["renewalRequested"] == false
                })
                .await?;
            ensure!(
                renewed["certificates"].as_array().is_some_and(|certs| certs.len() == 2),
                "lost renewal response created multiple new certificates"
            );
            ensure!(
                count(&target.requests(None).await?, "renew")? >= attempts + 2,
                "lost renewal response was not retried"
            );
            ensure!(
                target.control("faults", &json!({})).await?.body["drop_next_response"].is_null(),
                "drop-next-renew fault was never consumed"
            );
            let state = case.state(&authority)?;
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
            let token = new_token(case, 1).await?;
            case.write_pending(&token.text)?;
            let (id, _) = case.enrolled(&target, &token).await?;
            let connected = case
                .until_device(&target, &id, "connected channel", |device| device["connected"] == true)
                .await?;
            ensure!(
                connected["lastSeenAt"].as_str().is_some(),
                "channel did not update lastSeenAt"
            );
            ensure!(connected["metadata"].is_object(), "Hello metadata not stored");
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
            loop {
                let record = target.device(&id).await?;
                expect_status(&record, 200)?;
                ensure!(
                    record.body["connected"] == true,
                    "agent disconnected during make-before-break"
                );
                if current_thumbprint(&record.body).is_ok_and(|thumb| thumb != old_thumb) {
                    ensure!(
                        record.body["certificates"].as_array().is_some_and(|certs| certs
                            .iter()
                            .any(|cert| cert["thumbprint"] == old_thumb && cert["status"] == "retired")),
                        "old certificate not retired after new one connected"
                    );
                    break;
                }
                case.check_running()?;
                ensure!(start.elapsed() < WAIT, "agent did not renew over a live channel");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
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
                target.device(&id).await?.body["renewalRequested"] == true,
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
                let current = target.device(&id).await?;
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
            target.revoke(&id).await?;
            let _ = case.until_rejected(&target, &authority, &id, "device_revoked").await?;
            let revoked = target.device(&id).await?;
            ensure!(revoked.body["connected"] == false, "revoked agent remains connected");
            let certs = revoked.body["certificates"].clone();
            let attempts = if case.ctx.mock() {
                Some(target.requests(None).await?)
            } else {
                None
            };
            tokio::time::sleep(Duration::from_secs(2)).await;
            let later = target.device(&id).await?;
            ensure!(later.body["connected"] == false, "revoked agent reconnected");
            ensure!(
                later.body["certificates"] == certs,
                "revoked agent renewed a certificate"
            );
            if let Some(before) = attempts {
                let after = target.requests(None).await?;
                ensure!(
                    after["renew"] == before["renew"] && after["connect"] == before["connect"],
                    "rejected agent attempted renewal or reconnection"
                );
            }
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
            target.reset().await?;
            expect_status(&target.device(&id).await?, 404)?;
            let rejected = case.until_rejected(&target, &authority, &id, "device_unknown").await?;
            ensure!(rejected["rejected"]["at"].as_str().is_some(), "rejection time missing");
            let attempts = target.requests(None).await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            ensure!(
                case.state(&authority)?["rejected"]["code"] == "device_unknown",
                "unknown identity resumed connecting"
            );
            let later = target.requests(None).await?;
            ensure!(
                later["renew"] == attempts["renew"] && later["connect"] == attempts["connect"],
                "unknown device attempted renewal or reconnection"
            );
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
                state["channel_url"].is_null(),
                "agent stored a channel URL when none was advertised"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
            ensure!(
                target.device(&id).await?.body["connected"] == false,
                "agent opened an unavailable channel"
            );
            ensure!(
                count(&target.requests(None).await?, "connect")? == 0,
                "agent attempted Connect despite absent channel_url"
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
                first.device(&first_id).await?.body["connected"] == true,
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
            let (id, _) = case.enrolled(&target, &token).await?;
            let old = case
                .until_device(&target, &id, "old-root connection", |record| {
                    record["connected"] == true
                })
                .await?;
            let old_root = field(&old["certificate"], "issuer")?.to_owned();
            let started = if case.ctx.mock() {
                target.rotate(None).await?
            } else {
                crate::protocol::wait_rotation_idle(&target).await?;
                let deadline = (time::OffsetDateTime::now_utc() + time::Duration::seconds(8)).format(&Rfc3339)?;
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
            let rotation = target.admin(Method::GET, "/ca/rotation", None).await?;
            if rotation.body["phase"] == "rotating" {
                ensure!(
                    count(&rotation.body, "activeDevicesOnOldRoot")? < initial,
                    "agent migration did not reduce the old-root count"
                );
            }
            if !case.ctx.mock() {
                crate::protocol::wait_rotation_idle(&target).await?;
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
            let (id, _) = case.enrolled(&target, &token).await?;
            let before = target.device(&id).await?;
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
            Ok(())
        })
    })
    .await
}
