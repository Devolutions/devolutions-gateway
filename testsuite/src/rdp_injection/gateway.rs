//! Runs a real Gateway child process and exposes its logs for assertions.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::Child;

use crate::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use crate::dgw_config::{DgwConfig, DgwConfigHandle, VerbosityProfile};

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub struct LogBuffer(Arc<Mutex<String>>);

impl LogBuffer {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(String::new())))
    }

    pub fn snapshot(&self) -> String {
        strip_ansi(&self.0.lock().expect("log mutex"))
    }

    pub async fn wait_contains(&self, needle: &str) -> anyhow::Result<String> {
        self.wait_count(needle, 1).await
    }

    pub async fn wait_count(&self, needle: &str, count: usize) -> anyhow::Result<String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let snapshot = self.snapshot();
            if snapshot.matches(needle).count() >= count {
                return Ok(snapshot);
            }
            if Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for {count} occurrence(s) of {needle:?}; logs:\n{snapshot}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

pub struct GatewayProc {
    pub config: DgwConfigHandle,
    pub process: Child,
    pub logs: LogBuffer,
}

impl GatewayProc {
    pub async fn start() -> anyhow::Result<Self> {
        let config = DgwConfig::builder()
            .disable_token_validation(true)
            .verbosity_profile(VerbosityProfile::DEBUG)
            .build()
            .init()
            .context("init gateway config")?;

        let mut process = dgw_tokio_cmd()
            .env("DGATEWAY_CONFIG_PATH", config.config_dir())
            .env("RUST_LOG", "devolutions_gateway=debug")
            .env("NO_COLOR", "1")
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("start Devolutions Gateway")?;

        let logs = LogBuffer::new();
        spawn_stdio_collector(process.stdout.take(), Arc::clone(&logs.0));
        spawn_stdio_collector(process.stderr.take(), Arc::clone(&logs.0));

        wait_for_tcp_port(config.http_port())
            .await
            .context("wait for gateway HTTP port")?;

        Ok(Self { config, process, logs })
    }
}

fn spawn_stdio_collector<R>(stream: Option<R>, logs: Arc<Mutex<String>>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let Some(stream) = stream else {
        return;
    };
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => logs.lock().expect("log mutex").push_str(&line),
            }
        }
    });
}
