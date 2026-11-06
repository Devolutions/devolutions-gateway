//! Reads packages, managers and sources from the UniGetUI IPC API running on this machine, and installs, updates and
//! uninstalls packages through it.
//!
//! UniGetUI writes one endpoint registration file per running session under
//! `<local data>/UniGetUI/Configuration/IpcApiEndpoints` (`%LOCALAPPDATA%` on Windows, `~/.local/share` on Unix).
//! The agent runs as SYSTEM or root, so it scans every user profile and uses the most recent registration that
//! answers. The named-pipe transport is a Windows named pipe, or a Unix domain socket on Unix.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::protocol::{InstalledPackage, PackageManager, PackageSource};

const INSTALLED_PACKAGES_PATH: &str = "/uniget/v1/packages/installed";
const UPGRADABLE_PACKAGES_PATH: &str = "/uniget/v1/packages/updates";
const MANAGERS_PATH: &str = "/uniget/v1/managers";
const SOURCES_PATH: &str = "/uniget/v1/sources";
const DEFAULT_PIPE_NAME: &str = "UniGetUI.IPC";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
// UniGetUI answers a package operation only when the installer is finished.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy)]
enum Method {
    Get,
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum PackageOperation {
    Install,
    Update,
    Uninstall,
}

impl PackageOperation {
    fn path(self) -> &'static str {
        match self {
            Self::Install => "/uniget/v1/packages/install",
            Self::Update => "/uniget/v1/packages/update",
            Self::Uninstall => "/uniget/v1/packages/uninstall",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpcOperationResult {
    #[serde(default)]
    status: String,
    #[serde(default)]
    operation_status: String,
    message: Option<String>,
    #[serde(default)]
    output: Vec<String>,
}

#[derive(Debug, Clone)]
enum Transport {
    Tcp(u16),
    NamedPipe(String),
}

#[derive(Debug, Clone)]
struct Endpoint {
    file: PathBuf,
    token: String,
    transport: Transport,
    persisted_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Registration {
    token: Option<String>,
    transport: Option<serde_json::Value>,
    tcp_port: Option<u16>,
    named_pipe_name: Option<String>,
    #[cfg_attr(windows, allow(dead_code))]
    named_pipe_path: Option<String>,
    persisted_at_utc: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpcPackage {
    #[serde(default)]
    name: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    manager: String,
    #[serde(default)]
    new_version: String,
}

impl From<IpcPackage> for InstalledPackage {
    fn from(package: IpcPackage) -> Self {
        Self {
            manager: package.manager,
            source: package.source,
            id: package.id,
            name: package.name,
            version: package.version,
            available_version: package.new_version,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpcManager {
    #[serde(default)]
    name: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    ready: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpcSource {
    #[serde(default)]
    manager: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    url: String,
}

pub(super) async fn installed_packages() -> anyhow::Result<Vec<InstalledPackage>> {
    let packages: Vec<IpcPackage> = get_json(INSTALLED_PACKAGES_PATH, &[]).await?;
    let mut packages: Vec<InstalledPackage> = packages.into_iter().map(Into::into).collect();

    // The installed list does not include the newer version, so merge it from the updates list.
    // A failure here only hides the available versions; the inventory is still valid.
    match get_json::<Vec<IpcPackage>>(UPGRADABLE_PACKAGES_PATH, &[]).await {
        Ok(upgradable) => merge_available_versions(&mut packages, upgradable),
        Err(error) => warn!(error = format!("{error:#}"), "Failed to read UniGetUI upgradable packages"),
    }

    Ok(packages)
}

fn merge_available_versions(packages: &mut [InstalledPackage], upgradable: Vec<IpcPackage>) {
    for update in upgradable.into_iter().filter(|update| !update.new_version.is_empty()) {
        let same_package = |package: &InstalledPackage| package.manager == update.manager && package.id == update.id;
        // Match the source first; fall back to manager + id when UniGetUI reports a different source name.
        let index = packages
            .iter()
            .position(|package| same_package(package) && package.source == update.source)
            .or_else(|| packages.iter().position(|package| same_package(package)));
        if let Some(index) = index {
            packages[index].available_version = update.new_version;
        }
    }
}

/// Runs one package operation and waits for the end of the installer. An empty version means the latest version.
pub(super) async fn package_operation(
    operation: PackageOperation,
    manager: &str,
    source: &str,
    package_id: &str,
    version: &str,
) -> anyhow::Result<()> {
    let mut parameters = vec![("packageId", package_id), ("manager", manager)];
    if !source.is_empty() {
        parameters.push(("packageSource", source));
    }
    if matches!(operation, PackageOperation::Uninstall) {
        // Uninstallers come from the ARP entry, so winget cannot detect a machine-wide uninstaller that needs admin rights.
        parameters.push(("elevated", "true"));
    } else if !version.is_empty() {
        parameters.push(("version", version));
    }

    let result: IpcOperationResult =
        request_json(Method::Post, operation.path(), &parameters, OPERATION_TIMEOUT).await?;

    if result.status.eq_ignore_ascii_case("success") {
        return Ok(());
    }

    let detail = result
        .message
        .filter(|message| !message.is_empty())
        .or_else(|| result.output.last().cloned())
        .unwrap_or_else(|| result.operation_status.clone());

    // An upgrade of a package that is already on the latest version is not an error.
    if matches!(operation, PackageOperation::Update) && detail.contains(WINGET_UPDATE_NOT_APPLICABLE) {
        info!(package_id, "Package is already on the latest version");
        return Ok(());
    }

    bail!("UniGetUI operation failed: {detail}")
}

const WINGET_UPDATE_NOT_APPLICABLE: &str = "0x8A15002B";

pub(super) async fn managers() -> anyhow::Result<Vec<PackageManager>> {
    let managers: Vec<IpcManager> = get_json(MANAGERS_PATH, &[]).await?;
    // The IPC API does not expose the manager version. "Ready" means that UniGetUI found the manager executable.
    Ok(managers
        .into_iter()
        .map(|manager| PackageManager {
            name: manager.name,
            installed: manager.ready,
            enabled: manager.enabled,
            version: String::new(),
        })
        .collect())
}

pub(super) async fn sources() -> anyhow::Result<Vec<PackageSource>> {
    let sources: Vec<IpcSource> = get_json(SOURCES_PATH, &[]).await?;
    Ok(sources
        .into_iter()
        .map(|source| PackageSource {
            manager: source.manager,
            name: source.name,
            url: source.url,
        })
        .collect())
}

/// Sends a GET to the first UniGetUI endpoint that answers.
async fn get_json<T: DeserializeOwned>(path: &str, parameters: &[(&str, &str)]) -> anyhow::Result<T> {
    request_json(Method::Get, path, parameters, REQUEST_TIMEOUT).await
}

/// Sends a request to the first UniGetUI endpoint that answers.
async fn request_json<T: DeserializeOwned>(
    method: Method,
    path: &str,
    parameters: &[(&str, &str)],
    timeout: Duration,
) -> anyhow::Result<T> {
    let endpoints = discover_endpoints();
    if endpoints.is_empty() {
        bail!("no UniGetUI IPC endpoint registration found; is UniGetUI running?");
    }

    let mut last_error = None;
    for endpoint in endpoints {
        let query = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("token", &endpoint.token);
            for (name, value) in parameters {
                serializer.append_pair(name, value);
            }
            serializer.finish()
        };
        let path_and_query = format!("{path}?{query}");

        let started = Instant::now();
        match query_endpoint(&endpoint, method, &path_and_query, timeout).await {
            Ok(body) => {
                let request_ms = started.elapsed().as_millis();
                let parse_started = Instant::now();
                let result =
                    serde_json::from_str(&body).with_context(|| format!("invalid UniGetUI response for {path}"));
                info!(
                    path,
                    transport = ?endpoint.transport,
                    request_ms,
                    parse_ms = parse_started.elapsed().as_millis(),
                    bytes = body.len(),
                    "UniGetUI IPC request completed"
                );
                return result;
            }
            Err(error) => {
                warn!(
                    path,
                    file = %endpoint.file.display(),
                    transport = ?endpoint.transport,
                    elapsed_ms = started.elapsed().as_millis(),
                    error = format!("{error:#}"),
                    "UniGetUI endpoint failed"
                );
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no UniGetUI endpoint answered")))
}

async fn query_endpoint(
    endpoint: &Endpoint,
    method: Method,
    path_and_query: &str,
    timeout: Duration,
) -> anyhow::Result<String> {
    match &endpoint.transport {
        Transport::Tcp(port) => {
            let url = format!("http://localhost:{port}{path_and_query}");
            let client = reqwest::Client::builder().timeout(timeout).build()?;
            let request = match method {
                Method::Get => client.get(url),
                Method::Post => client.post(url).header(reqwest::header::CONTENT_LENGTH, 0),
            };
            let response = request.send().await.context("UniGetUI TCP request failed")?;
            let status = response.status();
            let body = response.text().await.context("failed to read UniGetUI response")?;
            if !status.is_success() {
                bail!("UniGetUI returned {status}: {}", body.trim());
            }
            Ok(body)
        }
        Transport::NamedPipe(name) => tokio::time::timeout(timeout, named_pipe_request(name, method, path_and_query))
            .await
            .context("UniGetUI named pipe request timed out")?,
    }
}

fn discover_endpoints() -> Vec<Endpoint> {
    let mut endpoints: Vec<Endpoint> = registration_directories()
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("json")))
        .filter_map(|path| parse_registration(&path))
        .collect();

    endpoints.sort_by(|a, b| b.persisted_at.cmp(&a.persisted_at));
    endpoints
}

fn parse_registration(path: &Path) -> Option<Endpoint> {
    let text = std::fs::read_to_string(path).ok()?;
    let registration: Registration = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let token = registration.token.filter(|token| !token.is_empty())?;

    let is_tcp = match registration.transport {
        Some(serde_json::Value::Number(number)) => number.as_u64() == Some(0),
        Some(serde_json::Value::String(value)) => value.eq_ignore_ascii_case("tcp"),
        _ => false,
    };

    let transport = if is_tcp {
        Transport::Tcp(registration.tcp_port.unwrap_or(7058))
    } else {
        let name = registration
            .named_pipe_name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| DEFAULT_PIPE_NAME.to_owned());

        // On Unix the pipe is a socket file; UniGetUI resolves relative names under /tmp.
        #[cfg(unix)]
        let name = match registration.named_pipe_path.filter(|path| !path.is_empty()) {
            Some(path) => path,
            None if name.starts_with('/') => name,
            None => format!("/tmp/{name}"),
        };

        Transport::NamedPipe(name)
    };

    Some(Endpoint {
        file: path.to_path_buf(),
        token,
        transport,
        persisted_at: registration.persisted_at_utc.unwrap_or_default(),
    })
}

#[cfg(unix)]
fn registration_directories() -> Vec<PathBuf> {
    const RELATIVE: [&str; 5] = [".local", "share", "UniGetUI", "Configuration", "IpcApiEndpoints"];

    let home_roots = if cfg!(target_os = "macos") { "/Users" } else { "/home" };
    let mut homes: Vec<PathBuf> = std::fs::read_dir(home_roots)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    homes.push(PathBuf::from("/root"));

    homes
        .into_iter()
        .map(|home| RELATIVE.iter().fold(home, |acc, part| acc.join(part)))
        .collect()
}

#[cfg(windows)]
fn registration_directories() -> Vec<PathBuf> {
    const RELATIVE: [&str; 5] = ["AppData", "Local", "UniGetUI", "Configuration", "IpcApiEndpoints"];

    let mut dirs = Vec::new();

    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        dirs.push(
            PathBuf::from(local_app_data)
                .join("UniGetUI")
                .join("Configuration")
                .join("IpcApiEndpoints"),
        );
    }

    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
    let users_dir = PathBuf::from(format!("{system_drive}\\Users"));
    if let Ok(entries) = std::fs::read_dir(users_dir) {
        for entry in entries.filter_map(Result::ok) {
            let dir = RELATIVE.iter().fold(entry.path(), |acc, part| acc.join(part));
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }

    dirs
}

#[cfg(windows)]
async fn named_pipe_request(pipe_name: &str, method: Method, path_and_query: &str) -> anyhow::Result<String> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe_path = format!(r"\\.\pipe\{pipe_name}");
    let pipe = ClientOptions::new()
        .open(&pipe_path)
        .with_context(|| format!("failed to open {pipe_path}"))?;

    stream_request(pipe, method, path_and_query).await
}

#[cfg(unix)]
async fn named_pipe_request(socket_path: &str, method: Method, path_and_query: &str) -> anyhow::Result<String> {
    let socket = tokio::net::UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("failed to connect to {socket_path}"))?;

    stream_request(socket, method, path_and_query).await
}

async fn stream_request<S>(mut pipe: S, method: Method, path_and_query: &str) -> anyhow::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let request = format!(
        "{} {path_and_query} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        method.as_str()
    );
    pipe.write_all(request.as_bytes())
        .await
        .context("failed to write request")?;
    pipe.flush().await?;

    let mut response = Vec::new();
    // The server may reset the pipe after the response, so keep what was read.
    if let Err(error) = pipe.read_to_end(&mut response).await
        && response.is_empty()
    {
        return Err(error).context("failed to read response");
    }

    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> anyhow::Result<String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&response[..header_end]);
    let body = &response[header_end + 4..];

    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let status = status_line.split_whitespace().nth(1).unwrap_or_default();
    let chunked = lines.any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });

    let body = if chunked { decode_chunked(body)? } else { body.to_vec() };
    let body = String::from_utf8(body).context("UniGetUI response is not UTF-8")?;
    if !status.starts_with('2') {
        bail!("UniGetUI returned {status_line}: {}", body.trim());
    }
    Ok(body)
}

fn decode_chunked(mut input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .context("malformed chunk header")?;
        let size_text = String::from_utf8_lossy(&input[..line_end]);
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).context("invalid chunk size")?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        let chunk = input.get(..size).context("truncated chunk")?;
        output.extend_from_slice(chunk);
        input = input.get(size + 2..).unwrap_or_default();
    }
}
