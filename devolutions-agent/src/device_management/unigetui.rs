//! Reads package inventory from the UniGetUI IPC API.
//!
//! On Windows, the Agent verifies the endpoint-owning process and routes each request to one instance with the
//! requested user SID, without retrying against another instance.

#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, IntoRawHandle as _};
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{Duration, Instant};

use agent_channel_proto::{InstalledPackage, PackageManager, PackageSource};
#[cfg(any(windows, test))]
use anyhow::Context as _;
use anyhow::bail;
#[cfg(windows)]
use now_package_broker::server::ProcessIdentity;
use serde::Deserialize;
use serde::de::DeserializeOwned;
#[cfg(windows)]
use win_api_wrappers::process::{Process, ProcessEntry32Iterator};
#[cfg(windows)]
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, HANDLE};
#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_LISTEN, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_CLASS,
    TCP_TABLE_OWNER_PID_ALL, TCP_TABLE_OWNER_PID_LISTENER,
};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::AF_INET;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, FILE_WRITE_DATA, SECURITY_IDENTIFICATION};
#[cfg(windows)]
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
#[cfg(windows)]
use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

const INSTALLED_PACKAGES_PATH: &str = "/uniget/v1/packages/installed";
const UPGRADABLE_PACKAGES_PATH: &str = "/uniget/v1/packages/updates";
const MANAGERS_PATH: &str = "/uniget/v1/managers";
const SOURCES_PATH: &str = "/uniget/v1/sources";
#[cfg(windows)]
const DEFAULT_PIPE_NAME: &str = "UniGetUI.IPC";
#[cfg(windows)]
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(windows)]
#[derive(Debug, Clone)]
enum Transport {
    Tcp(u16),
    NamedPipe(String),
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct Endpoint {
    file: PathBuf,
    token: String,
    transport: Transport,
    persisted_at: String,
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct EndpointIdentity {
    user_sid: String,
    session_id: u32,
    display_name: String,
    signature_verified: bool,
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct DiscoveredEndpoint {
    endpoint: Endpoint,
    identity: EndpointIdentity,
    process: Option<ProcessIdentity>,
}

#[cfg(windows)]
#[derive(Debug, Clone)]
pub(super) struct TargetInstance {
    endpoint: DiscoveredEndpoint,
}

/// UniGetUI targets cannot be resolved off Windows, so no instance exists.
#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub(super) enum TargetInstance {}

#[cfg(windows)]
fn select_target_endpoint<'a>(
    endpoints: &'a [DiscoveredEndpoint],
    target_user_sid: &str,
) -> Option<&'a DiscoveredEndpoint> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.identity.signature_verified && endpoint.identity.user_sid == target_user_sid)
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Registration {
    token: Option<String>,
    transport: Option<serde_json::Value>,
    tcp_port: Option<u16>,
    named_pipe_name: Option<String>,
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
    source_name: String,
    #[serde(default)]
    manager: String,
    #[serde(default)]
    new_version: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    reported_scope: Option<String>,
}

impl IpcPackage {
    fn reported_scope(&self) -> &str {
        self.reported_scope.as_deref().unwrap_or(&self.scope)
    }
}

impl From<IpcPackage> for InstalledPackage {
    fn from(package: IpcPackage) -> Self {
        let reported_scope = package.reported_scope.unwrap_or(package.scope);
        Self {
            manager: package.manager,
            source: package.source,
            source_name: package.source_name,
            id: package.id,
            name: package.name,
            version: package.version,
            available_version: package.new_version,
            scope: "UNKNOWN".to_owned(),
            reported_scope,
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
    #[serde(default)]
    health: IpcManagerHealth,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct IpcManagerHealth {
    #[serde(default)]
    state: String,
}

fn is_manager_loading(manager: &IpcManager) -> bool {
    manager.enabled && manager.health.state.eq_ignore_ascii_case("loading")
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

pub(super) async fn installed_packages(instance: &TargetInstance) -> anyhow::Result<Vec<InstalledPackage>> {
    let packages: Vec<IpcPackage> = get_json_on_endpoint(instance, INSTALLED_PACKAGES_PATH, &[]).await?;
    let mut packages: Vec<InstalledPackage> = packages.into_iter().map(Into::into).collect();

    // The installed list does not include the newer version, so merge it from the updates list.
    // A failure here only hides the available versions; the inventory is still valid.
    match get_json_on_endpoint::<Vec<IpcPackage>>(instance, UPGRADABLE_PACKAGES_PATH, &[]).await {
        Ok(upgradable) => merge_available_versions(&mut packages, upgradable),
        Err(error) => warn!(
            error = format!("{error:#}"),
            "Failed to read UniGetUI upgradable packages"
        ),
    }

    Ok(packages)
}

fn merge_available_versions(packages: &mut [InstalledPackage], upgradable: Vec<IpcPackage>) {
    for update in upgradable.into_iter().filter(|update| !update.new_version.is_empty()) {
        let same_package = |package: &InstalledPackage| {
            package.manager == update.manager
                && package.id == update.id
                && package.reported_scope == update.reported_scope()
        };
        let mut candidates = packages.iter().enumerate().filter(|(_, package)| {
            same_package(package)
                && if package.source_name.is_empty() || update.source_name.is_empty() {
                    !package.source.is_empty() && package.source == update.source
                } else {
                    package.source_name == update.source_name
                }
        });
        let index = candidates.next().map(|(index, _)| index);
        let index = if candidates.next().is_none() { index } else { None };
        if let Some(index) = index {
            packages[index].available_version = update.new_version;
        }
    }
}

pub(super) async fn managers(instance: &TargetInstance) -> anyhow::Result<(Vec<PackageManager>, bool)> {
    let managers: Vec<IpcManager> = get_json_on_endpoint(instance, MANAGERS_PATH, &[]).await?;
    let has_loading_manager = managers.iter().any(is_manager_loading);
    // The IPC API does not expose the manager version. "Ready" means that UniGetUI found the manager executable.
    let managers = managers
        .into_iter()
        .map(|manager| PackageManager {
            name: manager.name,
            installed: manager.ready,
            enabled: manager.enabled,
            version: String::new(),
        })
        .collect();
    Ok((managers, has_loading_manager))
}

pub(super) async fn sources(instance: &TargetInstance) -> anyhow::Result<Vec<PackageSource>> {
    let sources: Vec<IpcSource> = get_json_on_endpoint(instance, SOURCES_PATH, &[]).await?;
    Ok(sources
        .into_iter()
        .map(|source| PackageSource {
            manager: source.manager,
            name: source.name,
            url: source.url,
        })
        .collect())
}

pub(super) async fn resolve_target(target_user_sid: &str) -> anyhow::Result<TargetInstance> {
    #[cfg(windows)]
    {
        let endpoints = discover_endpoints_with_identity().await?.found;
        let endpoint = select_target_endpoint(&endpoints, target_user_sid)
            .context("no verified live UniGetUI instance belongs to the target user SID")?;
        Ok(TargetInstance {
            endpoint: endpoint.clone(),
        })
    }

    #[cfg(not(windows))]
    {
        let _ = target_user_sid;
        bail!("verified UniGetUI target routing is only supported on Windows")
    }
}

/// Lists every reportable instance, or fails when the scan cannot prove the list complete.
pub(super) async fn instances() -> anyhow::Result<Vec<agent_channel_proto::UniGetUiInstance>> {
    #[cfg(windows)]
    {
        instances_from_scan(discover_endpoints_with_identity().await?)
    }

    #[cfg(not(windows))]
    {
        bail!("UniGetUI discovery is only supported on Windows")
    }
}

#[cfg(windows)]
fn instances_from_scan(scan: Scan<DiscoveredEndpoint>) -> anyhow::Result<Vec<agent_channel_proto::UniGetUiInstance>> {
    if !scan.complete {
        bail!("UniGetUI discovery could not resolve every registered endpoint");
    }
    let mut instances: Vec<_> = scan
        .found
        .into_iter()
        .map(|endpoint| agent_channel_proto::UniGetUiInstance {
            user_sid: endpoint.identity.user_sid,
            session_id: endpoint.identity.session_id,
            display_name: endpoint.identity.display_name,
            signature_verified: endpoint.identity.signature_verified,
        })
        .collect();
    // Several registrations can name the same endpoint.
    instances.sort_by(|a, b| {
        (&a.user_sid, a.session_id, &a.display_name).cmp(&(&b.user_sid, b.session_id, &b.display_name))
    });
    instances.dedup();
    Ok(instances)
}

#[cfg(windows)]
async fn get_json_on_endpoint<T: DeserializeOwned>(
    instance: &TargetInstance,
    path: &str,
    parameters: &[(&str, &str)],
) -> anyhow::Result<T> {
    let endpoint = &instance.endpoint;
    let query = {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("token", &endpoint.endpoint.token);
        for (name, value) in parameters {
            serializer.append_pair(name, value);
        }
        serializer.finish()
    };
    let path_and_query = format!("{path}?{query}");
    let started = Instant::now();
    let body = query_verified_endpoint(endpoint, &path_and_query).await?;
    let parse_started = Instant::now();
    let result = serde_json::from_str(&body).with_context(|| format!("invalid UniGetUI response for {path}"))?;
    info!(
        path,
        transport = ?endpoint.endpoint.transport,
        request_ms = started.elapsed().as_millis(),
        parse_ms = parse_started.elapsed().as_millis(),
        bytes = body.len(),
        "UniGetUI IPC request completed"
    );
    Ok(result)
}

#[cfg(not(windows))]
async fn get_json_on_endpoint<T: DeserializeOwned>(
    instance: &TargetInstance,
    _path: &str,
    _parameters: &[(&str, &str)],
) -> anyhow::Result<T> {
    match *instance {}
}

#[cfg(windows)]
async fn query_verified_endpoint(endpoint: &DiscoveredEndpoint, path_and_query: &str) -> anyhow::Result<String> {
    let process = endpoint
        .process
        .as_ref()
        .context("verified UniGetUI process identity is not retained")?;
    process.ensure_valid()?;
    let process_id = process.process_id();

    let body = match &endpoint.endpoint.transport {
        Transport::Tcp(port) => {
            let stream = tokio::time::timeout(REQUEST_TIMEOUT, tokio::net::TcpStream::connect(("127.0.0.1", *port)))
                .await
                .context("UniGetUI TCP connection timed out")?
                .context("UniGetUI TCP connection failed")?;
            let client_port = stream
                .local_addr()
                .context("failed to query UniGetUI TCP client endpoint")?
                .port();
            if tcp_connection_process_id(*port, client_port)? != process_id {
                bail!("UniGetUI TCP connection belongs to another process");
            }
            tokio::time::timeout(REQUEST_TIMEOUT, stream_request(stream, path_and_query))
                .await
                .context("UniGetUI TCP request timed out")??
        }
        Transport::NamedPipe(name) => {
            let pipe_path = format!(r"\\.\pipe\{name}");
            let pipe = open_unigetui_pipe(&pipe_path).with_context(|| format!("failed to open {pipe_path}"))?;
            if named_pipe_server_process_id(pipe.as_raw_handle())? != process_id {
                bail!("UniGetUI named-pipe endpoint owner changed before the request");
            }
            tokio::time::timeout(REQUEST_TIMEOUT, stream_request(pipe, path_and_query))
                .await
                .context("UniGetUI named pipe request timed out")??
        }
    };

    process.ensure_valid()?;
    if endpoint_owner_process_id(&endpoint.endpoint).await? != process_id {
        bail!("UniGetUI endpoint owner changed during the request");
    }

    Ok(body)
}

/// Items found by one discovery stage, and whether that stage resolved everything it inspected.
#[cfg(windows)]
struct Scan<T> {
    found: Vec<T>,
    complete: bool,
}

/// How identity verification resolved one registered endpoint.
#[cfg(windows)]
enum Verification {
    Verified(Box<DiscoveredEndpoint>),
    /// The endpoint is conclusively not a reportable instance.
    Excluded,
    /// The endpoint might be a reportable instance.
    Unresolved,
}

#[cfg(windows)]
fn discover_endpoints() -> anyhow::Result<Scan<Endpoint>> {
    Ok(discover_in(registration_directories()?))
}

#[cfg(windows)]
fn discover_in(directories: Scan<PathBuf>) -> Scan<Endpoint> {
    let mut registrations = read_registrations(&directories.found);
    registrations.complete &= directories.complete;
    registrations
}

#[cfg(windows)]
fn read_registrations(directories: &[PathBuf]) -> Scan<Endpoint> {
    let mut scan = Scan {
        found: Vec::new(),
        complete: true,
    };
    for directory in directories {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                warn!(
                    directory = %directory.display(),
                    error = %error,
                    "Failed to read UniGetUI registration directory"
                );
                scan.complete = false;
                continue;
            }
        };
        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(error) => {
                    warn!(
                        directory = %directory.display(),
                        error = %error,
                        "Failed to read UniGetUI registration directory entry"
                    );
                    scan.complete = false;
                    // A failed enumeration can fail again on every call, so stop reading this directory.
                    break;
                }
            };
            if !path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("json")) {
                continue;
            }
            match parse_registration(&path) {
                Ok(Some(endpoint)) => scan.found.push(endpoint),
                Ok(None) => {}
                Err(error) => {
                    warn!(
                        file = %path.display(),
                        error = format!("{error:#}"),
                        "Failed to read UniGetUI registration"
                    );
                    scan.complete = false;
                }
            }
        }
    }
    scan.found.sort_by(|a, b| b.persisted_at.cmp(&a.persisted_at));
    scan
}

#[cfg(windows)]
async fn discover_endpoints_with_identity() -> anyhow::Result<Scan<DiscoveredEndpoint>> {
    let registrations = tokio::task::spawn_blocking(discover_endpoints)
        .await
        .context("UniGetUI registration worker failed")??;
    let mut scan = Scan {
        found: Vec::new(),
        complete: registrations.complete,
    };
    for endpoint in registrations.found {
        match verify_endpoint(endpoint).await {
            Verification::Verified(endpoint) => scan.found.push(*endpoint),
            Verification::Excluded => {}
            Verification::Unresolved => scan.complete = false,
        }
    }
    Ok(scan)
}

// UNTESTED: Automated tests do not run this classification against real UniGetUI processes.
// Only an absent endpoint, a non-UniGetUI owner or an elevated owner may be excluded; any other doubt must stay
// unresolved so that discovery never reports a partial list as complete. Check every early return when changing it.
#[cfg(windows)]
async fn verify_endpoint(endpoint: Endpoint) -> Verification {
    let process_id = match endpoint_owner(&endpoint).await {
        Ok(Some(process_id)) => process_id,
        Ok(None) => {
            debug!(file = %endpoint.file.display(), "UniGetUI endpoint is not listening");
            return Verification::Excluded;
        }
        Err(error) => {
            warn!(
                file = %endpoint.file.display(),
                error = format!("{error:#}"),
                "Failed to identify UniGetUI endpoint owner"
            );
            return Verification::Unresolved;
        }
    };
    let captured = tokio::task::spawn_blocking(move || {
        // UNTESTED: Automated tests do not bind either endpoint owner PID to its token SID, session and signature, which could misattribute a target.
        // Validate both transports with signed UniGetUI processes in multiple sessions before changing this path.
        let process = ProcessIdentity::capture(process_id)?;
        let user_sid = process.user_sid().to_string();
        let session_id = process.session_id()?;
        let display_name = process.display_name()?;
        Ok::<_, anyhow::Error>((process, user_sid, session_id, display_name))
    })
    .await;
    let (process, user_sid, session_id, display_name) = match captured {
        Ok(Ok(identity)) => identity,
        Ok(Err(error)) => {
            warn!(
                file = %endpoint.file.display(),
                process_id,
                error = format!("{error:#}"),
                "UniGetUI endpoint owner did not pass identity verification"
            );
            return Verification::Unresolved;
        }
        Err(error) => {
            warn!(
                file = %endpoint.file.display(),
                process_id,
                error = %error,
                "UniGetUI endpoint owner verification worker failed"
            );
            return Verification::Unresolved;
        }
    };

    // The captured handle keeps the process ID from being reused, so a matching owner is the captured process.
    match endpoint_owner(&endpoint).await {
        Ok(Some(confirmed_process_id)) if confirmed_process_id == process_id => {}
        Ok(_) => {
            warn!(
                file = %endpoint.file.display(),
                process_id,
                "UniGetUI endpoint owner changed during identity capture"
            );
            return Verification::Unresolved;
        }
        Err(error) => {
            warn!(
                file = %endpoint.file.display(),
                process_id,
                error = format!("{error:#}"),
                "Failed to confirm UniGetUI endpoint owner"
            );
            return Verification::Unresolved;
        }
    }
    if let Err(error) = process.ensure_process_instance() {
        warn!(
            file = %endpoint.file.display(),
            process_id,
            error = format!("{error:#}"),
            "UniGetUI process exited during identity capture"
        );
        return Verification::Unresolved;
    }

    let is_unigetui = process
        .executable_path()
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("UniGetUI.exe"));
    if !is_unigetui {
        warn!(
            file = %endpoint.file.display(),
            process_id,
            executable = %process.executable_path().display(),
            "UniGetUI endpoint owner is not UniGetUI.exe"
        );
        return Verification::Excluded;
    }
    // UNTESTED: An elevated UniGetUI must not be reported or targeted, because remote operations require an unelevated client.
    // Verify signed elevated and unelevated instances when changing process-token capture or this check.
    if process.is_elevated() {
        warn!(
            file = %endpoint.file.display(),
            process_id,
            "UniGetUI endpoint owner is elevated"
        );
        return Verification::Excluded;
    }
    // A failed signature check cannot distinguish an invalid signature from a verification error.
    if !process.signature_verified() {
        warn!(
            file = %endpoint.file.display(),
            process_id,
            "UniGetUI endpoint owner signature is not verified"
        );
        return Verification::Unresolved;
    }
    // UNTESTED: A process can use another account within a logged-on session, so its SID must match the session user.
    // Check mismatched and matching signed processes in real user sessions when changing this verification.
    if let Err(error) = process.ensure_logged_on_session() {
        warn!(
            file = %endpoint.file.display(),
            process_id,
            error = format!("{error:#}"),
            "UniGetUI endpoint owner is not the logged-on session user"
        );
        return Verification::Unresolved;
    }

    Verification::Verified(Box::new(DiscoveredEndpoint {
        endpoint,
        identity: EndpointIdentity {
            user_sid,
            session_id,
            display_name: format!("{display_name} (session {session_id})"),
            signature_verified: process.signature_verified(),
        },
        process: Some(process),
    }))
}

#[cfg(windows)]
async fn endpoint_owner_process_id(endpoint: &Endpoint) -> anyhow::Result<u32> {
    endpoint_owner(endpoint)
        .await?
        .context("UniGetUI endpoint is not listening")
}

/// Returns the process that owns `endpoint`, or `None` when nothing listens on it.
#[cfg(windows)]
async fn endpoint_owner(endpoint: &Endpoint) -> anyhow::Result<Option<u32>> {
    match &endpoint.transport {
        Transport::Tcp(port) => tcp_listener_owner(*port),
        Transport::NamedPipe(name) => {
            let pipe_path = format!(r"\\.\pipe\{name}");
            let pipe = match open_unigetui_pipe(&pipe_path) {
                Ok(pipe) => pipe,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error).with_context(|| format!("failed to open {pipe_path}")),
            };
            named_pipe_server_process_id(pipe.as_raw_handle()).map(Some)
        }
    }
}

#[cfg(windows)]
fn open_unigetui_pipe(path: &str) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let pipe = std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ.0 | FILE_WRITE_DATA.0)
        .custom_flags(FILE_FLAG_OVERLAPPED.0)
        .security_qos_flags(SECURITY_IDENTIFICATION.0)
        .open(path)?;

    // SAFETY: The new overlapped pipe handle is transferred to the Tokio client.
    unsafe { tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(pipe.into_raw_handle()) }
}

#[cfg(windows)]
fn named_pipe_server_process_id(handle: std::os::windows::io::RawHandle) -> anyhow::Result<u32> {
    let mut process_id = 0;
    // SAFETY: The handle is an open named-pipe client handle and `process_id` is writable.
    unsafe {
        GetNamedPipeServerProcessId(HANDLE(handle), &mut process_id)
            .context("failed to query UniGetUI named-pipe server process id")?
    };
    if process_id == 0 {
        bail!("UniGetUI named-pipe server reported an invalid process id");
    }
    Ok(process_id)
}

#[cfg(windows)]
fn tcp_port(port: u32) -> Option<u16> {
    u16::try_from(port).ok().map(u16::from_be)
}

/// Returns the process listening on `port`, or `None` when no IPv4 listener uses it.
#[cfg(windows)]
fn tcp_listener_owner(port: u16) -> anyhow::Result<Option<u32>> {
    let buffer = tcp_owner_table(TCP_TABLE_OWNER_PID_LISTENER)?;
    // SAFETY: `GetExtendedTcpTable` filled `buffer` with a MIB_TCPTABLE_OWNER_PID value.
    let table = unsafe { &*buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>() };
    // SAFETY: The table header is followed by `dwNumEntries` rows as specified by the API.
    let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
    match rows
        .iter()
        .find(|row| row.dwState == MIB_TCP_STATE_LISTEN.0 as u32 && tcp_port(row.dwLocalPort) == Some(port))
    {
        None => Ok(None),
        Some(row) if row.dwOwningPid == 0 => bail!("the TCP listener on UniGetUI port {port} reports no owner"),
        Some(row) => Ok(Some(row.dwOwningPid)),
    }
}

#[cfg(windows)]
fn tcp_connection_process_id(local_port: u16, remote_port: u16) -> anyhow::Result<u32> {
    let buffer = tcp_owner_table(TCP_TABLE_OWNER_PID_ALL)?;
    // SAFETY: `GetExtendedTcpTable` filled `buffer` with a MIB_TCPTABLE_OWNER_PID value.
    let table = unsafe { &*buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>() };
    // SAFETY: The table header is followed by `dwNumEntries` rows as specified by the API.
    let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
    rows.iter()
        .find(|row| {
            row.dwState == MIB_TCP_STATE_ESTAB.0 as u32
                && tcp_port(row.dwLocalPort) == Some(local_port)
                && tcp_port(row.dwRemotePort) == Some(remote_port)
        })
        .map(|row| row.dwOwningPid)
        .filter(|process_id| *process_id != 0)
        .with_context(|| format!("no TCP connection maps UniGetUI port {local_port} to client port {remote_port}"))
}

#[cfg(windows)]
fn tcp_owner_table(table_class: TCP_TABLE_CLASS) -> anyhow::Result<Vec<usize>> {
    let address_family = u32::from(AF_INET.0);
    let mut byte_count = 0;
    // SAFETY: The null table requests the required buffer size.
    let result = unsafe { GetExtendedTcpTable(None, &mut byte_count, false, address_family, table_class, 0) };
    if result != ERROR_INSUFFICIENT_BUFFER.0 {
        bail!("failed to size the TCP owner table: {result}");
    }

    let word_count = usize::try_from(byte_count)
        .context("TCP owner table size exceeds address space")?
        .div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; word_count];
    // SAFETY: `buffer` is aligned and large enough for the returned owner table.
    let result = unsafe {
        GetExtendedTcpTable(
            Some(buffer.as_mut_ptr().cast()),
            &mut byte_count,
            false,
            address_family,
            table_class,
            0,
        )
    };
    if result != 0 {
        bail!("failed to query the TCP owner table: {result}");
    }
    Ok(buffer)
}

/// Reads one endpoint registration, returning `None` when the file no longer exists.
#[cfg(windows)]
fn parse_registration(path: &Path) -> anyhow::Result<Option<Endpoint>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to read UniGetUI registration file"),
    };
    let registration: Registration =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).context("invalid UniGetUI registration")?;
    let token = registration
        .token
        .filter(|token| !token.is_empty())
        .context("UniGetUI registration has no token")?;

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
        ensure_local_pipe_name(&name)?;

        Transport::NamedPipe(name)
    };

    Ok(Some(Endpoint {
        file: path.to_path_buf(),
        token,
        transport,
        persisted_at: registration.persisted_at_utc.unwrap_or_default(),
    }))
}

/// Rejects a registered pipe name that Win32 path normalization could move outside the local pipe namespace.
#[cfg(windows)]
fn ensure_local_pipe_name(name: &str) -> anyhow::Result<()> {
    // `\\.\pipe\` uses 9 of the 256 characters that a full pipe name allows.
    const MAX_NAME_UTF16_UNITS: usize = 256 - 9;

    let is_local = name.encode_utf16().count() <= MAX_NAME_UTF16_UNITS
        && !name.trim_end_matches(['.', ' ']).is_empty()
        && !name.chars().any(|c| matches!(c, '\\' | '/') || c.is_control());
    if !is_local {
        bail!("UniGetUI registration names a pipe outside the local pipe namespace");
    }
    Ok(())
}

#[cfg(windows)]
fn registration_directories() -> anyhow::Result<Scan<PathBuf>> {
    const RELATIVE: [&str; 5] = ["AppData", "Local", "UniGetUI", "Configuration", "IpcApiEndpoints"];

    let mut dirs = Vec::new();
    // A UniGetUI process that cannot be inspected might use a portable registration directory.
    let mut complete = true;

    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        dirs.push(
            PathBuf::from(local_app_data)
                .join("UniGetUI")
                .join("Configuration")
                .join("IpcApiEndpoints"),
        );
    }

    match ProcessEntry32Iterator::new() {
        Ok(processes) => {
            for entry in processes {
                let process_id = entry.process_id();
                let executable_name = match entry.executable_name() {
                    Ok(name) => name,
                    Err(error) => {
                        warn!(process_id, error = %error, "Failed to inspect process name for portable UniGetUI discovery");
                        complete = false;
                        continue;
                    }
                };
                if !executable_name.eq_ignore_ascii_case("UniGetUI.exe") {
                    continue;
                }

                let process = match Process::get_by_pid(process_id, PROCESS_QUERY_LIMITED_INFORMATION) {
                    Ok(process) => process,
                    Err(error) => {
                        warn!(process_id, error = %error, "Failed to inspect process path for portable UniGetUI discovery");
                        complete = false;
                        continue;
                    }
                };
                let executable_path = match process.exe_path() {
                    Ok(path) => path,
                    Err(error) => {
                        warn!(process_id, error = %error, "Failed to inspect process path for portable UniGetUI discovery");
                        complete = false;
                        continue;
                    }
                };
                let Some(executable_directory) = executable_path.parent() else {
                    continue;
                };

                let mut installation_directories = vec![executable_directory.to_path_buf()];
                if executable_directory
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("Avalonia"))
                    && let Some(parent) = executable_directory.parent()
                {
                    installation_directories.push(parent.to_path_buf());
                }

                for installation_directory in installation_directories {
                    let Some(directory) = portable_registration_directory(&installation_directory) else {
                        continue;
                    };
                    if !dirs.iter().any(|existing: &PathBuf| {
                        existing
                            .to_string_lossy()
                            .eq_ignore_ascii_case(&directory.to_string_lossy())
                    }) {
                        dirs.push(directory);
                    }
                }
            }
        }
        Err(error) => {
            warn!(
                error = %error,
                "Failed to enumerate processes for portable UniGetUI discovery"
            );
            complete = false;
        }
    }

    let system_drive = std::env::var("SystemDrive").context("SystemDrive is not set")?;
    let users_dir = PathBuf::from(format!("{system_drive}\\Users"));
    match std::fs::read_dir(users_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.context("failed to read UniGetUI user profile directory entry")?;
                let dir = RELATIVE.iter().fold(entry.path(), |acc, part| acc.join(part));
                if !dirs
                    .iter()
                    .any(|existing: &PathBuf| existing.to_string_lossy().eq_ignore_ascii_case(&dir.to_string_lossy()))
                {
                    dirs.push(dir);
                }
            }
        }
        Err(error) => return Err(error).context("failed to read UniGetUI user profile directories"),
    }

    Ok(Scan { found: dirs, complete })
}

#[cfg(windows)]
fn portable_registration_directory(installation_directory: &Path) -> Option<PathBuf> {
    installation_directory.join("ForceUniGetUIPortable").is_file().then(|| {
        installation_directory
            .join("Settings")
            .join("Configuration")
            .join("IpcApiEndpoints")
    })
}

#[cfg(windows)]
async fn stream_request<S>(mut pipe: S, path_and_query: &str) -> anyhow::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let request = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
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

#[cfg(any(windows, test))]
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
        bail!("UniGetUI returned HTTP status {status}");
    }
    Ok(body)
}

#[cfg(any(windows, test))]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[tokio::test]
    async fn named_pipe_client_restricts_server_impersonation() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use win_api_wrappers::handle::HandleWrapper as _;
        use win_api_wrappers::thread::Thread;
        use windows::Win32::Security::{
            GetTokenInformation, RevertToSelf, SECURITY_IMPERSONATION_LEVEL, SecurityIdentification, TOKEN_QUERY,
            TokenImpersonationLevel,
        };
        use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;

        let name = format!(r"\\.\pipe\unigetui-qos-test-{}", uuid::Uuid::new_v4());
        let mut server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .expect("create pipe");
        let mut client = open_unigetui_pipe(&name).expect("connect client");
        server.connect().await.expect("accept client");
        client.write_all(b"x").await.expect("write request");
        server.read_exact(&mut [0]).await.expect("read request");

        // SAFETY: The server has read from this connected pipe.
        unsafe { ImpersonateNamedPipeClient(HANDLE(server.as_raw_handle())) }.expect("impersonate client");
        let level = (|| -> anyhow::Result<SECURITY_IMPERSONATION_LEVEL> {
            let token = Thread::current().token(TOKEN_QUERY, true)?;
            let mut level = SECURITY_IMPERSONATION_LEVEL::default();
            let mut returned = 0;
            // SAFETY: The token is open for query and the buffer has the size of the requested type.
            unsafe {
                GetTokenInformation(
                    token.handle().raw(),
                    TokenImpersonationLevel,
                    Some((&raw mut level).cast()),
                    u32::try_from(size_of::<SECURITY_IMPERSONATION_LEVEL>()).expect("impersonation level size"),
                    &mut returned,
                )
            }?;
            Ok(level)
        })();
        // SAFETY: Revert before the test thread runs any other work.
        unsafe { RevertToSelf() }.expect("revert impersonation");

        assert_eq!(level.expect("query impersonation level"), SecurityIdentification);
    }

    #[test]
    fn error_responses_do_not_echo_the_ipc_token() {
        // oracle: regression #2194
        let response = b"HTTP/1.1 500 Error\r\nContent-Length: 12\r\n\r\nipc-secret-x";

        let error = parse_http_response(response).expect_err("error response is rejected");

        assert!(!error.to_string().contains("ipc-secret-x"));
    }

    #[cfg(windows)]
    fn endpoint(file: &str, user_sid: &str) -> DiscoveredEndpoint {
        DiscoveredEndpoint {
            endpoint: Endpoint {
                file: PathBuf::from(file),
                token: "ipc-token".to_owned(),
                transport: Transport::NamedPipe("UniGetUI.IPC".to_owned()),
                persisted_at: String::new(),
            },
            identity: EndpointIdentity {
                user_sid: user_sid.to_owned(),
                session_id: 1,
                display_name: "DOMAIN\\user (session 1)".to_owned(),
                signature_verified: true,
            },
            process: None,
        }
    }

    #[cfg(windows)]
    #[test]
    fn target_resolution_selects_an_endpoint_owned_by_the_requested_sid() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
        let endpoints = [
            endpoint("other-user.json", "S-1-5-21-100"),
            endpoint("target-user.json", "S-1-5-21-200"),
        ];

        let selected = select_target_endpoint(&endpoints, "S-1-5-21-200");

        assert_eq!(
            selected.map(|endpoint| endpoint.identity.user_sid.as_str()),
            Some("S-1-5-21-200")
        );
    }

    #[cfg(windows)]
    #[test]
    fn target_resolution_does_not_fall_back_to_another_sid() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
        let endpoints = [endpoint("other-user.json", "S-1-5-21-100")];

        assert!(select_target_endpoint(&endpoints, "S-1-5-21-200").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn target_resolution_rejects_an_unverified_endpoint() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
        let mut endpoint = endpoint("unverified.json", "S-1-5-21-200");
        endpoint.identity.signature_verified = false;

        assert!(select_target_endpoint(&[endpoint], "S-1-5-21-200").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn target_resolution_accepts_another_live_session_of_the_same_sid() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
        let mut endpoint = endpoint("second-session.json", "S-1-5-21-200");
        endpoint.identity.session_id = 7;

        assert_eq!(
            select_target_endpoint(&[endpoint], "S-1-5-21-200").map(|endpoint| endpoint.identity.session_id),
            Some(7)
        );
    }

    #[test]
    fn missing_inventory_scope_remains_unknown() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let package: InstalledPackage = serde_json::from_str::<IpcPackage>(
            r#"{"name":"Example","id":"example","version":"1.0","manager":"winget"}"#,
        )
        .expect("deserialize package")
        .into();

        assert_eq!(package.scope, "UNKNOWN");
        assert!(package.reported_scope.is_empty());
    }

    #[test]
    fn manager_scope_does_not_claim_unproven_ownership() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let package: InstalledPackage = serde_json::from_str::<IpcPackage>(
            r#"{"name":"Example","id":"example","version":"1.0","manager":"bun","reportedScope":"Machine"}"#,
        )
        .expect("deserialize package")
        .into();

        assert_eq!(package.scope, "UNKNOWN");
        assert_eq!(package.reported_scope, "Machine");
    }

    #[test]
    fn inventory_preserves_the_canonical_source_separately_from_its_label() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let package: InstalledPackage = serde_json::from_str::<IpcPackage>(
            r#"{"source":"WinGet: winget","sourceName":"winget","id":"example","manager":"winget"}"#,
        )
        .expect("deserialize package")
        .into();

        assert_eq!(package.source, "WinGet: winget");
        assert_eq!(package.source_name, "winget");
    }

    #[test]
    fn inventory_does_not_infer_a_canonical_source_from_its_label() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let package: InstalledPackage =
            serde_json::from_str::<IpcPackage>(r#"{"source":"WinGet: winget","id":"example","manager":"winget"}"#)
                .expect("deserialize package")
                .into();

        assert_eq!(package.source, "WinGet: winget");
        assert!(package.source_name.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn portable_registration_directory_uses_the_settings_configuration_path() {
        // oracle: reference Devolutions/UniGetUI@da6be7b86100302a79a208e7ab4d5c6fcd695fd5:src/UniGetUI.Core.Logger/AppPaths.cs
        // oracle: reference Devolutions/UniGetUI@da6be7b86100302a79a208e7ab4d5c6fcd695fd5:src/UniGetUI.Core.Data/CoreData.cs
        // oracle: reference Devolutions/UniGetUI@da6be7b86100302a79a208e7ab4d5c6fcd695fd5:src/UniGetUI.Interface.IpcApi/IpcTransport.cs
        let installation_directory = tempfile::tempdir().expect("create portable installation directory");
        std::fs::write(installation_directory.path().join("ForceUniGetUIPortable"), "")
            .expect("create portable marker");

        assert_eq!(
            portable_registration_directory(installation_directory.path()),
            Some(
                installation_directory
                    .path()
                    .join("Settings")
                    .join("Configuration")
                    .join("IpcApiEndpoints")
            )
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[cfg(windows)]
    #[test]
    fn unreadable_registration_makes_the_scan_incomplete() {
        let directory = tempfile::tempdir().expect("create registration directory");
        std::fs::write(
            directory.path().join("valid.json"),
            r#"{"token":"secret","transport":"tcp","tcpPort":7058}"#,
        )
        .expect("write valid registration");
        std::fs::write(directory.path().join("partial.json"), r#"{"token":"#).expect("write partial registration");
        std::fs::write(directory.path().join("notes.txt"), "ignored").expect("write unrelated file");

        let scan = read_registrations(&[directory.path().to_path_buf()]);

        assert!(!scan.complete);
        let [endpoint] = scan.found.as_slice() else {
            panic!("expected only the valid registration");
        };
        assert!(matches!(endpoint.transport, Transport::Tcp(7058)));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[cfg(windows)]
    #[test]
    fn readable_registrations_complete_the_scan() {
        let directory = tempfile::tempdir().expect("create registration directory");
        std::fs::write(
            directory.path().join("pipe.json"),
            "\u{feff}{\"token\":\"secret\",\"transport\":\"namedpipe\"}",
        )
        .expect("write pipe registration");
        let missing = directory.path().join("missing");

        let scan = read_registrations(&[directory.path().to_path_buf(), missing]);

        assert!(scan.complete);
        let [endpoint] = scan.found.as_slice() else {
            panic!("expected the pipe registration");
        };
        assert!(matches!(&endpoint.transport, Transport::NamedPipe(name) if name == DEFAULT_PIPE_NAME));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[cfg(windows)]
    #[test]
    fn incomplete_scan_is_never_reported_as_a_list() {
        let scan = Scan {
            found: vec![endpoint("one.json", "S-1-5-21-100")],
            complete: false,
        };

        assert!(instances_from_scan(scan).is_err());
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[cfg(windows)]
    #[test]
    fn complete_scan_lists_all_instances() {
        let scan = Scan {
            found: vec![endpoint("b.json", "S-1-5-21-200"), endpoint("a.json", "S-1-5-21-100")],
            complete: true,
        };

        let instances = instances_from_scan(scan).expect("complete scan");

        assert_eq!(instances.len(), 2);
        assert!(instances.iter().any(|instance| instance.user_sid == "S-1-5-21-100"));
        assert!(instances.iter().any(|instance| instance.user_sid == "S-1-5-21-200"));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[cfg(windows)]
    #[rstest::rstest]
    #[case::unresolved_directories(false, false)]
    #[case::resolved_directories(true, true)]
    fn registration_scan_is_complete_only_when_directories_and_files_are(
        #[case] directories_complete: bool,
        #[case] expected_complete: bool,
    ) {
        let directory = tempfile::tempdir().expect("create registration directory");
        std::fs::write(
            directory.path().join("valid.json"),
            r#"{"token":"secret","transport":"tcp","tcpPort":7058}"#,
        )
        .expect("write valid registration");
        let directories = Scan {
            found: vec![directory.path().to_path_buf()],
            complete: directories_complete,
        };

        let scan = discover_in(directories);

        assert_eq!(scan.complete, expected_complete);
        assert_eq!(scan.found.len(), 1);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[cfg(windows)]
    #[test]
    fn malformed_registration_makes_discovery_incomplete_even_with_resolved_directories() {
        let directory = tempfile::tempdir().expect("create registration directory");
        std::fs::write(directory.path().join("partial.json"), r#"{"token":"#).expect("write partial registration");
        let directories = Scan {
            found: vec![directory.path().to_path_buf()],
            complete: true,
        };

        assert!(!discover_in(directories).complete);
    }

    // oracle: spec Microsoft "File path formats on Windows" §Path normalization
    #[cfg(windows)]
    #[test]
    fn registration_cannot_name_a_pipe_outside_the_local_pipe_namespace() {
        let directory = tempfile::tempdir().expect("create registration directory");
        for (file, name) in [
            ("unc.json", r"..\\UNC\\example.invalid\\share\\x"),
            ("slash.json", "../UNC/example.invalid/share/x"),
            ("parent.json", ".."),
            ("trimmed.json", ". ."),
        ] {
            std::fs::write(
                directory.path().join(file),
                format!(r#"{{"token":"secret","transport":"namedpipe","namedPipeName":"{name}"}}"#),
            )
            .expect("write registration");

            assert!(
                parse_registration(&directory.path().join(file)).is_err(),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn enabled_loading_manager_defers_inventory() {
        // oracle: regression #2194
        let manager: IpcManager =
            serde_json::from_str(r#"{"name":"npm","enabled":true,"ready":false,"health":{"state":"loading"}}"#)
                .expect("deserialize loading manager");

        assert!(is_manager_loading(&manager));
    }

    #[test]
    fn enabled_manager_not_found_does_not_defer_inventory() {
        // oracle: regression #2194
        let manager: IpcManager =
            serde_json::from_str(r#"{"name":"npm","enabled":true,"ready":false,"health":{"state":"not-found"}}"#)
                .expect("deserialize not-found manager");

        assert!(!is_manager_loading(&manager));
    }

    #[test]
    fn available_version_is_merged_into_the_matching_scope_only() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let mut packages = vec![
            InstalledPackage {
                manager: "winget".to_owned(),
                source: "winget".to_owned(),
                source_name: "winget".to_owned(),
                id: "example".to_owned(),
                name: "Example".to_owned(),
                version: "1.0".to_owned(),
                available_version: String::new(),
                scope: "UNKNOWN".to_owned(),
                reported_scope: "Machine".to_owned(),
            },
            InstalledPackage {
                manager: "winget".to_owned(),
                source: "winget".to_owned(),
                source_name: "winget".to_owned(),
                id: "example".to_owned(),
                name: "Example".to_owned(),
                version: "1.0".to_owned(),
                available_version: String::new(),
                scope: "UNKNOWN".to_owned(),
                reported_scope: "User".to_owned(),
            },
        ];

        merge_available_versions(
            &mut packages,
            vec![IpcPackage {
                name: "Example".to_owned(),
                id: "example".to_owned(),
                version: "1.0".to_owned(),
                source: "winget".to_owned(),
                source_name: "winget".to_owned(),
                manager: "winget".to_owned(),
                new_version: "2.0".to_owned(),
                scope: "User".to_owned(),
                reported_scope: None,
            }],
        );

        assert_eq!(packages[0].available_version, "");
        assert_eq!(packages[1].available_version, "2.0");
    }

    #[test]
    fn unknown_available_scope_does_not_match_a_known_installation_scope() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let mut packages = vec![InstalledPackage {
            manager: "winget".to_owned(),
            source: "winget".to_owned(),
            source_name: "winget".to_owned(),
            id: "example".to_owned(),
            name: "Example".to_owned(),
            version: "1.0".to_owned(),
            available_version: String::new(),
            scope: "UNKNOWN".to_owned(),
            reported_scope: "Machine".to_owned(),
        }];

        merge_available_versions(
            &mut packages,
            vec![IpcPackage {
                name: "Example".to_owned(),
                id: "example".to_owned(),
                version: "1.0".to_owned(),
                source: "winget".to_owned(),
                source_name: "winget".to_owned(),
                manager: "winget".to_owned(),
                new_version: "2.0".to_owned(),
                scope: String::new(),
                reported_scope: None,
            }],
        );

        assert_eq!(packages[0].available_version, "");
    }

    #[test]
    fn available_version_is_not_attributed_to_a_different_source() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let mut packages = vec![InstalledPackage {
            manager: "winget".to_owned(),
            source: "WinGet: first".to_owned(),
            source_name: "first".to_owned(),
            id: "example".to_owned(),
            name: "Example".to_owned(),
            version: "1.0".to_owned(),
            available_version: String::new(),
            scope: "UNKNOWN".to_owned(),
            reported_scope: "User".to_owned(),
        }];

        merge_available_versions(
            &mut packages,
            vec![IpcPackage {
                name: "Example".to_owned(),
                id: "example".to_owned(),
                version: "1.0".to_owned(),
                source: "WinGet: second".to_owned(),
                source_name: "second".to_owned(),
                manager: "winget".to_owned(),
                new_version: "2.0".to_owned(),
                scope: "User".to_owned(),
                reported_scope: None,
            }],
        );

        assert!(packages[0].available_version.is_empty());
    }

    #[test]
    fn available_version_is_not_attributed_to_an_ambiguous_source() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let package = |source_name: &str| InstalledPackage {
            manager: "winget".to_owned(),
            source: "redacted".to_owned(),
            source_name: source_name.to_owned(),
            id: "example".to_owned(),
            name: "Example".to_owned(),
            version: "1.0".to_owned(),
            available_version: String::new(),
            scope: "UNKNOWN".to_owned(),
            reported_scope: "User".to_owned(),
        };
        let mut packages = vec![package("first"), package("second")];

        merge_available_versions(
            &mut packages,
            vec![IpcPackage {
                name: "Example".to_owned(),
                id: "example".to_owned(),
                version: "1.0".to_owned(),
                source: "redacted".to_owned(),
                source_name: String::new(),
                manager: "winget".to_owned(),
                new_version: "2.0".to_owned(),
                scope: "User".to_owned(),
                reported_scope: None,
            }],
        );

        assert!(packages.iter().all(|package| package.available_version.is_empty()));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn tcp_listener_lookup_reports_the_loopback_listener_owner() {
        // oracle: spec GetExtendedTcpTable §Remarks
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind a loopback listener");
        let port = listener.local_addr().expect("query loopback address").port();
        let owner = tokio::task::spawn_blocking(move || tcp_listener_owner(port))
            .await
            .expect("TCP owner query worker")
            .expect("TCP listener owner");

        assert_eq!(owner, Some(std::process::id()));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn tcp_connection_lookup_reports_the_loopback_server_owner() {
        // oracle: spec GetExtendedTcpTable §Remarks
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind a loopback listener");
        let server_port = listener.local_addr().expect("query loopback address").port();
        let accept = tokio::spawn(async move { listener.accept().await.expect("accept loopback connection") });
        let client = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
            .await
            .expect("connect to loopback listener");
        let (server, _) = accept.await.expect("accept worker");
        let client_port = client.local_addr().expect("query client endpoint").port();
        let owner = tokio::task::spawn_blocking(move || tcp_connection_process_id(server_port, client_port))
            .await
            .expect("TCP owner query worker")
            .expect("TCP connection owner");

        assert_eq!(owner, std::process::id());
        drop(server);
        drop(client);
    }
}
