use std::ffi::OsString;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Serialize;
use tokio::process::Command;
use tokio::sync::Semaphore;

use crate::config::dto::PsuPowerShellConf;
use crate::psu_event_hub::models::WebsocketEventResponse;

const WORKER_SCRIPT: &str = r#"
param([string] $RequestPath)

function New-PsuResponse {
    [ordered]@{
        data = $null
        jobOutputs = @()
        complete = $true
        timeout = $false
        terminatingError = $null
    }
}

function Add-PsuJobOutput {
    param(
        [System.Collections.IDictionary] $Response,
        [int] $Type,
        [object] $Record
    )

    $data = if ($null -eq $Record) {
        $null
    } else {
        ($Record | Out-String).TrimEnd()
    }

    $Response.jobOutputs += ,([ordered]@{
        id = 0
        message = $null
        type = $Type
        data = $data
        timestamp = [DateTime]::UtcNow.ToString('O')
        jobId = 0
    })
}

function Split-PsuPipelineOutput {
    param(
        [System.Collections.IDictionary] $Response,
        [object[]] $Items
    )

    $pipeline = New-Object System.Collections.ArrayList

    foreach ($item in $Items) {
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            Add-PsuJobOutput -Response $Response -Type 4 -Record $item
        } elseif ($item -is [System.Management.Automation.WarningRecord]) {
            Add-PsuJobOutput -Response $Response -Type 3 -Record $item
        } elseif ($item -is [System.Management.Automation.InformationRecord]) {
            Add-PsuJobOutput -Response $Response -Type 0 -Record $item
        } elseif ($item -is [System.Management.Automation.VerboseRecord]) {
            Add-PsuJobOutput -Response $Response -Type 1 -Record $item
        } elseif ($item -is [System.Management.Automation.DebugRecord]) {
            Add-PsuJobOutput -Response $Response -Type 2 -Record $item
        } elseif ($item -is [System.Management.Automation.ProgressRecord]) {
            Add-PsuJobOutput -Response $Response -Type 5 -Record $item
        } else {
            [void] $pipeline.Add($item)
        }
    }

    $pipeline.ToArray()
}

$response = New-PsuResponse

try {
    $request = Get-Content -Raw -LiteralPath $RequestPath | ConvertFrom-Json

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'
    $InformationPreference = 'Continue'
    $WarningPreference = 'Continue'

    if ($request.kind -eq 'command') {
        $item = [System.Management.Automation.PSSerializer]::Deserialize([string] $request.data)

        if ($item -is [System.Management.Automation.PSObject] -and $item.GetType().FullName -eq 'System.Management.Automation.PSObject') {
            $item = $item.BaseObject
        }

        if ($item -isnot [hashtable]) {
            $response.terminatingError = 'Data was not a hashtable'
        } else {
            $powerShell = [System.Management.Automation.PowerShell]::Create()
            try {
                [void] $powerShell.AddCommand([string] $request.command)

                foreach ($key in $item.Keys) {
                    [void] $powerShell.AddParameter([string] $key, $item[$key])
                }

                $pipeline = $powerShell.Invoke()

                foreach ($record in $powerShell.Streams.Error) {
                    Add-PsuJobOutput -Response $response -Type 4 -Record $record
                }
                foreach ($record in $powerShell.Streams.Warning) {
                    Add-PsuJobOutput -Response $response -Type 3 -Record $record
                }
                foreach ($record in $powerShell.Streams.Information) {
                    Add-PsuJobOutput -Response $response -Type 0 -Record $record
                }
                foreach ($record in $powerShell.Streams.Verbose) {
                    Add-PsuJobOutput -Response $response -Type 1 -Record $record
                }
                foreach ($record in $powerShell.Streams.Debug) {
                    Add-PsuJobOutput -Response $response -Type 2 -Record $record
                }
                foreach ($record in $powerShell.Streams.Progress) {
                    Add-PsuJobOutput -Response $response -Type 5 -Record $record
                }

                if ($request.returnResult) {
                    $response.data = [System.Management.Automation.PSSerializer]::Serialize($pipeline)
                }
            } finally {
                $powerShell.Dispose()
            }
        }
    } elseif ($request.kind -eq 'script') {
        if ([string]::IsNullOrWhiteSpace([string] $request.scriptPath) -or -not (Test-Path -LiteralPath ([string] $request.scriptPath))) {
            $response.terminatingError = 'No script block found.'
        } else {
            $eventData = [System.Management.Automation.PSSerializer]::Deserialize([string] $request.data)
            Set-Variable -Name EventData -Value $eventData -Scope Local -Force
            Set-Variable -Name _ -Value $eventData -Scope Local -Force

            $items = . ([string] $request.scriptPath) *>&1
            $pipeline = Split-PsuPipelineOutput -Response $response -Items @($items)

            if ($request.returnResult) {
                $response.data = [System.Management.Automation.PSSerializer]::Serialize($pipeline)
            }
        }
    } elseif ($request.kind -eq 'secret') {
        $secretName = [string] $request.data
        $secret = Get-Secret -Name $secretName -AsPlainText -ErrorAction Stop
        if ($null -eq $secret) {
            $response.terminatingError = "Secret not found: $secretName"
        } else {
            $response.data = [string] $secret
        }
    } else {
        $response.terminatingError = "Unknown PSU worker request kind: $($request.kind)"
    }
} catch {
    $response.terminatingError = $_.Exception.Message
}

$response | ConvertTo-Json -Compress -Depth 16
"#;

const POWERSHELL_EXECUTION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone)]
pub(super) struct PowerShellWorker {
    conf: PsuPowerShellConf,
    permits: Arc<Semaphore>,
    worker_script: Arc<WorkerScriptFile>,
    execution_timeout: Duration,
}

impl PowerShellWorker {
    pub(super) fn new(conf: PsuPowerShellConf) -> anyhow::Result<Self> {
        Self::with_execution_timeout(conf, POWERSHELL_EXECUTION_TIMEOUT)
    }

    fn with_execution_timeout(conf: PsuPowerShellConf, execution_timeout: Duration) -> anyhow::Result<Self> {
        let worker_limit = effective_worker_limit(&conf);
        Ok(Self {
            conf,
            permits: Arc::new(Semaphore::new(worker_limit)),
            worker_script: Arc::new(WorkerScriptFile::new()?),
            execution_timeout,
        })
    }

    pub(super) async fn resolve_app_token(&self, app_token: &str) -> anyhow::Result<String> {
        let Some(secret_name) = secret_reference_name(app_token) else {
            return Ok(app_token.to_owned());
        };

        let response = self.run_request(WorkerRequest::secret(secret_name.to_owned())).await?;
        if let Some(error) = response.terminating_error {
            bail!("failed to resolve PSU AppToken secret {secret_name}: {error}");
        }

        response
            .data
            .filter(|secret| !secret.is_empty())
            .with_context(|| format!("PSU AppToken secret {secret_name} resolved to an empty value"))
    }

    pub(super) async fn execute_command(
        &self,
        command: String,
        data: String,
        return_result: bool,
    ) -> anyhow::Result<WebsocketEventResponse> {
        self.run_request(WorkerRequest::command(command, data, return_result))
            .await
    }

    pub(super) async fn execute_script(
        &self,
        script_path: Utf8PathBuf,
        data: String,
        return_result: bool,
    ) -> anyhow::Result<WebsocketEventResponse> {
        self.run_request(WorkerRequest::script(script_path, data, return_result))
            .await
    }

    async fn run_request(&self, request: WorkerRequest) -> anyhow::Result<WebsocketEventResponse> {
        let _permit = self
            .permits
            .acquire()
            .await
            .context("PSU PowerShell worker pool is closed")?;
        let request_file = TempRequestFile::write(&request).await?;

        self.invoke_worker(self.worker_script.path(), request_file.path()).await
    }

    async fn invoke_worker(
        &self,
        script_path: &Utf8Path,
        request_path: &Utf8Path,
    ) -> anyhow::Result<WebsocketEventResponse> {
        let executable = resolve_powershell_executable(&self.conf);
        let mut command = Command::new(&executable);
        command
            .arg("-NoLogo")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(script_path.as_std_path())
            .arg(request_path.as_std_path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(virtual_environment) = &self.conf.virtual_environment {
            command.env("PSMODULE_VENV_PATH", virtual_environment);
        }
        command.kill_on_drop(true);

        let output = match tokio::time::timeout(self.execution_timeout, command.output()).await {
            Ok(output) => output.with_context(|| {
                format!(
                    "failed to start PowerShell worker using {}",
                    executable.to_string_lossy()
                )
            })?,
            Err(_) => {
                warn!(
                    timeout_secs = self.execution_timeout.as_secs(),
                    "PowerShell worker timed out"
                );
                return Ok(WebsocketEventResponse::timeout("PowerShell worker timed out."));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "PowerShell worker exited with status {}: {}",
                output.status,
                stderr.trim()
            );
        }

        serde_json::from_slice(&output.stdout).context("failed to parse PowerShell worker response")
    }
}

#[derive(Debug)]
struct WorkerScriptFile {
    path: Utf8PathBuf,
    _temp_path: tempfile::TempPath,
}

impl WorkerScriptFile {
    fn new() -> anyhow::Result<Self> {
        let temp_path = tempfile::Builder::new()
            .prefix("devolutions-agent-psu-worker-")
            .suffix(".ps1")
            .tempfile_in(temp_dir()?.as_std_path())
            .context("failed to create temporary PSU worker script")?
            .into_temp_path();
        let path = Utf8PathBuf::from_path_buf(temp_path.to_path_buf())
            .map_err(|path| anyhow::anyhow!("non-UTF-8 PSU worker script path: {path:?}"))?;

        std::fs::write(&path, WORKER_SCRIPT).with_context(|| format!("failed to write PSU worker script at {path}"))?;

        Ok(Self {
            path,
            _temp_path: temp_path,
        })
    }

    fn path(&self) -> &Utf8Path {
        &self.path
    }
}

#[derive(Debug)]
struct TempRequestFile {
    path: Utf8PathBuf,
    _temp_path: tempfile::TempPath,
}

impl TempRequestFile {
    async fn write(request: &WorkerRequest) -> anyhow::Result<Self> {
        let request_json = serde_json::to_vec(request).context("failed to serialize PSU worker request")?;
        let temp_path = tempfile::Builder::new()
            .prefix("devolutions-agent-psu-")
            .suffix(".json")
            .tempfile_in(temp_dir()?.as_std_path())
            .context("failed to create temporary PSU worker request")?
            .into_temp_path();
        let path = Utf8PathBuf::from_path_buf(temp_path.to_path_buf())
            .map_err(|path| anyhow::anyhow!("non-UTF-8 PSU worker request path: {path:?}"))?;

        tokio::fs::write(&path, request_json)
            .await
            .with_context(|| format!("failed to write PSU worker request at {path}"))?;

        Ok(Self {
            path,
            _temp_path: temp_path,
        })
    }

    fn path(&self) -> &Utf8Path {
        &self.path
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerRequest {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_path: Option<Utf8PathBuf>,
    data: String,
    return_result: bool,
}

impl WorkerRequest {
    fn command(command: String, data: String, return_result: bool) -> Self {
        Self {
            kind: "command",
            command: Some(command),
            script_path: None,
            data,
            return_result,
        }
    }

    fn script(script_path: Utf8PathBuf, data: String, return_result: bool) -> Self {
        Self {
            kind: "script",
            command: None,
            script_path: Some(script_path),
            data,
            return_result,
        }
    }

    fn secret(secret_name: String) -> Self {
        Self {
            kind: "secret",
            command: None,
            script_path: None,
            data: secret_name,
            return_result: true,
        }
    }
}

fn secret_reference_name(app_token: &str) -> Option<&str> {
    let prefix = "$secret:";
    app_token
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .and_then(|_| app_token.get(prefix.len()..))
        .filter(|name| !name.is_empty())
}

fn effective_worker_limit(conf: &PsuPowerShellConf) -> usize {
    let max_worker_pool_size = conf.max_worker_pool_size.max(1);
    if conf.worker_pool_size > max_worker_pool_size {
        warn!(
            worker_pool_size = conf.worker_pool_size,
            max_worker_pool_size,
            "PSU worker pool size exceeds maximum, limiting concurrent workers to MaxWorkerPoolSize"
        );
    }
    max_worker_pool_size
}

fn resolve_powershell_executable(conf: &PsuPowerShellConf) -> OsString {
    if let Some(path) = &conf.executable_path {
        return path.as_str().into();
    }

    if let Some(selector) = &conf.version_selector {
        if selector.eq_ignore_ascii_case("pwsh")
            || selector.eq_ignore_ascii_case("pwsh-preview")
            || selector.eq_ignore_ascii_case("pwsh-lts")
            || selector.starts_with("pwsh-")
        {
            return selector.into();
        }

        return format!("pwsh-{selector}").into();
    }

    if conf.use_windows_power_shell {
        "powershell.exe".into()
    } else {
        "pwsh".into()
    }
}

fn temp_dir() -> anyhow::Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(std::env::temp_dir()).map_err(|path| anyhow::anyhow!("non-UTF-8 temp path: {path:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psu_event_hub::models::JobOutputType;

    const HASHTABLE_PS_VERSION_TABLE: &str = r#"<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Collections.Hashtable</T>
      <T>System.Object</T>
    </TN>
    <DCT>
      <En>
        <S N="Key">ValueOnly</S>
        <B N="Value">true</B>
      </En>
      <En>
        <S N="Key">Name</S>
        <S N="Value">PSVersionTable</S>
      </En>
    </DCT>
  </Obj>
</Objs>"#;

    const HASHTABLE_MESSAGE: &str = r#"<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Collections.Hashtable</T>
      <T>System.Object</T>
    </TN>
    <DCT>
      <En>
        <S N="Key">Message</S>
        <S N="Value">Hello World</S>
      </En>
    </DCT>
  </Obj>
</Objs>"#;

    const HASHTABLE_SECONDS: &str = r#"<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Collections.Hashtable</T>
      <T>System.Object</T>
    </TN>
    <DCT>
      <En>
        <S N="Key">Seconds</S>
        <I32 N="Value">10</I32>
      </En>
    </DCT>
  </Obj>
</Objs>"#;

    #[tokio::test]
    async fn command_execution_returns_clixml_result() {
        let worker = PowerShellWorker::new(PsuPowerShellConf::default()).expect("create worker");
        let response = worker
            .execute_command("Get-Variable".to_owned(), HASHTABLE_PS_VERSION_TABLE.to_owned(), true)
            .await
            .expect("execute command");

        assert!(response.complete);
        assert!(response.terminating_error.is_none());
        assert!(response.data.expect("serialized response").contains("<Objs"));
    }

    #[tokio::test]
    async fn command_execution_captures_error_stream() {
        let worker = PowerShellWorker::new(PsuPowerShellConf::default()).expect("create worker");
        let response = worker
            .execute_command("Write-Error".to_owned(), HASHTABLE_MESSAGE.to_owned(), true)
            .await
            .expect("execute command");

        assert!(response.complete);
        assert_eq!(response.job_outputs[0].output_type, JobOutputType::Error);
        assert!(
            response.job_outputs[0]
                .data
                .as_deref()
                .unwrap_or_default()
                .contains("Hello World")
        );
    }

    #[tokio::test]
    async fn command_execution_times_out() {
        let worker = PowerShellWorker::with_execution_timeout(PsuPowerShellConf::default(), Duration::from_millis(1))
            .expect("create worker");
        let response = worker
            .execute_command("Start-Sleep".to_owned(), HASHTABLE_SECONDS.to_owned(), true)
            .await
            .expect("execute command");

        assert!(response.complete);
        assert!(response.timeout);
        assert!(response.terminating_error.is_some());
    }

    #[tokio::test]
    async fn literal_app_token_does_not_require_secret_resolution() {
        let worker = PowerShellWorker::new(PsuPowerShellConf {
            executable_path: Some(Utf8PathBuf::from("missing-pwsh")),
            ..PsuPowerShellConf::default()
        })
        .expect("create worker");

        let token = worker.resolve_app_token("literal-token").await.expect("resolve token");

        assert_eq!(token, "literal-token");
    }

    #[test]
    fn secret_reference_name_is_case_insensitive() {
        assert_eq!(secret_reference_name("$secret:AppToken"), Some("AppToken"));
        assert_eq!(secret_reference_name("$SECRET:AppToken"), Some("AppToken"));
        assert_eq!(secret_reference_name("literal-token"), None);
    }

    #[test]
    fn effective_worker_limit_uses_configured_maximum() {
        let conf = PsuPowerShellConf {
            max_worker_pool_size: 3,
            ..PsuPowerShellConf::default()
        };

        assert_eq!(effective_worker_limit(&conf), 3);
    }
}
