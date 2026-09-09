param(
    [ValidateSet("Orchestrate", "Stage", "Server", "Run", "Signal", "Cleanup", "SelfTest")]
    [string] $Action = "Orchestrate",
    [string] $TesterPath,
    [string] $StagedTesterPath,
    [string] $StagingPath,
    [string] $AgentPath,
    [string] $TempPath,
    [string] $ReadyPath,
    [string] $StopPath,
    [string] $StatusPath,
    [string] $ServerOutputPath,
    [string] $Nonce,
    [string] $ExpectedClientSid
)

$ErrorActionPreference = "Stop"

function Test-ExplicitPsExecLaunchFailure {
    param([string] $Diagnostics)

    return $Diagnostics -match '(?im)^(Couldn''t install PSEXESVC service:|Error establishing communication with PsExec service|Access is denied\.)'
}

function Wait-ServerReadiness {
    param(
        [string] $Path,
        [string] $ServerStatusPath,
        [string] $ExpectedNonce,
        [int] $TimeoutMilliseconds,
        [int] $LaunchValue,
        [string] $LaunchDiagnostics
    )

    if (Test-ExplicitPsExecLaunchFailure $LaunchDiagnostics) {
        throw "LocalSystem test server launch failed (value $LaunchValue): $LaunchDiagnostics"
    }

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while (-not (Test-Path -LiteralPath $Path)) {
        if (Test-Path -LiteralPath $ServerStatusPath) {
            $status = Get-Content -LiteralPath $ServerStatusPath -Raw
            throw "LocalSystem test server exited with status $status before publishing readiness (launch value $LaunchValue): $LaunchDiagnostics"
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "Timed out waiting for LocalSystem test server readiness (launch value $LaunchValue): $LaunchDiagnostics"
        }
        Start-Sleep -Milliseconds 100
    }

    $readiness = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($readiness.Nonce -cne $ExpectedNonce) {
        throw "LocalSystem test server readiness nonce mismatch"
    }
    if ([string]::IsNullOrWhiteSpace($readiness.PipeName)) {
        throw "LocalSystem test server readiness has no pipe name"
    }
    if ($readiness.ServerPid -le 0 -or $readiness.AgentPid -le 0 -or $readiness.ServerPid -eq $readiness.AgentPid) {
        throw "LocalSystem test server readiness has invalid process identities"
    }
    if ($readiness.ServerSid -cne 'S-1-5-18' -or $readiness.AgentSid -cne 'S-1-5-18') {
        throw "LocalSystem test server readiness has non-SYSTEM identities"
    }

    return $readiness
}

function Remove-StagingPath {
    param([string] $Path)

    for ($attempt = 0; $attempt -lt 20 -and (Test-Path -LiteralPath $Path); $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force
        } catch {
            if ($attempt -eq 19) {
                throw "Failed to remove $Path after 20 attempts: $_"
            }
            Start-Sleep -Milliseconds 250
        }
    }
    if (Test-Path -LiteralPath $Path) {
        throw "Failed to remove $Path"
    }
}

function New-RandomSecurePassword {
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $password = [System.Security.SecureString]::new()
    foreach ($byte in $bytes) {
        $password.AppendChar($alphabet[$byte % $alphabet.Length])
    }
    foreach ($required in "Aa1!".ToCharArray()) {
        $password.AppendChar($required)
    }
    $password.MakeReadOnly()
    return $password
}

function New-StandardUserAccount {
    $name = "dgwpol$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    $password = New-RandomSecurePassword
    try {
        $user = New-LocalUser -Name $name -Password $password -AccountNeverExpires `
            -PasswordNeverExpires -UserMayNotChangePassword `
            -Description "Temporary Devolutions Agent policy E2E user"
        $usersGroup = Get-LocalGroup -SID "S-1-5-32-545"
        $isMember = Get-LocalGroupMember -Group $usersGroup -ErrorAction Stop |
            Where-Object { $_.SID.Value -eq $user.SID.Value }
        if (-not $isMember) {
            Add-LocalGroupMember -Group $usersGroup -Member $user -ErrorAction Stop
        }
        return [pscustomobject]@{
            Name = $name
            Sid = $user.SID.Value
            Credential = [System.Management.Automation.PSCredential]::new(
                $name,
                $password
            )
        }
    } catch {
        Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
        $password.Dispose()
        throw
    }
}

function Set-StandardUserTempAcl {
    param(
        [string] $Path,
        [string] $UserSid
    )

    New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
    & icacls.exe $Path /inheritance:r /grant:r `
        '*S-1-5-18:(OI)(CI)(F)' `
        '*S-1-5-32-544:(OI)(CI)(F)' `
        "*$($UserSid):(OI)(CI)(M)"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to protect the standard-user temporary directory"
    }
}

function Invoke-StandardUserClient {
    param(
        [System.Management.Automation.PSCredential] $Credential,
        [string] $UserSid,
        [string] $ClientTempPath,
        [string] $ScriptPath,
        [string] $TesterExecutablePath,
        [string] $AgentExecutablePath,
        [string] $ReadinessPath,
        [string] $ExpectedNonce
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command pwsh.exe -CommandType Application).Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.LoadUserProfile = $false
    $startInfo.UserName = $Credential.UserName
    $startInfo.Domain = "."
    $startInfo.Password = $Credential.Password
    $startInfo.WorkingDirectory = $ClientTempPath
    $startInfo.Environment["TEMP"] = $ClientTempPath
    $startInfo.Environment["TMP"] = $ClientTempPath
    foreach ($argument in @(
        "-NoProfile",
        "-File",
        $ScriptPath,
        "-Action",
        "Run",
        "-StagedTesterPath",
        $TesterExecutablePath,
        "-AgentPath",
        $AgentExecutablePath,
        "-TempPath",
        $ClientTempPath,
        "-ReadyPath",
        $ReadinessPath,
        "-Nonce",
        $ExpectedNonce,
        "-ExpectedClientSid",
        $UserSid
    )) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Failed to start the medium-integrity standard-user client"
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "Timed out waiting for the medium-integrity standard-user client"
        }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut = $stdout.GetAwaiter().GetResult()
            StdErr = $stderr.GetAwaiter().GetResult()
        }
    } finally {
        $process.Dispose()
    }
}

function Remove-StandardUserAccount {
    param(
        [string] $Name,
        [string] $Sid
    )

    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try {
            $profile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$Sid'" -ErrorAction Stop
            if ($profile) {
                $profile | Remove-CimInstance -ErrorAction Stop
            }
            if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) {
                Remove-LocalUser -Name $Name -ErrorAction Stop
            }
            if (-not (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) {
                return
            }
        } catch {
            if ($attempt -eq 19) {
                throw
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Temporary standard-user account still exists after 20 removal attempts"
}

function Invoke-RunnerSelfTests {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) "agent-policy-runner-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $root | Out-Null
    try {
        $ready = Join-Path $root "ready.json"
        $status = Join-Path $root "status"
        Set-Content -LiteralPath $ready -Value (
            @{
                Nonce = "nonce"
                PipeName = "\\.\pipe\test"
                ServerPid = 100
                ServerSid = "S-1-5-18"
                AgentPid = 200
                AgentSid = "S-1-5-18"
            } | ConvertTo-Json -Compress
        )
        Wait-ServerReadiness -Path $ready -ServerStatusPath $status -ExpectedNonce "nonce" `
            -TimeoutMilliseconds 50 -LaunchValue 6256 -LaunchDiagnostics "started detached process" | Out-Null

        Remove-Item -LiteralPath $ready
        try {
            Wait-ServerReadiness -Path $ready -ServerStatusPath $status -ExpectedNonce "nonce" `
                -TimeoutMilliseconds 50 -LaunchValue 6256 -LaunchDiagnostics "started detached process" | Out-Null
            throw "Missing-readiness simulation unexpectedly succeeded"
        } catch {
            if (
                $_ -notmatch "Timed out waiting for LocalSystem test server readiness" -or
                $_ -notmatch "started detached process"
            ) {
                throw
            }
        }

        try {
            Wait-ServerReadiness -Path $ready -ServerStatusPath $status -ExpectedNonce "nonce" `
                -TimeoutMilliseconds 5000 -LaunchValue 6 `
                -LaunchDiagnostics "Couldn't install PSEXESVC service: Access is denied." | Out-Null
            throw "Explicit-launch-failure simulation unexpectedly succeeded"
        } catch {
            if (
                $_ -notmatch "LocalSystem test server launch failed" -or
                $_ -notmatch "Couldn't install PSEXESVC service"
            ) {
                throw
            }
        }

        Remove-StagingPath -Path (Join-Path $root "already-absent")
    } finally {
        Remove-StagingPath -Path $root
    }
}

if ($Action -eq "SelfTest") {
    Invoke-RunnerSelfTests
    exit 0
}

if ($Action -eq "Run") {
    $env:TEMP = $TempPath
    $env:TMP = $TempPath
    & $StagedTesterPath $AgentPath standard-client $ExpectedClientSid $ReadyPath $Nonce
    exit $LASTEXITCODE
}

if ($Action -eq "Server") {
    try {
        & $StagedTesterPath $AgentPath standard-server $ReadyPath $StopPath $Nonce 2>&1 |
            Out-File -LiteralPath $ServerOutputPath
        $exitCode = $LASTEXITCODE
    } catch {
        $_ | Out-File -LiteralPath $ServerOutputPath -Append
        $exitCode = 1
    } finally {
        Set-Content -LiteralPath $StatusPath -Value $exitCode
    }
    exit $exitCode
}

if ($Action -eq "Signal") {
    if (-not (Test-Path -LiteralPath $StopPath)) {
        New-Item -ItemType File -Path $StopPath -ErrorAction Stop | Out-Null
    }
    exit 0
}

if ($Action -eq "Cleanup") {
    Remove-StagingPath -Path $StagingPath
    exit 0
}

if ($Action -eq "Stage") {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class AgentPolicyStandardUserTesterDirectory
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;
        internal int InheritHandle;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateDirectoryW(string path, ref SecurityAttributes securityAttributes);

    public static void Create(string path, byte[] securityDescriptor)
    {
        GCHandle pinnedDescriptor = GCHandle.Alloc(securityDescriptor, GCHandleType.Pinned);
        try
        {
            SecurityAttributes attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = pinnedDescriptor.AddrOfPinnedObject(),
                InheritHandle = 0,
            };
            if (!CreateDirectoryW(path, ref attributes))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            pinnedDescriptor.Free();
        }
    }
}
'@
    $directorySecurity = [System.Security.AccessControl.DirectorySecurity]::new()
    $directorySecurity.SetSecurityDescriptorSddlForm(
        'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)'
    )
    [AgentPolicyStandardUserTesterDirectory]::Create(
        $StagingPath,
        $directorySecurity.GetSecurityDescriptorBinaryForm()
    )
    if (Get-ChildItem -LiteralPath $StagingPath -Force) {
        throw "The atomically protected staged tester directory was not empty"
    }

    Copy-Item -LiteralPath $TesterPath -Destination $StagedTesterPath
    & icacls.exe $StagedTesterPath /setowner '*S-1-5-18'
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set the staged tester owner"
    }
    & icacls.exe $StagedTesterPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' '*S-1-5-32-545:(RX)'
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to protect the staged tester executable"
    }
    Get-Acl -LiteralPath $StagingPath | Format-List Owner, Sddl
    Get-Acl -LiteralPath $StagedTesterPath | Format-List Owner, Sddl
    exit 0
}

$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$testerPath = Join-Path $workspacePath "target/debug/agent-policy-tester.exe"
$agentPath = Join-Path $workspacePath "target/debug/devolutions-agent.exe"
$outputPath = Join-Path $PSScriptRoot "agent-policy-tester-unelevated.out"
$stagingPath = Join-Path $env:ProgramData "dgw-agent-policy-tester-$([guid]::NewGuid().ToString('N'))"
$stagedTesterPath = Join-Path $stagingPath "agent-policy-tester.exe"
$readyPath = Join-Path $stagingPath "standard-user-ready.json"
$stopPath = Join-Path $stagingPath "standard-user-stop"
$statusPath = Join-Path $stagingPath "standard-user-server.status"
$serverOutputPath = Join-Path $stagingPath "standard-user-server.out"
$nonce = [guid]::NewGuid().ToString("N")
$exitCode = 1
$coordinationReady = $false
$clientAccount = $null

try {
    Invoke-RunnerSelfTests
    Set-Content -LiteralPath $outputPath -Value ""

    $stageOutput = & psexec.exe -accepteula -s pwsh.exe -NoProfile -File $PSCommandPath `
        -Action Stage -TesterPath $testerPath -StagedTesterPath $stagedTesterPath -StagingPath $stagingPath 2>&1
    $stageExitCode = $LASTEXITCODE
    $stageOutput | Out-File $outputPath -Append
    if ($stageExitCode -ne 0) {
        throw "LocalSystem tester staging failed with exit code $stageExitCode"
    }

    $clientAccount = New-StandardUserAccount
    $clientTempPath = Join-Path $stagingPath "standard-user-temp"
    Set-StandardUserTempAcl -Path $clientTempPath -UserSid $clientAccount.Sid

    $serverOutput = & psexec.exe -accepteula -s -d pwsh.exe -NoProfile -File $PSCommandPath `
        -Action Server -StagedTesterPath $stagedTesterPath -AgentPath $agentPath -ReadyPath $readyPath `
        -StopPath $stopPath -StatusPath $statusPath -ServerOutputPath $serverOutputPath -Nonce $nonce 2>&1
    $serverStartExitCode = $LASTEXITCODE
    $serverOutput | Out-File $outputPath -Append
    "Detached server launch value: $serverStartExitCode" | Out-File $outputPath -Append
    $serverLaunchDiagnostics = ($serverOutput | Out-String).Trim()
    $readiness = Wait-ServerReadiness -Path $readyPath -ServerStatusPath $statusPath -ExpectedNonce $nonce `
        -TimeoutMilliseconds 30000 -LaunchValue $serverStartExitCode -LaunchDiagnostics $serverLaunchDiagnostics
    $coordinationReady = $true
    $readiness | ConvertTo-Json -Compress | Out-File $outputPath -Append

    $client = Invoke-StandardUserClient -Credential $clientAccount.Credential -UserSid $clientAccount.Sid `
        -ClientTempPath $clientTempPath -ScriptPath $PSCommandPath -TesterExecutablePath $stagedTesterPath `
        -AgentExecutablePath $agentPath -ReadinessPath $readyPath -ExpectedNonce $nonce
    $client.StdOut | Out-File $outputPath -Append
    $client.StdErr | Out-File $outputPath -Append
    $exitCode = $client.ExitCode
} catch {
    $_ | Out-File $outputPath -Append
    $exitCode = 1
} finally {
    if ($coordinationReady) {
        $signalOutput = & psexec.exe -accepteula -s pwsh.exe -NoProfile -File $PSCommandPath `
            -Action Signal -StopPath $stopPath 2>&1
        $signalExitCode = $LASTEXITCODE
        $signalOutput | Out-File $outputPath -Append
        if ($signalExitCode -ne 0 -and $exitCode -eq 0) {
            $exitCode = $signalExitCode
        }

        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $statusPath) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        if (Test-Path -LiteralPath $serverOutputPath) {
            Get-Content -LiteralPath $serverOutputPath | Out-File $outputPath -Append
        }
        if (Test-Path -LiteralPath $statusPath) {
            $serverExitCode = [int](Get-Content -LiteralPath $statusPath -Raw)
            if ($serverExitCode -ne 0 -and $exitCode -eq 0) {
                $exitCode = $serverExitCode
            }
        } elseif ($exitCode -eq 0) {
            "Timed out waiting for LocalSystem test server shutdown" | Out-File $outputPath -Append
            $exitCode = 1
        }
    }

    if ($clientAccount) {
        try {
            Remove-StandardUserAccount -Name $clientAccount.Name -Sid $clientAccount.Sid
        } catch {
            $_ | Out-File $outputPath -Append
            if ($exitCode -eq 0) {
                $exitCode = 1
            }
        } finally {
            $clientAccount.Credential.Password.Dispose()
        }
    }

    $cleanupOutput = & psexec.exe -accepteula -s pwsh.exe -NoProfile -File $PSCommandPath `
        -Action Cleanup -StagingPath $stagingPath 2>&1
    $cleanupExitCode = $LASTEXITCODE
    $cleanupOutput | Out-File $outputPath -Append
    if ($cleanupExitCode -ne 0 -and $exitCode -eq 0) {
        $exitCode = $cleanupExitCode
    }
}

exit $exitCode
