<#
.SYNOPSIS
Records how a genuinely unelevated standard user can open the real Devolutions Agent service process.

.DESCRIPTION
Registers the given agent binary with the SCM as the fixed-name `devolutions-agent` service running as LocalSystem,
starts it, and verifies the SCM state, the configured account and the live service-process token (S-1-5-18).
A freshly created standard user then verifies its own token (unelevated, not SYSTEM, medium integrity)
and records OpenProcess results, with Win32 error codes, against the exact live service PID.

The probe sends no grant and writes no package.
It does not prove any remote-grant, server-authentication or event-privacy property.

Installing a service is only allowed on a disposable GitHub-hosted runner.
The probe refuses to run if a `devolutions-agent` service already exists,
points the service at a private configuration directory through the per-service registry `Environment` value,
which Microsoft does not document as supported, so the probe fails unless the service demonstrably uses that directory,
and refuses to run if the default Agent data directory already exists,
and removes only the service, account and files it created.
#>
param(
    [ValidateSet("Probe", "Caller")]
    [string] $Action = "Probe",
    [string] $AgentPath,
    [uint32] $ServicePid,
    [string] $ExpectedSid
)

$ErrorActionPreference = "Stop"

$ServiceName = "devolutions-agent"
$SystemSid = "S-1-5-18"
$MediumIntegrityRid = 0x2000
$QueryLimitedInformation = 0x1000
$Synchronize = 0x100000

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class AgentProbeNative
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct TokenPrivileges
    {
        public uint Count;
        public long Luid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder name, ref uint size);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr buffer, int length, out int returned);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr text);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValueW(string system, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr token, bool disableAll, ref TokenPrivileges state, int length, IntPtr previous, IntPtr returned);

    private static Exception Failure(string operation)
    {
        return new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }

    private static T WithTokenInformation<T>(IntPtr token, int infoClass, int capacity, Func<IntPtr, T> read)
    {
        IntPtr buffer = Marshal.AllocHGlobal(capacity);
        try
        {
            int returned;
            if (!GetTokenInformation(token, infoClass, buffer, capacity, out returned))
            {
                throw Failure("GetTokenInformation(" + infoClass + ")");
            }
            return read(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string SidToString(IntPtr sid)
    {
        IntPtr text;
        if (!ConvertSidToStringSidW(sid, out text))
        {
            throw Failure("ConvertSidToStringSid");
        }
        try
        {
            return Marshal.PtrToStringUni(text);
        }
        finally
        {
            LocalFree(text);
        }
    }

    // Returns "<sid>|<elevated 0/1>|<integrity RID>" for a token.
    private static string Describe(IntPtr token)
    {
        string sid = WithTokenInformation(token, 1, 512, buffer => SidToString(Marshal.ReadIntPtr(buffer)));
        int elevated = WithTokenInformation(token, 20, 4, buffer => Marshal.ReadInt32(buffer));
        int integrity = WithTokenInformation(token, 25, 512, buffer =>
        {
            IntPtr label = Marshal.ReadIntPtr(buffer);
            int count = Marshal.ReadByte(GetSidSubAuthorityCount(label));
            return Marshal.ReadInt32(GetSidSubAuthority(label, (uint)(count - 1)));
        });
        return sid + "|" + elevated + "|" + integrity;
    }

    public static string DescribeCurrentToken()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x8, out token))
        {
            throw Failure("OpenProcessToken(current)");
        }
        try
        {
            return Describe(token);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    // Returns "<token description>|<image path>" for a live process; requires SeDebugPrivilege for SYSTEM processes.
    public static string DescribeProcess(uint pid)
    {
        IntPtr process = OpenProcess(0x1000, false, pid);
        if (process == IntPtr.Zero)
        {
            throw Failure("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, " + pid + ")");
        }
        try
        {
            IntPtr token;
            if (!OpenProcessToken(process, 0x8, out token))
            {
                throw Failure("OpenProcessToken(" + pid + ")");
            }
            try
            {
                var image = new StringBuilder(1024);
                uint size = (uint)image.Capacity;
                if (!QueryFullProcessImageNameW(process, 0, image, ref size))
                {
                    throw Failure("QueryFullProcessImageName(" + pid + ")");
                }
                return Describe(token) + "|" + image;
            }
            finally
            {
                CloseHandle(token);
            }
        }
        finally
        {
            CloseHandle(process);
        }
    }

    public static void EnablePrivilege(string name)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token))
        {
            throw Failure("OpenProcessToken(adjust)");
        }
        try
        {
            var state = new TokenPrivileges { Count = 1, Attributes = 2 };
            if (!LookupPrivilegeValueW(null, name, out state.Luid))
            {
                throw Failure("LookupPrivilegeValue(" + name + ")");
            }
            if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero))
            {
                throw Failure("AdjustTokenPrivileges(" + name + ")");
            }
            int error = Marshal.GetLastWin32Error();
            if (error != 0)
            {
                throw new Win32Exception(error, "AdjustTokenPrivileges(" + name + ") did not assign the privilege");
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    // Returns 0 when the handle was opened, otherwise the Win32 error code.
    public static int TryOpenProcess(uint pid, uint access)
    {
        IntPtr process = OpenProcess(access, false, pid);
        if (process == IntPtr.Zero)
        {
            return Marshal.GetLastWin32Error();
        }
        CloseHandle(process);
        return 0;
    }
}
'@

function Get-ProbeTokenDescription {
    param([string] $Raw)

    $parts = $Raw.Split('|')
    return [pscustomobject]@{
        Sid = $parts[0]
        Elevated = $parts[1] -ne "0"
        IntegrityRid = [int] $parts[2]
        ImagePath = if ($parts.Count -gt 3) { $parts[3] } else { $null }
    }
}

if ($Action -eq "Caller") {
    $token = Get-ProbeTokenDescription ([AgentProbeNative]::DescribeCurrentToken())
    if ($token.Sid -ne $ExpectedSid) {
        throw "Caller token SID is $($token.Sid), expected the probe account $ExpectedSid"
    }
    if ($token.Sid -eq $SystemSid) {
        throw "Caller token is SYSTEM"
    }
    if ($token.Elevated) {
        throw "Caller token is elevated"
    }
    if ($token.IntegrityRid -ne $MediumIntegrityRid) {
        throw "Caller integrity RID is 0x$($token.IntegrityRid.ToString('X')), expected medium 0x2000"
    }

    $attempts = [ordered]@{
        PROCESS_QUERY_LIMITED_INFORMATION = $QueryLimitedInformation
        SYNCHRONIZE = $Synchronize
        "PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE" = $QueryLimitedInformation -bor $Synchronize
    }
    $results = foreach ($name in $attempts.Keys) {
        $code = [AgentProbeNative]::TryOpenProcess($ServicePid, [uint32] $attempts[$name])
        [pscustomobject]@{ Access = $name; Opened = ($code -eq 0); Win32Error = $code }
    }

    [pscustomobject]@{
        CallerSid = $token.Sid
        CallerElevated = $token.Elevated
        CallerIntegrityRid = $token.IntegrityRid
        ServicePid = $ServicePid
        OpenProcess = @($results)
    } | ConvertTo-Json -Depth 4
    exit 0
}

function Assert-DisposableRunner {
    if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted") {
        throw "Refusing to install a service outside a disposable GitHub-hosted runner"
    }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The probe must run elevated to register the service"
    }
    if (
        (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName")
    ) {
        throw "A '$ServiceName' service already exists; refusing to touch it"
    }
    if (Test-Path -LiteralPath $DefaultDataPath) {
        throw "The default Agent data directory '$DefaultDataPath' already exists; refusing to risk altering it"
    }
}

function New-StandardUserAccount {
    $name = "dgwsvc$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
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

    $user = New-LocalUser -Name $name -Password $password -AccountNeverExpires -PasswordNeverExpires `
        -UserMayNotChangePassword -Description "Temporary Devolutions Agent service probe user"
    return [pscustomobject]@{
        Name = $name
        Sid = $user.SID.Value
        Password = $password
    }
}

function Invoke-StandardUserCaller {
    param($Account, [string] $ScriptPath, [string] $WorkPath, [uint32] $TargetPid)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command pwsh.exe -CommandType Application).Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.LoadUserProfile = $false
    $startInfo.UserName = $Account.Name
    $startInfo.Domain = "."
    $startInfo.Password = $Account.Password
    $startInfo.WorkingDirectory = $WorkPath
    $startInfo.Environment["TEMP"] = $WorkPath
    $startInfo.Environment["TMP"] = $WorkPath
    foreach ($argument in @(
        "-NoProfile", "-File", $ScriptPath, "-Action", "Caller",
        "-ServicePid", $TargetPid.ToString([System.Globalization.CultureInfo]::InvariantCulture),
        "-ExpectedSid", $Account.Sid
    )) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Failed to start the standard-user caller"
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "Timed out waiting for the standard-user caller"
        }
        $output = $stdout.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "The standard-user caller failed with exit code $($process.ExitCode): $($stderr.GetAwaiter().GetResult())"
        }
        return $output
    } finally {
        $process.Dispose()
    }
}

function Get-ServiceDetails {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if (-not $service) {
        throw "SCM has no '$ServiceName' service"
    }
    return $service
}

$DefaultDataPath = Join-Path $env:ProgramData "Devolutions\Agent"

# A canonical listing of every file (path, size, last write) so any change is detectable; absent is its own value.
function Get-DirectorySnapshot {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) { return "<absent>" }
    return (Get-ChildItem -LiteralPath $Path -Recurse -Force |
        Sort-Object FullName |
        ForEach-Object { "$($_.FullName)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" }) -join "`n"
}

function Invoke-ServiceProbe {
    param([string] $ResolvedAgentPath)

    $root = Join-Path $env:RUNNER_TEMP "agent-service-probe-$([guid]::NewGuid().ToString('N'))"
    $configPath = Join-Path $root "config"
    $callerPath = Join-Path $root "caller"
    $account = $null
    $serviceCreated = $false
    $cleanupErrors = [System.Collections.Generic.List[string]]::new()
    $probeError = $null
    $defaultDataBefore = Get-DirectorySnapshot $DefaultDataPath

    try {
        New-Item -ItemType Directory -Path $configPath, $callerPath -ErrorAction Stop | Out-Null
        $account = New-StandardUserAccount

        $scriptPath = Join-Path $root "probe.ps1"
        Copy-Item -LiteralPath $PSCommandPath -Destination $scriptPath
        & icacls.exe $root /grant "*$($account.Sid):(OI)(CI)(RX)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to grant the probe user read access to its script" }
        & icacls.exe $callerPath /grant "*$($account.Sid):(OI)(CI)(M)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to grant the probe user a writable temp directory" }

        # LocalSystem is named explicitly so the account never depends on a default.
        & sc.exe create $ServiceName binPath= "`"$ResolvedAgentPath`"" obj= LocalSystem start= demand | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }
        $serviceCreated = $true

        # Undocumented SCM behavior, not a supported guarantee: the post-start check below fails the probe if it is not applied.
        # Points the service's configuration and logs away from the default Agent data directory.
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name Environment `
            -PropertyType MultiString -Value @("DAGENT_CONFIG_PATH=$configPath") | Out-Null

        Start-Service -Name $ServiceName -ErrorAction Stop
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        do {
            $service = Get-ServiceDetails
            if ($service.State -eq "Running" -and $service.ProcessId -gt 0) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($service.State -ne "Running" -or $service.ProcessId -le 0) {
            throw "Service '$ServiceName' did not reach Running with a live PID (state $($service.State), PID $($service.ProcessId))"
        }

        if ($service.Name -cne $ServiceName) { throw "SCM service name is '$($service.Name)'" }
        if ($service.StartName -cne "LocalSystem") { throw "SCM service account is '$($service.StartName)', expected LocalSystem" }
        $servicePid = [uint32] $service.ProcessId

        # The service writes a default agent.json into whichever data directory it resolved,
        # so its appearance in the private directory shows the registry Environment value reached the process.
        $configFile = Join-Path $configPath "agent.json"
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $configFile -PathType Leaf) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $configFile -PathType Leaf)) {
            throw "The running service did not create agent.json in the private directory '$configPath'; the per-service Environment value was not applied"
        }
        $defaultDataAfter = Get-DirectorySnapshot $DefaultDataPath
        if ($defaultDataBefore -cne $defaultDataAfter) {
            throw "The default data directory '$DefaultDataPath' changed while the service ran:`nbefore: $defaultDataBefore`nafter: $defaultDataAfter"
        }

        [AgentProbeNative]::EnablePrivilege("SeDebugPrivilege")
        $serviceToken = Get-ProbeTokenDescription ([AgentProbeNative]::DescribeProcess($servicePid))
        if ($serviceToken.Sid -ne $SystemSid) {
            throw "Service process token SID is $($serviceToken.Sid), expected $SystemSid"
        }
        if ([IO.Path]::GetFullPath($serviceToken.ImagePath) -ine $ResolvedAgentPath) {
            throw "Service process image is '$($serviceToken.ImagePath)', expected '$ResolvedAgentPath'"
        }

        $caller = Invoke-StandardUserCaller -Account $account -ScriptPath $scriptPath -WorkPath $callerPath -TargetPid $servicePid

        $after = Get-ServiceDetails
        if ($after.State -ne "Running" -or $after.ProcessId -ne $servicePid) {
            throw "The service PID changed or the service stopped during the probe (PID $($after.ProcessId), state $($after.State))"
        }

        Write-Host "Service '$($service.Name)' PID $servicePid runs as '$($service.StartName)' with token SID $($serviceToken.Sid)"
        Write-Host "Image: $($serviceToken.ImagePath)"
        Write-Host "Service created agent.json in the private directory; the default data directory was unchanged"
        Write-Host "Standard-user caller results (recorded, not asserted):"
        Write-Host $caller
    } catch {
        $probeError = $_
    } finally {
        if ($serviceCreated) {
            try {
                $current = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($current -and $current.Status -ne "Stopped") {
                    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                    $current.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(60))
                }
                & sc.exe delete $ServiceName | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE" }
            } catch {
                $cleanupErrors.Add("Service cleanup failed: $_")
            }
        }
        if ($account) {
            try {
                $userProfile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($account.Sid)'" -ErrorAction Stop
                if ($userProfile) { $userProfile | Remove-CimInstance -ErrorAction Stop }
                Remove-LocalUser -Name $account.Name -ErrorAction Stop
            } catch {
                $cleanupErrors.Add("Account cleanup failed: $_")
            }
            $account.Password.Dispose()
        }
        try {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        } catch {
            $cleanupErrors.Add("Directory cleanup failed: $_")
        }
    }

    $messages = @()
    if ($probeError) { $messages += "Probe failed: $probeError" }
    $messages += $cleanupErrors
    if ($messages.Count -gt 0) {
        throw ($messages -join [Environment]::NewLine)
    }
}

Assert-DisposableRunner
if (-not $AgentPath -or -not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) {
    throw "-AgentPath must name the built devolutions-agent executable"
}
Invoke-ServiceProbe -ResolvedAgentPath ([IO.Path]::GetFullPath((Resolve-Path -LiteralPath $AgentPath).Path))
