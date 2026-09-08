param(
    [ValidateSet("Orchestrate", "Stage", "Run", "Cleanup")]
    [string] $Action = "Orchestrate",
    [string] $TesterPath,
    [string] $StagedTesterPath,
    [string] $StagingPath,
    [string] $AgentPath,
    [string] $TempPath
)

$ErrorActionPreference = "Stop"

if ($Action -eq "Run") {
    $env:TEMP = $TempPath
    $env:TMP = $TempPath
    & $StagedTesterPath $AgentPath unelevated
    exit $LASTEXITCODE
}

if ($Action -eq "Cleanup") {
    for ($attempt = 0; $attempt -lt 20 -and (Test-Path -LiteralPath $StagingPath); $attempt++) {
        try {
            Remove-Item -LiteralPath $StagingPath -Recurse -Force
        } catch {
            if ($attempt -eq 19) {
                throw "Failed to remove $StagingPath after 20 attempts: $_"
            }
            Start-Sleep -Milliseconds 250
        }
    }
    exit $(if (Test-Path -LiteralPath $StagingPath) { 1 } else { 0 })
}

if ($Action -eq "Stage") {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class AgentPolicyUnelevatedTesterNativeDirectory
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
    [AgentPolicyUnelevatedTesterNativeDirectory]::Create(
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
$tempPath = Join-Path $env:USERPROFILE "AppData\LocalLow\Temp"

try {
    Set-Content -LiteralPath $outputPath -Value ""
    New-Item -ItemType Directory -Path $tempPath -Force | Out-Null

    $stageOutput = & psexec.exe -accepteula -s pwsh.exe -NoProfile -File $PSCommandPath `
        -Action Stage -TesterPath $testerPath -StagedTesterPath $stagedTesterPath -StagingPath $stagingPath 2>&1
    $stageExitCode = $LASTEXITCODE
    $stageOutput | Out-File $outputPath -Append
    if ($stageExitCode -ne 0) {
        throw "LocalSystem tester staging failed with exit code $stageExitCode"
    }

    $testerOutput = & psexec.exe -accepteula -l pwsh.exe -NoProfile -File $PSCommandPath `
        -Action Run -StagedTesterPath $stagedTesterPath -AgentPath $agentPath -TempPath $tempPath 2>&1
    $exitCode = $LASTEXITCODE
    $testerOutput | Out-File $outputPath -Append
} catch {
    $_ | Out-File $outputPath -Append
    $exitCode = 1
} finally {
    $cleanupOutput = & psexec.exe -accepteula -s pwsh.exe -NoProfile -File $PSCommandPath `
        -Action Cleanup -StagingPath $stagingPath 2>&1
    $cleanupExitCode = $LASTEXITCODE
    $cleanupOutput | Out-File $outputPath -Append
    if ($cleanupExitCode -ne 0 -and $exitCode -eq 0) {
        $exitCode = $cleanupExitCode
    }
}

exit $exitCode
