param(
    [string] $DotnetPath = (Join-Path $env:ProgramFiles "dotnet\dotnet.exe")
)

$ErrorActionPreference = "Stop"

$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$testerPath = Join-Path $workspacePath "target/debug/agent-policy-tester.exe"
$agentPath = Join-Path $workspacePath "target/debug/devolutions-agent.exe"
$outputPath = Join-Path $PSScriptRoot "agent-policy-tester.out"
$stagingPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "dgw-agent-policy-tester-$([guid]::NewGuid().ToString('N'))"
$stagedTesterPath = Join-Path $stagingPath "agent-policy-tester.exe"
$stagedAgentPath = Join-Path $stagingPath "devolutions-agent.exe"
$installerProject = Join-Path $workspacePath "package\AgentWindowsManaged.Tests\DevolutionsAgent.Installer.Tests.csproj"
$installerOutput = Join-Path $workspacePath "package\AgentWindowsManaged.Tests\bin\Debug\net48"
$stagedInstallerOutput = Join-Path $stagingPath "installer-tests"
$resultsPath = Join-Path $PSScriptRoot "installer-test-results"
$exitCode = 1
$previousTemp = $env:TEMP
$previousTmp = $env:TMP

try {
    Set-Content -LiteralPath $outputPath -Value ""
    if (-not [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        throw "This runner requires LocalSystem"
    }
    if ([System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($workspacePath)).DriveType -ne 'Fixed') {
        throw "Use a local fixed-volume workspace path visible to LocalSystem, not a mapped drive"
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class AgentPolicyTesterNativeDirectory
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
        'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    )
    [AgentPolicyTesterNativeDirectory]::Create(
        $stagingPath,
        $directorySecurity.GetSecurityDescriptorBinaryForm()
    )
    if (Get-ChildItem -LiteralPath $stagingPath -Force) {
        throw "The atomically protected staged tester directory was not empty"
    }
    $env:TEMP = Join-Path $stagingPath "scratch"
    $env:TMP = $env:TEMP
    New-Item -ItemType Directory -Path $env:TEMP | Out-Null

    Copy-Item -LiteralPath $testerPath -Destination $stagedTesterPath
    Copy-Item -LiteralPath $agentPath -Destination $stagedAgentPath
    Copy-Item -LiteralPath $installerOutput -Destination $stagedInstallerOutput -Recurse
    & icacls.exe $stagingPath /setowner '*S-1-5-18' /T /Q 2>&1 | Out-File $outputPath -Append
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set the staged executable and installer test owners"
    }
    & icacls.exe $stagedTesterPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' 2>&1 |
        Out-File $outputPath -Append
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to protect the staged tester executable"
    }

    "Staged policy tester at $stagedTesterPath" | Out-File $outputPath -Append
    Get-Acl -LiteralPath $stagingPath | Format-List Owner, Sddl | Out-File $outputPath -Append
    Get-Acl -LiteralPath $stagedTesterPath | Format-List Owner, Sddl | Out-File $outputPath -Append
    & $stagedTesterPath $stagedAgentPath elevated 2>&1 | Out-File $outputPath -Append
    $exitCode = $LASTEXITCODE
    & (Join-Path $PSScriptRoot "run-installer-tests.ps1") `
        -ProjectPath $installerProject -TestOutputPath $stagedInstallerOutput `
        -AgentPath $stagedAgentPath -ResultsPath $resultsPath -DotnetPath $DotnetPath `
        2>&1 | Out-File $outputPath -Append
    if ($LASTEXITCODE -ne 0) {
        $exitCode = $LASTEXITCODE
    }
} catch {
    $_ | Out-File $outputPath -Append
    $exitCode = 1
} finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    for ($attempt = 0; $attempt -lt 20 -and (Test-Path -LiteralPath $stagingPath); $attempt++) {
        try {
            Remove-Item -LiteralPath $stagingPath -Recurse -Force
        } catch {
            if ($attempt -eq 19) {
                "Failed to remove $stagingPath after 20 attempts: $_" | Out-File $outputPath -Append
                $exitCode = 1
            } else {
                Start-Sleep -Milliseconds 250
            }
        }
    }
}

exit $exitCode
