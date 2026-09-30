param([int] $ProcessId, [Parameter(Mandatory)][string] $OutputPath, [string] $AgentDirectory)
$ErrorActionPreference = 'Stop'
try {
    Add-Type -Path "$PSScriptRoot\ServiceProbe.cs"
    [Diagnostics.Process]::EnterDebugMode()
    $service = Get-CimInstance Win32_Service -Filter "Name='DevolutionsGateway'"
    if (-not $service -or $service.ProcessId -ne $ProcessId -or $service.State -ne 'Running') {
        throw 'The Gateway service process changed before the token probe'
    }
    $data = Join-Path $env:ProgramData 'Devolutions\Gateway'
    $result = @{
        UserSid = [GatewayInstallerTests.ServiceProbe]::UserSid($ProcessId)
        GroupSids = @([GatewayInstallerTests.ServiceProbe]::GroupSids($ProcessId))
        ConfigReadable = [GatewayInstallerTests.ServiceProbe]::CanOpen($ProcessId, "$data\gateway.json", $false)
    }
    [GatewayInstallerTests.ServiceProbe]::WriteAndDelete($ProcessId, "$data\lab-probe-$([guid]::NewGuid().ToString('N')).tmp")
    $result.DataWritable = $true
    if ($AgentDirectory) {
        $result.UpdateCommandWritable = [GatewayInstallerTests.ServiceProbe]::CanOpen($ProcessId, "$AgentDirectory\update.json", $true)
        $result.UpdateStatusReadable = [GatewayInstallerTests.ServiceProbe]::CanOpen($ProcessId, "$AgentDirectory\update_status.json", $false)
        $result.UpdateStatusWritable = [GatewayInstallerTests.ServiceProbe]::CanOpen($ProcessId, "$AgentDirectory\update_status.json", $true)
    }
    $result | ConvertTo-Json | Set-Content -LiteralPath $OutputPath -Encoding UTF8
} catch {
    @{ Error = $_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    exit 1
} finally {
    [Diagnostics.Process]::LeaveDebugMode()
}
