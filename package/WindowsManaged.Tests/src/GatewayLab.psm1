Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\powershell\DevolutionsGateway\Private\Msi.ps1"
if (-not ('GatewayInstallerTests.ServiceProbe' -as [type])) {
    Add-Type -Path "$PSScriptRoot\ServiceProbe.cs"
}

function Get-GatewayLabMsi {
    param([Parameter(Mandatory)][string] $Path)
    $Path = (Resolve-Path -LiteralPath $Path).Path
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    try {
        $database = $installer.OpenDatabase($Path, 0)
        $properties = @{}
        foreach ($name in 'ProductCode', 'UpgradeCode', 'ProductVersion', 'ProductName') {
            $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$name'")
            try {
                [void]$view.Execute()
                $record = $view.Fetch()
                if (-not $record) { throw "MSI property $name is missing from $Path" }
                try { $properties[$name] = $record.StringData(1) }
                finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
            } finally {
                [void]$view.Close()
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
            }
        }
        if ($properties.ProductName -ne 'Devolutions Gateway') { throw "Not a Gateway MSI: $Path" }
        $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'DGWLAB_ROLLBACK_FIXTURE'")
        try {
            [void]$view.Execute()
            $record = $view.Fetch()
            $properties.IsRollbackFixture = $false
            if ($record) {
                try { $properties.IsRollbackFixture = $record.StringData(1) -eq '1' }
                finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
            }
        } finally {
            [void]$view.Close()
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        }
        $properties.Path = $Path
        $properties.SHA256 = (Get-FileHash -LiteralPath $Path).Hash
        $properties.Signature = [string](Get-AuthenticodeSignature -LiteralPath $Path).Status
        [pscustomobject]$properties
    } finally {
        if ($database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}

function Get-GatewayLabState {
    $service = Get-CimInstance Win32_Service -Filter "Name='DevolutionsGateway'"
    $data = Join-Path $env:ProgramData 'Devolutions\Gateway'
    [pscustomobject]@{
        Service = if ($service) { $service | Select-Object Name, State, StartMode, StartName, PathName, ProcessId } else { $null }
        ConfigHash = if (Test-Path -LiteralPath "$data\gateway.json") { (Get-FileHash -LiteralPath "$data\gateway.json").Hash } else { $null }
        DataSddl = if (Test-Path -LiteralPath $data) { (Get-Acl -LiteralPath $data).Sddl } else { $null }
    }
}

function Get-GatewayLabDaclKey {
    param([AllowEmptyString()][string] $Sddl)
    if (-not $Sddl) { return 'missing' }
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    $protected = [bool]($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
    if ($null -eq $descriptor.DiscretionaryAcl) { return "$protected|null" }
    # Windows can reorder Allow ACEs when restoring inheritance; retain order for any other ACL.
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.QualifiedAce] -or $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) { return $Sddl }
    }
    $entries = foreach ($ace in $descriptor.DiscretionaryAcl) {
        $bytes = New-Object byte[] $ace.BinaryLength
        $ace.GetBinaryForm($bytes, 0)
        [BitConverter]::ToString($bytes)
    }
    $ordered = [string[]]@($entries)
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    "$protected|$($ordered -join ';')"
}

function Invoke-GatewayLabMsi {
    param(
        [Parameter(Mandatory)] $Msi,
        [Parameter(Mandatory)][string] $LogPath,
        [ValidateSet('Install', 'Repair', 'Uninstall')][string] $Action = 'Install',
        [hashtable] $Properties = @{},
        [int[]] $ExpectedExitCode = @(0),
        [int] $TimeoutSeconds = 300
    )
    $arguments = switch ($Action) {
        Install { @('/i', ('"{0}"' -f $Msi.Path)) }
        Repair { @('/i', $Msi.ProductCode, 'REINSTALL=ALL', 'REINSTALLMODE=omus') }
        Uninstall { @('/x', $Msi.ProductCode) }
    }
    $arguments += @('/qn', '/norestart', 'REBOOT=ReallySuppress', '/l*v', ('"{0}"' -f $LogPath))
    foreach ($name in $Properties.Keys) {
        if ($name -eq 'REBOOT' -or $name -eq 'REBOOTPROMPT') { throw 'Reboot policy cannot be overridden in lab scenarios' }
        $arguments += ConvertTo-DGatewayMsiProperty -Name $name -Value ([string]$Properties[$name])
    }
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $arguments -PassThru
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $script:RecoveryRequired = $true
        throw "MSI operation exceeded ${TimeoutSeconds}s (PID $($process.Id)); execution stopped without killing the installer. Log: $LogPath"
    }
    $process.Refresh()
    $code = $process.ExitCode
    $process.Dispose()
    if ($code -in @(3010, 1641)) {
        $script:RecoveryRequired = $true
        throw "MSI reported reboot status $code; approval is required before continuing. Log: $LogPath"
    }
    if ($code -notin $ExpectedExitCode) { throw "Unexpected MSI exit code $code; expected $ExpectedExitCode. Log: $LogPath" }
    $code
}

function Test-GatewayLabRecoveryRequired {
    [bool](Get-Variable -Name RecoveryRequired -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
}

function Wait-GatewayLabService {
    param([ValidateSet('Running', 'Stopped')][string] $State, [int] $TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $service = Get-CimInstance Win32_Service -Filter "Name='DevolutionsGateway'"
        if ($service -and $service.State -eq $State) { return $service }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Gateway did not reach $State within ${TimeoutSeconds}s"
}

function Stop-GatewayLabService {
    $service = Get-Service DevolutionsGateway
    try {
        if ($service.Status -ne 'Stopped') { $service.Stop() }
        Wait-GatewayLabService Stopped -TimeoutSeconds 120 | Out-Null
    } finally { $service.Dispose() }
}

function Initialize-GatewayLabConfiguration {
    param([int] $Port)
    $path = Join-Path $env:ProgramData 'Devolutions\Gateway\gateway.json'
    $directory = Split-Path -Parent $path
    $installDirectory = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Devolutions\Gateway').InstallDir
    $module = Join-Path $installDirectory 'PowerShell\Modules\DevolutionsGateway\DevolutionsGateway.psd1'
    $command = "Import-Module '$($module.Replace("'", "''"))'; New-DGatewayProvisionerKeyPair -ConfigPath '$($directory.Replace("'", "''"))'"
    # A separate process avoids retaining installed module DLLs across MSI upgrades.
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command $command | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to generate the lab provisioner key pair' }
    $config = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $config | Add-Member -NotePropertyName Listeners -NotePropertyValue @(
        @{ InternalUrl = "http://127.0.0.1:$Port"; ExternalUrl = "http://127.0.0.1:$Port" }
    ) -Force
    $config | Add-Member -NotePropertyName Hostname -NotePropertyValue 'localhost' -Force
    [IO.File]::WriteAllText($path, ($config | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
}

function Invoke-GatewayLabServiceProbe {
    param([int] $ProcessId, [Parameter(Mandatory)][string] $OutputDirectory, [string] $AgentDirectory)
    $name = 'GatewayLabProbe-' + [guid]::NewGuid().ToString('N')
    $output = Join-Path $OutputDirectory "$name.json"
    $arguments = '-NoProfile -NonInteractive -File "{0}" -ProcessId {1} -OutputPath "{2}"' -f "$PSScriptRoot\Invoke-ServiceProbe.ps1", $ProcessId, $output
    if ($AgentDirectory) { $arguments += ' -AgentDirectory "{0}"' -f $AgentDirectory }
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 120)
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
    try {
        Start-ScheduledTask -TaskName $name
        $deadline = [DateTime]::UtcNow.AddSeconds(150)
        do {
            Start-Sleep -Milliseconds 250
            $task = Get-ScheduledTask -TaskName $name
            if ($task.State -ne 'Running' -and (Test-Path -LiteralPath $output)) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($task.State -eq 'Running') { throw "Run-owned token probe is still running: $name" }
        if (-not (Test-Path -LiteralPath $output)) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $name
            $taskInfo | Select-Object LastRunTime, LastTaskResult | ConvertTo-Json |
                Set-Content -LiteralPath "$output.task.json" -Encoding UTF8
            throw "Token probe produced no result (task result $($taskInfo.LastTaskResult)): $name"
        }
        $result = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
        if ($result.PSObject.Properties.Name -contains 'Error') { throw "Token probe failed: $($result.Error)" }
        if ((Get-ScheduledTaskInfo -TaskName $name).LastTaskResult -ne 0) { throw "Token probe task failed: $name" }
        $result
    } finally {
        if ((Get-ScheduledTask -TaskName $name).State -ne 'Running') {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
        }
    }
}

function Test-GatewayLabRuntime {
    param([Parameter(Mandatory)] $Account, [int] $Port, [Parameter(Mandatory)][string] $OutputDirectory)
    $service = Wait-GatewayLabService Running
    $probe = Invoke-GatewayLabServiceProbe -ProcessId ([int]$service.ProcessId) -OutputDirectory $OutputDirectory
    $actual = $probe.UserSid
    if ($actual -ne $Account.Sid) { throw "Process identity $actual does not match expected $($Account.Sid)" }
    if (-not $probe.ConfigReadable -or -not $probe.DataWritable) {
        throw 'Service token cannot read its configuration'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/jet/health" -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return $probe }
        } catch [System.Net.WebException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Gateway health endpoint did not return HTTP 200'
}

function New-GatewayLabAccounts {
    param([Parameter(Mandatory)] $Lab, [string[]] $Kinds)
    $accounts = [Collections.Generic.List[object]]::new()
    $Lab.Resources = [Collections.Generic.List[object]]::new()
    foreach ($builtin in @(
        @{ Kind = 'NetworkService'; Name = 'NT AUTHORITY\NetworkService'; Sid = 'S-1-5-20' },
        @{ Kind = 'Virtual'; Name = 'NT SERVICE\DevolutionsGateway'; Sid = $null }
    )) {
        if ($builtin.Kind -notin $Kinds) { continue }
        $sid = if ($builtin.Sid) { $builtin.Sid } else {
            $sidOutput = & "$env:SystemRoot\System32\sc.exe" showsid DevolutionsGateway
            if ($LASTEXITCODE -ne 0 -or ($sidOutput -join "`n") -notmatch 'S-1-5-80(?:-\d+){5}') {
                throw 'SCM did not return the Gateway service SID'
            }
            $Matches[0]
        }
        $accounts.Add([pscustomobject]@{ Kind = $builtin.Kind; Name = $builtin.Name; Sid = $sid; Credential = $null })
    }
    foreach ($kind in @('Local', 'LocalDollar') | Where-Object { $_ -in $Kinds }) {
        $name = "dgwl$($Lab.RunId.Substring(0, 8))"
        if ($kind -eq 'LocalDollar') { $name += '$' }
        $bytes = New-Object byte[] 24
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $password = ConvertTo-SecureString ('Aa9!"\$;' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
        $user = New-LocalUser -Name $name -Password $password -Description "GatewayLab $($Lab.RunId)" -AccountNeverExpires
        $Lab.Resources.Add([pscustomobject]@{ Type = 'LocalUser'; Id = $user.Sid.Value; Name = $name })
        Save-GatewayLabManifest $Lab
        $accounts.Add([pscustomobject]@{
            Kind = $kind; Name = "$env:COMPUTERNAME\$name"; Sid = $user.Sid.Value
            Credential = [pscredential]::new("$env:COMPUTERNAME\$name", $password)
        })
    }
    if (@($Kinds | Where-Object { $_ -in @('Domain', 'Smsa', 'Gmsa') }).Count) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain
        $ou = New-ADOrganizationalUnit -Name "GatewayLab-$($Lab.RunId)" -Path $domain.DistinguishedName -ProtectedFromAccidentalDeletion:$false -PassThru
        $Lab.Resources.Add([pscustomobject]@{ Type = 'OU'; Id = [string]$ou.ObjectGuid })
        Save-GatewayLabManifest $Lab
        if ('Domain' -in $Kinds) {
            $name = "dgwd$($Lab.RunId.Substring(0, 8))"
            $password = ConvertTo-SecureString ("Aa9!" + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
            $user = New-ADUser -Name $name -SamAccountName $name -Path $ou.DistinguishedName -AccountPassword $password -Enabled $true -PassThru
            $Lab.Resources.Add([pscustomobject]@{ Type = 'ADUser'; Id = [string]$user.ObjectGuid; Sid = [string]$user.Sid })
            Save-GatewayLabManifest $Lab
            $accounts.Add([pscustomobject]@{
                Kind = 'Domain'; Name = "$($domain.NetBIOSName)\$name"; Sid = [string]$user.Sid
                Credential = [pscredential]::new("$($domain.NetBIOSName)\$name", $password)
            })
        }
        foreach ($kind in @('Smsa', 'Gmsa') | Where-Object { $_ -in $Kinds }) {
            if ($kind -eq 'Gmsa') {
                $configuration = (Get-ADRootDSE).configurationNamingContext
                $keys = @(Get-ADObject -SearchBase "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$configuration" -Filter 'ObjectClass -eq "msKds-ProvRootKey"')
                if (-not $keys.Count) {
                    $Lab.Blocked.Add('Gmsa: the domain has no KDS root key; no domain-wide changes were authorized')
                    continue
                }
            }
            $name = "dgwm$($Lab.RunId.Substring(0, 7))$($kind.Substring(0, 1))"
            $parameters = @{ Name = $name; Path = $ou.DistinguishedName; Enabled = $true; PassThru = $true }
            if ($kind -eq 'Smsa') { $parameters.RestrictToSingleComputer = $true }
            else {
                $group = New-ADGroup -Name "$name-hosts" -GroupScope Global -Path $ou.DistinguishedName -PassThru
                $Lab.Resources.Add([pscustomobject]@{ Type = 'ADGroup'; Id = [string]$group.ObjectGuid })
                Save-GatewayLabManifest $Lab
                $computer = Get-ADComputer $env:COMPUTERNAME
                Add-ADGroupMember -Identity $group -Members $computer
                $parameters.DNSHostName = "$name.$($domain.DNSRoot)"
                # Direct host authorization avoids refreshing machine tickets for a newly created group.
                $parameters.PrincipalsAllowedToRetrieveManagedPassword = @($group.DistinguishedName, $computer.DistinguishedName)
            }
            $account = New-ADServiceAccount @parameters
            $Lab.Resources.Add([pscustomobject]@{ Type = 'MSA'; Id = [string]$account.ObjectGuid; Name = $name; Sid = [string]$account.Sid })
            Save-GatewayLabManifest $Lab
            Add-ADComputerServiceAccount -Identity $env:COMPUTERNAME -ServiceAccount $account
            Install-ADServiceAccount -Identity $name
            if (-not (Test-ADServiceAccount -Identity $name)) { throw "$kind password retrieval failed for the run-owned account" }
            $accounts.Add([pscustomobject]@{
                Kind = $kind; Name = "$($domain.NetBIOSName)\$name`$"; Sid = [string]$account.Sid; Credential = $null
            })
        }
    }
    $accounts.ToArray()
}

function Save-GatewayLabManifest {
    param([Parameter(Mandatory)] $Lab)
    [ordered]@{
        RunId = $Lab.RunId; Computer = $env:COMPUTERNAME
        Resources = @($Lab.Resources.ToArray()); Blocked = @($Lab.Blocked.ToArray())
        Msi = $Lab.Msi; NextMsi = $Lab.NextMsi
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$($Lab.Output)\manifest.json" -Encoding UTF8
}

function Protect-GatewayLabArtifacts {
    param([Parameter(Mandatory)][string] $Directory)
    $items = @(Get-Item -LiteralPath $Directory) + @(Get-ChildItem -LiteralPath $Directory -Recurse -Force)
    if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
        throw 'Refusing to reset artifact permissions across a reparse point'
    }
    foreach ($item in $items) {
        $acl = Get-Acl -LiteralPath $item.FullName
        $acl.SetAccessRuleProtection($false, $false)
        foreach ($rule in @($acl.Access | Where-Object { -not $_.IsInherited })) { [void]$acl.RemoveAccessRuleSpecific($rule) }
        Set-Acl -LiteralPath $item.FullName -AclObject $acl
    }
}

function Remove-GatewayLabAccounts {
    param([Parameter(Mandatory)] $Lab)
    if (Test-GatewayLabRecoveryRequired) {
        throw 'MSI state is uncertain or requires a reboot; retaining test accounts for recovery'
    }
    if ((Get-GatewayLabState).Service) { throw 'Gateway is still installed; retaining its test accounts for recovery' }
    for ($index = $Lab.Resources.Count - 1; $index -ge 0; $index--) {
        $resource = $Lab.Resources[$index]
        switch ($resource.Type) {
            LocalUser {
                [GatewayInstallerTests.ServiceProbe]::SetTestAccountRights($resource.Id, $true)
                Remove-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($resource.Id))
            }
            ADUser {
                [GatewayInstallerTests.ServiceProbe]::SetTestAccountRights($resource.Sid, $true)
                Remove-ADUser -Identity $resource.Id -Confirm:$false
            }
            MSA {
                [GatewayInstallerTests.ServiceProbe]::SetTestAccountRights($resource.Sid, $true)
                if ([GatewayInstallerTests.ServiceProbe]::IsManaged("$($resource.Name)`$")) {
                    Uninstall-ADServiceAccount -Identity $resource.Id -Force
                }
                Remove-ADComputerServiceAccount -Identity $env:COMPUTERNAME -ServiceAccount $resource.Id -Confirm:$false
                Remove-ADServiceAccount -Identity $resource.Id -Confirm:$false
            }
            ADGroup { Remove-ADGroup -Identity $resource.Id -Confirm:$false }
            OU { Remove-ADOrganizationalUnit -Identity $resource.Id -Confirm:$false }
            default { throw "Unknown lab resource type: $($resource.Type)" }
        }
        $Lab.Resources.RemoveAt($index)
        Save-GatewayLabManifest $Lab
    }
}

function Start-GatewayLabAgent {
    param([string] $Executable, [string] $Directory, $Target, [switch] $AllowUnsigned)
    New-Item -ItemType Directory -Path $Directory | Out-Null
    $productInfo = @{
        Gateway = @{ Current = @{
            Version = "20$($Target.ProductVersion)"
            Files = @(@{ Arch = 'x64'; Type = 'msi'; Url = ([uri]$Target.Path).AbsoluteUri; Hash = $Target.SHA256 })
        } }
    }
    [IO.File]::WriteAllText("$Directory\productinfo.json", ($productInfo | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    $config = @{
        Updater = @{ Enabled = $true }
        Session = @{ Enabled = $false }
        __debug__ = @{
            productinfo_url = ([uri]"$Directory\productinfo.json").AbsoluteUri
            allow_unsafe_updater_urls = $true
            skip_msi_signature_validation = [bool]$AllowUnsigned
        }
    }
    [IO.File]::WriteAllText("$Directory\agent.json", ($config | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    $name = 'GatewayLabAgent-' + [guid]::NewGuid().ToString('N')
    $arguments = '-NoProfile -NonInteractive -File "{0}" -Executable "{1}" -Directory "{2}"' -f "$PSScriptRoot\Start-AgentProbe.ps1", $Executable, $Directory
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal | Out-Null
    $result = [pscustomobject]@{ TaskName = $name; Directory = $Directory; Executable = $Executable }
    try {
        Start-ScheduledTask -TaskName $name
        $deadline = [DateTime]::UtcNow.AddSeconds(45)
        while (-not (Test-Path -LiteralPath "$Directory\update_status.json")) {
            if ([DateTime]::UtcNow -gt $deadline) { throw "Agent did not initialize its status file; see $Directory" }
            Start-Sleep -Milliseconds 250
        }
        $processId = [int](Get-Content -LiteralPath "$Directory\process.id")
        if (-not (Get-Process -Id $processId -ErrorAction SilentlyContinue)) { throw 'Agent exited during initialization' }
        $result
    } catch {
        Stop-GatewayLabAgent $result
        throw
    }
}

function Stop-GatewayLabAgent {
    param($Agent)
    if (Test-GatewayLabRecoveryRequired) {
        throw "Retaining the Agent task for inspection of an uncertain MSI operation: $($Agent.TaskName)"
    }
    $path = "$($Agent.Directory)\process.id"
    if (Test-Path -LiteralPath $path) {
        $processId = [int](Get-Content -LiteralPath $path)
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$processId"
        if ($process) {
            if ($process.ExecutablePath -ne $Agent.Executable) { throw 'Agent probe PID has been reused; refusing termination' }
            Stop-Process -Id $processId -Force
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ((Get-ScheduledTask -TaskName $Agent.TaskName).State -eq 'Running') {
        if ([DateTime]::UtcNow -gt $deadline) { throw "Agent wrapper task did not finish: $($Agent.TaskName)" }
        Start-Sleep -Milliseconds 200
    }
    Unregister-ScheduledTask -TaskName $Agent.TaskName -Confirm:$false
    Protect-GatewayLabArtifacts -Directory $Agent.Directory
}

function Invoke-GatewayLabAgentUpdate {
    param($Agent, [string] $ExpectedVersion, [string] $ExpectedError, [string] $RequestedVersion = 'latest', [int] $TimeoutSeconds = 240)
    $manifest = @{ VersionMajor = 2; VersionMinor = 2; Products = @{ Gateway = @{ Version = $RequestedVersion } } } |
        ConvertTo-Json -Depth 4 -Compress
    [IO.File]::WriteAllText("$($Agent.Directory)\update.json", $manifest, [Text.UTF8Encoding]::new($false))
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $path = "$($Agent.Directory)\update_status.json"
        $status = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($status -and $status.Products -and $status.Products.PSObject.Properties.Name -contains 'Gateway') {
            $gateway = $status.Products.Gateway
            $errorProperty = $gateway.PSObject.Properties['LastUpdateError']
            if ($ExpectedError -and $errorProperty -and $errorProperty.Value -like $ExpectedError) { return $status }
            if (-not $ExpectedError -and $gateway.Version -match ('^' + [regex]::Escape($ExpectedVersion) + '(\.0)?$') -and -not $errorProperty) { return $status }
            if (-not $ExpectedError -and $errorProperty) { throw "Agent update failed: $($errorProperty.Value)" }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    $script:RecoveryRequired = $true
    throw "Agent did not reach the expected update result; inspect the owned Agent task and MSI state: $($Agent.Directory)"
}

Export-ModuleMember -Function *-GatewayLab*
