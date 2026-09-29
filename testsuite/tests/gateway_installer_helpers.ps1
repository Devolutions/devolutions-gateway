param(
    [string] $InstallerAssembly = "$PSScriptRoot\..\..\package\WindowsManaged\bin\Release\net471\DevolutionsGateway.exe"
)

$ErrorActionPreference = 'Stop'
$assemblyPath = (Resolve-Path -LiteralPath $InstallerAssembly).Path
$assembly = [Reflection.Assembly]::LoadFrom($assemblyPath)
$jsonAssembly = [Reflection.Assembly]::LoadFrom((Join-Path (Split-Path $assemblyPath) 'Newtonsoft.Json.dll'))
$flags = [Reflection.BindingFlags]'Static,Instance,Public,NonPublic'
$accountType = $assembly.GetType('DevolutionsGateway.Helpers.GatewayServiceAccount', $true)
$policyType = $assembly.GetType('DevolutionsGateway.Helpers.CertificateStorePermissions', $true)
$nativeType = $assembly.GetType('DevolutionsGateway.Actions.WinAPI', $true)
$script:passed = 0

function Assert-True {
    param([bool] $Condition, [string] $Name)
    if (-not $Condition) { throw "FAIL: $Name" }
    $script:passed++
    "PASS: $Name"
}

function Invoke-Helper {
    param([Type] $Type, [string] $Method, [object[]] $Arguments)
    $Type.GetMethod($Method, $flags).Invoke($null, $Arguments)
}

function Assert-Throws {
    param([scriptblock] $Action, [string] $Message, [string] $Name, [int] $NativeError = 0, [Type] $ExceptionType = [Exception])
    $caught = $null
    try { & $Action | Out-Null }
    catch {
        $caught = $_.Exception
        while ($caught.InnerException) { $caught = $caught.InnerException }
    }
    Assert-True ($null -ne $caught -and $ExceptionType.IsInstanceOfType($caught) -and $caught.Message -like "*$Message*" -and
        ($NativeError -eq 0 -or ($caught -is [ComponentModel.Win32Exception] -and $caught.NativeErrorCode -eq $NativeError))) $Name
}

function New-Config {
    param([string] $Json)
    ,($jsonAssembly.GetType('Newtonsoft.Json.Linq.JObject', $true).GetMethod(
        'Parse', [Type[]]@([string])).Invoke($null, @($Json)))
}

function Get-AccountProperty {
    param($Account, [string] $Name)
    $accountType.GetProperty($Name, $flags).GetValue($Account)
}

$networkSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-20')
$virtualAccount = Invoke-Helper $accountType 'ResolveConfigured' @('NT SERVICE\DevolutionsGateway', 'DevolutionsGateway')
$virtualSid = Get-AccountProperty $virtualAccount 'Sid'
$missingService = 'DgwInstallerHelperTests-' + [Guid]::NewGuid().ToString('N')
$defaultAccount = Invoke-Helper $accountType 'ResolveConfigured' @('', $missingService)
Assert-True ((Get-AccountProperty $defaultAccount 'Sid').Equals($networkSid)) 'No existing service defaults to Network Service'
$override = Invoke-Helper $accountType 'ResolveConfigured' @('NT SERVICE\DevolutionsGateway', 'DevolutionsGateway')
Assert-True ((Get-AccountProperty $override 'Sid').Equals($virtualSid)) 'Explicit virtual account wins without SCM discovery'
Assert-Throws {
    Invoke-Helper $accountType 'ResolveConfigured' @('NT AUTHORITY\SYSTEM', $missingService)
} 'not supported' 'Unsupported explicit identity does not fall back to Network Service'
Assert-Throws {
    Invoke-Helper $accountType 'ResolveConfigured' @('', 'Invalid/Service/Name')
} '' 'SCM errors other than missing service are not converted into default identity' -NativeError 123

$eventLogName = Invoke-Helper $accountType 'QueryExistingAccount' @('EventLog', $null)
$eventLogSid = [Security.Principal.NTAccount]::new($eventLogName).Translate([Security.Principal.SecurityIdentifier])
if ($eventLogSid.Value -in @('S-1-5-18', 'S-1-5-19')) {
    Assert-Throws {
        Invoke-Helper $accountType 'ResolveConfigured' @('', 'EventLog')
    } 'not supported' 'An existing unsupported SCM identity is not replaced with the Network Service default'
} else {
    $eventLogAccount = Invoke-Helper $accountType 'ResolveConfigured' @('', 'EventLog')
    Assert-True ((Get-AccountProperty $eventLogAccount 'Sid').Equals($eventLogSid)) 'Omitted identity follows the actual SCM account'
}

$existingName = Invoke-Helper $accountType 'QueryExistingAccount' @('DevolutionsGateway', $null)
if ($existingName) {
    $existing = Invoke-Helper $accountType 'ResolveConfigured' @('', 'DevolutionsGateway')
    $explicit = Invoke-Helper $accountType 'ResolveConfigured' @($existingName, 'DevolutionsGateway')
    Assert-True ((Get-AccountProperty $existing 'Sid').Equals((Get-AccountProperty $explicit 'Sid'))) 'Omitted identity uses the existing SCM identity'
} else {
    'SKIP: Existing Gateway SCM identity check (Gateway is not installed)'
}

$retainedConfigs = @(
    '{"TlsCertificateSource":"System"}',
    '{"TlsCertificateSource":"System","TlsCertificateStoreLocation":null}',
    '{"TlsCertificateSource":"System","TlsCertificateStoreLocation":"CurrentUser"}',
    '{"TlsCertificateSource":"System","TlsCertificateStoreLocation":"CurrentService"}'
)
foreach ($json in $retainedConfigs) {
    $config = New-Config $json
    foreach ($alias in @('NT AUTHORITY\NetworkService', 'nt authority\networkservice', $networkSid.Translate([Security.Principal.NTAccount]).Value)) {
        $hash = Invoke-Helper $policyType 'ValidateExisting' @($config, $networkSid, $alias, $false)
        Assert-True (-not [string]::IsNullOrEmpty($hash)) "Same SID is retained for $json with alias $alias"
        $preserved = Invoke-Helper $policyType 'PreserveExisting' @($config, $hash)
        Assert-True $preserved 'Deferred decision preserves the unchanged configuration without certificate lookup or grant'
    }
    $hash = Invoke-Helper $policyType 'ValidateExisting' @($config, $virtualSid, 'nt service\devolutionsgateway', $false)
    Assert-True (-not [string]::IsNullOrEmpty($hash)) 'Virtual-account casing resolves to the same SID'
    Assert-Throws {
        Invoke-Helper $policyType 'ValidateExisting' @($config, $virtualSid, 'NT AUTHORITY\NetworkService', $false)
    } 'Changing the service account' 'Different SID is rejected before removal'
    Assert-Throws {
        Invoke-Helper $policyType 'ValidateExisting' @($config, $networkSid, '', $false)
    } 'same existing service account' 'Missing existing service cannot authorize retained profile/service stores'
    Assert-Throws {
        Invoke-Helper $policyType 'ValidateExisting' @($config, $networkSid, 'NT AUTHORITY\NetworkService', $true)
    } 'without reconfiguration' 'Reconfiguration cannot authorize retention'
    Assert-Throws {
        Invoke-Helper $policyType 'PreserveExisting' @($config, '')
    } 'not validated for retention' 'Deferred profile/service-store access fails without private preflight evidence'
    $changed = New-Config ($json.TrimEnd('}') + ',"Hostname":"changed.example"}')
    Assert-Throws {
        Invoke-Helper $policyType 'PreserveExisting' @($changed, $hash)
    } 'changed after validation' 'Modified configuration is rejected by deferred decision'
    $machine = New-Config '{"TlsCertificateSource":"System","TlsCertificateStoreLocation":"LocalMachine"}'
    Assert-Throws {
        Invoke-Helper $policyType 'PreserveExisting' @($machine, $hash)
    } 'changed after validation' 'Switching a retained store to LocalMachine after validation is rejected'
}

foreach ($location in @('""', '"unknown"', '"localmachine"', '"2"', '2', '{}', '[]')) {
    $config = New-Config ('{"TlsCertificateSource":"System","TlsCertificateStoreLocation":' + $location + '}')
    Assert-Throws {
        Invoke-Helper $policyType 'ValidateExisting' @($config, $networkSid, 'NT AUTHORITY\NetworkService', $false)
    } 'TlsCertificateStoreLocation must be' "Invalid location $location is rejected before removal"
    Assert-Throws {
        Invoke-Helper $policyType 'PreserveExisting' @($config, '')
    } 'TlsCertificateStoreLocation must be' "Invalid location $location is rejected by the deferred guard"
}
foreach ($json in @('{}', '{"TlsCertificateSource":"External"}', '{"TlsCertificateSource":"System","TlsCertificateStoreLocation":"LocalMachine"}')) {
    $config = New-Config $json
    $hash = Invoke-Helper $policyType 'ValidateExisting' @($config, $virtualSid, '', $true)
    Assert-True ([string]::IsNullOrEmpty($hash)) 'External/machine configurations do not need profile retention'
    Assert-True (-not (Invoke-Helper $policyType 'PreserveExisting' @($config, $hash))) 'External/machine configurations follow normal checked permission processing'
}
Invoke-Helper $policyType 'ValidateSelection' @([Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
Assert-Throws {
    Invoke-Helper $policyType 'ValidateSelection' @([Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
} 'Select a LocalMachine' 'Wizard CurrentUser selection is rejected rather than targeting the interactive profile'
Assert-Throws {
    Invoke-Helper $policyType 'ValidateSelection' @([Enum]::ToObject([Security.Cryptography.X509Certificates.StoreLocation], 99))
} 'Select a LocalMachine' 'Invalid wizard store location is rejected'

$openPolicy = $nativeType.GetMethod('LsaOpenPolicy', $flags)
Assert-True ($openPolicy.GetParameters()[0].ParameterType -eq [IntPtr]) 'LSA SystemName parameter is a nullable pointer'
$attributesType = $nativeType.GetNestedType('LSA_OBJECT_ATTRIBUTES', $flags)
$attributes = [Activator]::CreateInstance($attributesType)
$attributesType.GetField('Length', $flags).SetValue($attributes, [uint32][Runtime.InteropServices.Marshal]::SizeOf($attributes))
$arguments = [object[]]@([IntPtr]::Zero, $attributes, [uint32]0x800, [IntPtr]::Zero)
$status = $openPolicy.Invoke($null, $arguments)
$handle = [IntPtr]$arguments[3]
try {
    Assert-True ($status -eq 0 -and $handle -ne [IntPtr]::Zero) 'Native local policy opens with NULL SystemName and lookup-only access'
} finally {
    if ($handle -ne [IntPtr]::Zero) {
        $closeStatus = Invoke-Helper $nativeType 'LsaClose' @($handle)
        Assert-True ($closeStatus -eq 0) 'Native policy handle closes without granting rights'
    }
}

foreach ($culture in @('en-us', 'fr-fr', 'de-de')) {
    [xml] $localization = [Text.Encoding]::UTF8.GetString(
        [IO.File]::ReadAllBytes("$PSScriptRoot\..\..\package\WindowsManaged\Resources\DevolutionsGateway_$culture.wxl"))
    $template = @($localization.WixLocalization.String | Where-Object Id -eq 'PrivateKeyPermissionWillBeGranted')[0].InnerText
    $message = [string]::Format($template, 'EXAMPLE\GatewayUser')
    Assert-True ($message.Contains('EXAMPLE\GatewayUser') -and -not $message.Contains('{0}')) "$culture warning names the resolved identity"
    Assert-True (@($localization.WixLocalization.String | Where-Object Id -eq 'ViewErrorsButton').Count -eq 0) "$culture does not restore removed evaluation UI"
}
$propertyType = $assembly.GetType('DevolutionsGateway.Properties.GatewayProperties', $true)
$retentionProperty = $propertyType.GetField('preservedCertificateConfigHash', $flags).GetValue($null)
Assert-True ($retentionProperty.Id -ceq 'P.PreservedCertificateConfigHash' -and
    $retentionProperty.Hidden -and -not $retentionProperty.Public) 'Retention evidence is hidden and private, not a public bypass flag'

$selectionType = $assembly.GetType('DevolutionsGateway.Helpers.CertificateSelection', $true)
$selectString = $selectionType.GetMethod('Select', $flags, $null, [Type[]]@(
    [Security.Cryptography.X509Certificates.StoreLocation], [string], [string], [bool]), $null)
$selectEnum = $selectionType.GetMethod('Select', $flags, $null, [Type[]]@(
    [Security.Cryptography.X509Certificates.StoreLocation], [Security.Cryptography.X509Certificates.StoreName], [string], [bool]), $null)
$missingSubject = [Guid]::NewGuid().ToString('N')
$machineLocation = [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
foreach ($name in @('My', 'CA', 'Root')) {
    $result = $selectString.Invoke($null, @($machineLocation, $name, $missingSubject, $false))
    Assert-True ($result.GetType().GetProperty('MatchCount', $flags).GetValue($result) -eq 0) "Read-only string selector opens $name without remapping"
}
$result = $selectEnum.Invoke($null, @($machineLocation, [Security.Cryptography.X509Certificates.StoreName]::CertificateAuthority, $missingSubject, $false))
Assert-True ($result.GetType().GetProperty('MatchCount', $flags).GetValue($result) -eq 0) 'UI CertificateAuthority enum still opens the canonical CA store'
$missingStore = 'DgwInstallerHelperTests-' + [Guid]::NewGuid().ToString('N')
Assert-Throws {
    $selectString.Invoke($null, @($machineLocation, $missingStore, $missingSubject, $false))
} '' 'Custom store names reach native lookup, and missing-store errors are not hidden' -ExceptionType ([Security.Cryptography.CryptographicException])
Assert-True (-not (Test-Path -LiteralPath "HKLM:\Software\Microsoft\SystemCertificates\$missingStore")) 'Read-only lookup does not create a missing custom store'
"$script:passed helper checks passed; no installation, service mutation, or account-right grant was performed"
