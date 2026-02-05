
. "$PSScriptRoot/../Private/CertificateHelper.ps1"
. "$PSScriptRoot/../Private/PlatformHelper.ps1"
. "$PSScriptRoot/../Private/TokenHelper.ps1"

$script:DGatewayConfigFileName = 'gateway.json'
$script:DGatewayCertificateFileName = 'server.crt'
$script:DGatewayPrivateKeyFileName = 'server.key'
$script:DGatewayProvisionerPublicKeyFileName = 'provisioner.pem'
$script:DGatewayProvisionerPrivateKeyFileName = 'provisioner.key'
$script:DGatewayDelegationPublicKeyFileName = 'delegation.pem'
$script:DGatewayDelegationPrivateKeyFileName = 'delegation.key'
$script:DGatewayCustomUsersFileName = 'users.txt'

function Get-DGatewayVersion {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet('PSModule', 'Installed')]
        [string] $Type
    )

    if ($Type -eq 'PSModule') {
        $ManifestPath = "$PSScriptRoot/../DevolutionsGateway.psd1"
        $Manifest = Import-PowerShellDataFile -Path $ManifestPath
        $DGatewayVersion = $Manifest.ModuleVersion
    } elseif ($Type -eq 'Installed') {
        if ($IsWindows) {
            $UninstallReg = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' `
            | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_ -Match 'Devolutions Gateway' }
            if ($UninstallReg) {
                $DGatewayVersion = '20' + $UninstallReg.DisplayVersion
            }
        } elseif ($IsMacOS) {
            throw 'not supported'
        } elseif ($IsLinux) {
            $PackageName = 'devolutions-gateway'
            $DpkgStatus = $(dpkg -s $PackageName 2>$null)
            $DpkgMatches = $($DpkgStatus | Select-String -AllMatches -Pattern 'version: (\S+)').Matches
            if ($DpkgMatches) {
                $VersionQuad = $DpkgMatches.Groups[1].Value
                $VersionTriple = $VersionQuad -Replace '^(\d+)\.(\d+)\.(\d+)\.(\d+)$', "`$1.`$2.`$3"
                $DGatewayVersion = $VersionTriple
            }
        }
    }

    $DGatewayVersion
}

class DGatewayListener {
    [string] $InternalUrl
    [string] $ExternalUrl

    DGatewayListener() { }

    DGatewayListener([string] $InternalUrl, [string] $ExternalUrl) {
        $this.InternalUrl = $InternalUrl
        $this.ExternalUrl = $ExternalUrl
    }

    DGatewayListener([PSCustomObject] $object) {
        $this.InternalUrl = $object.InternalUrl
        $this.ExternalUrl = $object.ExternalUrl
    }

    DGatewayListener([Hashtable] $table) {
        $this.InternalUrl = $table.InternalUrl
        $this.ExternalUrl = $table.ExternalUrl
    }
}

function New-DGatewayListener() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ListenerUrl,
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $ExternalUrl
    )

    return [DGatewayListener]::new($ListenerUrl, $ExternalUrl)
}

class DGatewaySubProvisionerKey {
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Id

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Value

    [ValidateNotNullOrEmpty()]
    [ValidateSet('Spki','Rsa')]
    [string] $Format

    [ValidateNotNullOrEmpty()]
    [ValidateSet('Multibase','Base64', 'Base64Pad', 'Base64Url', 'Base64UrlPad')]
    [string] $Encoding

    DGatewaySubProvisionerKey(
        [string] $Id,
        [string] $Value,
        [string] $Format = 'Spki',
        [string] $Encoding = 'Multibase'
    ) {
        $this.Id = $Id
        $this.Value = $Value
        $this.Format = $Format
        $this.Encoding = $Encoding
    }

    DGatewaySubProvisionerKey([PSCustomObject] $object) {
        $this.Id = $object.Id
        $this.Value = $object.Value
        $this.Format = $object.Format
        $this.Encoding = $object.Encoding
    }

    DGatewaySubProvisionerKey([Hashtable] $table) {
        $this.Id = $table.Id
        $this.Value = $table.Value
        $this.Format = $table.Format
        $this.Encoding = $table.Encoding
    }
}

class DGatewaySubscriber {
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [System.Uri] $Url

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Token

    DGatewaySubscriber(
        [System.Uri] $Url,
        [string] $Token
    ) {
        $this.Url = $Url
        $this.Token = $Token
    }

    DGatewaySubscriber([PSCustomObject] $object) {
        $this.Url = $object.Url
        $this.Token = $object.Token
    }

    DGatewaySubscriber([Hashtable] $table) {
        $this.Url = $table.Url
        $this.Token = $table.Token
    }
}

class DGatewayNgrokTunnel {
    [string] $Proto
    [string] $Metadata
    [string[]] $AllowCidrs
    [string[]] $DenyCidrs

    # HTTP tunnel
    [string] $Domain
    [System.Nullable[System.Single]] $CircuitBreaker
    [System.Nullable[System.Boolean]] $Compression

    # TCP tunnel
    [string] $RemoteAddr

    DGatewayNgrokTunnel() { }
}

class DGatewayNgrokConfig {
    [string] $AuthToken
    [System.Nullable[System.UInt32]] $HeartbeatInterval
    [System.Nullable[System.UInt32]] $HeartbeatTolerance
    [string] $Metadata
    [string] $ServerAddr
    [PSCustomObject] $Tunnels

    DGatewayNgrokConfig() { }

    DGatewayNgrokConfig([PSCustomObject] $object) {
        $this.AuthToken = $object.AuthToken
        $this.HeartbeatInterval = $object.HeartbeatInterval
        $this.HeartbeatTolerance = $object.HeartbeatTolerance
        $this.Metadata = $object.Metadata
        $this.ServerAddr = $object.ServerAddr
        $this.Tunnels = $object.Tunnels
    }

    DGatewayNgrokConfig([Hashtable] $table) {
        $this.AuthToken = $table.AuthToken
        $this.HeartbeatInterval = $table.HeartbeatInterval
        $this.HeartbeatTolerance = $table.HeartbeatTolerance
        $this.Metadata = $table.Metadata
        $this.ServerAddr = $table.ServerAddr
        $this.Tunnels = $table.Tunnels
    }
}

function New-DGatewayNgrokTunnel() {
    [CmdletBinding(DefaultParameterSetName = 'http')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'http',
            HelpMessage = "HTTP tunnel")]
        [switch] $Http,

        [Parameter(Mandatory = $false, ParameterSetName = 'tcp',
            HelpMessage = "TCP tunnel")]
        [switch] $Tcp,

        [Parameter(Mandatory = $false,
            HelpMessage = "User-defined metadata that appears when listing tunnel sessions with ngrok")]
        [string] $Metadata,

        [ValidateScript({
            $_ -match '^((\d{1,3}\.){3}\d{1,3}\/\d{1,2}|([\dA-Fa-f]{0,4}:){2,7}[\dA-Fa-f]{0,4}\/\d{1,3})$'
        })]
        [Parameter(Mandatory = $false,
            HelpMessage = "Reject connections that do not match the given CIDRs")]
        [string[]] $AllowCidrs,

        [ValidateScript({
            $_ -match '^((\d{1,3}\.){3}\d{1,3}\/\d{1,2}|([\dA-Fa-f]{0,4}:){2,7}[\dA-Fa-f]{0,4}\/\d{1,3})$'
        })]
        [Parameter(Mandatory = $false,
            HelpMessage = "Reject connections that match the given CIDRs")]
        [string[]] $DenyCidrs,

        [ValidateScript({
            $_ -match '^(\*\.)?([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)*[a-zA-Z]{2,}$'
        })]
        [Parameter(Mandatory = $false, ParameterSetName = 'http',
            HelpMessage = "Any valid domain or hostname previously registered with ngrok")]
        [string] $Domain,

        [ValidateRange(0.0, 1.0)]
        [Parameter(Mandatory = $false, ParameterSetName = 'http',
            HelpMessage = "Reject requests when 5XX responses exceed this ratio")]
        [System.Single] $CircuitBreaker,

        [Parameter(Mandatory = $false, ParameterSetName = 'http',
            HelpMessage = "Use gzip compression on HTTP responses")]
        [System.Boolean] $Compression,

        [ValidateScript({
            $_ -match '^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)*[a-zA-Z]{2,}:\d{1,5}$'
        })]
        [Parameter(Mandatory = $false, ParameterSetName = 'tcp',
            HelpMessage = "The remote TCP address and port to bind. For example: remote_addr: 2.tcp.ngrok.io:21746")]
        [string] $RemoteAddr
    )

    $tunnel = [DGatewayNgrokTunnel]::new()

    if ($Tcp) {
        $tunnel.Proto = "tcp"
    } else {
        $tunnel.Proto = "http"
    }

    $properties = [DGatewayNgrokTunnel].GetProperties() | ForEach-Object { $_.Name }
    foreach ($param in $PSBoundParameters.GetEnumerator()) {
        if ($properties -Contains $param.Key) {
            $tunnel.($param.Key) = $param.Value
        }
    }

    $tunnel
}

function New-DGatewayNgrokConfig() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $AuthToken
    )

    $ngrok = [DGatewayNgrokConfig]::new()
    $ngrok.AuthToken = $AuthToken
    $ngrok
}

class DGatewayWebAppConfig {
    [bool] $Enabled
    [string] $Authentication
    [System.Nullable[System.UInt32]] $AppTokenMaximumLifetime
    [System.Nullable[System.UInt32]] $LoginLimitRate
    [string] $UsersFile
    [string] $StaticRootPath

    DGatewayWebAppConfig() { }

    DGatewayWebAppConfig([PSCustomObject] $object) {
        $this.Enabled = $object.Enabled
        $this.Authentication = $object.Authentication
        $this.AppTokenMaximumLifetime = $object.AppTokenMaximumLifetime
        $this.LoginLimitRate = $object.LoginLimitRate
        $this.UsersFile = $object.UsersFile
        $this.StaticRootPath = $object.StaticRootPath
    }

    DGatewayWebAppConfig([Hashtable] $table) {
        $this.Enabled = $table.Enabled
        $this.Authentication = $table.Authentication
        $this.AppTokenMaximumLifetime = $table.AppTokenMaximumLifetime
        $this.LoginLimitRate = $table.LoginLimitRate
        $this.UsersFile = $table.UsersFile
        $this.StaticRootPath = $table.StaticRootPath
    }
}

function New-DGatewayWebAppConfig() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool] $Enabled,

        [Parameter(Mandatory = $true)]
        [ValidateSet("None", "Custom")]
        [string] $Authentication
    )

    $webapp = [DGatewayWebAppConfig]::new()
    $webapp.Enabled = $Enabled
    $webapp.Authentication = $Authentication
    $webapp
}

enum VerbosityProfile {
    Default
    Debug
    Tls
    All
    Quiet
}

class DGatewayConfig {
    [System.Nullable[Guid]] $Id
    [string] $Hostname

    [string] $RecordingPath

    [string] $TlsCertificateFile
    [string] $TlsPrivateKeyFile
    [string] $TlsPrivateKeyPassword

    [string] $TlsCertificateSource
    [string] $TlsCertificateSubjectName
    [string] $TlsCertificateStoreName
    [string] $TlsCertificateStoreLocation

    [string] $ProvisionerPublicKeyFile
    [string] $ProvisionerPrivateKeyFile
    [string] $DelegationPublicKeyFile
    [string] $DelegationPrivateKeyFile
    [DGatewaySubProvisionerKey] $SubProvisionerPublicKey

    [DGatewayListener[]] $Listeners
    [DGatewaySubscriber] $Subscriber

    [DGatewayNgrokConfig] $Ngrok
    
    [DGatewayWebAppConfig] $WebApp

    [string] $LogDirective
    [string] $VerbosityProfile
}

function Remove-NullObjectProperties {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, Mandatory)]
        [object[]] $InputObject
    )
    process {
        foreach ($OldObj in $InputObject) {
            $NonNullProperties = $OldObj.PSObject.Properties | Where-Object {
                ($_.Value -is [Array] -and $_.Value.Count -gt 0) -or
                (-Not [string]::IsNullOrEmpty($_.Value))
            } | Select-Object -ExpandProperty Name
            $NewObj = $OldObj | Select-Object $NonNullProperties
            $NewObj.PSObject.Properties |
                Where-Object { $_.TypeNameOfValue.EndsWith('PSCustomObject') } |
                ForEach-Object {
                    $NewObj."$($_.Name)" = $NewObj."$($_.Name)" | Remove-NullObjectProperties
                }
            $NewObj
        }
    }
}

function Save-DGatewayConfig {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Mandatory = $true)]
        [DGatewayConfig] $Config
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $ConfigFile = Join-Path $ConfigPath $DGatewayConfigFileName
    $ConfigClean = $Config | ConvertTo-Json -Depth 4 | ConvertFrom-Json # drop class type info
    $ConfigData = $ConfigClean | Remove-NullObjectProperties | ConvertTo-Json -Depth 4

    [System.IO.File]::WriteAllLines($ConfigFile, $ConfigData, $(New-Object System.Text.UTF8Encoding $False))
}

function Set-DGatewayConfig {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $Force,

        [Guid] $Id,
        [string] $Hostname,

        [string] $RecordingPath,

        [DGatewayListener[]] $Listeners,
        [DGatewaySubscriber] $Subscriber,

        [string] $TlsCertificateFile,
        [string] $TlsPrivateKeyFile,
        [string] $TlsPrivateKeyPassword,

        [ValidateSet("External", "System")]
        [string] $TlsCertificateSource,
        [string] $TlsCertificateSubjectName,
        [string] $TlsCertificateStoreName,
        [ValidateSet("CurrentUser", "LocalMachine", "CurrentService")]
        [string] $TlsCertificateStoreLocation,

        [string] $ProvisionerPublicKeyFile,
        [string] $ProvisionerPrivateKeyFile,

        [string] $DelegationPublicKeyFile,
        [string] $DelegationPrivateKeyFile,

        [DGatewaySubProvisionerKey] $SubProvisionerPublicKey,

        [DGatewayNgrokConfig] $Ngrok,

        [DGatewayWebAppConfig] $WebApp,

        [VerbosityProfile] $VerbosityProfile
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath

    if (-Not (Test-Path -Path $ConfigPath -PathType 'Container')) {
        New-Item -Path $ConfigPath -ItemType 'Directory' | Out-Null
    }

    $ConfigFile = Join-Path $ConfigPath $DGatewayConfigFileName

    if (-Not (Test-Path -Path $ConfigFile -PathType 'Leaf')) {
        $config = [DGatewayConfig]::new()
    } else {
        $config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    }

    $properties = [DGatewayConfig].GetProperties() | ForEach-Object { $_.Name }
    foreach ($param in $PSBoundParameters.GetEnumerator()) {
        if ($properties -Contains $param.Key) {
            $config.($param.Key) = $param.Value
        }
    }

    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function Get-DGatewayConfig {
    [CmdletBinding()]
    [OutputType('DGatewayConfig')]
    param(
        [string] $ConfigPath,
        [switch] $NullProperties,
        [switch] $Expand
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath

    $ConfigFile = Join-Path $ConfigPath $DGatewayConfigFileName

    $config = [DGatewayConfig]::new()

    if (-Not (Test-Path -Path $ConfigFile -PathType 'Leaf')) {
        if ($NullProperties) {
            return $config
        }
    }

    $ConfigData = Get-Content -Path $ConfigFile -Encoding UTF8
    $json = $ConfigData | ConvertFrom-Json

    [DGatewayConfig].GetProperties() | ForEach-Object {
        $Name = $_.Name
        if ($json.PSObject.Properties[$Name]) {
            $Property = $json.PSObject.Properties[$Name]
            $Value = $Property.Value
            $config.$Name = $Value
        }
    }

    if ($Expand) {
        Expand-DGatewayConfig $config
    }

    if (-Not $NullProperties) {
        $Properties = $Config.PSObject.Properties.Name
        $NonNullProperties = $Properties.Where( { -Not [string]::IsNullOrEmpty($Config.$_) })
        $Config = $Config | Select-Object $NonNullProperties
    }

    return $config
}

function Expand-DGatewayConfig {
    param(
        [DGatewayConfig] $Config
    )
}

function Find-DGatewayConfig {
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    if (-Not $ConfigPath) {
        $CurrentPath = Get-Location
        $ConfigFile = Join-Path $CurrentPath $DGatewayConfigFileName

        if (Test-Path -Path $ConfigFile -PathType 'Leaf') {
            $ConfigPath = $CurrentPath
        }
    }

    if (-Not $ConfigPath) {
        $ConfigPath = Get-DGatewayPath
    }

    if ($Env:DGATEWAY_CONFIG_PATH) {
        $ConfigPath = $Env:DGATEWAY_CONFIG_PATH
    }

    return $ConfigPath
}

function Enter-DGatewayConfig {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [switch] $ChangeDirectory
    )

    if ($ConfigPath) {
        $ConfigPath = Resolve-Path $ConfigPath
        $Env:DGATEWAY_CONFIG_PATH = $ConfigPath
    }

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath

    if ($ChangeDirectory) {
        Set-Location $ConfigPath
    }
}

function Exit-DGatewayConfig {
    Remove-Item Env:DGATEWAY_CONFIG_PATH
}

function Get-DGatewayPath() {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidateSet('ConfigPath')]
        [string] $PathType = 'ConfigPath'
    )

    $DisplayName = 'Gateway'
    $CompanyName = 'Devolutions'

    if ($IsWindows) {
        $ConfigPath = $Env:ProgramData + "\${CompanyName}\${DisplayName}"
    } elseif ($IsMacOS) {
        $ConfigPath = "/Library/Application Support/${CompanyName} ${DisplayName}"
    } elseif ($IsLinux) {
        $ConfigPath = '/etc/devolutions-gateway'
    }

    switch ($PathType) {
        'ConfigPath' { $ConfigPath }
        default { throw("Invalid path type: $PathType") }
    }
}

function Get-DGatewayRecordingPath {
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties

    $RecordingPath = $Config.RecordingPath

    if ([string]::IsNullOrEmpty($RecordingPath)) {
        $RecordingPath = Join-Path $ConfigPath "recordings"
    }

    $RecordingPath
}

function Set-DGatewayRecordingPath {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $RecordingPath
    )

    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    $Config.RecordingPath = $RecordingPath
    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function Reset-DGatewayRecordingPath {
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    $Config.RecordingPath = $null
    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function Get-DGatewayHostname {
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    $(Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties).Hostname
}

function Set-DGatewayHostname {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Hostname
    )

    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    $Config.Hostname = $Hostname
    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function Get-DGatewayListeners {
    [CmdletBinding()]
    [OutputType('DGatewayListener[]')]
    param(
        [string] $ConfigPath
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    $Config.Listeners
}

function Set-DGatewayListeners {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyCollection()]
        [DGatewayListener[]] $Listeners
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    $Config.Listeners = $Listeners
    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function New-DGatewayCertificate {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $Hostname,
        [switch] $Force
    )

    if (-Not $IsWindows) {
        throw "unsupported platform"
    }

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties

    if ([string]::IsNullOrEmpty($Hostname)) {
        $Hostname = $Config.Hostname
    }

    if ([string]::IsNullOrEmpty($Hostname)) {
        $Hostname = [System.Environment]::MachineName
    }

    Set-DGatewayHostname -ConfigPath:$ConfigPath $Hostname

    $Password = "cert123!" # dummy password (it's just a self-signed certificate)
    $SecurePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText

    # Create a self-signed certificate for the specified hostname and export to a .pfx file
    $NotBefore = Get-Date
    $ExtendedKeyUsage = "2.5.29.37={text}1.3.6.1.5.5.7.3.1"
    $Params = @{
        DnsName = $Hostname
        CertStoreLocation = "cert:\CurrentUser\My"
        KeyExportPolicy = "Exportable"
        KeyAlgorithm = "RSA"
        KeyLength = 2048
        HashAlgorithm = 'SHA256'
        TextExtension = @($ExtendedKeyUsage)
        KeyUsageProperty = "All"
        KeyUsage = 'CertSign', 'DigitalSignature', 'KeyEncipherment'
        NotBefore = $NotBefore.AddHours(-1)
        NotAfter = $NotBefore.AddYears(5)
    }
    $Certificate = New-SelfSignedCertificate @Params
    
    $PfxCertificateFile = Join-Path ([System.IO.Path]::GetTempPath()) "gateway-$Hostname.pfx"
    Export-PfxCertificate -Cert $Certificate -FilePath $PfxCertificateFile -Password $securePassword | Out-Null
    Remove-Item -Path ("cert:\CurrentUser\My\" + $Certificate.Thumbprint) | Out-Null

    Import-DGatewayCertificate -ConfigPath:$ConfigPath -CertificateFile $PfxCertificateFile -Password $Password
    Remove-Item $PfxCertificateFile | Out-Null # remove temporary .pfx file
}

function Import-DGatewayCertificate {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $CertificateFile,
        [string] $PrivateKeyFile,
        [string] $Password
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties

    $result = Get-PemCertificate -CertificateFile:$CertificateFile `
        -PrivateKeyFile:$PrivateKeyFile -Password:$Password
        
    $CertificateData = $result.Certificate
    $PrivateKeyData = $result.PrivateKey

    New-Item -Path $ConfigPath -ItemType 'Directory' -Force | Out-Null

    $CertificateFile = Join-Path $ConfigPath $DGatewayCertificateFileName
    $PrivateKeyFile = Join-Path $ConfigPath $DGatewayPrivateKeyFileName

    Set-Content -Path $CertificateFile -Value $CertificateData -Force
    Set-Content -Path $PrivateKeyFile -Value $PrivateKeyData -Force

    $Config.TlsCertificateFile = $DGatewayCertificateFileName
    $Config.TlsPrivateKeyFile = $DGatewayPrivateKeyFileName

    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function New-DGatewayProvisionerKeyPair {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [int] $KeySize = 2048,
        [switch] $Force
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties

    if (-Not (Test-Path -Path $ConfigPath)) {
        New-Item -Path $ConfigPath -ItemType 'Directory' -Force | Out-Null
    }

    $PublicKeyFile = Join-Path $ConfigPath $DGatewayProvisionerPublicKeyFileName
    $PrivateKeyFile = Join-Path $ConfigPath $DGatewayProvisionerPrivateKeyFileName

    if ((Test-Path -Path $PublicKeyFile) -Or (Test-Path -Path $PrivateKeyFile)) {
        if (-Not $Force) {
            throw "$PublicKeyFile or $PrivateKeyFile already exists, use -Force to overwrite"
        }

        Remove-Item $PublicKeyFile -Force | Out-Null
        Remove-Item $PrivateKeyFile -Force | Out-Null
    }

    $KeyPair = New-RsaKeyPair -KeySize:$KeySize

    $PublicKeyData = $KeyPair.PublicKey
    $Config.ProvisionerPublicKeyFile = $DGatewayProvisionerPublicKeyFileName
    Set-Content -Path $PublicKeyFile -Value $PublicKeyData -Force

    $PrivateKeyData = $KeyPair.PrivateKey
    $Config.ProvisionerPrivateKeyFile = $DGatewayProvisionerPrivateKeyFileName
    Set-Content -Path $PrivateKeyFile -Value $PrivateKeyData -Force

    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function Import-DGatewayProvisionerKey {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $PublicKeyFile,
        [string] $PrivateKeyFile
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties

    if ($PublicKeyFile) {
        if (-Not (Test-Path -Path $PublicKeyFile)) {
            throw "$PublicKeyFile doesn't exist"
        }

        $PublicKeyData = Get-Content -Path $PublicKeyFile -Encoding UTF8

        if (!$PublicKeyData) {
            throw "$PublicKeyFile appears to be empty"          
        }

        $OutputFile = Join-Path $ConfigPath $DGatewayProvisionerPublicKeyFileName
        $Config.ProvisionerPublicKeyFile = $DGatewayProvisionerPublicKeyFileName
        New-Item -Path $ConfigPath -ItemType 'Directory' -Force | Out-Null
        Set-Content -Path $OutputFile -Value $PublicKeyData -Force
    }

    if ($PrivateKeyFile) {
        if (-Not (Test-Path -Path $PrivateKeyFile)) {
            throw "$PrivateKeyFile doesn't exist"
        }

        $PrivateKeyData = Get-Content -Path $PrivateKeyFile -Encoding UTF8

        if (!$PrivateKeyData) {
            throw "$PrivateKeyFile appears to be empty"          
        }

        $OutputFile = Join-Path $ConfigPath $DGatewayProvisionerPrivateKeyFileName
        $Config.ProvisionerPrivateKeyFile = $DGatewayProvisionerPrivateKeyFileName
        New-Item -Path $ConfigPath -ItemType 'Directory' -Force | Out-Null
        Set-Content -Path $OutputFile -Value $PrivateKeyData -Force
    }

    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function New-DGatewayDelegationKeyPair {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [int] $KeySize = 2048,
        [switch] $Force
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties

    if (-Not (Test-Path -Path $ConfigPath)) {
        New-Item -Path $ConfigPath -ItemType 'Directory' -Force | Out-Null
    }

    $PublicKeyFile = Join-Path $ConfigPath $DGatewayDelegationPublicKeyFileName
    $PrivateKeyFile = Join-Path $ConfigPath $DGatewayDelegationPrivateKeyFileName

    if ((Test-Path -Path $PublicKeyFile) -Or (Test-Path -Path $PrivateKeyFile)) {
        if (-Not $Force) {
            throw "$PublicKeyFile or $PrivateKeyFile already exists, use -Force to overwrite"
        }

        Remove-Item $PublicKeyFile -Force | Out-Null
        Remove-Item $PrivateKeyFile -Force | Out-Null
    }

    $KeyPair = New-RsaKeyPair -KeySize:$KeySize

    $PublicKeyData = $KeyPair.PublicKey
    $Config.DelegationPublicKeyFile = $DGatewayDelegationPublicKeyFileName
    Set-Content -Path $PublicKeyFile -Value $PublicKeyData -Force

    $PrivateKeyData = $KeyPair.PrivateKey
    $Config.DelegationPrivateKeyFile = $DGatewayDelegationPrivateKeyFileName
    Set-Content -Path $PrivateKeyFile -Value $PrivateKeyData -Force

    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function Import-DGatewayDelegationKey {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $PublicKeyFile,
        [string] $PrivateKeyFile
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties

    if ($PublicKeyFile) {
        $PublicKeyData = Get-Content -Path $PublicKeyFile -Encoding UTF8
        $OutputFile = Join-Path $ConfigPath $DGatewayDelegationPublicKeyFileName
        $Config.DelegationPublicKeyFile = $DGatewayDelegationPublicKeyFileName
        New-Item -Path $ConfigPath -ItemType 'Directory' -Force | Out-Null
        Set-Content -Path $OutputFile -Value $PublicKeyData -Force
    }

    if ($PrivateKeyFile) {
        $PrivateKeyData = Get-Content -Path $PrivateKeyFile -Encoding UTF8
        $OutputFile = Join-Path $ConfigPath $DGatewayDelegationPrivateKeyFileName
        $Config.DelegationPrivateKeyFile = $DGatewayDelegationPrivateKeyFileName
        New-Item -Path $ConfigPath -ItemType 'Directory' -Force | Out-Null
        Set-Content -Path $OutputFile -Value $PrivateKeyData -Force
    }

    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function New-DGatewayToken {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,

        [ValidateSet('ASSOCIATION', 'SCOPE', 'BRIDGE', 'JMUX', 'JREC')]
        [Parameter(Mandatory = $true)]
        [string] $Type, # token type

        # public common claims
        [DateTime] $ExpirationTime, # exp
        [DateTime] $NotBefore, # nbf
        [DateTime] $IssuedAt, # iat

        # private association claims
        [string] $AssociationId, # jet_aid
        [ValidateSet('unknown', 'wayk', 'rdp', 'ard', 'vnc', 'ssh', 'ssh-pwsh', 'sftp', 'scp',
            'winrm-http-pwsh', 'winrm-https-pwsh', 'http', 'https', 'ldap', 'ldaps')]
        [string] $ApplicationProtocol, # jet_ap
        [ValidateSet('fwd', 'rdv')]
        [string] $ConnectionMode, # jet_cm
        [string] $DestinationHost, # dst_hst

        # private jrec claims
        [ValidateSet('push', 'pull')]
        [string] $RecordingOperation = 'push', # jet_rop

        # private scope claims
        [string] $Scope, # scope

        # private bridge claims
        [string] $Target, # target

        # signature parameters
        [string] $PrivateKeyFile
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties

    if (-Not $PrivateKeyFile) {
        if (-Not $Config.ProvisionerPrivateKeyFile) {
            throw "Config file is missing ``ProvisionerPrivateKeyFile``. Alternatively, use -PrivateKeyFile argument."
        }

        if ([System.IO.Path]::IsPathRooted($Config.ProvisionerPrivateKeyFile)) {
            $PrivateKeyFile = $Config.ProvisionerPrivateKeyFile
        } else {
            $PrivateKeyFile = Join-Path $ConfigPath $Config.ProvisionerPrivateKeyFile
        }
    }

    if (-Not (Test-Path -Path $PrivateKeyFile -PathType 'Leaf')) {
        throw "$PrivateKeyFile cannot be found."
    }

    $PrivateKey = ConvertTo-RsaPrivateKey $(Get-Content $PrivateKeyFile -Raw)

    $CurrentTime = Get-Date

    if (-Not $NotBefore) {
        $NotBefore = $CurrentTime
    }

    if (-Not $IssuedAt) {
        $IssuedAt = $CurrentTime
    }

    if (-Not $ExpirationTime) {
        $ExpirationTime = $CurrentTime.AddMinutes(2)
    }

    $iat = [System.DateTimeOffset]::new($IssuedAt).ToUnixTimeSeconds()
    $nbf = [System.DateTimeOffset]::new($NotBefore).ToUnixTimeSeconds()
    $exp = [System.DateTimeOffset]::new($ExpirationTime).ToUnixTimeSeconds()
    $jti = (New-Guid).ToString()

    $Header = [PSCustomObject]@{
        alg = 'RS256'
        typ = 'JWT'
        cty = $Type
    }

    $Payload = [PSCustomObject]@{
        iat    = $iat
        nbf    = $nbf
        exp    = $exp
        jti    = $jti
    }

    if ($Type -eq 'ASSOCIATION') {
        if (-Not $ApplicationProtocol) {
            if ($ConnectionMode -eq 'fwd') {
                $ApplicationProtocol = 'rdp'
            } else {
                $ApplicationProtocol = 'wayk'
            }
        }

        $Payload | Add-Member -MemberType NoteProperty -Name 'jet_ap' -Value $ApplicationProtocol
        
        if (-Not $ConnectionMode) {
            if ($DestinationHost) {
                $ConnectionMode = 'fwd'
            } else {
                $ConnectionMode = 'rdv'
            }
        }
            
        $Payload | Add-Member -MemberType NoteProperty -Name 'jet_cm' -Value $ConnectionMode

        if (-Not $AssociationId) {
            $AssociationId = New-Guid
        }

        $Payload | Add-Member -MemberType NoteProperty -Name 'jet_aid' -Value $AssociationId

        if ($DestinationHost) {
            $Payload | Add-Member -MemberType NoteProperty -Name 'dst_hst' -Value $DestinationHost
        }
    }

    if ($Type -eq 'JMUX') {
        if (-Not $DestinationHost) {
            throw "DestinationHost is required"
        }

        if ($ApplicationProtocol) {
            $Payload | Add-Member -MemberType NoteProperty -Name 'jet_ap' -Value $ApplicationProtocol
        }
        
        if (-Not $AssociationId) {
            $AssociationId = New-Guid
        }

        $Payload | Add-Member -MemberType NoteProperty -Name 'jet_aid' -Value $AssociationId

        $Payload | Add-Member -MemberType NoteProperty -Name 'dst_hst' -Value $DestinationHost
    }

    if ($Type -eq 'JREC') {
        if (-Not $RecordingOperation) {
            throw "RecordingOperation is required"
        }

        if ($ApplicationProtocol) {
            $Payload | Add-Member -MemberType NoteProperty -Name 'jet_ap' -Value $ApplicationProtocol
        }

        $Payload | Add-Member -MemberType NoteProperty -Name 'jet_rop' -Value $RecordingOperation.ToLower()
        
        if (-Not $AssociationId) {
            $AssociationId = New-Guid
        }

        $Payload | Add-Member -MemberType NoteProperty -Name 'jet_aid' -Value $AssociationId

        if ($DestinationHost) {
            $Payload | Add-Member -MemberType NoteProperty -Name 'dst_hst' -Value $DestinationHost
        }
    }

    if (($Type -eq 'SCOPE') -and ($Scope)) {
        $Payload | Add-Member -MemberType NoteProperty -Name 'scope' -Value $Scope
    }

    if (($Type -eq 'BRIDGE') -and ($Target)) {
        $Payload | Add-Member -MemberType NoteProperty -Name 'target' -Value $Target
    }

    New-JwtRs256 -Header $Header -Payload $Payload -PrivateKey $PrivateKey
}

function ConvertTo-DGatewayHash
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $Password
    )

    $parameters = [Devolutions.Picky.Argon2Params]::New.Invoke(@())
    $algorithm = [Devolutions.Picky.Argon2Algorithm]::Argon2id
    $argon2 = [Devolutions.Picky.Argon2]::New.Invoke(@($algorithm, $parameters))
    $argon2.HashPassword($Password)
}

function Get-DGatewayUsersFilePath
{
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    
    if ($Config.WebApp.UsersFile) {
        $fileName = $Config.WebApp.UsersFile
    } else {
        $fileName = $script:DGatewayCustomUsersFileName
    }

    $filePath = Join-Path -Path $ConfigPath -ChildPath $fileName
    return $filePath
}

function Set-DGatewayUser {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Mandatory=$true, Position=0)]
        [string] $Username,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $Password
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath

    $filePath = Get-DGatewayUsersFilePath -ConfigPath $ConfigPath
    $hash = ConvertTo-DGatewayHash -Password $Password

    $fileContent = @()
    if (Test-Path $filePath) {
        try {
            $fileContent = [System.IO.File]::ReadLines($filePath)
        }
        catch {
            Write-Host "Error reading file: $_"
            return
        }
    }

    $entry = "$Username`:$hash"
    $updated = $false

    $fileContentList = New-Object System.Collections.Generic.List[System.String]
    foreach ($line in $fileContent) {
        $fileContentList.Add($line)
    }

    for ($i = 0; $i -lt $fileContentList.Count; $i++) {
        if ((-Not [string]::IsNullOrEmpty($fileContentList[$i])) -And
            $fileContentList[$i].StartsWith("${Username}:")) {
            $fileContentList[$i] = $entry
            $updated = $true
            break
        }
    }

    if (-Not $updated) {
        $fileContentList.Add($entry)
    }

    [System.IO.File]::WriteAllLines($filePath, $fileContentList)
}

function Remove-DGatewayUser {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Mandatory=$true, Position=0)]
        [string] $Username
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath

    $filePath = Get-DGatewayUsersFilePath -ConfigPath $ConfigPath
    $fileContent = Get-Content $filePath

    $newContent = $fileContent | Where-Object { $_ -notmatch "^${Username}:" }
    Set-Content -Path $filePath -Value $newContent
}

function Get-DGatewayUser {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $Username
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath

    $filePath = Get-DGatewayUsersFilePath -ConfigPath $ConfigPath
    $fileContent = Get-Content $filePath
    $users = @()

    foreach ($line in $fileContent) {
        # Splitting at the first ':' character
        $splitIndex = $line.IndexOf(':')
        if ($splitIndex -lt 0) { continue }

        $user = $line.Substring(0, $splitIndex)
        $hash = $line.Substring($splitIndex + 1)

        $users += New-Object PSObject -Property @{
            User = $user
            Hash = $hash
        }
    }

    if ($Username) {
        $user = $users | Where-Object { $_.User -eq $Username }
        return $user
    } else {
        return $users
    }
}

function Get-DGatewayPackage {
    [CmdletBinding()]
    param(
        [string] $RequiredVersion,
        [ValidateSet('Windows', 'Linux')]
        [string] $Platform
    )

    $Version = Get-DGatewayVersion 'PSModule'

    if ($RequiredVersion) {
        $Version = $RequiredVersion
    }

    if (-Not $Platform) {
        if ($IsWindows) {
            $Platform = 'Windows'
        } else {
            $Platform = 'Linux'
        }
    }

    $GitHubDownloadUrl = 'https://github.com/Devolutions/devolutions-gateway/releases/download/'

    if ($Platform -eq 'Windows') {
        $Architecture = 'x86_64'
        $PackageFileName = "DevolutionsGateway-${Architecture}-${Version}.msi"
    } elseif ($Platform -eq 'Linux') {
        $Architecture = 'amd64'
        $PackageFileName = "devolutions-gateway_${Version}.0_${Architecture}.deb"
    }

    $DownloadUrl = "${GitHubDownloadUrl}v${Version}/$PackageFileName"

    [PSCustomObject]@{
        Url     = $DownloadUrl;
        Version = $Version;
    }
}

function Install-DGatewayPackage {
    [CmdletBinding()]
    param(
        [string] $RequiredVersion,
        [switch] $Quiet,
        [switch] $Force
    )

    $Version = Get-DGatewayVersion 'PSModule'

    if ($RequiredVersion) {
        $Version = $RequiredVersion
    }

    $InstalledVersion = Get-DGatewayVersion 'Installed'

    if (($InstalledVersion -eq $Version) -and (-Not $Force)) {
        Write-Host "Devolutions Gateway is already installed ($Version)"
        return
    }

    $TempPath = Join-Path $([System.IO.Path]::GetTempPath()) "dgateway-${Version}"
    New-Item -ItemType Directory -Path $TempPath -ErrorAction SilentlyContinue | Out-Null

    $Package = Get-DGatewayPackage -RequiredVersion $Version
    $DownloadUrl = $Package.Url

    $DownloadFile = Split-Path -Path $DownloadUrl -Leaf
    $DownloadFilePath = Join-Path $TempPath $DownloadFile
    Write-Host "Downloading $DownloadUrl"

    $WebClient = [System.Net.WebClient]::new()
    $WebClient.DownloadFile($DownloadUrl, $DownloadFilePath)
    $WebClient.Dispose()

    $DownloadFilePath = Resolve-Path $DownloadFilePath

    if ($IsWindows) {
        $Display = '/passive'
        if ($Quiet) {
            $Display = '/quiet'
        }
        $InstallLogFile = Join-Path $TempPath 'DGateway_Install.log'
        $MsiArgs = @(
            '/i', "`"$DownloadFilePath`"",
            $Display,
            '/norestart',
            '/log', "`"$InstallLogFile`""
        )

        Start-Process 'msiexec.exe' -ArgumentList $MsiArgs -Wait -NoNewWindow

        Remove-Item -Path $InstallLogFile -Force -ErrorAction SilentlyContinue
    } elseif ($IsMacOS) {
        throw  'unsupported platform'
    } elseif ($IsLinux) {
        $DpkgArgs = @(
            '-i', $DownloadFilePath
        )
        if ((id -u) -eq 0) {
            Start-Process 'dpkg' -ArgumentList $DpkgArgs -Wait
        } else {
            $DpkgArgs = @('dpkg') + $DpkgArgs
            Start-Process 'sudo' -ArgumentList $DpkgArgs -Wait
        }
    }

    Remove-Item -Path $TempPath -Force -Recurse
}

function Uninstall-DGatewayPackage {
    [CmdletBinding()]
    param(
        [switch] $Quiet
    )

    if ($IsWindows) {
        $UninstallReg = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' `
        | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_ -Match 'Devolutions Gateway' }
        if ($UninstallReg) {
            $UninstallString = $($UninstallReg.UninstallString `
                    -Replace 'msiexec.exe', '' -Replace '/I', '' -Replace '/X', '').Trim()
            $Display = '/passive'
            if ($Quiet) {
                $Display = '/quiet'
            }
            $MsiArgs = @(
                '/X', $UninstallString, $Display
            )
            Start-Process 'msiexec.exe' -ArgumentList $MsiArgs -Wait
        }
    } elseif ($IsMacOS) {
        throw  'unsupported platform'
    } elseif ($IsLinux) {
        if (Get-DGatewayVersion 'Installed') {
            $AptArgs = @(
                '-y', 'remove', 'devolutions-gateway', '--purge'
            )
            if ((id -u) -eq 0) {
                Start-Process 'apt-get' -ArgumentList $AptArgs -Wait
            } else {
                $AptArgs = @('apt-get') + $AptArgs
                Start-Process 'sudo' -ArgumentList $AptArgs -Wait
            }
        }
    }
}

function Start-DGateway {
    [CmdletBinding()]

    param(
        [string]$ServiceName
    )

    if (-Not [String]::IsNullOrWhiteSpace($ServiceName)) {
        $DGatewayService = $ServiceName
    } elseif ($IsWindows) {
        $DGatewayService = 'devolutionsgateway'
    } elseif ($IsLinux) {
        $DGatewayService = 'devolutions-gateway.service'  
    } else {
        throw 'Service name is empty'
    }

    if ($IsWindows) {
        Start-Service -Name $DGatewayService
    } elseif ($IsLinux) {
        & systemctl start $DGatewayService
    } else {
        throw 'Not implemented'
    }
}

function Stop-DGateway {
    [CmdletBinding()]

    param(
        [string]$ServiceName
    )

    if (-Not [String]::IsNullOrWhiteSpace($serviceName)) {
        $DGatewayService = $ServiceName
    } elseif ($IsWindows) {
        $DGatewayService = 'devolutionsgateway'
    } elseif ($IsLinux) {
        $DGatewayService = 'devolutions-gateway.service'  
    } else {
        throw 'Service name is empty'
    }

    if ($IsWindows) {
        Stop-Service -Name $DGatewayService
    } elseif ($IsLinux) {
        & systemctl stop $DGatewayService
    } else {
        throw 'Not implemented'
    }
}

function Restart-DGateway {
    [CmdletBinding()]

    param(
        [string]$ServiceName
    )

    if (-Not [String]::IsNullOrWhiteSpace($ServiceName)) {
        $DGatewayService = $ServiceName
    } elseif ($IsWindows) {
        $DGatewayService = 'devolutionsgateway'
    } elseif ($IsLinux) {
        $DGatewayService = 'devolutions-gateway.service'  
    } else {
        throw 'Service name is empty'
    }

    if ($IsWindows) {
        Restart-Service -Name $DGatewayService
    } elseif ($IsLinux) {
        & systemctl restart $DGatewayService
    } else {
        throw 'Not implemented'
    }    
}

function Get-DGatewayService {
    [CmdletBinding()]

    param(
        [string]$ServiceName
    )

    if (-Not [String]::IsNullOrWhiteSpace($ServiceName)) {
        $DGatewayService = $ServiceName
    } elseif ($IsWindows) {
        $DGatewayService = 'devolutionsgateway'
    } elseif ($IsLinux) {
        $DGatewayService = 'devolutions-gateway.service'  
    } else {
        throw 'Service name is empty'
    }

    if ($IsWindows) {
        $Result = Get-Service -Name $DGatewayService

        If ($Result) {
            [PSCustomObject]@{
                "Name"   = $Result.Name
                "Status" = $Result.Status
            }
        } else {
            throw 'Service not found'
        }
    } elseif ($IsLinux) {
        $Result = & systemctl list-units --type=service --all --no-pager $DGatewayService --no-legend

        if ($Result) {
            $ID, $Load, $Active, $Status, $Description = ($Result.Trim()) -Split '\s+', 5

            If ($ID -And $Active) {
                [PSCustomObject]@{
                    "Name"   = $ID
                    "Status" = if ($Active -EQ 'active') { 'Running' } else { 'Stopped' }
                }
            } else {
                throw 'Unable to return service status'
            }
        } else {
            throw 'Service not found'
        }
    } else {
        throw 'Not implemented'
    }
}