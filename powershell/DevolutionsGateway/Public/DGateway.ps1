
. "$PSScriptRoot/../Private/CertificateHelper.ps1"
. "$PSScriptRoot/../Private/PlatformHelper.ps1"
. "$PSScriptRoot/../Private/DockerHelper.ps1"
. "$PSScriptRoot/../Private/TokenHelper.ps1"

$script:DGatewayConfigFileName = 'gateway.json'
$script:DGatewayCertificateFileName = 'certificate.pem'
$script:DGatewayPrivateKeyFileName = 'certificate.key'
$script:DGatewayProvisionerPublicKeyFileName = 'provisioner.pem'
$script:DGatewayProvisionerPrivateKeyFileName = 'provisioner.key'
$script:DGatewayDelegationPublicKeyFileName = 'delegation.pem'
$script:DGatewayDelegationPrivateKeyFileName = 'delegation.key'

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

function Get-DGatewayImage {
    param(
        [string] $Platform
    )

    $DGatewayVersion = Get-DGatewayVersion 'PSModule'

    $image = if ($Platform -ne 'windows') {
        "devolutions/devolutions-gateway:${DGatewayVersion}-buster"
    } else {
        "devolutions/devolutions-gateway:${DGatewayVersion}-servercore-ltsc2019"
    }

    return $image
}

class DGatewayListener {
    [string] $InternalUrl
    [string] $ExternalUrl

    DGatewayListener() { }

    DGatewayListener([string] $InternalUrl, [string] $ExternalUrl) {
        $this.InternalUrl = $InternalUrl
        $this.ExternalUrl = $ExternalUrl
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

class DGatewayConfig {
    [string] $FarmName
    [string[]] $FarmMembers

    [string] $Hostname
    [DGatewayListener[]] $Listeners
    [string[]] $ApplicationProtocols

    [string] $CertificateFile
    [string] $PrivateKeyFile
    [string] $ProvisionerPublicKeyFile
    [string] $ProvisionerPrivateKeyFile
    [string] $DelegationPublicKeyFile
    [string] $DelegationPrivateKeyFile

    [string] $DockerPlatform
    [string] $DockerIsolation
    [string] $DockerRestartPolicy
    [string] $DockerImage
    [string] $DockerContainerName
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

    $Properties = $Config.PSObject.Properties.Name
    $NonNullProperties = $Properties.Where( { -Not [string]::IsNullOrEmpty($Config.$_) })
    $ConfigData = $Config | Select-Object $NonNullProperties | ConvertTo-Json

    [System.IO.File]::WriteAllLines($ConfigFile, $ConfigData, $(New-Object System.Text.UTF8Encoding $False))
}

function Set-DGatewayConfig {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [string] $FarmName,
        [string[]] $FarmMembers,
        [string] $Hostname,
        [DGatewayListener[]] $Listeners,
        [string[]] $ApplicationProtocols,

        [string] $CertificateFile,
        [string] $PrivateKeyFile,
        [string] $ProvisionerPublicKeyFile,
        [string] $ProvisionerPrivateKeyFile,
        [string] $DelegationPublicKeyFile,
        [string] $DelegationPrivateKeyFile,

        [ValidateSet('linux', 'windows')]
        [string] $DockerPlatform,
        [ValidateSet('process', 'hyperv')]
        [string] $DockerIsolation,
        [ValidateSet('no', 'on-failure', 'always', 'unless-stopped')]
        [string] $DockerRestartPolicy,
        [string] $DockerImage,
        [string] $DockerContainerName,
        [string] $Force
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath

    if (-Not (Test-Path -Path $ConfigPath -PathType 'Container')) {
        New-Item -Path $ConfigPath -ItemType 'Directory'
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

    if (-Not $config.DockerPlatform) {
        if ($IsWindows) {
            $config.DockerPlatform = 'windows'
        } else {
            $config.DockerPlatform = 'linux'
        }
    }

    if (-Not $config.DockerRestartPolicy) {
        $config.DockerRestartPolicy = 'always'
    }

    if (-Not $config.DockerImage) {
        $config.DockerImage = Get-DGatewayImage -Platform $config.DockerPlatform
    }

    if (-Not $config.DockerContainerName) {
        $config.DockerContainerName = 'devolutions-gateway'
    }
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

function Get-DGatewayFarmName {
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    $(Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties).FarmName
}

function Set-DGatewayFarmName {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $FarmName
    )

    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    $Config.FarmName = $FarmName
    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
}

function Get-DGatewayFarmMembers {
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    $(Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties).FarmMembers
}

function Set-DGatewayFarmMembers {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyCollection()]
        [string[]] $FarmMembers
    )

    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    $Config.FarmMembers = $FarmMembers
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

function Get-DGatewayApplicationProtocols {
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    $(Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties).ApplicationProtocols
}

function Set-DGatewayApplicationProtocols {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyCollection()]
        [ValidateSet('none', 'rdp', 'wayk', 'pwsh')]
        [string[]] $ApplicationProtocols
    )

    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    $Config.ApplicationProtocols = $ApplicationProtocols
    Save-DGatewayConfig -ConfigPath:$ConfigPath -Config:$Config
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

    $Config.CertificateFile = $DGatewayCertificateFileName
    $Config.PrivateKeyFile = $DGatewayPrivateKeyFileName

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
        $PublicKeyData = Get-Content -Path $PublicKeyFile -Encoding UTF8
        $OutputFile = Join-Path $ConfigPath $DGatewayProvisionerPublicKeyFileName
        $Config.ProvisionerPublicKeyFile = $DGatewayProvisionerPublicKeyFileName
        New-Item -Path $ConfigPath -ItemType 'Directory' -Force | Out-Null
        Set-Content -Path $OutputFile -Value $PublicKeyData -Force
    }

    if ($PrivateKeyFile) {
        $PrivateKeyData = Get-Content -Path $PrivateKeyFile -Encoding UTF8
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

        [ValidateSet('association', 'scope')]
        [Parameter(Mandatory = $true)]
        [string] $Type, #type

        # public common claims
        [DateTime] $ExpirationTime, # exp
        [DateTime] $NotBefore, # nbf
        [DateTime] $IssuedAt, # iat

        # private association claims
        [string] $DestinationHost, # dst_hst
        [ValidateSet('none', 'rdp', 'wayk', 'pwsh')]
        [string] $ApplicationProtocol, # jet_ap
        [ValidateSet('fwd', 'rdv')]
        [string] $ConnectionMode, # jet_cm
        
        #private scope claims
        [string] $Scope, # scope

        # signature parameters
        [string] $PrivateKeyFile
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $Config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties

    if (-Not $PrivateKeyFile) {
        $PrivateKeyFile = Join-Path $ConfigPath $Config.ProvisionerPrivateKeyFile
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
    
    $Header = [PSCustomObject]@{
        alg = 'RS256'
        typ = 'JWT'
    }
    
    $Payload = [PSCustomObject]@{
        iat    = $iat
        nbf    = $nbf
        exp    = $exp
        type   = $Type
    }

    if ($Type -eq 'association') {
        if (-Not $ApplicationProtocol) {
            if ($ConnectionMode -eq 'fwd') {
                $ApplicationProtocol = 'rdp'
            } else {
                $ApplicationProtocol = 'wayk'
            }
        }

        if (-Not $ConnectionMode) {
            if ($DestinationHost) {
                $ConnectionMode = 'fwd'
            } else {
                $ConnectionMode = 'rdv'
            }
        }
            
        $Payload | Add-Member -MemberType NoteProperty -Name 'jet_ap' -Value $ApplicationProtocol
        $Payload | Add-Member -MemberType NoteProperty -Name 'jet_cm' -Value $ConnectionMode

        if ($DestinationHost) {
            $Payload | Add-Member -MemberType NoteProperty -Name 'dst_hst' -Value $DestinationHost
        }    
    }


    if (($Type -eq 'scope') -and ($Scope)) {
        $Payload | Add-Member -MemberType NoteProperty -Name 'scope' -Value $Scope
    }

    New-JwtRs256 -Header $Header -Payload $Payload -PrivateKey $PrivateKey
}

function Get-DGatewayService {
    param(
        [string] $ConfigPath,
        [DGatewayConfig] $Config
    )

    if ($config.DockerPlatform -eq 'linux') {
        $ContainerConfigPath = '/etc/devolutions-gateway'
    } else {
        $ContainerConfigPath = 'C:\ProgramData\Devolutions\Gateway'
    }

    $Service = [DockerService]::new()
    $Service.ContainerName = $config.DockerContainerName
    $Service.Image = $config.DockerImage
    $Service.Platform = $config.DockerPlatform
    $Service.Isolation = $config.DockerIsolation
    $Service.RestartPolicy = $config.DockerRestartPolicy
    $Service.TargetPorts = @()

    foreach ($Listener in $config.Listeners) {
        $InternalUrl = $Listener.InternalUrl -Replace '://\*', '://localhost'
        $url = [System.Uri]::new($InternalUrl)
        $Service.TargetPorts += @($url.Port)
    }
    $Service.TargetPorts = $Service.TargetPorts | Select-Object -Unique

    $Service.PublishAll = $true
    $Service.Environment = [ordered]@{
        'DGATEWAY_CONFIG_PATH' = $ContainerConfigPath;
        'RUST_BACKTRACE'       = '1';
        'RUST_LOG'             = 'info';
    }
    $Service.Volumes = @("${ConfigPath}:${ContainerConfigPath}")
    $Service.External = $false

    return $Service
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

function Update-DGatewayImage {
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    Expand-DGatewayConfig -Config $config

    $Service = Get-DGatewayService -ConfigPath:$ConfigPath -Config:$config
    Request-ContainerImage -Name $Service.Image
}

function Get-DGatewayLaunchType {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidateSet('Detect', 'Container', 'Service')]
        [string] $LaunchType = 'Detect'
    )

    if ($LaunchType -eq 'Detect') {
        if (Get-DGatewayVersion 'Installed') {
            $LaunchType = 'Service'
        } elseif ($(Get-Command 'docker' -ErrorAction SilentlyContinue)) {
            $LaunchType = 'Container'
        } else {
            $LaunchType = $null
        }
    }

    $LaunchType
}

function Start-DGateway {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Position = 0)]
        [ValidateSet('Detect', 'Container', 'Service')]
        [string] $LaunchType = 'Detect'
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    Expand-DGatewayConfig -Config:$config

    $LaunchType = Get-DGatewayLaunchType $LaunchType

    if (-Not $LaunchType) {
        throw 'No suitable Devolutions Gateway launch type detected'
    }

    if ($LaunchType -eq 'Container') {
        $Service = Get-DGatewayService -ConfigPath:$ConfigPath -Config:$config

        # pull docker images only if they are not cached locally
        if (-Not (Get-ContainerImageId -Name $Service.Image)) {
            Request-ContainerImage -Name $Service.Image
        }
    
        Start-DockerService -Service $Service -Remove
    } elseif ($LaunchType -eq 'Service') {
        if ($IsWindows) {
            Start-Service 'DevolutionsGateway'
        } else {
            throw 'not implemented'
        }
    }
}

function Stop-DGateway {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Position = 0)]
        [ValidateSet('Detect', 'Container', 'Service')]
        [string] $LaunchType = 'Detect',
        [switch] $Remove
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    $config = Get-DGatewayConfig -ConfigPath:$ConfigPath -NullProperties
    Expand-DGatewayConfig -Config $config

    $LaunchType = Get-DGatewayLaunchType $LaunchType

    if (-Not $LaunchType) {
        throw 'No suitable Devolutions Gateway launch type detected'
    }

    if ($LaunchType -eq 'Container') {
        $Service = Get-DGatewayService -ConfigPath:$ConfigPath -Config:$config

        Write-Host "Stopping $($Service.ContainerName)"
        Stop-Container -Name $Service.ContainerName -Quiet
    
        if ($Remove) {
            Remove-Container -Name $Service.ContainerName
        }
    } elseif ($LaunchType -eq 'Service') {
        if ($IsWindows) {
            Stop-Service 'DevolutionsGateway'
        } else {
            throw 'not implemented'
        }
    }
}

function Restart-DGateway {
    [CmdletBinding()]
    param(
        [string] $ConfigPath,
        [Parameter(Position = 0)]
        [ValidateSet('Detect', 'Container', 'Service')]
        [string] $LaunchType = 'Detect'
    )

    $ConfigPath = Find-DGatewayConfig -ConfigPath:$ConfigPath
    Stop-DGateway -ConfigPath:$ConfigPath -LaunchType:$LaunchType
    Start-DGateway -ConfigPath:$ConfigPath -LaunchType:$LaunchType
}
