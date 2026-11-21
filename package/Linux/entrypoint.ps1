Import-Module DevolutionsGateway -ErrorAction Stop

$Hostname = 'localhost'
$WebPort = 7171
$WebScheme = 'http'
$TcpPort = 8181
$TcpEnabled = $true
$WebAppEnabled = $false
$WebAppAuthentication = 'None'

if ($Env:WEB_SCHEME) {
    $WebScheme = $Env:WEB_SCHEME
}

$ExternalWebScheme = $WebScheme

if ($Env:EXTERNAL_WEB_SCHEME) {
    $ExternalWebScheme = $Env:EXTERNAL_WEB_SCHEME
}

if (Test-Path Env:WEB_PORT) {
    $WebPort = $Env:WEB_PORT
}
if (Test-Path Env:PORT) {
    $WebPort = $Env:PORT
}

$ExternalWebPort = $WebPort

if (Test-Path Env:EXTERNAL_WEB_PORT) {
    $ExternalWebPort = $Env:EXTERNAL_WEB_PORT
}

if (Test-Path Env:HOSTNAME) {
    $Hostname = $Env:HOSTNAME
}
if (Test-Path Env:WEBSITE_HOSTNAME) {
    $Hostname = $Env:WEBSITE_HOSTNAME

    if (Test-Path Env:WEBSITE_INSTANCE_ID) {
        # Azure Web App always uses HTTPS on port 443 externally
        $ExternalWebScheme = 'https'
        $ExternalWebPort = 443
    }
}

if ($Env:WEB_APP_ENABLED) {
    try {
        $WebAppEnabled = [bool]::Parse($Env:WEB_APP_ENABLED)
    } catch {
        $WebAppEnabled = $false
    }
}

if ($WebAppEnabled) {
    # standalone web app doesn't really handle TCP
    $TcpEnabled = $false
}

if ($Env:TCP_ENABLED) {
    try {
        $TcpEnabled = [bool]::Parse($Env:TCP_ENABLED)
    } catch {
        $TcpEnabled = $false
    }
}

if (Test-Path Env:TCP_PORT) {
    $TcpPort = $Env:TCP_PORT
}

$ExternalTcpPort = $TcpPort

if (Test-Path Env:EXTERNAL_TCP_PORT) {
    $ExternalTcpPort = $Env:EXTERNAL_TCP_PORT
}

$TcpHostname = '*'
if (Test-Path Env:TCP_HOSTNAME) {
    $TcpHostname = $Env:TCP_HOSTNAME
}

if ($Env:WEB_APP_USERNAME -and $Env:WEB_APP_PASSWORD) {
    $WebAppAuthentication = 'Custom'
}

if ($Env:WEB_APP_AUTHENTICATION) {
    $WebAppAuthentication = $Env:WEB_APP_AUTHENTICATION
}

$WebListener = New-DGatewayListener "$WebScheme`://*:$WebPort" "$ExternalWebScheme`://*:$ExternalWebPort"
$TcpListener = New-DGatewayListener "tcp://*:$TcpPort" "tcp://$TcpHostname`:$ExternalTcpPort"

if ($TcpEnabled) {
    $Listeners = @($WebListener, $TcpListener)
} else {
    $Listeners = @($WebListener)
}

$WebApp = New-DGatewayWebAppConfig -Enabled $WebAppEnabled -Authentication $WebAppAuthentication

$ConfigParams = @{
    Hostname  = $Hostname
    Listeners = $Listeners
    WebApp    = $WebApp
}
Set-DGatewayConfig @ConfigParams

if ($WebAppAuthentication -eq 'Custom') {
    if ($Env:WEB_APP_USERNAME -and $Env:WEB_APP_PASSWORD) {
        Set-DGatewayUser -Username $Env:WEB_APP_USERNAME -Password $Env:WEB_APP_PASSWORD
    }
}

if (Test-Path Env:RECORDING_PATH) {
    $RecordingPath = $Env:RECORDING_PATH
    Set-DGatewayRecordingPath -RecordingPath $RecordingPath
}

if (Test-Path Env:VERBOSITY_PROFILE) {
    $VerbosityProfile = $Env:VERBOSITY_PROFILE
    Set-DGatewayConfig -VerbosityProfile $VerbosityProfile
}

$ProvisionerPublicKeyFile = $null
if ($Env:PROVISIONER_PUBLIC_KEY_B64) {
    try {
        $ProvisionerPublicKeyFile = "/tmp/provisioner.pem"
        [IO.File]::WriteAllBytes($ProvisionerPublicKeyFile, [Convert]::FromBase64String($Env:PROVISIONER_PUBLIC_KEY_B64))
    } catch {
        throw "Failed to decode PROVISIONER_PUBLIC_KEY_B64: $_"
    }
}

$ProvisionerPrivateKeyFile = $null
if ($Env:PROVISIONER_PRIVATE_KEY_B64) {
    try {
        $ProvisionerPrivateKeyFile = "/tmp/provisioner.key"
        [IO.File]::WriteAllBytes($ProvisionerPrivateKeyFile, [Convert]::FromBase64String($Env:PROVISIONER_PRIVATE_KEY_B64))
    } catch {
        throw "Failed to decode PROVISIONER_PRIVATE_KEY_B64: $_"
    }
}

if ($ProvisionerPublicKeyFile -or $ProvisionerPrivateKeyFile) {
    Write-Host "Importing provisioner keys..."
    Import-DGatewayProvisionerKey -PublicKeyFile $ProvisionerPublicKeyFile -PrivateKeyFile $ProvisionerPrivateKeyFile
    Remove-Item @($ProvisionerPublicKeyFile, $ProvisionerPrivateKeyFile) -ErrorAction SilentlyContinue | Out-Null
} else {
    Write-Host "Generating provisioner keys..."
    New-DGatewayProvisionerKeyPair -Force
}

$TlsCertificateFile = $null
if ($Env:TLS_CERTIFICATE_B64) {
    try {
        $TlsCertificateFile = "/tmp/tls-certificate.pem"
        [IO.File]::WriteAllBytes($TlsCertificateFile, [Convert]::FromBase64String($Env:TLS_CERTIFICATE_B64))
    } catch {
        throw "Failed to decode TLS_CERTIFICATE_B64: $_"
    }
}

$TlsPrivateKeyFile = $null
if ($Env:TLS_PRIVATE_KEY_B64) {
    try {
        $TlsPrivateKeyFile = "/tmp/tls-private-key.pem"
        [IO.File]::WriteAllBytes($TlsPrivateKeyFile, [Convert]::FromBase64String($Env:TLS_PRIVATE_KEY_B64))
    } catch {
        throw "Failed to decode TLS_PRIVATE_KEY_B64: $_"
    }
}

$TlsCertificatePassword = $null
if ($Env:TLS_CERTIFICATE_PASSWORD) {
    $TlsCertificatePassword = $Env:TLS_CERTIFICATE_PASSWORD
}

if ($TlsCertificateFile -or $TlsPrivateKeyFile) {
    Write-Host "Importing TLS certificate..."
    Import-DGatewayCertificate `
        -CertificateFile $TlsCertificateFile `
        -PrivateKeyFile $TlsPrivateKeyFile `
        -Password $TlsCertificatePassword
    Remove-Item @($TlsCertificateFile, $TlsPrivateKeyFile) -ErrorAction SilentlyContinue | Out-Null
}

$Config = Get-DGatewayConfig -NullProperties
if ($WebScheme -eq 'https' -and
    [string]::IsNullOrEmpty($Config.TlsCertificateFile) -and
    [string]::IsNullOrEmpty($Config.TlsPrivateKeyFile)) {
    Write-Host "Generating self-signed TLS certificate for '$Hostname'..."

    $TlsCertificateFile = "/tmp/gateway-$Hostname.pem"
    $TlsPrivateKeyFile = "/tmp/gateway-$Hostname.key"
    $Arguments = @(
        "req", "-x509", "-nodes",
        "-newkey", "rsa:2048",
        "-keyout", $TlsPrivateKeyFile,
        "-out", $TlsCertificateFile,
        "-subj", "/CN=$Hostname",
        "-addext", "subjectAltName=DNS:$Hostname",
        "-days", "1825"
    )

    $Output = & openssl @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed:`n$Output"
    }

    Import-DGatewayCertificate -CertificateFile $TlsCertificateFile -PrivateKeyFile $TlsPrivateKeyFile
    Remove-Item @($TlsCertificateFile, $TlsPrivateKeyFile) -ErrorAction SilentlyContinue | Out-Null
}

& "$Env:DGATEWAY_EXECUTABLE_PATH"
[System.Environment]::ExitCode = $LASTEXITCODE
