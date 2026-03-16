param(
    [switch]$Clean,
    [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$Root = "D:\devolutions-gateway"
$TestDir = "D:\devolutions-gateway\test-output"
$GatewayConfigDir = "D:\devolutions-gateway\test-output\gateway-config"
$GatewayConfig = "D:\devolutions-gateway\test-output\gateway-config\gateway.json"
$AgentConfig = "D:\devolutions-gateway\test-output\agent-config.toml"
$GatewayWireGuardPrivateKeyFile = "D:\devolutions-gateway\test-output\gateway-wireguard-private-key.txt"
$ProvisionerPrivateKeyFile = "D:\devolutions-gateway\test-output\provisioner-private.pem"
$ProvisionerPublicKeyFile = "D:\devolutions-gateway\test-output\provisioner-public.pem"
$GatewayStdOut = "D:\devolutions-gateway\test-output\gateway.stdout.log"
$GatewayStdErr = "D:\devolutions-gateway\test-output\gateway.stderr.log"
$GatewayPidFile = "D:\devolutions-gateway\test-output\gateway.pid"
$DockerImage = "devolutions-gateway-agent-test"
$DockerContainer = "wireguard-agent-test"
$EnrollContainer = "wireguard-agent-enroll"
$GatewayExe = "D:\devolutions-gateway\target\debug\devolutions-gateway.exe"
$PythonClient = "D:\devolutions-gateway\test-websocket-relay.py"
$SessionId = "11111111-1111-1111-1111-111111111111"

function Stop-TestEnvironment {
    Get-Process -Name "devolutions-gateway" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $GatewayPidFile) {
        $gatewayPid = Get-Content -LiteralPath $GatewayPidFile -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($gatewayPid) {
            Stop-Process -Id ([int]$gatewayPid) -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $GatewayPidFile -Force -ErrorAction SilentlyContinue
    }

    foreach ($container in @($DockerContainer, $EnrollContainer)) {
        $containerId = docker ps -aq -f "name=$container" | Out-String
        $containerId = $containerId.Trim()
        if ($containerId) {
            docker rm -f $container | Out-Null
        }
    }
}

function Assert-LastExitCode {
    param([string]$Action)

    if ($LASTEXITCODE -ne 0) {
        throw "$Action failed with exit code $LASTEXITCODE."
    }
}

function Wait-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        try {
            $client = [System.Net.Sockets.TcpClient]::new()
            $task = $client.ConnectAsync($HostName, $Port)
            if ($task.Wait(500) -and $client.Connected) {
                $client.Dispose()
                return
            }
            $client.Dispose()
        } catch {
        }

        Start-Sleep -Milliseconds 500
    }

    throw "Timed out waiting for $HostName`:$Port"
}

function Get-WireGuardKeyPair {
    $output = cargo run -q -p devolutions-gateway-agent -- keygen 2>$null | Out-String

    if ($output -match "Private key \(keep secret!\):\s+([A-Za-z0-9+/=]+)\s+Public key \(share with gateway\):\s+([A-Za-z0-9+/=]+)") {
        return @{
            Private = $matches[1]
            Public = $matches[2]
        }
    }

    throw "Failed to parse WireGuard keygen output.`n$output"
}

function Show-DiagnosticsAndFail {
    param([string]$Message)

    Write-Host $Message -ForegroundColor Red

    if (Test-Path -LiteralPath $GatewayStdOut) {
        Write-Host "`n=== Gateway stdout ===" -ForegroundColor Yellow
        Get-Content -LiteralPath $GatewayStdOut
    }

    if (Test-Path -LiteralPath $GatewayStdErr) {
        Write-Host "`n=== Gateway stderr ===" -ForegroundColor Yellow
        Get-Content -LiteralPath $GatewayStdErr
    }

    Write-Host "`n=== Agent container logs ===" -ForegroundColor Yellow
    docker logs $DockerContainer

    throw $Message
}

function Invoke-JsonPost {
    param(
        [string]$Uri,
        [hashtable]$Body,
        [hashtable]$Headers = @{}
    )

    $json = $Body | ConvertTo-Json -Depth 8
    return Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -ContentType "application/json" -Body $json
}

function Invoke-TextPost {
    param(
        [string]$Uri,
        [hashtable]$Body,
        [hashtable]$Headers = @{}
    )

    $json = $Body | ConvertTo-Json -Depth 8
    return Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -ContentType "application/json" -Body $json
}

function Invoke-DockerEnroll {
    param(
        [string]$EnrollmentString,
        [string]$OutputConfigPath
    )

    if (Test-Path -LiteralPath $OutputConfigPath) {
        Remove-Item -LiteralPath $OutputConfigPath -Force
    }

    $createArgs = @(
        "create",
        "--name",
        $EnrollContainer,
        "--add-host",
        "host.docker.internal:host-gateway",
        "--entrypoint",
        "/usr/local/bin/devolutions-gateway-agent",
        $DockerImage,
        "enroll",
        "--enrollment-string",
        $EnrollmentString,
        "--config",
        "/tmp/agent-config.toml",
        "--advertise-subnet",
        "127.0.0.0/8",
        "--advertise-subnet",
        "172.0.0.0/8",
        "--advertise-subnet",
        "192.168.0.0/16"
    )

    & docker @createArgs | Out-Null
    Assert-LastExitCode "docker create enroll"

    docker start -a $EnrollContainer
    Assert-LastExitCode "docker start enroll"

    docker cp "${EnrollContainer}:/tmp/agent-config.toml" $OutputConfigPath | Out-Null
    Assert-LastExitCode "docker cp enrolled config"

    docker rm -f $EnrollContainer | Out-Null
    Assert-LastExitCode "docker rm enroll"

    if (-not (Test-Path -LiteralPath $OutputConfigPath)) {
        throw "Enrollment did not produce $OutputConfigPath."
    }
}

function Get-AgentIdFromConfig {
    param([string]$Path)

    $content = Get-Content -LiteralPath $Path -Raw
    if ($content -match 'agent_id\s*=\s*"([^"]+)"') {
        return $matches[1]
    }

    throw "Failed to parse agent_id from $Path"
}

function Wait-AgentOnline {
    param(
        [string]$AgentId,
        [string]$AppToken,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $agent = Invoke-RestMethod `
                -Method Get `
                -Uri "http://127.0.0.1:7171/jet/agents/$AgentId" `
                -Headers @{ Authorization = "Bearer $AppToken"; Accept = "application/json" }

            if ($agent.status -eq "online") {
                return
            }
        } catch {
        }

        Start-Sleep -Milliseconds 500
    }

    throw "Timed out waiting for agent $AgentId to become online."
}

if ($Clean) {
    Stop-TestEnvironment
    if (Test-Path -LiteralPath $TestDir) {
        Remove-Item -LiteralPath $TestDir -Recurse -Force
    }
    Write-Host "Cleaned WireGuard enrollment test environment." -ForegroundColor Green
    exit 0
}

Stop-TestEnvironment

New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
New-Item -ItemType Directory -Path $GatewayConfigDir -Force | Out-Null

Write-Host "=== WireGuard Dynamic Enrollment E2E Test ===" -ForegroundColor Cyan

Write-Host "`n[1/9] Building gateway binary..." -ForegroundColor Yellow
cargo build -q -p devolutions-gateway --bin devolutions-gateway
Assert-LastExitCode "cargo build gateway"

Write-Host "`n[2/9] Building Docker agent image..." -ForegroundColor Yellow
docker build -f "D:\devolutions-gateway\Dockerfile.agent-test" -t $DockerImage "D:\devolutions-gateway"
Assert-LastExitCode "docker build"

Write-Host "`n[3/9] Generating provisioner keypair..." -ForegroundColor Yellow
& openssl genrsa -out $ProvisionerPrivateKeyFile 2048 | Out-Null
Assert-LastExitCode "openssl genrsa"
& openssl rsa -in $ProvisionerPrivateKeyFile -pubout -out $ProvisionerPublicKeyFile | Out-Null
Assert-LastExitCode "openssl rsa -pubout"

Write-Host "`n[4/9] Generating Gateway WireGuard keypair..." -ForegroundColor Yellow
$gatewayKeyPair = Get-WireGuardKeyPair
$gatewayKeyPair.Private | Out-File -LiteralPath $GatewayWireGuardPrivateKeyFile -Encoding ascii -NoNewline

Write-Host "`n[5/9] Writing Gateway config without static peers..." -ForegroundColor Yellow
$gatewayConfigObject = [ordered]@{
    Hostname = "127.0.0.1"
    ProvisionerPublicKeyFile = $ProvisionerPublicKeyFile
    ProvisionerPrivateKeyFile = $ProvisionerPrivateKeyFile
    Listeners = @(
        [ordered]@{
            InternalUrl = "http://127.0.0.1:7171"
            ExternalUrl = "http://127.0.0.1:7171"
        }
    )
    WebApp = [ordered]@{
        Enabled = $true
        Authentication = "None"
    }
    WireGuard = [ordered]@{
        Enabled = $true
        Port = 51820
        PrivateKeyFile = $GatewayWireGuardPrivateKeyFile
        TunnelNetwork = "10.10.0.0/16"
        GatewayIp = "10.10.0.1"
    }
    VerbosityProfile = "All"
}
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText(
    $GatewayConfig,
    ($gatewayConfigObject | ConvertTo-Json -Depth 8),
    $utf8NoBom
)

Write-Host "`n[6/9] Starting Gateway..." -ForegroundColor Yellow
$gatewayProcess = Start-Process -FilePath $GatewayExe `
    -ArgumentList "--config-path", $GatewayConfigDir `
    -RedirectStandardOutput $GatewayStdOut `
    -RedirectStandardError $GatewayStdErr `
    -PassThru
$gatewayProcess.Id | Out-File -LiteralPath $GatewayPidFile -Encoding ascii -NoNewline

Wait-TcpPort -HostName "127.0.0.1" -Port 7171 -TimeoutSeconds 30

if ($gatewayProcess.HasExited) {
    Show-DiagnosticsAndFail "Gateway exited before becoming ready."
}

Write-Host "`n[7/9] Generating enrollment string from Gateway..." -ForegroundColor Yellow
$appToken = Invoke-TextPost `
    -Uri "http://127.0.0.1:7171/jet/webapp/app-token" `
    -Body @{
        content_type = "WEBAPP"
        subject = "automation"
        lifetime = 3600
    }

$enrollmentResponse = Invoke-JsonPost `
    -Uri "http://127.0.0.1:7171/jet/webapp/agent-enrollment-string" `
    -Headers @{ Authorization = "Bearer $appToken" } `
    -Body @{
        name = "docker-test-agent"
        apiBaseUrl = "http://host.docker.internal:7171"
        wireguardHost = "host.docker.internal"
        lifetime = 3600
    }

$enrollmentString = $enrollmentResponse.enrollmentString
if (-not $enrollmentString) {
    throw "Gateway did not return an enrollment string."
}

Write-Host "`n[8/9] Enrolling agent dynamically and starting Docker container..." -ForegroundColor Yellow
Invoke-DockerEnroll -EnrollmentString $enrollmentString -OutputConfigPath $AgentConfig
$agentId = Get-AgentIdFromConfig -Path $AgentConfig

docker run -d `
    --name $DockerContainer `
    --add-host host.docker.internal:host-gateway `
    -v "${AgentConfig}:/app/agent-config.toml:ro" `
    -p 8888:8080 `
    $DockerImage | Out-Null
Assert-LastExitCode "docker run"

Wait-AgentOnline -AgentId $agentId -AppToken $appToken

Write-Host "`n[9/9] Generating session token and exercising real relay path..." -ForegroundColor Yellow
$token = cargo run -q --manifest-path "D:\devolutions-gateway\tools\tokengen\Cargo.toml" -- sign `
    --provisioner-key $ProvisionerPrivateKeyFile `
    forward `
    --dst-hst "localhost:8080" `
    --jet-aid $SessionId `
    --jet-agent-id $agentId | Out-String
Assert-LastExitCode "tokengen sign"
$token = $token.Trim()

$pythonArgs = @(
    $PythonClient
    "--gateway-url", "ws://127.0.0.1:7171"
    "--session-id", $SessionId
    "--token", $token
)

$clientSucceeded = $false
for ($attempt = 1; $attempt -le 10; $attempt++) {
    Write-Host "  Python client attempt $attempt/10" -ForegroundColor DarkYellow
    python @pythonArgs
    if ($LASTEXITCODE -eq 0) {
        $clientSucceeded = $true
        break
    }
    Start-Sleep -Seconds 2
}

if (-not $clientSucceeded) {
    Show-DiagnosticsAndFail "Python client did not receive the HTTP response through the enrolled agent tunnel."
}

Write-Host "`nDynamic enrollment WireGuard relay test passed." -ForegroundColor Green

if (-not $KeepRunning) {
    Stop-TestEnvironment
}
