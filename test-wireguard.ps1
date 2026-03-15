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
$GatewayExe = "D:\devolutions-gateway\target\debug\devolutions-gateway.exe"
$PythonClient = "D:\devolutions-gateway\test-websocket-relay.py"

function Stop-TestEnvironment {
    Get-Process -Name "devolutions-gateway" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $GatewayPidFile) {
        $gatewayPid = Get-Content -LiteralPath $GatewayPidFile -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($gatewayPid) {
            Stop-Process -Id ([int]$gatewayPid) -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $GatewayPidFile -Force -ErrorAction SilentlyContinue
    }

    $containerId = docker ps -aq -f "name=$DockerContainer" | Out-String
    $containerId = $containerId.Trim()
    if ($containerId) {
        docker rm -f $DockerContainer | Out-Null
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

if ($Clean) {
    Stop-TestEnvironment
    if (Test-Path -LiteralPath $TestDir) {
        Remove-Item -LiteralPath $TestDir -Recurse -Force
    }
    Write-Host "Cleaned WireGuard test environment." -ForegroundColor Green
    exit 0
}

Stop-TestEnvironment

New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
New-Item -ItemType Directory -Path $GatewayConfigDir -Force | Out-Null

Write-Host "=== WireGuard Agent Tunneling E2E Test ===" -ForegroundColor Cyan

Write-Host "`n[1/8] Building gateway binary..." -ForegroundColor Yellow
cargo build -q -p devolutions-gateway --bin devolutions-gateway
Assert-LastExitCode "cargo build"

Write-Host "`n[2/8] Building Docker agent image..." -ForegroundColor Yellow
docker build -f "D:\devolutions-gateway\Dockerfile.agent-test" -t $DockerImage "D:\devolutions-gateway"
Assert-LastExitCode "docker build"

Write-Host "`n[3/8] Generating provisioner keypair..." -ForegroundColor Yellow
& openssl genrsa -out $ProvisionerPrivateKeyFile 2048 | Out-Null
Assert-LastExitCode "openssl genrsa"
& openssl rsa -in $ProvisionerPrivateKeyFile -pubout -out $ProvisionerPublicKeyFile | Out-Null
Assert-LastExitCode "openssl rsa -pubout"

Write-Host "`n[4/8] Generating WireGuard keypairs..." -ForegroundColor Yellow
$gatewayKeyPair = Get-WireGuardKeyPair
$agentKeyPair = Get-WireGuardKeyPair

$gatewayKeyPair.Private | Out-File -LiteralPath $GatewayWireGuardPrivateKeyFile -Encoding ascii -NoNewline

$agentId = "00000000-0000-0000-0000-000000000001"
$sessionId = "11111111-1111-1111-1111-111111111111"

Write-Host "`n[5/8] Writing gateway and agent configs..." -ForegroundColor Yellow
$gatewayConfigObject = [ordered]@{
    Hostname = "127.0.0.1"
    ProvisionerPublicKeyFile = $ProvisionerPublicKeyFile
    Listeners = @(
        [ordered]@{
            InternalUrl = "http://127.0.0.1:7171"
            ExternalUrl = "http://127.0.0.1:7171"
        }
    )
    WireGuard = [ordered]@{
        Enabled = $true
        Port = 51820
        PrivateKeyFile = $GatewayWireGuardPrivateKeyFile
        TunnelNetwork = "10.10.0.0/16"
        GatewayIp = "10.10.0.1"
        Peers = @(
            [ordered]@{
                AgentId = $agentId
                Name = "docker-test-agent"
                PublicKey = $agentKeyPair.Public
                AssignedIp = "10.10.0.2"
            }
        )
    }
    VerbosityProfile = "All"
}
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText(
    $GatewayConfig,
    ($gatewayConfigObject | ConvertTo-Json -Depth 8),
    $utf8NoBom
)

$agentConfigContent = @"
agent_id = "$agentId"
name = "docker-test-agent"
gateway_endpoint = "host.docker.internal:51820"
private_key = "$($agentKeyPair.Private)"
gateway_public_key = "$($gatewayKeyPair.Public)"
assigned_ip = "10.10.0.2"
gateway_ip = "10.10.0.1"
advertise_subnets = ["127.0.0.0/8", "172.0.0.0/8", "192.168.0.0/16"]
keepalive_interval = 25
"@
[System.IO.File]::WriteAllText($AgentConfig, $agentConfigContent, $utf8NoBom)

Write-Host "`n[6/8] Starting gateway..." -ForegroundColor Yellow
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

Write-Host "`n[7/8] Starting Docker agent container..." -ForegroundColor Yellow
docker run -d `
    --name $DockerContainer `
    --add-host host.docker.internal:host-gateway `
    -v "${AgentConfig}:/app/agent-config.toml:ro" `
    -p 8888:8080 `
    $DockerImage | Out-Null
Assert-LastExitCode "docker run"

Start-Sleep -Seconds 3

Write-Host "`n[8/8] Generating token and running Python client..." -ForegroundColor Yellow
$token = cargo run -q --manifest-path "D:\devolutions-gateway\tools\tokengen\Cargo.toml" -- sign `
    --provisioner-key $ProvisionerPrivateKeyFile `
    forward `
    --dst-hst "localhost:8080" `
    --jet-aid $sessionId `
    --jet-agent-id $agentId | Out-String
Assert-LastExitCode "tokengen sign"
$token = $token.Trim()

$pythonArgs = @(
    $PythonClient
    "--gateway-url", "ws://127.0.0.1:7171"
    "--session-id", $sessionId
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
    Show-DiagnosticsAndFail "Python client did not receive the HTTP response through the tunnel."
}

Write-Host "`nEnd-to-end WireGuard relay test passed." -ForegroundColor Green

if (-not $KeepRunning) {
    Stop-TestEnvironment
}
