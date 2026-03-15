param(
    [switch]$Clean,
    [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$Root = "D:\devolutions-gateway"
$TestDir = "D:\devolutions-gateway\test-output-multi-agent"
$GatewayConfigDir = "D:\devolutions-gateway\test-output-multi-agent\gateway-config"
$GatewayConfig = "D:\devolutions-gateway\test-output-multi-agent\gateway-config\gateway.json"
$GatewayWireGuardPrivateKeyFile = "D:\devolutions-gateway\test-output-multi-agent\gateway-wireguard-private-key.txt"
$ProvisionerPrivateKeyFile = "D:\devolutions-gateway\test-output-multi-agent\provisioner-private.pem"
$ProvisionerPublicKeyFile = "D:\devolutions-gateway\test-output-multi-agent\provisioner-public.pem"
$GatewayStdOut = "D:\devolutions-gateway\test-output-multi-agent\gateway.stdout.log"
$GatewayStdErr = "D:\devolutions-gateway\test-output-multi-agent\gateway.stderr.log"
$GatewayPidFile = "D:\devolutions-gateway\test-output-multi-agent\gateway.pid"
$AgentAConfig = "D:\devolutions-gateway\test-output-multi-agent\agent-a-config.toml"
$AgentBConfig = "D:\devolutions-gateway\test-output-multi-agent\agent-b-config.toml"
$DockerImage = "devolutions-gateway-agent-test"
$AgentAContainer = "wireguard-agent-test-a"
$AgentBContainer = "wireguard-agent-test-b"
$GatewayExe = "D:\devolutions-gateway\target\debug\devolutions-gateway.exe"
$PythonClient = "D:\devolutions-gateway\test-websocket-relay.py"
$TargetIp = "127.0.0.1"
$TargetSubnet = "127.0.0.0/8"
$TargetAddress = "$TargetIp`:8080"
$OfflineTimeoutSeconds = 35

function Stop-TestEnvironment {
    Get-Process -Name "devolutions-gateway" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $GatewayPidFile) {
        $gatewayPid = Get-Content -LiteralPath $GatewayPidFile -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($gatewayPid) {
            Stop-Process -Id ([int]$gatewayPid) -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $GatewayPidFile -Force -ErrorAction SilentlyContinue
    }

    foreach ($container in @($AgentAContainer, $AgentBContainer)) {
        $containerId = docker ps -aq -f "name=$container" | Out-String
        $containerId = $containerId.Trim()
        if ($containerId) {
            cmd /c "docker rm -f $container >nul 2>&1"

            $deadline = (Get-Date).AddSeconds(15)
            do {
                Start-Sleep -Milliseconds 250
                $containerId = docker ps -aq -f "name=$container" | Out-String
                $containerId = $containerId.Trim()
            } while ($containerId -and (Get-Date) -lt $deadline)
        }
    }
}

function Ensure-TestDirectories {
    [System.IO.Directory]::CreateDirectory($TestDir) | Out-Null
    [System.IO.Directory]::CreateDirectory($GatewayConfigDir) | Out-Null
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

    foreach ($container in @($AgentAContainer, $AgentBContainer)) {
        Write-Host "`n=== Container logs: $container ===" -ForegroundColor Yellow
        docker logs $container
    }

    throw $Message
}

function Write-AgentConfig {
    param(
        [string]$Path,
        [string]$AgentId,
        [string]$AgentName,
        [string]$PrivateKey,
        [string]$GatewayPublicKey,
        [string]$AssignedIp
    )

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $content = @"
agent_id = "$AgentId"
name = "$AgentName"
gateway_endpoint = "host.docker.internal:51820"
private_key = "$PrivateKey"
gateway_public_key = "$GatewayPublicKey"
assigned_ip = "$AssignedIp"
gateway_ip = "10.10.0.1"
advertise_subnets = ["$TargetSubnet"]
keepalive_interval = 25
"@
    [System.IO.File]::WriteAllText($Path, $content, $utf8NoBom)
}

function Start-AgentContainer {
    param(
        [string]$ContainerName,
        [string]$ConfigPath,
        [string]$Message
    )

    docker run -d `
        --name $ContainerName `
        --add-host host.docker.internal:host-gateway `
        -e "TEST_HTTP_MESSAGE=$Message" `
        -v "${ConfigPath}:/app/agent-config.toml:ro" `
        $DockerImage | Out-Null
    Assert-LastExitCode "docker run $ContainerName"
}

function Get-ForwardToken {
    param(
        [string]$SessionId,
        [string]$AgentId = ""
    )

    $cargoArgs = @(
        "run",
        "-q",
        "--manifest-path",
        "D:\devolutions-gateway\tools\tokengen\Cargo.toml",
        "--",
        "sign",
        "--provisioner-key",
        $ProvisionerPrivateKeyFile,
        "forward",
        "--dst-hst",
        $TargetAddress,
        "--jet-aid",
        $SessionId
    )

    if ($AgentId) {
        $cargoArgs += @("--jet-agent-id", $AgentId)
    }

    $token = cargo @cargoArgs | Out-String
    Assert-LastExitCode "tokengen sign"
    return $token.Trim()
}

function Invoke-PythonClient {
    param(
        [string]$SessionId,
        [string]$Token,
        [string]$ExpectedMarker
    )

    $pythonArgs = @(
        $PythonClient
        "--gateway-url", "ws://127.0.0.1:7171"
        "--session-id", $SessionId
        "--token", $Token
        "--request", "GET / HTTP/1.1`r`nHost: $TargetIp`r`nConnection: close`r`n`r`n"
        "--expected-marker", $ExpectedMarker
    )

    $output = python @pythonArgs
    if ($output) {
        $output | Write-Host
    }

    return ($LASTEXITCODE -eq 0)
}

if ($Clean) {
    Stop-TestEnvironment
    if (Test-Path -LiteralPath $TestDir) {
        Remove-Item -LiteralPath $TestDir -Recurse -Force
    }
    Write-Host "Cleaned multi-agent WireGuard test environment." -ForegroundColor Green
    exit 0
}

Stop-TestEnvironment

Ensure-TestDirectories

Write-Host "=== WireGuard Multi-Agent TDD Test ===" -ForegroundColor Cyan

Write-Host "`n[1/10] Building gateway binary..." -ForegroundColor Yellow
cargo build -q -p devolutions-gateway --bin devolutions-gateway
Assert-LastExitCode "cargo build"

Write-Host "`n[2/10] Building Docker agent image..." -ForegroundColor Yellow
docker build -f "D:\devolutions-gateway\Dockerfile.agent-test" -t $DockerImage "D:\devolutions-gateway"
Assert-LastExitCode "docker build"

Write-Host "`n[3/10] Generating provisioner keypair..." -ForegroundColor Yellow
Ensure-TestDirectories
& openssl genrsa -out $ProvisionerPrivateKeyFile 2048 | Out-Null
Assert-LastExitCode "openssl genrsa"
& openssl rsa -in $ProvisionerPrivateKeyFile -pubout -out $ProvisionerPublicKeyFile | Out-Null
Assert-LastExitCode "openssl rsa -pubout"

Write-Host "`n[4/10] Generating WireGuard keypairs..." -ForegroundColor Yellow
$gatewayKeyPair = Get-WireGuardKeyPair
$agentAKeyPair = Get-WireGuardKeyPair
$agentBKeyPair = Get-WireGuardKeyPair
$gatewayKeyPair.Private | Out-File -LiteralPath $GatewayWireGuardPrivateKeyFile -Encoding ascii -NoNewline

$agentAId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
$agentBId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

Write-Host "`n[5/10] Writing gateway and agent configs..." -ForegroundColor Yellow
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
                AgentId = $agentAId
                Name = "docker-test-agent-a"
                PublicKey = $agentAKeyPair.Public
                AssignedIp = "10.10.0.2"
            },
            [ordered]@{
                AgentId = $agentBId
                Name = "docker-test-agent-b"
                PublicKey = $agentBKeyPair.Public
                AssignedIp = "10.10.0.3"
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

Write-AgentConfig -Path $AgentAConfig -AgentId $agentAId -AgentName "docker-test-agent-a" `
    -PrivateKey $agentAKeyPair.Private -GatewayPublicKey $gatewayKeyPair.Public -AssignedIp "10.10.0.2"
Write-AgentConfig -Path $AgentBConfig -AgentId $agentBId -AgentName "docker-test-agent-b" `
    -PrivateKey $agentBKeyPair.Private -GatewayPublicKey $gatewayKeyPair.Public -AssignedIp "10.10.0.3"

Write-Host "`n[6/10] Starting gateway..." -ForegroundColor Yellow
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

Write-Host "`n[7/10] Starting agent A..." -ForegroundColor Yellow
Start-AgentContainer -ContainerName $AgentAContainer -ConfigPath $AgentAConfig -Message "Hello from Agent A"
Start-Sleep -Seconds 5

Write-Host "`n[8/10] Verifying agent A baseline route..." -ForegroundColor Yellow
$sessionA = "11111111-1111-1111-1111-111111111111"
$tokenA = Get-ForwardToken -SessionId $sessionA -AgentId $agentAId
if (-not (Invoke-PythonClient -SessionId $sessionA -Token $tokenA -ExpectedMarker "Hello from Agent A")) {
    Show-DiagnosticsAndFail "Baseline multi-agent test failed: agent A did not serve the target."
}

Write-Host "`n[9/10] Verifying that missing agent_id does not auto-route..." -ForegroundColor Yellow
$sessionDirect = "99999999-9999-9999-9999-999999999999"
$tokenDirect = Get-ForwardToken -SessionId $sessionDirect
if (Invoke-PythonClient -SessionId $sessionDirect -Token $tokenDirect -ExpectedMarker "Hello from Agent A") {
    Show-DiagnosticsAndFail "Direct session unexpectedly routed through an agent without jet_agent_id."
}

Write-Host "`n[10/10] Starting agent B and checking explicit agent routing..." -ForegroundColor Yellow
Start-AgentContainer -ContainerName $AgentBContainer -ConfigPath $AgentBConfig -Message "Hello from Agent B"
Start-Sleep -Seconds 8

$sessionB = "22222222-2222-2222-2222-222222222222"
$tokenB = Get-ForwardToken -SessionId $sessionB -AgentId $agentBId
if (-not (Invoke-PythonClient -SessionId $sessionB -Token $tokenB -ExpectedMarker "Hello from Agent B")) {
    Show-DiagnosticsAndFail "Explicit agent routing check failed: expected agent B to serve the target."
}

docker rm -f $AgentBContainer | Out-Null
Assert-LastExitCode "docker rm -f $AgentBContainer"
Start-Sleep -Seconds $OfflineTimeoutSeconds

$sessionFallback = "33333333-3333-3333-3333-333333333333"
$tokenFallback = Get-ForwardToken -SessionId $sessionFallback -AgentId $agentBId
if (Invoke-PythonClient -SessionId $sessionFallback -Token $tokenFallback -ExpectedMarker "Hello from Agent B") {
    Show-DiagnosticsAndFail "Explicit agent routing should fail when the chosen agent is offline."
}

Write-Host "`n[11/10] Restarting agent B and checking explicit reconnect..." -ForegroundColor Yellow
Start-AgentContainer -ContainerName $AgentBContainer -ConfigPath $AgentBConfig -Message "Hello from Agent B"
Start-Sleep -Seconds 8

$sessionReconnect = "44444444-4444-4444-4444-444444444444"
$tokenReconnect = Get-ForwardToken -SessionId $sessionReconnect -AgentId $agentBId
if (-not (Invoke-PythonClient -SessionId $sessionReconnect -Token $tokenReconnect -ExpectedMarker "Hello from Agent B")) {
    Show-DiagnosticsAndFail "Explicit agent reconnect check failed: expected agent B after reconnect."
}

Write-Host "`nExplicit-agent WireGuard TDD test passed." -ForegroundColor Green

if (-not $KeepRunning) {
    Stop-TestEnvironment
}
