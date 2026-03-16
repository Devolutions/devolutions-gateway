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
$GatewayExe = "D:\devolutions-gateway\target\debug\devolutions-gateway.exe"
$PythonClient = "D:\devolutions-gateway\test-websocket-relay.py"
$DockerImage = "devolutions-gateway-agent-test"
$TargetAddress = "localhost:8080"
$OfflineTimeoutSeconds = 35

$Agents = @(
    @{
        Name = "multi-agent-a"
        Marker = "Hello from Agent A"
        ConfigPath = "D:\devolutions-gateway\test-output-multi-agent\agent-a-config.toml"
        RuntimeContainer = "wireguard-agent-test-a"
        EnrollContainer = "wireguard-agent-enroll-a"
        SessionId = "11111111-1111-1111-1111-111111111111"
    },
    @{
        Name = "multi-agent-b"
        Marker = "Hello from Agent B"
        ConfigPath = "D:\devolutions-gateway\test-output-multi-agent\agent-b-config.toml"
        RuntimeContainer = "wireguard-agent-test-b"
        EnrollContainer = "wireguard-agent-enroll-b"
        SessionId = "22222222-2222-2222-2222-222222222222"
    },
    @{
        Name = "multi-agent-c"
        Marker = "Hello from Agent C"
        ConfigPath = "D:\devolutions-gateway\test-output-multi-agent\agent-c-config.toml"
        RuntimeContainer = "wireguard-agent-test-c"
        EnrollContainer = "wireguard-agent-enroll-c"
        SessionId = "33333333-3333-3333-3333-333333333333"
    }
)

function Stop-TestEnvironment {
    Get-Process -Name "devolutions-gateway" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $GatewayPidFile) {
        $gatewayPid = Get-Content -LiteralPath $GatewayPidFile -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($gatewayPid) {
            Stop-Process -Id ([int]$gatewayPid) -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $GatewayPidFile -Force -ErrorAction SilentlyContinue
    }

    foreach ($agent in $Agents) {
        foreach ($container in @($agent.RuntimeContainer, $agent.EnrollContainer)) {
            $containerId = docker ps -aq -f "name=$container" | Out-String
            $containerId = $containerId.Trim()
            if ($containerId) {
                docker rm -f $container | Out-Null
            }
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

    foreach ($agent in $Agents) {
        Write-Host "`n=== Container logs: $($agent.RuntimeContainer) ===" -ForegroundColor Yellow
        docker logs $agent.RuntimeContainer
    }

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
        [string]$ContainerName,
        [string]$EnrollmentString,
        [string]$OutputConfigPath
    )

    if (Test-Path -LiteralPath $OutputConfigPath) {
        Remove-Item -LiteralPath $OutputConfigPath -Force
    }

    $createArgs = @(
        "create",
        "--name",
        $ContainerName,
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
    Assert-LastExitCode "docker create enroll $ContainerName"

    docker start -a $ContainerName
    Assert-LastExitCode "docker start enroll $ContainerName"

    docker cp "${ContainerName}:/tmp/agent-config.toml" $OutputConfigPath | Out-Null
    Assert-LastExitCode "docker cp enrolled config $ContainerName"

    docker rm -f $ContainerName | Out-Null
    Assert-LastExitCode "docker rm enroll $ContainerName"

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

function Wait-AgentOffline {
    param(
        [string]$AgentId,
        [string]$AppToken,
        [int]$TimeoutSeconds = 45
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $agent = Invoke-RestMethod `
                -Method Get `
                -Uri "http://127.0.0.1:7171/jet/agents/$AgentId" `
                -Headers @{ Authorization = "Bearer $AppToken"; Accept = "application/json" }

            if ($agent.status -eq "offline") {
                return
            }
        } catch {
        }

        Start-Sleep -Milliseconds 500
    }

    throw "Timed out waiting for agent $AgentId to become offline."
}

function Get-AgentsResponse {
    param([string]$AppToken)

    return Invoke-RestMethod `
        -Method Get `
        -Uri "http://127.0.0.1:7171/jet/agents" `
        -Headers @{ Authorization = "Bearer $AppToken"; Accept = "application/json" }
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
        "--request", "GET / HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n"
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
    Write-Host "Cleaned dynamic multi-agent WireGuard test environment." -ForegroundColor Green
    exit 0
}

Stop-TestEnvironment

[System.IO.Directory]::CreateDirectory($TestDir) | Out-Null
[System.IO.Directory]::CreateDirectory($GatewayConfigDir) | Out-Null

Write-Host "=== WireGuard Dynamic Multi-Agent E2E Test ===" -ForegroundColor Cyan

Write-Host "`n[1/10] Building gateway binary..." -ForegroundColor Yellow
cargo build -q -p devolutions-gateway --bin devolutions-gateway
Assert-LastExitCode "cargo build gateway"

Write-Host "`n[2/10] Building Docker agent image..." -ForegroundColor Yellow
docker build -f "D:\devolutions-gateway\Dockerfile.agent-test" -t $DockerImage "D:\devolutions-gateway"
Assert-LastExitCode "docker build"

Write-Host "`n[3/10] Generating provisioner keypair..." -ForegroundColor Yellow
& openssl genrsa -out $ProvisionerPrivateKeyFile 2048 | Out-Null
Assert-LastExitCode "openssl genrsa"
& openssl rsa -in $ProvisionerPrivateKeyFile -pubout -out $ProvisionerPublicKeyFile | Out-Null
Assert-LastExitCode "openssl rsa -pubout"

Write-Host "`n[4/10] Generating Gateway WireGuard keypair..." -ForegroundColor Yellow
$gatewayKeyPair = Get-WireGuardKeyPair
$gatewayKeyPair.Private | Out-File -LiteralPath $GatewayWireGuardPrivateKeyFile -Encoding ascii -NoNewline

Write-Host "`n[5/10] Writing Gateway config without static peers..." -ForegroundColor Yellow
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

Write-Host "`n[6/10] Starting Gateway..." -ForegroundColor Yellow
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

Write-Host "`n[7/10] Generating app token and enrolling three agents..." -ForegroundColor Yellow
$appToken = Invoke-TextPost `
    -Uri "http://127.0.0.1:7171/jet/webapp/app-token" `
    -Body @{
        content_type = "WEBAPP"
        subject = "automation"
        lifetime = 3600
    }

foreach ($agent in $Agents) {
    $enrollmentResponse = Invoke-JsonPost `
        -Uri "http://127.0.0.1:7171/jet/webapp/agent-enrollment-string" `
        -Headers @{ Authorization = "Bearer $appToken" } `
        -Body @{
            name = $agent.Name
            apiBaseUrl = "http://host.docker.internal:7171"
            wireguardHost = "host.docker.internal"
            lifetime = 3600
        }

    Invoke-DockerEnroll `
        -ContainerName $agent.EnrollContainer `
        -EnrollmentString $enrollmentResponse.enrollmentString `
        -OutputConfigPath $agent.ConfigPath

    $agent.AgentId = Get-AgentIdFromConfig -Path $agent.ConfigPath
}

$agentsResponse = Get-AgentsResponse -AppToken $appToken
if ($agentsResponse.agents.Count -ne 3) {
    Show-DiagnosticsAndFail "Expected 3 enrolled agents, got $($agentsResponse.agents.Count)."
}

Write-Host "`n[8/10] Starting all enrolled agent containers..." -ForegroundColor Yellow
foreach ($agent in $Agents) {
    Start-AgentContainer -ContainerName $agent.RuntimeContainer -ConfigPath $agent.ConfigPath -Message $agent.Marker
}

foreach ($agent in $Agents) {
    Wait-AgentOnline -AgentId $agent.AgentId -AppToken $appToken -TimeoutSeconds 45
}

Write-Host "`n[9/10] Verifying explicit routing for all three agents..." -ForegroundColor Yellow
foreach ($agent in $Agents) {
    $token = Get-ForwardToken -SessionId $agent.SessionId -AgentId $agent.AgentId
    if (-not (Invoke-PythonClient -SessionId $agent.SessionId -Token $token -ExpectedMarker $agent.Marker)) {
        Show-DiagnosticsAndFail "Explicit agent routing failed for $($agent.Name)."
    }
}

$sessionDirect = "99999999-9999-9999-9999-999999999999"
$tokenDirect = Get-ForwardToken -SessionId $sessionDirect
if (Invoke-PythonClient -SessionId $sessionDirect -Token $tokenDirect -ExpectedMarker $Agents[0].Marker) {
    Show-DiagnosticsAndFail "Direct session unexpectedly routed through an agent without jet_agent_id."
}

Write-Host "`n[10/10] Verifying isolation when one enrolled peer goes offline and comes back..." -ForegroundColor Yellow
$agentB = $Agents[1]
$agentA = $Agents[0]
$agentC = $Agents[2]

docker rm -f $agentB.RuntimeContainer | Out-Null
Assert-LastExitCode "docker rm -f $($agentB.RuntimeContainer)"
Wait-AgentOffline -AgentId $agentB.AgentId -AppToken $appToken -TimeoutSeconds $OfflineTimeoutSeconds

$offlineToken = Get-ForwardToken -SessionId "44444444-4444-4444-4444-444444444444" -AgentId $agentB.AgentId
if (Invoke-PythonClient -SessionId "44444444-4444-4444-4444-444444444444" -Token $offlineToken -ExpectedMarker $agentB.Marker) {
    Show-DiagnosticsAndFail "Explicit agent B route should fail while agent B is offline."
}

$tokenA = Get-ForwardToken -SessionId "55555555-5555-5555-5555-555555555555" -AgentId $agentA.AgentId
if (-not (Invoke-PythonClient -SessionId "55555555-5555-5555-5555-555555555555" -Token $tokenA -ExpectedMarker $agentA.Marker)) {
    Show-DiagnosticsAndFail "Agent A should still work while agent B is offline."
}

$tokenC = Get-ForwardToken -SessionId "66666666-6666-6666-6666-666666666666" -AgentId $agentC.AgentId
if (-not (Invoke-PythonClient -SessionId "66666666-6666-6666-6666-666666666666" -Token $tokenC -ExpectedMarker $agentC.Marker)) {
    Show-DiagnosticsAndFail "Agent C should still work while agent B is offline."
}

Start-AgentContainer -ContainerName $agentB.RuntimeContainer -ConfigPath $agentB.ConfigPath -Message $agentB.Marker
Wait-AgentOnline -AgentId $agentB.AgentId -AppToken $appToken -TimeoutSeconds 45

$reconnectToken = Get-ForwardToken -SessionId "77777777-7777-7777-7777-777777777777" -AgentId $agentB.AgentId
if (-not (Invoke-PythonClient -SessionId "77777777-7777-7777-7777-777777777777" -Token $reconnectToken -ExpectedMarker $agentB.Marker)) {
    Show-DiagnosticsAndFail "Agent B should work again after reconnect."
}

Write-Host "`nDynamic enrollment multi-agent WireGuard test passed." -ForegroundColor Green

if (-not $KeepRunning) {
    Stop-TestEnvironment
}
