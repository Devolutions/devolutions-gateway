[CmdletBinding()]
param(
    [string] $ImageName = 'devolutions-agent-psu-grpc-poc',
    [string] $ContainerName = 'devo-agent-linux-poc',
    [string] $ServerUrl = 'http://host.docker.internal:5006',
    [string] $AgentId = 'devo-agent-linux',
    [string] $DisplayName = 'Devolutions Agent Linux',
    [string] $AppToken,
    [string[]] $Hubs = @('default'),
    [switch] $NoBuild
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

if (-not $NoBuild) {
    docker build `
        --file (Join-Path $PSScriptRoot 'Dockerfile.psu-grpc-poc') `
        --tag $ImageName `
        $repoRoot
}

$existing = docker ps -a --filter "name=^/$ContainerName$" --format '{{.ID}}'
if ($existing) {
    docker rm -f $ContainerName | Out-Null
}

$dockerArgs = @(
    'run',
    '--rm',
    '-it',
    '--name', $ContainerName,
    '--add-host', 'host.docker.internal:host-gateway',
    '-e', "PSU_SERVER_URL=$ServerUrl",
    '-e', "PSU_AGENT_ID=$AgentId",
    '-e', "PSU_DISPLAY_NAME=$DisplayName",
    '-e', "PSU_HUBS=$($Hubs -join ',')"
)

if (-not [string]::IsNullOrWhiteSpace($AppToken)) {
    $dockerArgs += @('-e', "PSU_APP_TOKEN=$AppToken")
}

$dockerArgs += $ImageName

docker @dockerArgs
