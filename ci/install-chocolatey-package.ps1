param(
    [Parameter(Mandatory = $true)]
    [string]$Package,

    [string]$Version,

    [string[]]$AdditionalArguments = @(),

    [ValidateRange(1, 10)]
    [int]$Attempts = 3
)

$ErrorActionPreference = 'Stop'

$arguments = @('install', $Package, '--yes', '--no-progress')
if ($Version) {
    $arguments += @('--version', $Version)
}
$arguments += $AdditionalArguments

for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    & choco @arguments
    if ($LASTEXITCODE -eq 0) {
        exit 0
    }

    if ($attempt -eq $Attempts) {
        throw "Chocolatey failed to install $Package after $Attempts attempts"
    }

    $delaySeconds = 10 * $attempt
    Write-Warning "Chocolatey failed to install $Package (attempt $attempt/$Attempts); retrying in $delaySeconds seconds"
    Start-Sleep -Seconds $delaySeconds
}
