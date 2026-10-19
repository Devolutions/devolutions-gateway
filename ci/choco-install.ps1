#!/usr/bin/env pwsh

# Installs a Chocolatey package, retrying because the community feed intermittently fails with gateway timeouts.
# Throws once all attempts fail, so the calling step fails instead of leaving the package missing for later steps.

param(
	[Parameter(Mandatory=$true, Position=0)]
	[string] $Package,

	[string[]] $ArgumentList = @(),

	[int] $MaxAttempts = 4,

	[int] $RetryDelaySeconds = 30
)

$ErrorActionPreference = "Stop"

for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
	Write-Host "Installing $Package (attempt $Attempt of $MaxAttempts)"
	& choco install $Package --no-progress @ArgumentList

	if ($LASTEXITCODE -eq 0) {
		return
	}

	if ($Attempt -lt $MaxAttempts) {
		$Delay = $RetryDelaySeconds * $Attempt
		Write-Host "choco install $Package failed with exit code $LASTEXITCODE; retrying in $Delay seconds"
		Start-Sleep -Seconds $Delay
	}
}

throw "choco install $Package failed after $MaxAttempts attempts with exit code $LASTEXITCODE"
