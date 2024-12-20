#!/bin/env pwsh

$ErrorActionPreference = "Stop"

$targets = @(
	@{
		Folder = './dotnet-client'
		Config = './dotnet-client/config.json'
		Generator = 'csharp'
		SpecFile = './pedm-api.yaml'
		TemplatesDir = './dotnet-client/templates'
	}
	@{
		Folder = '../../devolutions-pedm-shared/devolutions-pedm-client-http'
		Config = '../../devolutions-pedm-shared/devolutions-pedm-client-http/config.json'
		Generator = 'rust'
		SpecFile = './pedm-api.yaml'
		TemplatesDir = '../../devolutions-pedm-shared/devolutions-pedm-client-http'
	}
)

Push-Location -Path $PSScriptRoot
$RootDirectory = git rev-parse --show-toplevel

# Update the version in dotnet-client
$NewVersion = Get-Date -Format "yyyy.M.d"
$ConfigJson = Get-Content -Path $targets[0].Config | ConvertFrom-Json
$CurrentVersion = $ConfigJson.packageVersion
$ConfigJson.packageVersion = $NewVersion
$ConfigJson = $ConfigJson | ConvertTo-Json
Set-Content -Path $targets[0].Config -Value $ConfigJson
Write-Host "Current version is $CurrentVersion"
Write-Host "Next version is $NewVersion"
Write-Host

try {
	ForEach ($target in $targets)
	{
		$target
		Write-Host

		Write-Host "Clean target"
		Get-Content -Path "$($target.Folder)/.openapi-generator/FILES" | Where { $_ -Ne ".openapi-generator-ignore" } | ForEach { Write-Host "REMOVE $($target.Folder)/$_"; Remove-Item -Path "$($target.Folder)/$_" -Force -ErrorAction Ignore }
		Write-Host

		Write-Host "Generate target"

		$Cmd = @(
			'npx', 
			'openapi-generator-cli', 
			'generate', 
			'-i',
			$target.SpecFile,
			'-g',
			$target.Generator,
			'-c',
			$target.Config,
			'-o',
			$target.Folder
		)

		if ($target.TemplatesDir -Ne $null)
		{
			$Cmd += @('-t', $target.TemplatesDir)
		}

		$Cmd = $Cmd -Join ' '
		Write-Host $Cmd
		Invoke-Expression $Cmd

		Write-Host

		$FilesPath = Join-Path $(Convert-Path -LiteralPath $target.Folder) ".openapi-generator" "FILES"
		$PathsToFormat = Get-Content -Path $FilesPath | Where-Object { $_ -Like "*.rs" } | ForEach-Object { Join-Path $(Convert-Path -LiteralPath $target.Folder) $_ }

		Push-Location $RootDirectory

		try {
			foreach ($PathToFormat in $PathsToFormat)
			{
				rustfmt $PathToFormat
			}
		}
		finally {
			Pop-Location
		}

		Write-Host
	}
} finally {
	Pop-Location
}
