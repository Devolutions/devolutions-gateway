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
	}
} finally {
	Pop-Location
}
