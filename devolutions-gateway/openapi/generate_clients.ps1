#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

$targets = @(
	@{
		Folder = './doc'
		Config = './doc/config.json'
		Generator = 'asciidoc'
		SpecFile = './gateway-api.yaml'
		TemplatesDir = './doc/templates'
	}
	@{
		Folder = './dotnet-client'
		Config = './dotnet-client/config.json'
		Generator = 'csharp-netcore'
		SpecFile = './gateway-api.yaml'
		TemplatesDir = './dotnet-client/templates'
	}
	@{
		Folder = './ts-fetch-client'
		Config = './ts-fetch-client/config.json'
		Generator = 'typescript-fetch'
		SpecFile = './gateway-api.yaml'
		TemplatesDir = './ts-fetch-client/templates'
	}
	@{
		Folder = './dotnet-subscriber'
		Config = './dotnet-subscriber/config.json'
		Generator = 'aspnetcore'
		SpecFile = './subscriber-api.yaml'
	}
)

ForEach ($target in $targets)
{
	$target
	Write-Host

	Write-Host "Clean target"
	Get-Content -Path "$($target.Folder)/.openapi-generator/FILES" | Where { $_ -Ne ".openapi-generator-ignore" } | ForEach { Write-Host "REMOVE $($target.Folder)/$_"; Remove-Item -Path "$($target.Folder)/$_" -Force }
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

Pop-Location
