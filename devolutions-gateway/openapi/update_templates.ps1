#!/bin/env pwsh

param(
	[Parameter(Mandatory=$true)]
	[string] $OpenApiGeneratorPath
)

$ErrorActionPreference = "Stop"

$targets = @(
	@{
		Folder = './doc'
		Generator = 'asciidoc-documentation'
		TemplatesDir = './doc/templates'
	}
	@{
		Folder = './dotnet-client'
		Generator = 'csharp-netcore'
		TemplatesDir = './dotnet-client/templates'
	}
	@{
		Folder = './ts-angular-client'
		Generator = 'typescript-angular'
		TemplatesDir = './ts-angular-client/templates'
	}
	@{
		Folder = './dotnet-subscriber'
		Generator = 'aspnetcore'
	}
)

Push-Location -Path $PSScriptRoot

try {
	ForEach ($target in $targets)
	{
		$target
		Write-Host

		if ($target.TemplatesDir -eq $null) {
			Write-Host "No custom template for" $target.Folder
		} else {
			$basePath = [System.IO.Path]::GetFullPath($target.TemplatesDir)
			$originalTemplatesDir = "$OpenApiGeneratorPath/modules/openapi-generator/src/main/resources/$($target.Generator)/"

			ForEach ($customTemplate in Get-ChildItem -Recurse -Path "$basePath" | Where-Object { $_.GetType().Name -Eq 'FileInfo' })
			{
				$relativePath = $customTemplate.FullName.SubString($basePath.Length + 1)
				$originalTemplate = Join-Path -Path "$originalTemplatesDir" -ChildPath "$relativePath"
				Write-Host "Copy $originalTemplate to $($customTemplate.FullName)"
				Copy-Item -Path "$originalTemplate" -Destination "$($customTemplate.FullName)"
			}
		}

		Write-Host
	}

} finally {
	Pop-Location
}
