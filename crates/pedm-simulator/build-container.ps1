#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

try {
    docker build -t pedm-simulator .
} finally {
	Pop-Location
}

