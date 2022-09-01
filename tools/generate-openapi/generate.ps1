#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

cargo run -- gateway > ../../devolutions-gateway/openapi/gateway-api.yaml
cargo run -- subscriber > ../../devolutions-gateway/openapi/subscriber-api.yaml

Pop-Location
