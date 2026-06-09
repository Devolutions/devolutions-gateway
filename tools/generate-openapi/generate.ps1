#!/bin/env pwsh

$ErrorActionPreference = "Stop"

Push-Location -Path $PSScriptRoot

cargo run -- gateway | Out-File -Encoding UTF8 ../../devolutions-gateway/openapi/gateway-api.yaml
cargo run -- subscriber | Out-File -Encoding UTF8 ../../devolutions-gateway/openapi/subscriber-api.yaml
cargo run -- pedm | Out-File -Encoding UTF8 ../../crates/devolutions-pedm/openapi/pedm-api.yaml
cargo run -- unigetui-broker | Out-File -Encoding UTF8 ../../crates/unigetui-broker/openapi/unigetui-broker-api.yaml

Pop-Location
