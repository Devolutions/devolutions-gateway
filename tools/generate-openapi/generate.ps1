#!/bin/env pwsh

cargo run -- gateway > ../../devolutions-gateway/openapi/gateway-api.yaml
cargo run -- subscriber > ../../devolutions-gateway/openapi/subscriber-api.yaml
