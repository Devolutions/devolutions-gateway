#!/bin/bash
cargo run > ../../devolutions-gateway/doc/api.yaml
cargo run -- subscriber > ../../devolutions-gateway/doc/subscriber-api.yaml
