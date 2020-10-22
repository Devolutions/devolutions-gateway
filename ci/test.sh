set -ex

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

cargo build
cargo build --release
cargo build --examples

cargo test -p jet-proto -p devolutions-gateway
cargo test -p jet-proto -p devolutions-gateway --release
