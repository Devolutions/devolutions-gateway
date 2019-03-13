set -ex

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

pushd ./rdp-proto && \
    cargo clippy --all-targets --all-features -- -D warnings && \
    cargo build --target wasm32-unknown-unknown && \
    cargo build --target wasm32-unknown-unknown --release && \
popd

cargo build
cargo build --release
cargo build --examples

cargo test -p rdp-proto -p jet-proto -p devolutions-jet
cargo test -p rdp-proto -p jet-proto -p devolutions-jet --release
