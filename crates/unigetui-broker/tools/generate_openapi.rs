//! Generates the OpenAPI 3.1 description of the broker's HTTP API.
//!
//! Writes `openapi/unigetui-broker-api.yaml` directly from the Rust types via
//! `aide` + `schemars`. The document also carries the `PolicyDocument` schema as
//! a component (see `server::openapi`).
//!
//! Writing the file directly (rather than piping stdout through a shell) keeps the
//! output UTF-8 and LF-terminated, avoiding console-encoding mojibake.
//!
//! Usage: `cargo run -p unigetui-broker --bin generate-broker-openapi`

#![allow(clippy::print_stdout, reason = "this is a developer-facing CLI tool")]

use std::path::Path;

fn main() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out_path = crate_dir.join("openapi").join("unigetui-broker-api.yaml");

    let yaml = serde_yaml::to_string(&unigetui_broker::server::openapi()).expect("BUG: OpenAPI serialization failed");

    std::fs::write(&out_path, &yaml).unwrap_or_else(|e| panic!("failed to write {}: {e}", out_path.display()));

    println!("Wrote {}", out_path.display());
}
