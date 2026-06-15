//! Generates the JSON schema for the policy document.
//!
//! Usage: `cargo run -p unigetui-broker-policy --bin generate-unigetui-broker-policy-schema`

#![allow(clippy::print_stdout, reason = "this is a developer-facing CLI tool")]

use std::path::Path;

use serde_json::{Map, Value};
use unigetui_broker_policy::POLICY_SCHEMA_URI;
use unigetui_broker_policy::schema::policy_schema_json;

fn main() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out_path = crate_dir.join("schema").join("unigetui.package-policy.schema.json");

    let schema = with_id(policy_schema_json(), POLICY_SCHEMA_URI);
    let json = serde_json::to_string_pretty(&schema).expect("BUG: schema serialization failed");

    std::fs::write(&out_path, &json).unwrap_or_else(|e| panic!("failed to write {}: {e}", out_path.display()));

    println!("Wrote {}", out_path.display());
}

fn with_id(schema: Value, id: &str) -> Value {
    let Value::Object(existing) = schema else {
        panic!("BUG: schema root is not an object");
    };

    let mut object = Map::new();
    object.insert("$id".to_owned(), Value::String(id.to_owned()));
    object.extend(existing);

    Value::Object(object)
}
