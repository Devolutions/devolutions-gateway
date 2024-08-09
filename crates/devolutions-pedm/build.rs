use devolutions_pedm_shared::build::target_dir;
use devolutions_pedm_shared::policy::Configuration;
use schemars::schema_for;
use std::fs;
use std::io::Result;

fn main() -> Result<()> {
    let schema = schema_for!(Configuration);

    let mut out_path = target_dir()?;
    out_path.push("policy.schema.json");

    fs::write(
        &out_path,
        serde_json::to_string_pretty(&schema).expect("failed to serialize PEDM schema"),
    )?;

    Ok(())
}
