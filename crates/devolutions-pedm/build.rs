use std::path::Path;
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    // This expects the PEDM crate to be in repo_root/crates/devolutions-pedm.
    let repo_root = Path::new(&manifest_dir)
        .parent()
        .expect("crates dir missing")
        .parent()
        .expect("repo root missing");

    let version = fs::read_to_string(repo_root.join("VERSION"))
        .expect("failed to read VERSION file")
        .trim_end()
        .to_string();
    println!("cargo:rustc-env=VERSION={}", version);
    Ok(())
}
