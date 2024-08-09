use devolutions_pedm_shared::build::target_dir;
use fs_extra::dir::CopyOptions;
use std::error::Error;
use std::path::PathBuf;
use std::{env, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let target = target_dir()?;
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let options = CopyOptions {
        overwrite: true,
        copy_inside: true,
        ..Default::default()
    };

    fs_extra::dir::copy(crate_dir.join("Assets"), &target, &options)?;

    fs::copy(crate_dir.join("AppxManifest.xml"), target.join("AppxManifest.xml"))?;

    Ok(())
}
