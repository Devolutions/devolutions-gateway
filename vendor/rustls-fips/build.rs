//! This build script allows us to enable the `read_buf` language feature only
//! for Rust Nightly.
//!
//! See the comment in lib.rs to understand why we need this.

#[cfg_attr(feature = "read_buf", rustversion::not(nightly))]
fn main() {
    enable_fips_aws_lc_module();
}

#[cfg(feature = "read_buf")]
#[rustversion::nightly]
fn main() {
    enable_fips_aws_lc_module();
    println!("cargo:rustc-cfg=read_buf");
}

fn enable_fips_aws_lc_module() {
    if cfg!(feature = "fips") && !cfg!(feature = "aws_lc_rs") {
        println!("cargo:rustc-cfg=feature=\"aws_lc_rs\"");
    }
}
