fn main() {
    if cfg!(feature = "aws-lc-rs-fips") && !cfg!(feature = "aws-lc-rs") {
        println!("cargo:rustc-cfg=feature=\"aws-lc-rs\"");
    }
}
