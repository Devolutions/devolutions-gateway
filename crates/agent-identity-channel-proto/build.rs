fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to locate vendored protoc");
    // SAFETY: Build scripts run single-threaded for this crate before prost-build reads PROTOC.
    unsafe { std::env::set_var("PROTOC", protoc) };

    println!("cargo:rerun-if-changed=proto/channel.proto");

    tonic_build::configure()
        .build_transport(false)
        .compile_protos(&["proto/channel.proto"], &["proto"])
        .expect("failed to compile agent identity channel proto");
}
