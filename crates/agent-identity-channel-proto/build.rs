fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to locate vendored protoc");

    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);

    tonic_build::configure()
        .build_transport(false)
        .compile_protos_with_config(config, &["proto/channel.proto"], &["proto"])
        .expect("failed to compile agent identity channel proto");
}
