fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_build::configure()
        .build_client(false)
        .compile_protos_with_config(prost, &["tests/psu_run_as/agent_control.proto"], &["tests/psu_run_as"])?;
    Ok(())
}
