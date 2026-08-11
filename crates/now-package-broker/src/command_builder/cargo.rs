//! Cargo command-line builder.

use anyhow::bail;
use now_policy_api::{Architecture, Elevation, Operation, PackageRequest, Scope};

use super::set_if_specified;

const CRATES_IO_SOURCE_NAME: &str = "crates.io";
const CRATES_IO_SOURCE_URL: &str = "https://index.crates.io";

/// Build the Cargo command line from a validated request.
///
/// Returns the command as a list of arguments (first element is the executable).
pub fn build_cargo_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_cargo_request(request)?;

    let operation = match request.operation {
        Operation::Install | Operation::Update => "install",
        Operation::Uninstall => "uninstall",
    };

    let mut command = vec![
        "cargo.exe".to_owned(),
        operation.to_owned(),
        request.package.id.0.clone(),
    ];

    match request.operation {
        Operation::Install => {
            set_if_specified(&mut command, "--version", request.package.version.as_deref());
            set_if_specified(
                &mut command,
                "--root",
                request.options.custom_install_location.as_deref(),
            );
        }
        Operation::Update => {
            command.push("--force".to_owned());
            set_if_specified(&mut command, "--version", request.package.version.as_deref());
            set_if_specified(
                &mut command,
                "--root",
                request.options.custom_install_location.as_deref(),
            );
        }
        Operation::Uninstall => {
            set_if_specified(
                &mut command,
                "--root",
                request.options.custom_install_location.as_deref(),
            );
        }
    }

    Ok(command)
}

fn validate_cargo_request(request: &PackageRequest) -> anyhow::Result<()> {
    if request.client.requested_elevation == Elevation::Elevated {
        bail!("cargo elevated operations are not supported by the broker");
    }
    if request.options.scope == Some(Scope::Machine) {
        bail!("cargo machine-scope operations are not supported by the broker");
    }
    if !request.source.name.eq_ignore_ascii_case(CRATES_IO_SOURCE_NAME) {
        bail!("cargo package source must be crates.io");
    }
    if !is_valid_crates_io_crate_name(&request.package.id.0) {
        bail!("cargo package identifier must be a valid crates.io crate name");
    }
    if let Some(url) = request.source.url.as_deref()
        && !is_crates_io_url(url)
    {
        bail!("cargo package source URLs other than crates.io are not supported by the broker");
    }
    if let Some(architecture) = request.package.architecture
        && architecture != Architecture::Neutral
    {
        bail!("cargo package architecture selection is not supported by the broker");
    }
    if request.package.channel.is_some() {
        bail!("cargo package channels are not supported by the broker");
    }
    if request.operation == Operation::Uninstall && request.package.version.is_some() {
        bail!("cargo uninstall does not support version-pinned removals");
    }
    if request.options.interactive {
        bail!("cargo interactive operations are not supported by the broker");
    }
    if request.options.skip_hash_check {
        bail!("cargo skip-hash-check operations are not supported by the broker");
    }
    if request.options.pre_release {
        bail!("cargo prerelease selection is not supported by the broker");
    }
    if let Some(param) = request.options.custom_parameters.iter().find(|param| !param.is_empty()) {
        bail!("cargo custom parameters are not supported by the broker: {}", param.0);
    }
    if request.options.pre_operation_command.is_some() || request.options.post_operation_command.is_some() {
        bail!("cargo pre/post-operation commands are not supported by the broker");
    }
    if !request.options.kill_before_operation.is_empty() {
        bail!("cargo kill-before-operation is not supported by the broker");
    }
    if request.options.uninstall_previous {
        bail!("cargo uninstall-previous operations are not supported by the broker");
    }
    if request.options.no_upgrade {
        bail!("cargo no-upgrade operations are not supported by the broker");
    }

    Ok(())
}

fn is_crates_io_url(url: &str) -> bool {
    url.trim_end_matches('/').eq_ignore_ascii_case(CRATES_IO_SOURCE_URL)
}

fn is_valid_crates_io_crate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use now_policy_api::*;

    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn make_request() -> PackageRequest {
        PackageRequest {
            request_kind: PackageRequestKind,
            request_version: API_VERSION_STR.into(),
            request_id: ResourceId::from("req-cargo-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: ManagerName::Cargo,
            source: RequestSource {
                name: "crates.io".to_owned(),
                url: Some("https://index.crates.io/".to_owned()),
            },
            package: RequestPackage {
                id: PackageIdentifier::from("ripgrep".to_owned()),
                version: Some(VersionString("15.1.0".to_owned())),
                architecture: None,
                channel: None,
            },
            options: RequestOptions {
                scope: Some(Scope::User),
                interactive: false,
                skip_hash_check: false,
                pre_release: false,
                custom_install_location: None,
                custom_parameters: Vec::new(),
                pre_operation_command: None,
                post_operation_command: None,
                kill_before_operation: Vec::new(),
                uninstall_previous: false,
                no_upgrade: false,
            },
            client: ClientContext {
                transport: Transport::HttpNamedPipe,
                requested_elevation: Elevation::Standard,
                effective_user: "DOMAIN\\user".to_owned(),
                client_executable_path: "C:\\Program Files\\Devolutions\\Package Broker\\PackageBrokerClient.exe"
                    .to_owned(),
                client_version: "1.0.0".to_owned(),
            },
            include_command_preview: false,
            capture_output: false,
        }
    }

    #[test]
    fn install_uses_cargo_install_with_version_and_root() {
        let mut request = make_request();
        request.options.custom_install_location = Some("C:\\Tools\\Cargo".to_owned());

        let cmd = build_cargo_command(&request).expect("build command");

        assert_eq!(
            cmd,
            strings(&[
                "cargo.exe",
                "install",
                "ripgrep",
                "--version",
                "15.1.0",
                "--root",
                "C:\\Tools\\Cargo"
            ])
        );
    }

    #[test]
    fn update_forces_cargo_install_and_preserves_target_version() {
        let mut request = make_request();
        request.operation = Operation::Update;

        let cmd = build_cargo_command(&request).expect("build command");

        assert_eq!(
            cmd,
            strings(&["cargo.exe", "install", "ripgrep", "--force", "--version", "15.1.0"])
        );
    }

    #[test]
    fn uninstall_uses_cargo_uninstall() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.package.version = None;

        let cmd = build_cargo_command(&request).expect("build command");

        assert_eq!(cmd, strings(&["cargo.exe", "uninstall", "ripgrep"]));
    }

    #[test]
    fn uninstall_rejects_version() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;

        let error = build_cargo_command(&request).expect_err("version-pinned uninstall should fail");

        assert!(error.to_string().contains("version-pinned"));
    }

    #[test]
    fn elevated_cargo_operations_are_rejected() {
        let mut request = make_request();
        request.client.requested_elevation = Elevation::Elevated;

        let error = build_cargo_command(&request).expect_err("elevated cargo should fail");

        assert!(error.to_string().contains("elevated"));
    }

    #[test]
    fn machine_scope_cargo_operations_are_rejected() {
        let mut request = make_request();
        request.options.scope = Some(Scope::Machine);

        let error = build_cargo_command(&request).expect_err("machine-scope cargo should fail");

        assert!(error.to_string().contains("machine-scope"));
    }

    #[test]
    fn non_crates_io_source_is_rejected() {
        let mut request = make_request();
        request.source.name = "internal".to_owned();

        let error = build_cargo_command(&request).expect_err("custom source should fail");

        assert!(error.to_string().contains("crates.io"));
    }

    #[test]
    fn option_like_package_id_is_rejected() {
        let mut request = make_request();
        request.package.id = PackageIdentifier::from("--list".to_owned());

        let error = build_cargo_command(&request).expect_err("option-like package id should fail");

        assert!(error.to_string().contains("valid crates.io crate name"));
    }

    #[test]
    fn custom_parameters_are_rejected() {
        let mut request = make_request();
        request.options.custom_parameters =
            vec![CustomParameterString("--git=https://example.invalid/repo".to_owned())];

        let error = build_cargo_command(&request).expect_err("custom parameters should fail");

        assert!(error.to_string().contains("custom parameters"));
    }

    #[test]
    fn skip_hash_check_is_rejected() {
        let mut request = make_request();
        request.options.skip_hash_check = true;

        let error = build_cargo_command(&request).expect_err("skip hash should fail");

        assert!(error.to_string().contains("skip-hash-check"));
    }

    #[test]
    fn pre_post_commands_are_rejected() {
        let mut request = make_request();
        request.options.pre_operation_command = Some("echo before".to_owned());

        let error = build_cargo_command(&request).expect_err("pre command should fail");

        assert!(error.to_string().contains("pre/post-operation"));
    }
}
