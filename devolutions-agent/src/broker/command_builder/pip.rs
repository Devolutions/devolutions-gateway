//! Pip command-line builder.

use anyhow::bail;
use now_policy_api::{Architecture, Elevation, Operation, PackageRequest, Scope};

/// Build the Pip command line from a validated request.
///
/// The Windows executor resolves `python.exe` from the target user's environment.
pub fn build_pip_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_pip_request(request)?;

    let mut command = vec![
        "python.exe".to_owned(),
        "-m".to_owned(),
        "pip".to_owned(),
        "--isolated".to_owned(),
    ];

    match request.operation {
        Operation::Install => command.push("install".to_owned()),
        Operation::Update => {
            command.push("install".to_owned());
            command.push("--upgrade".to_owned());
        }
        Operation::Uninstall => command.push("uninstall".to_owned()),
    }

    let package = if matches!(request.operation, Operation::Install | Operation::Update) {
        request.package.version.as_deref().map_or_else(
            || request.package.id.0.clone(),
            |version| format!("{}=={version}", request.package.id),
        )
    } else {
        request.package.id.0.clone()
    };
    command.push(package);

    command.push("--no-input".to_owned());
    command.push("--no-color".to_owned());
    command.push("--no-cache".to_owned());

    if matches!(request.operation, Operation::Uninstall) {
        command.push("--yes".to_owned());
    } else {
        if request.options.pre_release {
            command.push("--pre".to_owned());
        }
        command.push("--user".to_owned());
    }

    Ok(command)
}

fn validate_pip_request(request: &PackageRequest) -> anyhow::Result<()> {
    if request.client.requested_elevation == Elevation::Elevated {
        bail!("pip elevated operations are not supported by the broker");
    }
    if request.options.scope == Some(Scope::Machine) {
        bail!("pip machine-scope operations are not supported by the broker");
    }
    if request.source.url.is_some() {
        bail!("pip package sources with urls are not supported by the broker");
    }
    if !request.source.name.eq_ignore_ascii_case("pip") {
        bail!("pip package source must be pip");
    }
    validate_distribution_name(&request.package.id.0)?;
    if let Some(version) = request.package.version.as_deref() {
        validate_version(version)?;
    }
    if request
        .package
        .architecture
        .is_some_and(|architecture| architecture != Architecture::Neutral)
    {
        bail!("pip package architecture selection is not supported by the broker");
    }
    if request
        .package
        .channel
        .as_deref()
        .is_some_and(|channel| !channel.is_empty())
    {
        bail!("pip package channels are not supported by the broker");
    }
    if matches!(request.operation, Operation::Uninstall) && request.package.version.is_some() {
        bail!("pip uninstall does not support version pinning");
    }
    if request.options.interactive {
        bail!("pip interactive operations are not supported by the broker");
    }
    if request.options.skip_hash_check {
        bail!("pip hash-check skipping is not supported by the broker");
    }
    if request
        .options
        .custom_install_location
        .as_deref()
        .is_some_and(|location| !location.is_empty())
    {
        bail!("pip custom install locations are not supported by the broker");
    }
    if let Some(param) = request.options.custom_parameters.iter().find(|param| !param.is_empty()) {
        bail!("pip custom parameters are not supported by the broker: {}", param.0);
    }
    if request.options.uninstall_previous {
        bail!("pip uninstall-previous operations are not supported by the broker");
    }
    if request.options.no_upgrade {
        bail!("pip no-upgrade operations are not supported by the broker");
    }
    if matches!(request.operation, Operation::Uninstall) && request.options.pre_release {
        bail!("pip pre-release selection is not supported for uninstall");
    }

    Ok(())
}

fn validate_distribution_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        bail!("pip package id is required");
    }

    let mut chars = name.chars();
    let first = chars.next().expect("name is not empty");
    let last = chars.next_back().unwrap_or(first);
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        bail!("pip package id must be a plain Python distribution name");
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("pip package id must be a plain Python distribution name");
    }

    Ok(())
}

fn validate_version(version: &str) -> anyhow::Result<()> {
    if version.is_empty() {
        bail!("pip package version is required when specified");
    }
    if !version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '!' | '+' | '-' | '_'))
    {
        bail!("pip package version contains unsupported characters");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use now_policy_api::*;

    use super::*;

    fn make_request() -> PackageRequest {
        PackageRequest {
            request_kind: PackageRequestKind,
            request_version: API_VERSION_STR.into(),
            request_id: ResourceId::from("req-pip-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: ManagerName::Pip,
            source: RequestSource {
                name: "pip".to_owned(),
                url: None,
            },
            package: RequestPackage {
                id: PackageIdentifier::from("requests".to_owned()),
                version: None,
                architecture: None,
                channel: None,
            },
            options: RequestOptions {
                scope: None,
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
    fn pip_install_matches_unigetui_semantics() {
        let mut request = make_request();
        request.package.version = Some(VersionString("2.31.0".to_owned()));
        request.options.scope = Some(Scope::User);
        request.options.pre_release = true;

        let cmd = build_pip_command(&request).expect("build command");

        assert_eq!(
            cmd,
            [
                "python.exe",
                "-m",
                "pip",
                "--isolated",
                "install",
                "requests==2.31.0",
                "--no-input",
                "--no-color",
                "--no-cache",
                "--pre",
                "--user"
            ]
        );
    }

    #[test]
    fn pip_update_uses_install_upgrade() {
        let mut request = make_request();
        request.operation = Operation::Update;

        let cmd = build_pip_command(&request).expect("build command");

        assert_eq!(
            cmd[..6],
            ["python.exe", "-m", "pip", "--isolated", "install", "--upgrade"]
        );
        assert!(cmd.contains(&"requests".to_owned()));
        assert!(cmd.contains(&"--user".to_owned()));
    }

    #[test]
    fn pip_uninstall_is_noninteractive_and_omits_install_only_flags() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.options.scope = Some(Scope::User);

        let cmd = build_pip_command(&request).expect("build command");

        assert_eq!(
            cmd,
            [
                "python.exe",
                "-m",
                "pip",
                "--isolated",
                "uninstall",
                "requests",
                "--no-input",
                "--no-color",
                "--no-cache",
                "--yes"
            ]
        );
    }

    #[test]
    fn pip_rejects_elevated_operations() {
        let mut request = make_request();
        request.client.requested_elevation = Elevation::Elevated;

        let error = build_pip_command(&request).expect_err("elevated pip should fail");

        assert!(error.to_string().contains("elevated"));
    }

    #[test]
    fn pip_rejects_machine_scope() {
        let mut request = make_request();
        request.options.scope = Some(Scope::Machine);

        let error = build_pip_command(&request).expect_err("machine-scope pip should fail");

        assert!(error.to_string().contains("machine-scope"));
    }

    #[test]
    fn pip_rejects_custom_parameters() {
        let mut request = make_request();
        request.options.custom_parameters = vec![CustomParameterString("--break-system-packages".to_owned())];

        let error = build_pip_command(&request).expect_err("custom parameters should fail");

        assert!(error.to_string().contains("custom parameters"));
    }

    #[test]
    fn pip_rejects_unsupported_source_url() {
        let mut request = make_request();
        request.source.url = Some("https://mirror.example.test/simple/".to_owned());

        let error = build_pip_command(&request).expect_err("source URLs should fail");

        assert!(error.to_string().contains("sources with urls"));
    }

    #[test]
    fn pip_rejects_requirement_injection_in_package_id() {
        for package_id in [
            "--index-url=https://attacker.example/simple",
            "requests @ https://attacker.example/requests.whl",
            "requests\"&calc",
        ] {
            let mut request = make_request();
            request.package.id = PackageIdentifier::from(package_id.to_owned());

            let error = build_pip_command(&request).expect_err("package id should fail");

            assert!(error.to_string().contains("plain Python distribution name"));
        }
    }

    #[test]
    fn pip_rejects_unsafe_version_characters() {
        let mut request = make_request();
        request.package.version = Some(VersionString("1.0 @ https://attacker.example/pkg.whl".to_owned()));

        let error = build_pip_command(&request).expect_err("version should fail");

        assert!(error.to_string().contains("unsupported characters"));
    }
}
