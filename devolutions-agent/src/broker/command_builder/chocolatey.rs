//! Chocolatey command-line builder.

use anyhow::bail;
use now_policy_api::{Architecture, Operation, PackageRequest, Scope};

use super::set_if_true;

/// Build the Chocolatey command line from a validated request.
///
/// Returns the command as a list of arguments (first element is the executable).
pub fn build_chocolatey_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_chocolatey_request(request)?;

    let operation = match request.operation {
        Operation::Install => "install",
        Operation::Update => "upgrade",
        Operation::Uninstall => "uninstall",
    };

    let mut command = vec![
        "choco.exe".to_owned(),
        operation.to_owned(),
        request.package.id.0.clone(),
        "-y".to_owned(),
    ];

    set_if_true(&mut command, "--notsilent", request.options.interactive);

    if matches!(request.operation, Operation::Install | Operation::Update) {
        command.push("--no-progress".to_owned());
        command.push("--source".to_owned());
        command.push(chocolatey_source(request)?.to_owned());

        if request.package.architecture == Some(Architecture::X86) {
            command.push("--forcex86".to_owned());
        }

        set_if_true(&mut command, "--prerelease", request.options.pre_release);

        if request.options.skip_hash_check {
            command.push("--ignore-checksums".to_owned());
            command.push("--force".to_owned());
        }

        if let Some(version) = request.package.version.as_deref() {
            command.push(format!("--version={version}"));
            command.push("--allow-downgrade".to_owned());
        }
    }

    Ok(command)
}

fn validate_chocolatey_request(request: &PackageRequest) -> anyhow::Result<()> {
    if request.package.channel.is_some() {
        bail!("Chocolatey package channels are not supported by the broker");
    }

    if request.options.scope == Some(Scope::User) {
        bail!("Chocolatey user scope is not supported by the broker");
    }

    if matches!(
        request.package.architecture,
        Some(Architecture::Arm64 | Architecture::Neutral)
    ) {
        bail!("Chocolatey only supports native x64/default or explicit x86 architecture selection");
    }

    if request
        .options
        .custom_install_location
        .as_deref()
        .is_some_and(|location| !location.is_empty())
    {
        bail!("Chocolatey custom install locations are not supported by the broker");
    }

    if let Some(param) = request.options.custom_parameters.iter().find(|param| !param.is_empty()) {
        bail!(
            "Chocolatey custom parameters are not supported by the broker: {}",
            param.0
        );
    }

    if request.options.no_upgrade {
        bail!("Chocolatey no-upgrade requests are not supported by the broker");
    }

    if request.options.uninstall_previous {
        bail!("Chocolatey uninstall-previous requests are not supported by the broker");
    }

    if matches!(request.operation, Operation::Uninstall) {
        if request.options.skip_hash_check {
            bail!("Chocolatey skip-hash-check is not supported for uninstall operations");
        }
        if request.options.pre_release {
            bail!("Chocolatey prerelease selection is not supported for uninstall operations");
        }
        if request.package.architecture.is_some() {
            bail!("Chocolatey architecture selection is not supported for uninstall operations");
        }
    }

    if matches!(request.operation, Operation::Install | Operation::Update) {
        chocolatey_source(request)?;
    }

    Ok(())
}

fn chocolatey_source(request: &PackageRequest) -> anyhow::Result<&str> {
    let source = request.source.url.as_deref().unwrap_or(&request.source.name).trim();
    if source.is_empty() {
        bail!("Chocolatey package source is required");
    }
    Ok(source)
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
            request_id: ResourceId::from("req-choco-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: ManagerName::Chocolatey,
            source: RequestSource {
                name: "community".to_owned(),
                url: None,
            },
            package: RequestPackage {
                id: PackageIdentifier::from("git".to_owned()),
                version: Some(VersionString("2.48.1".to_owned())),
                architecture: None,
                channel: None,
            },
            options: RequestOptions {
                scope: Some(Scope::Machine),
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
                requested_elevation: Elevation::Elevated,
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
    fn install_matches_chocolatey_semantics() {
        let request = make_request();
        let cmd = build_chocolatey_command(&request).expect("build command");

        assert_eq!(
            cmd,
            [
                "choco.exe",
                "install",
                "git",
                "-y",
                "--no-progress",
                "--source",
                "community",
                "--version=2.48.1",
                "--allow-downgrade"
            ]
        );
    }

    #[test]
    fn update_supports_x86_prerelease_skip_hash_and_source_url() {
        let mut request = make_request();
        request.operation = Operation::Update;
        request.source.url = Some("https://community.chocolatey.org/api/v2/".to_owned());
        request.package.architecture = Some(Architecture::X86);
        request.options.pre_release = true;
        request.options.skip_hash_check = true;
        request.options.interactive = true;

        let cmd = build_chocolatey_command(&request).expect("build command");

        assert_eq!(cmd[1], "upgrade");
        assert!(cmd.contains(&"--notsilent".to_owned()));
        assert!(cmd.contains(&"https://community.chocolatey.org/api/v2/".to_owned()));
        assert!(cmd.contains(&"--forcex86".to_owned()));
        assert!(cmd.contains(&"--prerelease".to_owned()));
        assert!(cmd.contains(&"--ignore-checksums".to_owned()));
        assert!(cmd.contains(&"--force".to_owned()));
    }

    #[test]
    fn install_accepts_explicit_x64_without_forcex86() {
        let mut request = make_request();
        request.package.architecture = Some(Architecture::X64);

        let cmd = build_chocolatey_command(&request).expect("build command");

        assert!(!cmd.contains(&"--forcex86".to_owned()));
    }

    #[test]
    fn uninstall_omits_install_only_options_and_version() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.package.version = Some(VersionString("2.48.1".to_owned()));
        request.options.interactive = true;

        let cmd = build_chocolatey_command(&request).expect("build command");

        assert_eq!(cmd, ["choco.exe", "uninstall", "git", "-y", "--notsilent"]);
    }

    #[test]
    fn custom_parameters_are_rejected() {
        let mut request = make_request();
        request.options.custom_parameters = vec![CustomParameterString("--allow-empty-checksums".to_owned())];

        let error = build_chocolatey_command(&request).expect_err("custom parameter should fail");

        assert!(error.to_string().contains("custom parameters"));
    }

    #[test]
    fn unsupported_security_sensitive_uninstall_options_are_rejected() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.options.skip_hash_check = true;

        let error = build_chocolatey_command(&request).expect_err("skip hash should fail");

        assert!(error.to_string().contains("skip-hash-check"));
    }

    #[test]
    fn unsupported_scope_architecture_and_location_are_rejected() {
        let mut request = make_request();
        request.options.scope = Some(Scope::User);
        assert!(build_chocolatey_command(&request).is_err());

        request = make_request();
        request.package.architecture = Some(Architecture::Arm64);
        assert!(build_chocolatey_command(&request).is_err());

        request = make_request();
        request.package.architecture = Some(Architecture::Neutral);
        assert!(build_chocolatey_command(&request).is_err());

        request = make_request();
        request.options.custom_install_location = Some("C:\\Tools".to_owned());
        assert!(build_chocolatey_command(&request).is_err());
    }
}
