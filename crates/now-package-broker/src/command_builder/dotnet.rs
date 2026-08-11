//! .NET tool command-line builder.
//!
//! Mirrors UniGetUI's `.NET Tool` manager command shape:
//! `dotnet tool <install|update|uninstall> <package-id>`.
//! The broker pins the executable to the trusted Program Files .NET SDK path so
//! elevated execution never searches a user-controlled `PATH` for `dotnet.exe`.

use anyhow::bail;
use now_policy_api::{Architecture, Operation, PackageRequest, Scope};

use super::{set_if_specified, set_if_true};

const NUGET_ORG_V3_SOURCE: &str = "https://api.nuget.org/v3/index.json";

/// Build the .NET tool command line from a validated request.
///
/// Returns the command as a list of arguments (first element is the executable).
pub fn build_dotnet_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_dotnet_request(request)?;

    let operation = match request.operation {
        Operation::Install => "install",
        Operation::Update => "update",
        Operation::Uninstall => "uninstall",
    };

    let mut command = vec![
        trusted_dotnet_executable(),
        "tool".to_owned(),
        operation.to_owned(),
        request.package.id.0.clone(),
    ];

    set_if_specified(
        &mut command,
        "--tool-path",
        request.options.custom_install_location.as_deref(),
    );

    if request.options.custom_install_location.is_none() {
        command.push("--global".to_owned());
    }

    if matches!(request.operation, Operation::Install | Operation::Update) {
        append_source(&mut command, request)?;
        set_if_specified(&mut command, "--version", request.package.version.as_deref());
        set_if_true(&mut command, "--prerelease", request.options.pre_release);

        set_if_specified(
            &mut command,
            "--arch",
            request.package.architecture.and_then(|arch| match arch {
                Architecture::X86 => Some("x86"),
                Architecture::X64 => Some("x64"),
                Architecture::Arm64 => Some("arm64"),
                Architecture::Neutral => None,
            }),
        );
    }

    Ok(command)
}

fn validate_dotnet_request(request: &PackageRequest) -> anyhow::Result<()> {
    if request.client.requested_elevation == now_policy_api::Elevation::Elevated
        && !trusted_dotnet_executable_is_program_files_path()
    {
        bail!("elevated .NET tool operations require the trusted Program Files dotnet.exe path");
    }

    if request.options.interactive {
        bail!(".NET interactive operations are not supported by the broker");
    }
    if request.options.skip_hash_check {
        bail!(".NET skip hash check is not supported by the broker");
    }
    if request.options.no_upgrade {
        bail!(".NET no-upgrade operations are not supported by the broker");
    }
    if request.options.uninstall_previous {
        bail!(".NET uninstall-previous operations are not supported by the broker");
    }
    if matches!(request.options.scope, Some(Scope::Machine)) {
        bail!(".NET machine scope is not supported by the broker");
    }
    if let Some(param) = request.options.custom_parameters.iter().find(|param| !param.is_empty()) {
        bail!(".NET custom parameters are not supported by the broker: {}", param.0);
    }
    if matches!(request.operation, Operation::Uninstall) && request.package.architecture.is_some() {
        bail!(".NET architecture selection is not supported for uninstall operations");
    }
    if matches!(request.operation, Operation::Uninstall) && request.options.pre_release {
        bail!(".NET prerelease selection is not supported for uninstall operations");
    }
    if matches!(request.operation, Operation::Install | Operation::Update) {
        dotnet_source(request)?;
    }

    Ok(())
}

fn append_source(command: &mut Vec<String>, request: &PackageRequest) -> anyhow::Result<()> {
    command.push("--source".to_owned());
    command.push(dotnet_source(request)?.to_owned());
    Ok(())
}

fn dotnet_source(request: &PackageRequest) -> anyhow::Result<&str> {
    if !request.source.name.eq_ignore_ascii_case("nuget.org") {
        bail!(".NET install and update operations only support the nuget.org source");
    }

    if let Some(url) = request.source.url.as_deref()
        && !url.trim().is_empty()
        && !url.eq_ignore_ascii_case(NUGET_ORG_V3_SOURCE)
    {
        bail!(".NET nuget.org source URL must match the broker-trusted canonical URL");
    }

    Ok(NUGET_ORG_V3_SOURCE)
}

pub(crate) fn trusted_dotnet_executable() -> String {
    let program_files = std::env::var("ProgramFiles")
        .ok()
        .filter(|path| trusted_program_files_path(path))
        .unwrap_or_else(|| r"C:\Program Files".to_owned());
    format!("{}\\dotnet\\dotnet.exe", program_files.trim_end_matches(['\\', '/']))
}

fn trusted_dotnet_executable_is_program_files_path() -> bool {
    trusted_dotnet_executable()
        .to_lowercase()
        .starts_with(r"c:\program files\dotnet\dotnet.exe")
        || std::env::var("ProgramFiles")
            .ok()
            .filter(|path| trusted_program_files_path(path))
            .is_some()
}

fn trusted_program_files_path(path: &str) -> bool {
    let path = path.trim_end_matches(['\\', '/']);
    path.len() >= 3 && path.as_bytes().get(1) == Some(&b':') && path.as_bytes().get(2) == Some(&b'\\')
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
            request_id: ResourceId::from("req-dotnet-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: ManagerName::Dotnet,
            source: RequestSource {
                name: "nuget.org".to_owned(),
                url: Some("https://api.nuget.org/v3/index.json".to_owned()),
            },
            package: RequestPackage {
                id: PackageIdentifier::from("dotnetsay".to_owned()),
                version: Some(VersionString("2.1.7".to_owned())),
                architecture: Some(Architecture::X64),
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
    fn install_uses_trusted_program_files_dotnet_and_nuget_source() {
        let request = make_request();
        let cmd = build_dotnet_command(&request).expect("build command");

        assert!(cmd[0].ends_with(r"\dotnet\dotnet.exe"));
        assert_ne!(cmd[0], "dotnet.exe");
        assert_eq!(cmd[1], "tool");
        assert_eq!(cmd[2], "install");
        assert!(cmd.contains(&"dotnetsay".to_owned()));
        assert!(cmd.contains(&"--global".to_owned()));
        assert!(cmd.contains(&"--source".to_owned()));
        assert!(cmd.contains(&"https://api.nuget.org/v3/index.json".to_owned()));
        assert!(cmd.contains(&"--version".to_owned()));
        assert!(cmd.contains(&"2.1.7".to_owned()));
        assert!(cmd.contains(&"--arch".to_owned()));
        assert!(cmd.contains(&"x64".to_owned()));
    }

    #[test]
    fn update_uses_update_operation_and_prerelease() {
        let mut request = make_request();
        request.operation = Operation::Update;
        request.options.pre_release = true;

        let cmd = build_dotnet_command(&request).expect("build command");

        assert_eq!(cmd[2], "update");
        assert!(cmd.contains(&"--prerelease".to_owned()));
    }

    #[test]
    fn uninstall_omits_source_version_architecture() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.package.version = Some(VersionString("2.1.7".to_owned()));
        request.package.architecture = None;

        let cmd = build_dotnet_command(&request).expect("build command");

        assert_eq!(cmd[2], "uninstall");
        assert!(!cmd.contains(&"--source".to_owned()));
        assert!(!cmd.contains(&"--version".to_owned()));
        assert!(!cmd.contains(&"--arch".to_owned()));
    }

    #[test]
    fn custom_tool_path_is_supported_without_global_scope() {
        let mut request = make_request();
        request.options.custom_install_location = Some(r"C:\Tools\dotnet".to_owned());

        let cmd = build_dotnet_command(&request).expect("build command");

        assert!(cmd.contains(&"--tool-path".to_owned()));
        assert!(cmd.contains(&r"C:\Tools\dotnet".to_owned()));
        assert!(!cmd.contains(&"--global".to_owned()));
    }

    #[test]
    fn custom_parameters_are_rejected() {
        let mut request = make_request();
        request.options.custom_parameters = vec![CustomParameterString("--configfile user.config".to_owned())];

        let error = build_dotnet_command(&request).expect_err("custom parameters should fail");

        assert!(error.to_string().contains("custom parameters"));
    }

    #[test]
    fn skip_hash_check_is_rejected() {
        let mut request = make_request();
        request.options.skip_hash_check = true;

        let error = build_dotnet_command(&request).expect_err("skip hash should fail");

        assert!(error.to_string().contains("skip hash check"));
    }

    #[test]
    fn interactive_operations_are_rejected() {
        let mut request = make_request();
        request.options.interactive = true;

        let error = build_dotnet_command(&request).expect_err("interactive should fail");

        assert!(error.to_string().contains("interactive"));
    }

    #[test]
    fn winget_only_upgrade_options_are_rejected() {
        let mut request = make_request();
        request.options.no_upgrade = true;

        let error = build_dotnet_command(&request).expect_err("no-upgrade should fail");

        assert!(error.to_string().contains("no-upgrade"));

        request.options.no_upgrade = false;
        request.options.uninstall_previous = true;
        let error = build_dotnet_command(&request).expect_err("uninstall-previous should fail");

        assert!(error.to_string().contains("uninstall-previous"));
    }

    #[test]
    fn uninstall_rejects_install_only_options() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;

        let error = build_dotnet_command(&request).expect_err("architecture should fail");
        assert!(error.to_string().contains("architecture"));

        request.package.architecture = None;
        request.options.pre_release = true;
        let error = build_dotnet_command(&request).expect_err("prerelease should fail");
        assert!(error.to_string().contains("prerelease"));
    }

    #[test]
    fn unspecified_scope_uses_user_global_tool_store() {
        let mut request = make_request();
        request.options.scope = None;

        let cmd = build_dotnet_command(&request).expect("build command");

        assert!(cmd.contains(&"--global".to_owned()));
    }

    #[test]
    fn machine_scope_is_rejected() {
        let mut request = make_request();
        request.options.scope = Some(Scope::Machine);

        let error = build_dotnet_command(&request).expect_err("machine scope should fail");

        assert!(error.to_string().contains("machine scope"));
    }

    #[test]
    fn install_accepts_default_nuget_org_without_url() {
        let mut request = make_request();
        request.source.url = None;

        let cmd = build_dotnet_command(&request).expect("build command");

        assert!(cmd.contains(&"https://api.nuget.org/v3/index.json".to_owned()));
    }

    #[test]
    fn install_rejects_untrusted_source_url_for_nuget_org_name() {
        let mut request = make_request();
        request.source.url = Some("https://example.invalid/v3/index.json".to_owned());

        let error = build_dotnet_command(&request).expect_err("untrusted source URL should fail");

        assert!(error.to_string().contains("canonical URL"));
    }

    #[test]
    fn install_rejects_non_canonical_source_names() {
        let mut request = make_request();
        request.source.name = "private".to_owned();
        request.source.url = Some("https://packages.example.invalid/v3/index.json".to_owned());

        let error = build_dotnet_command(&request).expect_err("private source should fail");

        assert!(error.to_string().contains("nuget.org"));
    }
}
