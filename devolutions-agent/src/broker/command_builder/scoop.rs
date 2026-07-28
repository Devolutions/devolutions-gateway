//! Scoop command-line builder.
//!
//! UniGetUI runs Scoop through the user's `scoop.ps1` script. The broker keeps
//! that unelevated user-profile behavior and rejects elevated/global Scoop
//! operations instead of resolving a user-controlled script with an elevated token.

use anyhow::bail;
use now_policy_api::{Architecture, Elevation, Operation, PackageRequest, Scope};

/// Build a Scoop command from a validated request.
///
/// The command is returned as a PowerShell inline script so the Windows executor
/// can materialize it in a protected temporary `.ps1` file and replace the
/// PowerShell host with a trusted system path.
pub fn build_scoop_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_scoop_request(request)?;

    let operation = match request.operation {
        Operation::Install => "install",
        Operation::Update => "update",
        Operation::Uninstall => "uninstall",
    };

    let mut scoop_args = vec![operation.to_owned(), scoop_package_ref(request)?];

    if matches!(request.operation, Operation::Install | Operation::Update) && request.options.skip_hash_check {
        scoop_args.push("--skip-hash-check".to_owned());
    }

    if matches!(request.operation, Operation::Install)
        && let Some(arch) = request.package.architecture
    {
        let arch = match arch {
            Architecture::X64 => "64bit",
            Architecture::X86 => "32bit",
            Architecture::Arm64 => "arm64",
            Architecture::Neutral => bail!("Scoop does not support the Neutral architecture"),
        };
        scoop_args.push("--arch".to_owned());
        scoop_args.push(arch.to_owned());
    }

    for param in &request.options.custom_parameters {
        if !param.is_empty() {
            scoop_args.push(param.0.clone());
        }
    }

    for arg in &scoop_args {
        validate_script_argument(arg)?;
    }

    let mut script = String::new();
    append_statement(&mut script, "$ErrorActionPreference = 'Stop'");
    append_statement(
        &mut script,
        "$scoop = (Get-Command -Name 'scoop.ps1' -CommandType ExternalScript -ErrorAction Stop | Select-Object -First 1).Source",
    );
    append_raw(&mut script, "& $scoop");
    for arg in &scoop_args {
        append_ps_arg(&mut script, arg);
    }
    script.push(';');
    append_statement(&mut script, "exit $LASTEXITCODE");

    Ok(vec![
        "powershell.exe".to_owned(),
        "-NoProfile".to_owned(),
        "-ExecutionPolicy".to_owned(),
        "Bypass".to_owned(),
        "-Command".to_owned(),
        script,
    ])
}

fn validate_scoop_request(request: &PackageRequest) -> anyhow::Result<()> {
    if request.client.requested_elevation == Elevation::Elevated {
        bail!(
            "Scoop elevated execution is not supported by the broker because scoop.ps1 is resolved from the target user profile"
        );
    }
    if request.options.scope == Some(Scope::Machine) {
        bail!("Scoop machine/global scope is not supported by the broker");
    }
    if request.source.name.trim().is_empty() {
        bail!("Scoop package source name is required");
    }
    if request.package.version.is_some() {
        bail!("Scoop package versions are not supported by the broker");
    }
    if request.package.channel.is_some() {
        bail!("Scoop package channels are not supported by the broker");
    }
    if request.options.interactive {
        bail!("Scoop interactive installation is not supported by the broker");
    }
    if request.options.pre_release {
        bail!("Scoop pre-release installation is not supported by the broker");
    }
    if request.options.custom_install_location.is_some() {
        bail!("Scoop custom install locations are not supported by the broker");
    }
    if request.options.no_upgrade {
        bail!("Scoop no-upgrade is not supported by the broker");
    }
    if request.options.uninstall_previous {
        bail!("Scoop uninstall-previous is not supported by the broker");
    }
    if request.options.skip_hash_check && matches!(request.operation, Operation::Uninstall) {
        bail!("Scoop skip-hash-check is only supported for install and update operations");
    }
    if request.package.architecture.is_some() && !matches!(request.operation, Operation::Install) {
        bail!("Scoop architecture selection is only supported for install operations");
    }

    for param in &request.options.custom_parameters {
        if param.is_empty() {
            continue;
        }
        if is_global_scope_parameter(&param.0) {
            bail!(
                "Scoop global scope custom parameters are not supported by the broker: {}",
                param.0
            );
        }
        validate_script_argument(&param.0)?;
    }

    Ok(())
}

fn scoop_package_ref(request: &PackageRequest) -> anyhow::Result<String> {
    let source = request.source.name.trim();
    validate_script_argument(source)?;
    validate_script_argument(&request.package.id.0)?;

    if source_is_direct_manifest(source) {
        Ok(request.package.id.0.clone())
    } else {
        Ok(format!("{source}/{}", request.package.id.0))
    }
}

fn source_is_direct_manifest(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    source.contains("...") || source.contains(":\\") || lower.starts_with("http://") || lower.starts_with("https://")
}

fn is_global_scope_parameter(param: &str) -> bool {
    param.split_whitespace().any(|part| {
        let part = part.to_ascii_lowercase();
        part == "-g" || part == "--global" || part.starts_with("--global=")
    })
}

fn validate_script_argument(value: &str) -> anyhow::Result<()> {
    if value.contains(['\0', '\r', '\n']) {
        bail!("Scoop command arguments cannot contain control line separators");
    }
    Ok(())
}

fn append_statement(script: &mut String, statement: &str) {
    append_raw(script, statement);
    script.push(';');
}

fn append_raw(script: &mut String, value: &str) {
    if !script.is_empty() {
        script.push(' ');
    }
    script.push_str(value);
}

fn append_ps_arg(script: &mut String, value: &str) {
    append_raw(script, &quote_ps(value));
}

fn quote_ps(value: &str) -> String {
    let escaped = value.replace('\'', "''");
    format!("'{escaped}'")
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
            request_id: ResourceId::from("req-scoop-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: ManagerName::Scoop,
            source: RequestSource {
                name: "main".to_owned(),
                url: Some("https://github.com/ScoopInstaller/Main".to_owned()),
            },
            package: RequestPackage {
                id: PackageIdentifier::from("7zip".to_owned()),
                version: None,
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

    fn script_of(cmd: &[String]) -> &str {
        assert_eq!(cmd[0], "powershell.exe");
        assert_eq!(cmd[1], "-NoProfile");
        assert_eq!(cmd[2], "-ExecutionPolicy");
        assert_eq!(cmd[3], "Bypass");
        assert_eq!(cmd[4], "-Command");
        &cmd[5]
    }

    #[test]
    fn install_uses_bucket_package_ref_and_architecture() {
        let mut request = make_request();
        request.package.architecture = Some(Architecture::X64);
        request.options.skip_hash_check = true;

        let cmd = build_scoop_command(&request).expect("build command");
        let script = script_of(&cmd);

        assert!(script.contains("Get-Command -Name 'scoop.ps1'"));
        assert!(script.contains("& $scoop 'install' 'main/7zip' '--skip-hash-check' '--arch' '64bit'"));
        assert!(script.contains("; exit $LASTEXITCODE;"));
    }

    #[test]
    fn update_uses_update_verb_and_custom_parameters() {
        let mut request = make_request();
        request.operation = Operation::Update;
        request.source.name = "versions".to_owned();
        request.options.custom_parameters = vec![CustomParameterString("--quiet".to_owned())];

        let cmd = build_scoop_command(&request).expect("build command");
        let script = script_of(&cmd);

        assert!(script.contains("& $scoop 'update' 'versions/7zip' '--quiet'"));
    }

    #[test]
    fn uninstall_allows_custom_purge_parameter() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.options.custom_parameters = vec![CustomParameterString("--purge".to_owned())];

        let cmd = build_scoop_command(&request).expect("build command");
        let script = script_of(&cmd);

        assert!(script.contains("& $scoop 'uninstall' 'main/7zip' '--purge'"));
        assert!(!script.contains("--skip-hash-check"));
    }

    #[test]
    fn direct_manifest_source_omits_bucket_prefix() {
        let mut request = make_request();
        request.source.name = "https://example.test/app.json".to_owned();

        let cmd = build_scoop_command(&request).expect("build command");
        let script = script_of(&cmd);

        assert!(script.contains("& $scoop 'install' '7zip'"));
        assert!(!script.contains("https://example.test/app.json/7zip"));
    }

    #[test]
    fn elevated_execution_is_rejected() {
        let mut request = make_request();
        request.client.requested_elevation = Elevation::Elevated;

        let error = build_scoop_command(&request).expect_err("elevated Scoop should fail");

        assert!(error.to_string().contains("elevated execution"));
    }

    #[test]
    fn machine_scope_is_rejected() {
        let mut request = make_request();
        request.options.scope = Some(Scope::Machine);

        let error = build_scoop_command(&request).expect_err("machine-scope Scoop should fail");

        assert!(error.to_string().contains("machine/global scope"));
    }

    #[test]
    fn global_custom_parameter_is_rejected() {
        let mut request = make_request();
        request.options.custom_parameters = vec![CustomParameterString("--global".to_owned())];

        let error = build_scoop_command(&request).expect_err("global parameter should fail");

        assert!(error.to_string().contains("global scope custom parameters"));
    }

    #[test]
    fn unsupported_options_are_rejected() {
        let mut request = make_request();
        request.package.version = Some(VersionString("1.2.3".to_owned()));
        assert!(
            build_scoop_command(&request)
                .expect_err("version should fail")
                .to_string()
                .contains("versions")
        );

        let mut request = make_request();
        request.options.custom_install_location = Some("C:\\Tools".to_owned());
        assert!(
            build_scoop_command(&request)
                .expect_err("install location should fail")
                .to_string()
                .contains("custom install locations")
        );

        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.options.skip_hash_check = true;
        assert!(
            build_scoop_command(&request)
                .expect_err("skip hash uninstall should fail")
                .to_string()
                .contains("skip-hash-check")
        );
    }
}
