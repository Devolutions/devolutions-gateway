//! WinGet command-line builder.

use super::{set_if_specified, set_if_true};
use crate::model::{Architecture, Operation, PackageRequest, Scope};

/// Build the WinGet command line from a validated request.
///
/// Returns the command as a list of arguments (first element is the executable).
pub fn build_winget_command(request: &PackageRequest) -> Vec<String> {
    let operation = match request.operation {
        Operation::Install => "install",
        Operation::Update => "upgrade",
        Operation::Uninstall => "uninstall",
    };

    let mut command = vec![
        "winget.exe".to_owned(),
        operation.to_owned(),
        "--id".to_owned(),
        request.package.id.0.clone(),
        "--source".to_owned(),
        request.source.name.clone(),
        "--exact".to_owned(),
        "--accept-source-agreements".to_owned(),
    ];

    set_if_specified(&mut command, "--version", request.package.version.as_deref());

    set_if_specified(
        &mut command,
        "--architecture",
        request.package.architecture.map(|arch| match arch {
            Architecture::X86 => "x86",
            Architecture::X64 => "x64",
            Architecture::Arm64 => "arm64",
            Architecture::Neutral => "neutral",
        }),
    );

    set_if_specified(
        &mut command,
        "--scope",
        match request.options.scope {
            Some(Scope::User) => Some("user"),
            Some(Scope::Machine) => Some("machine"),
            None => None,
        },
    );

    set_if_true(&mut command, "--interactive", request.options.interactive);

    set_if_true(&mut command, "--silent", !request.options.interactive);
    set_if_true(&mut command, "--disable-interactivity", !request.options.interactive);

    set_if_true(&mut command, "--ignore-security-hash", request.options.skip_hash_check);

    set_if_specified(
        &mut command,
        "--location",
        request.options.custom_install_location.as_deref(),
    );

    // Append any custom parameters.
    for param in &request.options.custom_parameters {
        if !param.is_empty() {
            command.push(param.0.clone());
        }
    }

    if matches!(request.operation, Operation::Install | Operation::Update) {
        command.push("--accept-package-agreements".to_owned());
    }

    command
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::model::*;

    fn make_request() -> PackageRequest {
        PackageRequest {
            _schema: RequestSchemaUri,
            request_version: SemanticVersion::from("1.0.0"),
            request_type: PackageOperation,
            request_id: ResourceId::from("req-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: RequestManager {
                name: ManagerName::Winget,
                display_name: "WinGet".to_owned(),
                executable_friendly_name: "winget".to_owned(),
            },
            source: RequestSource {
                name: "winget".to_owned(),
                url: None,
                is_virtual_manager: None,
            },
            package: RequestPackage {
                id: PackageIdentifier::from("Mozilla.Firefox".to_owned()),
                name: "Firefox".to_owned(),
                version: None,
                architecture: None,
                channel: None,
            },
            options: RequestOptions {
                scope: None,
                interactive: false,
                run_as_administrator: false,
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
            broker: BrokerContext {
                requested_elevation: Elevation::Elevated,
                effective_user: "DOMAIN\\user".to_owned(),
                client_version: None,
                client_process_path: None,
            },
        }
    }

    #[test]
    fn test_basic_install_command() {
        let request = make_request();
        let cmd = build_winget_command(&request);
        assert_eq!(cmd[0], "winget.exe");
        assert_eq!(cmd[1], "install");
        assert!(cmd.contains(&"--id".to_owned()));
        assert!(cmd.contains(&"Mozilla.Firefox".to_owned()));
        assert!(cmd.contains(&"--silent".to_owned()));
        assert!(cmd.contains(&"--accept-source-agreements".to_owned()));
    }

    #[test]
    fn test_upgrade_command() {
        let mut request = make_request();
        request.operation = Operation::Update;
        request.package.version = Some(SemanticVersion::from("120.0.0"));

        let cmd = build_winget_command(&request);
        assert_eq!(cmd[1], "upgrade");
        assert!(cmd.contains(&"--version".to_owned()));
        assert!(cmd.contains(&"120.0.0".to_owned()));
    }
}
