//! Command-line builder for WinGet operations.
//!
//! Constructs the command the broker would execute from validated request fields.
//! The broker never executes client-supplied commands directly.

use crate::models::{Operation, PackageRequest, Scope};

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
        "--exact".to_owned(),
    ];

    add_pair(&mut command, "--source", Some(&request.source.name));

    if let Some(scope) = &request.options.scope {
        let scope_str = match scope {
            Scope::User => "user",
            Scope::Machine => "machine",
        };
        command.push("--scope".to_owned());
        command.push(scope_str.to_owned());
    }

    // Version: use explicit version option first, then package new_version for updates.
    let version = request
        .options
        .version
        .as_deref()
        .or(request.package.new_version.as_deref());
    add_pair(&mut command, "--version", version);

    if request.options.interactive {
        command.push("--interactive".to_owned());
    } else {
        command.push("--silent".to_owned());
    }

    if let Some(arch) = &request.options.architecture {
        command.push("--architecture".to_owned());
        command.push(arch.to_string());
    }

    if request.options.skip_hash_check {
        command.push("--ignore-security-hash".to_owned());
    }

    add_pair(
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

    // Accept agreements non-interactively.
    command.push("--accept-source-agreements".to_owned());
    if matches!(request.operation, Operation::Install | Operation::Update) {
        command.push("--accept-package-agreements".to_owned());
    }

    command
}

fn add_pair(command: &mut Vec<String>, flag: &str, value: Option<&str>) {
    if let Some(v) = value
        && !v.is_empty()
    {
        command.push(flag.to_owned());
        command.push(v.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::models::*;

    fn make_request() -> PackageRequest {
        PackageRequest {
            schema: RequestSchemaUri,
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
                current_version: None,
                new_version: None,
                channel: None,
            },
            options: RequestOptions {
                scope: None,
                architecture: None,
                version: None,
                interactive: false,
                run_as_administrator: false,
                skip_hash_check: false,
                pre_release: false,
                custom_install_location: None,
                custom_parameters: Vec::new(),
                pre_operation_command: None,
                post_operation_command: None,
                kill_before_operation: Vec::new(),
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
        request.package.new_version = Some(SemanticVersion::from("120.0.0"));

        let cmd = build_winget_command(&request);
        assert_eq!(cmd[1], "upgrade");
        assert!(cmd.contains(&"--version".to_owned()));
        assert!(cmd.contains(&"120.0.0".to_owned()));
    }
}
