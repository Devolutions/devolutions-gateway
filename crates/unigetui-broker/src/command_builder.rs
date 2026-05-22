//! Command-line builder for WinGet operations.
//!
//! Constructs the command the broker would execute from validated request fields.
//! The broker never executes client-supplied commands directly.

use crate::models::PackageRequest;

/// Build the WinGet command line from a validated request.
///
/// Returns the command as a list of arguments (first element is the executable).
pub fn build_winget_command(request: &PackageRequest) -> Vec<String> {
    let operation = match request.operation.as_str() {
        "install" => "install",
        "update" => "upgrade",
        "uninstall" => "uninstall",
        other => panic!("unsupported operation: {other}"),
    };

    let mut command = vec![
        "winget.exe".to_owned(),
        operation.to_owned(),
        "--id".to_owned(),
        request.package.id.clone(),
        "--exact".to_owned(),
    ];

    add_pair(&mut command, "--source", Some(&request.source.name));
    add_pair(&mut command, "--scope", request.options.scope.as_deref());

    // Version: use explicit version option first, then package new_version for updates.
    let version = request
        .options
        .version
        .as_deref()
        .or(request.package.new_version.as_deref());
    add_pair(&mut command, "--version", version);

    if request.options.interactive.unwrap_or(false) {
        command.push("--interactive".to_owned());
    } else {
        command.push("--silent".to_owned());
    }

    add_pair(&mut command, "--architecture", request.options.architecture.as_deref());

    if request.options.skip_hash_check.unwrap_or(false) {
        command.push("--ignore-security-hash".to_owned());
    }

    add_pair(
        &mut command,
        "--location",
        request.options.custom_install_location.as_deref(),
    );

    // Append any custom parameters.
    if let Some(params) = &request.options.custom_parameters {
        for param in params {
            if !param.is_empty() {
                command.push(param.clone());
            }
        }
    }

    // Accept source agreements non-interactively.
    command.push("--accept-source-agreements".to_owned());
    command.push("--accept-package-agreements".to_owned());

    command
}

fn add_pair(command: &mut Vec<String>, flag: &str, value: Option<&str>) {
    if let Some(v) = value {
        if !v.is_empty() {
            command.push(flag.to_owned());
            command.push(v.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    #[test]
    fn test_basic_install_command() {
        let request = PackageRequest {
            request_version: "1.0.0".to_owned(),
            request_type: "packageOperation".to_owned(),
            request_id: "test".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            operation: "install".to_owned(),
            manager: RequestManager {
                name: "Winget".to_owned(),
                display_name: None,
                executable_friendly_name: None,
            },
            source: RequestSource {
                name: "winget".to_owned(),
                url: None,
                is_virtual_manager: None,
            },
            package: RequestPackage {
                id: "Microsoft.VisualStudioCode".to_owned(),
                name: "VS Code".to_owned(),
                version: None,
                new_version: None,
            },
            options: RequestOptions {
                scope: Some("machine".to_owned()),
                architecture: Some("x64".to_owned()),
                interactive: Some(false),
                run_as_administrator: Some(true),
                skip_hash_check: Some(false),
                pre_release: Some(false),
                version: None,
                custom_parameters: Some(vec![]),
                custom_install_location: None,
                kill_before_operation: None,
                pre_operation_command: None,
                post_operation_command: None,
            },
            broker: BrokerContext {
                requested_elevation: "elevated".to_owned(),
                effective_user: "TEST\\user".to_owned(),
                client_version: "3.0.0".to_owned(),
            },
        };

        let cmd = build_winget_command(&request);
        assert_eq!(cmd[0], "winget.exe");
        assert_eq!(cmd[1], "install");
        assert!(cmd.contains(&"--id".to_owned()));
        assert!(cmd.contains(&"Microsoft.VisualStudioCode".to_owned()));
        assert!(cmd.contains(&"--exact".to_owned()));
        assert!(cmd.contains(&"--silent".to_owned()));
        assert!(cmd.contains(&"--scope".to_owned()));
        assert!(cmd.contains(&"machine".to_owned()));
    }

    #[test]
    fn test_upgrade_command() {
        let request = PackageRequest {
            request_version: "1.0.0".to_owned(),
            request_type: "packageOperation".to_owned(),
            request_id: "test".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            operation: "update".to_owned(),
            manager: RequestManager {
                name: "Winget".to_owned(),
                display_name: None,
                executable_friendly_name: None,
            },
            source: RequestSource {
                name: "winget".to_owned(),
                url: None,
                is_virtual_manager: None,
            },
            package: RequestPackage {
                id: "Git.Git".to_owned(),
                name: "Git".to_owned(),
                version: Some("2.40.0".to_owned()),
                new_version: Some("2.41.0".to_owned()),
            },
            options: RequestOptions {
                scope: None,
                architecture: None,
                interactive: Some(false),
                run_as_administrator: None,
                skip_hash_check: None,
                pre_release: None,
                version: None,
                custom_parameters: None,
                custom_install_location: None,
                kill_before_operation: None,
                pre_operation_command: None,
                post_operation_command: None,
            },
            broker: BrokerContext {
                requested_elevation: "elevated".to_owned(),
                effective_user: "TEST\\user".to_owned(),
                client_version: "3.0.0".to_owned(),
            },
        };

        let cmd = build_winget_command(&request);
        assert_eq!(cmd[1], "upgrade");
        assert!(cmd.contains(&"--version".to_owned()));
        assert!(cmd.contains(&"2.41.0".to_owned()));
    }
}
