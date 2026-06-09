//! PowerShell command-line builders for WinPS 5.x and PowerShell 7.x.

use crate::model::{Operation, PackageRequest, Scope};

/// Build a Windows PowerShell 5.x command from a validated request.
pub fn build_powershell5_command(request: &PackageRequest) -> Vec<String> {
    let mut script = String::new();

    let verb = match request.operation {
        Operation::Install => "Install-Module",
        Operation::Update => "Update-Module",
        Operation::Uninstall => "Uninstall-Module",
    };

    append_flag_value(&mut script, verb, &request.package.id.0);
    append_raw(&mut script, "-Confirm:$false");
    append_raw(&mut script, "-Force");

    if !matches!(request.operation, Operation::Uninstall) {
        if request.options.pre_release {
            append_raw(&mut script, "-AllowPrerelease");
        }

        match request.options.scope {
            Some(Scope::Machine) => append_raw(&mut script, "-Scope AllUsers"),
            Some(Scope::User) | None => append_raw(&mut script, "-Scope CurrentUser"),
        }
    }

    if matches!(request.operation, Operation::Install) {
        if request.options.skip_hash_check {
            append_raw(&mut script, "-SkipPublisherCheck");
        }

        if let Some(version) = request.package.version.as_deref() {
            append_flag_value(&mut script, "-RequiredVersion", version);
        }
    }

    for param in &request.options.custom_parameters {
        if !param.is_empty() {
            append_raw(&mut script, &param.0);
        }
    }

    vec![
        "powershell.exe".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        script,
    ]
}

/// Build a PowerShell 7.x command from a validated request.
pub fn build_powershell7_command(request: &PackageRequest) -> Vec<String> {
    let mut script = String::new();

    let verb = match request.operation {
        Operation::Install => "Install-PSResource",
        Operation::Update => "Update-PSResource",
        Operation::Uninstall => "Uninstall-PSResource",
    };

    append_flag_value(&mut script, verb, &request.package.id.0);
    append_raw(&mut script, "-Confirm:$false");

    match request.operation {
        Operation::Install => {
            if let Some(version) = request.package.version.as_deref() {
                append_flag_value(&mut script, "-Version", version);
            }
        }
        Operation::Update => append_raw(&mut script, "-Force"),
        Operation::Uninstall => {
            if let Some(version) = request.package.version.as_deref() {
                append_flag_value(&mut script, "-Version", version);
            }
        }
    }

    if !matches!(request.operation, Operation::Uninstall) {
        append_raw(&mut script, "-TrustRepository");
        append_raw(&mut script, "-AcceptLicense");

        if request.options.pre_release {
            append_raw(&mut script, "-Prerelease");
        }

        match request.options.scope {
            Some(Scope::Machine) => append_raw(&mut script, "-Scope AllUsers"),
            Some(Scope::User) | None => append_raw(&mut script, "-Scope CurrentUser"),
        }
    }

    for param in &request.options.custom_parameters {
        if !param.is_empty() {
            append_raw(&mut script, &param.0);
        }
    }

    vec![
        "pwsh.exe".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        script,
    ]
}

fn append_raw(script: &mut String, value: &str) {
    if !script.is_empty() {
        script.push(' ');
    }
    script.push_str(value);
}

fn append_flag_value(script: &mut String, flag_or_verb: &str, value: &str) {
    append_raw(script, flag_or_verb);
    append_raw(script, &quote_ps(value));
}

fn quote_ps(value: &str) -> String {
    let escaped = value.replace('"', "`\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::model::*;

    fn make_request(manager: ManagerName) -> PackageRequest {
        PackageRequest {
            _schema: RequestSchemaUri,
            request_version: SemanticVersion::from("1.0.0"),
            request_type: PackageOperation,
            request_id: ResourceId::from("req-ps-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: RequestManager {
                name: manager,
                display_name: "PowerShell".to_owned(),
                executable_friendly_name: "pwsh.exe".to_owned(),
            },
            source: RequestSource {
                name: "PSGallery".to_owned(),
                url: None,
                is_virtual_manager: None,
            },
            package: RequestPackage {
                id: PackageIdentifier::from("Pester".to_owned()),
                name: "Pester".to_owned(),
                version: Some(VersionString("5.6.0".to_owned())),
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
            broker: BrokerContext {
                requested_elevation: Elevation::Elevated,
                effective_user: "DOMAIN\\user".to_owned(),
                client_version: None,
                client_process_path: None,
            },
        }
    }

    #[test]
    fn powershell5_builder_uses_install_module() {
        let request = make_request(ManagerName::PowerShell);
        let cmd = build_powershell5_command(&request);
        assert_eq!(cmd[0], "powershell.exe");
        assert!(cmd[3].contains("Install-Module"));
        assert!(cmd[3].contains("-Scope CurrentUser"));
        assert!(cmd[3].contains("-RequiredVersion"));
    }

    #[test]
    fn powershell7_builder_uses_install_psresource() {
        let request = make_request(ManagerName::PowerShell7);
        let cmd = build_powershell7_command(&request);
        assert_eq!(cmd[0], "pwsh.exe");
        assert!(cmd[3].contains("Install-PSResource"));
        assert!(cmd[3].contains("-TrustRepository"));
        assert!(cmd[3].contains("-AcceptLicense"));
    }
}
