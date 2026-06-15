//! PowerShell command-line builders for WinPS 5.x and PowerShell 7.x.
//!
//! These mirror UniGetUI's own PowerShell manager helpers so the broker runs the
//! same command the unelevated client would have run:
//! - PowerShell 5 uses PowerShellGet (`Install-Module`/`Update-Module`/`Uninstall-Module`)
//!   invoked as `powershell.exe -NoProfile -Command <script>`.
//! - PowerShell 7 uses PSResourceGet (`Install-PSResource`/`Update-PSResource`/
//!   `Uninstall-PSResource`) invoked as `pwsh.exe -NoProfile -Command <script>`.
//!
//! Like UniGetUI, neither builder pins a `-Repository`/source: the package source is
//! part of the policy-matched request identity, but the executed command lets the
//! PowerShell module resolver pick the repository. Options that don't apply to
//! PowerShell modules (interactive, custom install location, winget's no-upgrade /
//! uninstall-previous) are intentionally omitted.

use crate::model::{Operation, PackageRequest, Scope};

/// Build a Windows PowerShell 5.x (PowerShellGet) command from a validated request.
pub fn build_powershell5_command(request: &PackageRequest) -> Vec<String> {
    let mut script = String::new();

    let verb = match request.operation {
        Operation::Install => "Install-Module",
        Operation::Update => "Update-Module",
        Operation::Uninstall => "Uninstall-Module",
    };

    append_raw(&mut script, verb);
    append_flag_value(&mut script, "-Name", &request.package.id.0);
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

/// Build a PowerShell 7.x (PSResourceGet) command from a validated request.
pub fn build_powershell7_command(request: &PackageRequest) -> Vec<String> {
    let mut script = String::new();

    let verb = match request.operation {
        Operation::Install => "Install-PSResource",
        Operation::Update => "Update-PSResource",
        Operation::Uninstall => "Uninstall-PSResource",
    };

    append_raw(&mut script, verb);
    append_flag_value(&mut script, "-Name", &request.package.id.0);
    append_raw(&mut script, "-Confirm:$false");

    match request.operation {
        Operation::Install => {
            if let Some(version) = request.package.version.as_deref() {
                append_flag_value(&mut script, "-Version", version);
            }
        }
        Operation::Update => append_raw(&mut script, "-Force"),
        // Uninstall removes the installed resource without pinning a version.
        Operation::Uninstall => {}
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
            capture_output: false,
        }
    }

    /// The full PowerShell command line is `exe -NoProfile -Command <script>`.
    fn script_of(cmd: &[String]) -> &str {
        assert_eq!(cmd[1], "-NoProfile");
        assert_eq!(cmd[2], "-Command");
        &cmd[3]
    }

    #[test]
    fn powershell5_install_matches_unigetui_semantics() {
        let request = make_request(ManagerName::PowerShell);
        let cmd = build_powershell5_command(&request);
        let script = script_of(&cmd);
        assert_eq!(cmd[0], "powershell.exe");
        // verb, then -Name <id>, -Confirm:$false, -Force.
        assert!(script.starts_with("Install-Module -Name \"Pester\" -Confirm:$false -Force"));
        assert!(script.contains("-Scope CurrentUser"));
        assert!(script.contains("-RequiredVersion \"5.6.0\""));
        // UniGetUI does not pin a repository for PowerShell operations.
        assert!(!script.contains("-Repository"));
    }

    #[test]
    fn powershell5_machine_scope_is_allusers() {
        let mut request = make_request(ManagerName::PowerShell);
        request.options.scope = Some(Scope::Machine);
        let script = build_powershell5_command(&request)[3].clone();
        assert!(script.contains("-Scope AllUsers"));
    }

    #[test]
    fn powershell5_prerelease_and_skiphash() {
        let mut request = make_request(ManagerName::PowerShell);
        request.options.pre_release = true;
        request.options.skip_hash_check = true;
        let script = build_powershell5_command(&request)[3].clone();
        assert!(script.contains("-AllowPrerelease"));
        assert!(script.contains("-SkipPublisherCheck"));
    }

    #[test]
    fn powershell5_uninstall_omits_scope_and_version() {
        let mut request = make_request(ManagerName::PowerShell);
        request.operation = Operation::Uninstall;
        let script = build_powershell5_command(&request)[3].clone();
        assert!(script.starts_with("Uninstall-Module -Name \"Pester\""));
        assert!(!script.contains("-Scope"));
        assert!(!script.contains("-RequiredVersion"));
        assert!(!script.contains("-SkipPublisherCheck"));
    }

    #[test]
    fn powershell7_install_matches_unigetui_semantics() {
        let request = make_request(ManagerName::PowerShell7);
        let cmd = build_powershell7_command(&request);
        let script = script_of(&cmd);
        assert_eq!(cmd[0], "pwsh.exe");
        assert!(script.starts_with("Install-PSResource -Name \"Pester\" -Confirm:$false"));
        assert!(script.contains("-Version \"5.6.0\""));
        assert!(script.contains("-TrustRepository"));
        assert!(script.contains("-AcceptLicense"));
        assert!(script.contains("-Scope CurrentUser"));
        assert!(!script.contains("-Repository"));
    }

    #[test]
    fn powershell7_update_uses_force_not_version() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.operation = Operation::Update;
        let script = build_powershell7_command(&request)[3].clone();
        assert!(script.contains("Update-PSResource"));
        assert!(script.contains("-Force"));
        assert!(!script.contains("-Version"));
        assert!(script.contains("-TrustRepository"));
    }

    #[test]
    fn powershell7_uninstall_omits_version_and_trust_flags() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.operation = Operation::Uninstall;
        let script = build_powershell7_command(&request)[3].clone();
        assert!(script.starts_with("Uninstall-PSResource -Name \"Pester\" -Confirm:$false"));
        // Uninstall must not pin a version (it would remove only the matching version,
        // or fail if it does not match what is installed).
        assert!(!script.contains("-Version"));
        assert!(!script.contains("-TrustRepository"));
        assert!(!script.contains("-AcceptLicense"));
        assert!(!script.contains("-Scope"));
    }

    #[test]
    fn powershell_custom_parameters_are_appended() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.options.custom_parameters = vec![CustomParameterString("-Reinstall".to_owned())];
        let script = build_powershell7_command(&request)[3].clone();
        assert!(script.contains("-Reinstall"));
    }
}
