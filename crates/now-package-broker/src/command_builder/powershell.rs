//! PowerShell command-line builders for WinPS 5.x and PowerShell 7.x.
//!
//! These mirror package broker client PowerShell manager helpers so the broker runs the
//! same command the unelevated client would have run:
//! - PowerShell 5 uses PowerShellGet (`Install-Module`/`Update-Module`/`Uninstall-Module`)
//!   prepared as `powershell.exe -NoProfile -Command <script>`.
//! - PowerShell 7 uses PSResourceGet (`Install-PSResource`/`Update-PSResource`/
//!   `Uninstall-PSResource`) prepared as `pwsh.exe -NoProfile -Command <script>`.
//!
//! The Windows executor materializes these scripts into temporary `.ps1` files before launch.
//!
//! Both builders bind the policy-matched request source as the PowerShell repository and
//! pin the invariant culture so repository lookup does not depend on the host locale.
//! Uninstall and `Update-Module` take no `-Repository`: they act on installed modules, and
//! `Update-Module` updates from the repository a module was installed from. Those commands
//! first check that every installed version came from the requested source instead.
//! Options that don't apply to PowerShell modules (interactive, custom install
//! location, winget's no-upgrade / uninstall-previous) are intentionally omitted.

use anyhow::bail;
use now_policy_api::{ManagerName, Operation, PackageRequest, Scope};

use super::{quote_powershell_literal, uses_default_source, validate_package_version, validate_source_name};

/// Version range syntax accepted by PSResourceGet, such as `[1.0, 2.0)` or `1.*`.
const POWERSHELL7_VERSION_RANGE_CHARACTERS: &[char] = &['[', ']', '(', ')', ',', '*', ' '];

/// Makes every error terminate the script with a nonzero exit, and pins culture-sensitive
/// lookups, including `-Repository` name matching, to the invariant culture instead of the
/// host locale.
///
/// The preference is global because script-module functions such as PowerShellGet's
/// `Install-Module` read it from the global scope, not from the calling script.
const SCRIPT_PREFIX: &str = "$global:ErrorActionPreference = 'Stop'; [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture;";

/// The executor reports the script's exit code, and a script that reaches its end without an
/// error has succeeded.
const SCRIPT_SUFFIX: &str = "; exit 0";

/// Build a Windows PowerShell 5.x (PowerShellGet) command from a validated request.
pub fn build_powershell5_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_powershell_request(request, false)?;

    let mut script = SCRIPT_PREFIX.to_owned();

    if request.operation != Operation::Install {
        // PowerShellGet 1.x has no `-AllowPrerelease`; 2.x lists prerelease versions only with it.
        append_raw(&mut script, "$installedModuleQuery = @{ Name =");
        append_raw(&mut script, &quote_powershell_literal(&request.package.id.0));
        append_raw(
            &mut script,
            "; AllVersions = $true; ErrorAction = 'Stop' }; if ((Get-Command Get-InstalledModule).Parameters.ContainsKey('AllowPrerelease')) { $installedModuleQuery.AllowPrerelease = $true };",
        );
        append_installed_repository_check(&mut script, "Get-InstalledModule @installedModuleQuery", request)?;
    }

    let verb = match request.operation {
        Operation::Install => "Install-Module",
        Operation::Update => "Update-Module",
        Operation::Uninstall => "Uninstall-Module",
    };

    append_raw(&mut script, verb);
    append_flag_value(&mut script, "-Name", &request.package.id.0);
    if request.operation == Operation::Install {
        append_repository(&mut script, request)?;
    }
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

    if matches!(request.operation, Operation::Install | Operation::Update) {
        // `Update-Module` has no `-SkipPublisherCheck`, so updates keep the publisher check.
        if request.options.skip_hash_check && request.operation == Operation::Install {
            append_raw(&mut script, "-SkipPublisherCheck");
        }

        if let Some(version) = request.package.version.as_deref() {
            append_flag_value(&mut script, "-RequiredVersion", version);
        }
    }

    script.push_str(SCRIPT_SUFFIX);

    Ok(vec![
        "powershell.exe".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        script,
    ])
}

/// Build a PowerShell 7.x (PSResourceGet) command from a validated request.
pub fn build_powershell7_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    build_powershell7(request, false)
}

/// Build a PowerShell 7.x command for a remote grant.
///
/// Unlike [`build_powershell7_command`], this accepts an update with an empty source and
/// passes an authorized installed scope to uninstall.
/// The caller must enforce the grant's target-user token and requested elevation.
pub(super) fn build_powershell7_remote_grant_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    build_powershell7(request, true)
}

fn build_powershell7(request: &PackageRequest, remote_grant: bool) -> anyhow::Result<Vec<String>> {
    validate_powershell_request(request, remote_grant)?;

    let mut script = SCRIPT_PREFIX.to_owned();

    if request.operation == Operation::Uninstall {
        let lookup = format!(
            "Get-InstalledPSResource -Name {} -ErrorAction Stop",
            quote_powershell_literal(&request.package.id.0)
        );
        append_installed_repository_check(&mut script, &lookup, request)?;
    }

    let verb = match request.operation {
        Operation::Install => "Install-PSResource",
        Operation::Update => "Update-PSResource",
        Operation::Uninstall => "Uninstall-PSResource",
    };

    append_raw(&mut script, verb);
    append_flag_value(&mut script, "-Name", &request.package.id.0);
    if request.operation != Operation::Uninstall
        && let Some(repository) = repository(request)?
    {
        append_flag_value(&mut script, "-Repository", repository);
    }
    append_raw(&mut script, "-Confirm:$false");

    match request.operation {
        Operation::Install | Operation::Update => {
            if let Some(version) = request.package.version.as_deref() {
                append_flag_value(&mut script, "-Version", version);
            }
            if matches!(request.operation, Operation::Update) {
                append_raw(&mut script, "-Force");
            }
        }
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
    } else if remote_grant {
        match request.options.scope {
            Some(Scope::Machine) => append_raw(&mut script, "-Scope AllUsers"),
            Some(Scope::User) => append_raw(&mut script, "-Scope CurrentUser"),
            None => {}
        }
    }

    script.push_str(SCRIPT_SUFFIX);

    Ok(vec![
        "pwsh.exe".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        script,
    ])
}

fn validate_powershell_request(request: &PackageRequest, allow_default_update_source: bool) -> anyhow::Result<()> {
    if request.source.url.is_some() {
        bail!("PowerShell package sources with URLs are not supported by the broker");
    }
    let repository = repository(request)?;
    // Update-PSResource without -Repository searches every registered repository and the script trusts them.
    if repository.is_none()
        && !allow_default_update_source
        && request.manager == ManagerName::PowerShell7
        && request.operation == Operation::Update
    {
        bail!("PowerShell 7 updates require a named package source");
    }
    // `Update-Module -Name` and PSResourceGet accept wildcard patterns.
    if request.package.id.0.contains(['*', '?', '[', ']']) {
        bail!("PowerShell module names cannot contain wildcard characters");
    }
    if let Some(repository) = repository {
        validate_source_name("PowerShell", repository)?;
    }
    // Uninstall ignores the version, so only versions that reach the command are restricted.
    if request.operation != Operation::Uninstall
        && let Some(version) = request.package.version.as_deref()
    {
        // Only PSResourceGet's `-Version` accepts ranges; PowerShellGet's `-RequiredVersion` is exact.
        let extra = if request.manager == ManagerName::PowerShell7 {
            POWERSHELL7_VERSION_RANGE_CHARACTERS
        } else {
            &[]
        };
        validate_package_version("PowerShell", version, extra)?;
    }
    if let Some(param) = request.options.custom_parameters.iter().find(|param| !param.is_empty()) {
        bail!(
            "PowerShell custom parameters are not supported by the broker: {}",
            param.0
        );
    }

    Ok(())
}

/// The repository name, or `None` when update or uninstall leaves the source to the manager.
fn repository(request: &PackageRequest) -> anyhow::Result<Option<&str>> {
    if uses_default_source("PowerShell", request)? {
        return Ok(None);
    }
    let repository = request.source.name.trim();
    if repository.is_empty() {
        bail!("PowerShell package source name is required");
    }
    Ok(Some(repository))
}

fn append_repository(script: &mut String, request: &PackageRequest) -> anyhow::Result<()> {
    let Some(repository) = repository(request)? else {
        bail!("PowerShell package source name is required");
    };
    append_flag_value(script, "-Repository", repository);
    Ok(())
}

/// Fail the script unless every installed version that `lookup` lists was installed from
/// the requested source, so a command without `-Repository` only acts on modules from the
/// source that policy evaluation matched.
/// An empty source acts on the installed module whatever repository it came from.
fn append_installed_repository_check(
    script: &mut String,
    lookup: &str,
    request: &PackageRequest,
) -> anyhow::Result<()> {
    let Some(repository) = repository(request)? else {
        return Ok(());
    };
    append_raw(
        script,
        &format!(
            "if (@({lookup} | Where-Object {{ $_.Repository -ne {} }}).Count -ne 0) {{ throw 'The installed module was not installed from the requested repository.' }};",
            quote_powershell_literal(repository),
        ),
    );
    Ok(())
}

fn append_raw(script: &mut String, value: &str) {
    if !script.is_empty() {
        script.push(' ');
    }
    script.push_str(value);
}

fn append_flag_value(script: &mut String, flag_or_verb: &str, value: &str) {
    append_raw(script, flag_or_verb);
    append_raw(script, &quote_powershell_literal(value));
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use now_policy_api::*;

    use super::*;

    fn make_request(manager: ManagerName) -> PackageRequest {
        PackageRequest {
            request_kind: PackageRequestKind,
            request_version: API_VERSION_STR.into(),
            request_id: ResourceId::from("req-ps-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager,
            source: RequestSource {
                name: "PSGallery".to_owned(),
                url: None,
            },
            package: RequestPackage {
                id: PackageIdentifier::from("Pester".to_owned()),
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

    /// The full PowerShell command line is `exe -NoProfile -Command <script>`.
    fn script_of(cmd: &[String]) -> &str {
        assert_eq!(cmd[1], "-NoProfile");
        assert_eq!(cmd[2], "-Command");
        &cmd[3]
    }

    /// Split a script into the statements before the `verb` call and the call itself.
    fn split_at_call<'a>(script: &'a str, verb: &str) -> (&'a str, &'a str) {
        script.split_at(script.find(verb).expect("package command call"))
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn empty_source_update_and_uninstall_skip_repository_checks() {
        for (manager, operation) in [
            (ManagerName::PowerShell, Operation::Update),
            (ManagerName::PowerShell, Operation::Uninstall),
            (ManagerName::PowerShell7, Operation::Uninstall),
        ] {
            let mut request = make_request(manager);
            request.operation = operation;
            request.source.name = String::new();
            let cmd = if manager == ManagerName::PowerShell {
                build_powershell5_command(&request)
            } else {
                build_powershell7_command(&request)
            }
            .expect("empty source");
            let script = script_of(&cmd);
            assert!(!script.contains("-Repository"), "{script}");
            assert!(!script.contains("Where-Object"), "{script}");
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn remote_grant_allows_powershell7_default_source_update_only() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.operation = Operation::Update;
        request.source.name = String::new();

        build_powershell7_command(&request).expect_err("local policy requires a named source");

        let cmd = build_powershell7_remote_grant_command(&request).expect("grant update");
        let script = script_of(&cmd);
        // oracle: reference PSResourceGet 1.2.0 `Update-PSResource`, the cmdlet that updates a resource
        assert!(script.contains("Update-PSResource"), "{script}");
        assert!(!script.contains("-Repository"), "{script}");

        request.operation = Operation::Install;
        build_powershell7_remote_grant_command(&request).expect_err("install still needs a source");

        request.operation = Operation::Update;
        request.source.url = Some("https://example.test/feed".to_owned());
        build_powershell7_remote_grant_command(&request).expect_err("URLs remain unsupported");
    }

    // oracle: mutant making the remote-grant update command differ from the local one, such as dropping `-Repository`, when the request names a source
    #[test]
    fn remote_grant_named_source_update_is_unchanged() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.operation = Operation::Update;

        assert_eq!(
            build_powershell7_remote_grant_command(&request).expect("grant"),
            build_powershell7_command(&request).expect("local"),
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    // The cmdlet's scope parameter selects the resource to remove:
    // https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.psresourceget/uninstall-psresource
    #[test]
    fn remote_grant_powershell7_uninstall_selects_reported_scope() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.operation = Operation::Uninstall;
        request.source.name = String::new();
        request.options.scope = Some(Scope::Machine);

        let remote = build_powershell7_remote_grant_command(&request).expect("grant uninstall");
        assert!(script_of(&remote).contains("-Scope AllUsers"));
        let local = build_powershell7_command(&request).expect("local uninstall");
        assert!(!script_of(&local).contains("-Scope"));

        request.options.scope = None;
        let remote = build_powershell7_remote_grant_command(&request).expect("grant uninstall");
        assert!(!script_of(&remote).contains("-Scope"));
    }

    #[test]
    fn empty_source_is_rejected_for_install_and_powershell7_update() {
        for (manager, operation) in [
            // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
            (ManagerName::PowerShell, Operation::Install),
            // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
            (ManagerName::PowerShell7, Operation::Install),
            // oracle: mutant accepting an empty source for a PowerShell 7 update on the local-policy path
            (ManagerName::PowerShell7, Operation::Update),
        ] {
            let mut request = make_request(manager);
            request.operation = operation;
            request.source.name = String::new();
            let result = if manager == ManagerName::PowerShell {
                build_powershell5_command(&request)
            } else {
                build_powershell7_command(&request)
            };
            result.expect_err("named source is required");
        }
    }
    #[test]
    fn powershell5_install_matches_package_broker_client_semantics() {
        let request = make_request(ManagerName::PowerShell);
        let cmd = build_powershell5_command(&request).expect("build command");
        let script = script_of(&cmd);
        assert_eq!(cmd[0], "powershell.exe");
        // verb, then -Name <id>, -Confirm:$false, -Force.
        assert!(script.starts_with(&format!(
            "{SCRIPT_PREFIX} Install-Module -Name 'Pester' -Repository 'PSGallery' -Confirm:$false -Force"
        )));
        assert!(script.contains("-Scope CurrentUser"));
        assert!(script.contains("-RequiredVersion '5.6.0'"));
    }

    #[test]
    fn powershell5_machine_scope_is_allusers() {
        let mut request = make_request(ManagerName::PowerShell);
        request.options.scope = Some(Scope::Machine);
        let cmd = build_powershell5_command(&request).expect("build command");
        let script = script_of(&cmd);
        assert!(script.contains("-Scope AllUsers"));
    }

    #[test]
    fn powershell5_prerelease_and_skiphash() {
        let mut request = make_request(ManagerName::PowerShell);
        request.options.pre_release = true;
        request.options.skip_hash_check = true;
        let cmd = build_powershell5_command(&request).expect("build command");
        let script = script_of(&cmd);
        assert!(script.contains("-AllowPrerelease"));
        assert!(script.contains("-SkipPublisherCheck"));
    }

    #[test]
    fn powershell5_uninstall_omits_scope_and_version() {
        let mut request = make_request(ManagerName::PowerShell);
        request.operation = Operation::Uninstall;
        let cmd = build_powershell5_command(&request).expect("build command");
        let (_, uninstall) = split_at_call(script_of(&cmd), "Uninstall-Module");
        // oracle: reference PowerShellGet 2.2.5 and 1.0.0.1 `Uninstall-Module`, which have no `-Repository` parameter
        assert!(uninstall.starts_with("Uninstall-Module -Name 'Pester' -Confirm:$false -Force"));
        assert!(!uninstall.contains("-Repository"));
        assert!(!uninstall.contains("-Scope"));
        assert!(!uninstall.contains("-RequiredVersion"));
        assert!(!uninstall.contains("-SkipPublisherCheck"));
    }

    // oracle: mutant dropping the installed-repository check that binds a command without `-Repository` to the requested source
    #[test]
    fn powershell_commands_without_repository_check_installed_repository() {
        for (manager, operation, verb, lookup) in [
            (
                ManagerName::PowerShell,
                Operation::Update,
                "Update-Module",
                "Get-InstalledModule @installedModuleQuery",
            ),
            (
                ManagerName::PowerShell,
                Operation::Uninstall,
                "Uninstall-Module",
                "Get-InstalledModule @installedModuleQuery",
            ),
            (
                ManagerName::PowerShell7,
                Operation::Uninstall,
                "Uninstall-PSResource",
                "Get-InstalledPSResource -Name 'Pester' -ErrorAction Stop",
            ),
        ] {
            let mut request = make_request(manager);
            request.operation = operation;
            let cmd = crate::command_builder::build_command(&request).expect("build command");
            let (check, _) = split_at_call(script_of(&cmd), verb);
            assert!(
                check.contains(&format!(
                    "if (@({lookup} | Where-Object {{ $_.Repository -ne 'PSGallery' }}).Count -ne 0) {{ throw "
                )),
                "{verb}: {check}"
            );
        }

        for (manager, operation) in [
            (ManagerName::PowerShell, Operation::Install),
            (ManagerName::PowerShell7, Operation::Install),
            (ManagerName::PowerShell7, Operation::Update),
        ] {
            let mut request = make_request(manager);
            request.operation = operation;
            let cmd = crate::command_builder::build_command(&request).expect("build command");
            assert!(!script_of(&cmd).contains("Get-Installed"), "{manager:?} {operation:?}");
        }
    }

    #[test]
    fn powershell5_installed_module_lookup_lists_every_version() {
        for operation in [Operation::Update, Operation::Uninstall] {
            let mut request = make_request(ManagerName::PowerShell);
            request.operation = operation;
            let cmd = build_powershell5_command(&request).expect("build command");
            let script = script_of(&cmd);
            assert!(script.contains("$installedModuleQuery = @{ Name = 'Pester' ; AllVersions = $true;"));
            // oracle: reference PowerShellGet 2.2.5 `Get-InstalledModule`, which lists prerelease versions only with `-AllowPrerelease`, a parameter PowerShellGet 1.0.0.1 lacks
            assert!(script.contains(
                "if ((Get-Command Get-InstalledModule).Parameters.ContainsKey('AllowPrerelease')) { $installedModuleQuery.AllowPrerelease = $true };"
            ));
        }
    }

    #[test]
    fn powershell5_update_omits_unsupported_parameters() {
        let mut request = make_request(ManagerName::PowerShell);
        request.operation = Operation::Update;
        request.options.skip_hash_check = true;
        let cmd = build_powershell5_command(&request).expect("build command");
        let (_, update) = split_at_call(script_of(&cmd), "Update-Module");
        assert!(update.starts_with("Update-Module -Name 'Pester' -Confirm:$false -Force"));
        // oracle: reference PowerShellGet 2.2.5 and 1.0.0.1 `Update-Module`, which have neither a `-Repository` nor a `-SkipPublisherCheck` parameter
        assert!(!update.contains("-Repository"));
        assert!(!update.contains("-SkipPublisherCheck"));
        assert!(update.contains("-Scope CurrentUser"));
        assert!(update.contains("-RequiredVersion '5.6.0'"));
    }

    // oracle: spec PowerShell about_Quoting_Rules §Single-quoted strings
    #[test]
    fn powershell5_update_repository_check_escapes_literals() {
        let mut request = make_request(ManagerName::PowerShell);
        request.operation = Operation::Update;
        request.package.id = PackageIdentifier::from("Vendor's.Module".to_owned());
        let cmd = build_powershell5_command(&request).expect("build command");
        let script = script_of(&cmd);
        assert!(script.contains("$installedModuleQuery = @{ Name = 'Vendor''s.Module' ;"));
        assert!(script.contains("Update-Module -Name 'Vendor''s.Module'"));
    }

    #[test]
    fn powershell7_install_matches_package_broker_client_semantics() {
        let request = make_request(ManagerName::PowerShell7);
        let cmd = build_powershell7_command(&request).expect("build command");
        let script = script_of(&cmd);
        assert_eq!(cmd[0], "pwsh.exe");
        assert!(script.starts_with(&format!(
            "{SCRIPT_PREFIX} Install-PSResource -Name 'Pester' -Repository 'PSGallery' -Confirm:$false"
        )));
        assert!(script.contains("-Version '5.6.0'"));
        assert!(script.contains("-TrustRepository"));
        assert!(script.contains("-AcceptLicense"));
        assert!(script.contains("-Scope CurrentUser"));
    }

    #[test]
    fn powershell7_update_uses_force_and_version() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.operation = Operation::Update;
        let cmd = build_powershell7_command(&request).expect("build command");
        let script = script_of(&cmd);
        assert!(script.contains("Update-PSResource"));
        assert!(script.contains("-Force"));
        assert!(script.contains("-Version '5.6.0'"));
        assert!(script.contains("-TrustRepository"));
    }

    #[test]
    fn powershell7_uninstall_omits_version_and_trust_flags() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.operation = Operation::Uninstall;
        let cmd = build_powershell7_command(&request).expect("build command");
        let (_, uninstall) = split_at_call(script_of(&cmd), "Uninstall-PSResource");
        // oracle: reference PSResourceGet 1.2.0 `Uninstall-PSResource`, which has no `-Repository` parameter
        assert!(uninstall.starts_with("Uninstall-PSResource -Name 'Pester' -Confirm:$false"));
        assert!(!uninstall.contains("-Repository"));
        // Uninstall must not pin a version (it would remove only the matching version,
        // or fail if it does not match what is installed).
        assert!(!uninstall.contains("-Version"));
        assert!(!uninstall.contains("-TrustRepository"));
        assert!(!uninstall.contains("-AcceptLicense"));
        assert!(!uninstall.contains("-Scope"));
    }

    #[test]
    fn powershell_custom_parameters_are_rejected() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.options.custom_parameters = vec![CustomParameterString("-Reinstall".to_owned())];
        let error = build_powershell7_command(&request).expect_err("custom parameters should fail");
        assert!(error.to_string().contains("custom parameters"));
    }

    #[test]
    fn powershell_literals_escape_apostrophes() {
        let mut request = make_request(ManagerName::PowerShell);
        request.package.id = PackageIdentifier::from("Vendor's.Module".to_owned());
        let cmd = build_powershell5_command(&request).expect("build command");
        let script = script_of(&cmd);
        assert!(script.contains("-Name 'Vendor''s.Module'"));
    }

    #[test]
    fn powershell_literals_double_every_single_quote_character() {
        for quote in ['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
            let mut request = make_request(ManagerName::PowerShell7);
            request.package.id = PackageIdentifier::from(format!("Vendor{quote}Module"));
            let cmd = build_powershell7_command(&request).expect("build command");
            let script = script_of(&cmd);
            assert!(
                script.contains(&format!("-Name 'Vendor{quote}{quote}Module'")),
                "quote {quote:?} must be doubled: {script}"
            );
        }
    }

    #[test]
    fn powershell_uninstall_ignores_version_selectors() {
        for manager in [ManagerName::PowerShell, ManagerName::PowerShell7] {
            let mut request = make_request(manager);
            request.operation = Operation::Uninstall;
            request.package.version = Some(VersionString("[1.0, 2.0)".to_owned()));
            let cmd = crate::command_builder::build_command(&request).expect("uninstall ignores the version");
            assert!(!script_of(&cmd).contains("1.0"));
        }
    }

    #[test]
    fn powershell_module_names_reject_wildcards() {
        for name in ["Pester*", "Pest?r", "[Pp]ester", "Pester]"] {
            for manager in [ManagerName::PowerShell, ManagerName::PowerShell7] {
                let mut request = make_request(manager);
                request.operation = Operation::Update;
                request.package.id = PackageIdentifier::from(name.to_owned());
                let error = crate::command_builder::build_command(&request).expect_err("wildcards must be rejected");
                assert!(error.to_string().contains("wildcard"), "{name}: {error:#}");
            }
        }
    }

    #[test]
    fn powershell_version_and_source_reject_unsupported_characters() {
        for value in [
            "1.0'",
            "1.0\u{2018}",
            "1.0\u{2019}",
            "1.0\u{201A}",
            "1.0\u{201B}",
            "1.0;x",
            "$x",
            "$(calc)",
            "1.0`x",
            "1.0\"",
            "1.0\nx",
            "-1.0",
        ] {
            let mut request = make_request(ManagerName::PowerShell);
            request.package.version = Some(VersionString(value.to_owned()));
            build_powershell5_command(&request).expect_err("unsupported version characters must be rejected");
        }

        for value in [
            "PS'Gallery",
            "PS\u{2018}Gallery",
            "PS\u{2019}Gallery",
            "PS;Gallery",
            "$Gallery",
            "PS$(calc)",
            "PS`Gallery",
            "PS\"Gallery",
            "PS\nGallery",
            "-Gallery",
        ] {
            let mut request = make_request(ManagerName::PowerShell7);
            request.source.name = value.to_owned();
            build_powershell7_command(&request).expect_err("unsupported source characters must be rejected");
        }
    }

    #[test]
    fn powershell7_accepts_version_ranges() {
        let mut request = make_request(ManagerName::PowerShell7);
        request.package.version = Some(VersionString("[1.0.0, 2.0.0)".to_owned()));
        let cmd = build_powershell7_command(&request).expect("build command");
        assert!(script_of(&cmd).contains("-Version '[1.0.0, 2.0.0)'"));

        let mut request = make_request(ManagerName::PowerShell);
        request.package.version = Some(VersionString("[1.0.0, 2.0.0)".to_owned()));
        build_powershell5_command(&request).expect_err("PowerShellGet -RequiredVersion only accepts exact versions");
    }

    /// Runs the generated script for a module that is not installed, under a `Restricted` execution policy for this process only.
    #[cfg(windows)]
    fn run_for_missing_module(manager: ManagerName, operation: Operation, source: &str) -> Option<i32> {
        let mut request = make_request(manager);
        request.operation = operation;
        request.source.name = source.to_owned();
        request.package.id = PackageIdentifier::from("Devolutions-NoSuchModule-7f3c".to_owned());
        let build = if manager == ManagerName::PowerShell7 {
            build_powershell7_command
        } else {
            build_powershell5_command
        };
        let mut cmd = build(&request).expect("build command");
        cmd.splice(2..2, ["-ExecutionPolicy".to_owned(), "Restricted".to_owned()]);
        crate::executor::run_prepared_for_test(&cmd, None)
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[cfg(windows)]
    #[test]
    fn powershell5_script_fails_for_a_module_that_is_not_installed() {
        for operation in [Operation::Update, Operation::Uninstall] {
            for source in ["PSGallery", ""] {
                assert_ne!(
                    run_for_missing_module(ManagerName::PowerShell, operation, source),
                    Some(0),
                    "{operation:?} from {source:?}"
                );
            }
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[cfg(windows)]
    #[test]
    fn powershell7_script_fails_for_a_resource_that_is_not_installed() {
        let pwsh =
            std::path::Path::new(&std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_owned()))
                .join(r"PowerShell\7\pwsh.exe");
        if !pwsh.exists() {
            // PowerShell 7 is optional on Windows; nothing to check without it.
            return;
        }
        for source in ["PSGallery", ""] {
            assert_ne!(
                run_for_missing_module(ManagerName::PowerShell7, Operation::Uninstall, source),
                Some(0),
                "uninstall from {source:?}"
            );
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn scripts_fail_closed_and_exit_explicitly() {
        for manager in [ManagerName::PowerShell, ManagerName::PowerShell7] {
            for operation in [Operation::Install, Operation::Update, Operation::Uninstall] {
                let mut request = make_request(manager);
                request.operation = operation;
                let cmd = if manager == ManagerName::PowerShell7 {
                    build_powershell7_command(&request)
                } else {
                    build_powershell5_command(&request)
                }
                .expect("build command");
                let script = script_of(&cmd);
                assert!(
                    script.starts_with("$global:ErrorActionPreference = 'Stop';"),
                    "{manager:?} {operation:?}"
                );
                assert!(script.ends_with("; exit 0"), "{manager:?} {operation:?}");
            }
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[cfg(windows)]
    #[test]
    fn script_fails_on_a_non_terminating_error_inside_a_module_function() {
        let mut cmd = build_powershell5_command(&make_request(ManagerName::PowerShell)).expect("build command");
        // A dynamic module has its own session state, like PowerShellGet's script module.
        *cmd.last_mut().expect("script argument") = format!(
            "{SCRIPT_PREFIX} New-Module -ScriptBlock {{ function Test-Fails {{ [CmdletBinding()] param() Write-Error 'failed'; 'continued' }} }} | Import-Module; Test-Fails{SCRIPT_SUFFIX}"
        );

        assert_ne!(crate::executor::run_prepared_for_test(&cmd, None), Some(0));
    }
}
