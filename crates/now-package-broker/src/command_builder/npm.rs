//! npm command-line builder.
//!
//! UniGetUI runs npm through Windows PowerShell on Windows.
//! The broker follows the same shape so the Windows executor can materialize the
//! script through its protected PowerShell wrapper.
//! The script calls `npm.cmd` rather than `npm`, which PowerShell resolves to the `npm.ps1` shim that a `Restricted` execution policy refuses to run.
//!
//! Elevated npm operations are rejected because npm resolves through user PATH
//! and a `npm.cmd` shim.

use anyhow::bail;
use now_policy_api::{Architecture, Elevation, Operation, PackageRequest, Scope};

use super::{quote_powershell_literal, uses_default_source, validate_npm_package_name, validate_package_version};

/// npm version selectors that are inert when passed through the `npm.cmd` shim, such as `~1.2` or `1.x`.
const NPM_VERSION_EXTRA_CHARACTERS: &[char] = &['~', '*'];

/// Build an npm command from a validated request.
pub fn build_npm_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_npm_request(request)?;

    let mut script = String::from("$ErrorActionPreference = 'Stop'; npm.cmd");

    match request.operation {
        Operation::Install | Operation::Update => {
            append_raw(&mut script, "install");
            append_value(&mut script, &install_spec(request)?);
            append_raw(&mut script, "--global");
        }
        Operation::Uninstall => {
            append_raw(&mut script, "uninstall");
            append_value(&mut script, &local_package_name(&request.package.id.0));
            append_raw(&mut script, "--global");
        }
    }
    // The executor reports the script's exit code, so the script must forward npm's own.
    script.push_str("; exit $LASTEXITCODE");

    Ok(vec![
        "powershell.exe".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        script,
    ])
}

fn validate_npm_request(request: &PackageRequest) -> anyhow::Result<()> {
    if request.client.requested_elevation == Elevation::Elevated {
        bail!("npm elevated operations are not supported by the broker");
    }
    if request.options.scope == Some(Scope::Machine) {
        bail!("npm machine-scope operations are not supported by the broker");
    }
    if request.source.url.is_some() {
        bail!("npm package sources with URLs are not supported by the broker");
    }
    if !uses_default_source("npm", request)? && !request.source.name.eq_ignore_ascii_case("npm") {
        bail!("npm package source must be 'npm'");
    }
    match request.package.architecture {
        Some(Architecture::X86 | Architecture::X64 | Architecture::Arm64) => {
            bail!("npm package architecture selection is not supported by the broker");
        }
        Some(Architecture::Neutral) | None => {}
    }
    if request.options.pre_release {
        bail!("npm prerelease selection is not supported by the broker");
    }
    if request.package.channel.is_some() {
        bail!("npm package channels are not supported by the broker");
    }
    if request.options.interactive {
        bail!("npm interactive operations are not supported by the broker");
    }
    if request.options.skip_hash_check {
        bail!("npm skip-hash-check operations are not supported by the broker");
    }
    if request.options.custom_install_location.is_some() {
        bail!("npm custom install locations are not supported by the broker");
    }
    if let Some(param) = request.options.custom_parameters.iter().find(|param| !param.is_empty()) {
        bail!("npm custom parameters are not supported by the broker: {}", param.0);
    }
    if request.options.uninstall_previous {
        bail!("npm uninstall-previous operations are not supported by the broker");
    }
    if request.options.no_upgrade {
        bail!("npm no-upgrade operations are not supported by the broker");
    }

    validate_script_value("package id", &request.package.id.0)?;
    validate_npm_package_id(&request.package.id.0)?;
    if let Some(version) = request.package.version.as_deref() {
        validate_script_value("package version", version)?;
        // Uninstall ignores the version, so only versions that reach npm are restricted.
        if request.operation != Operation::Uninstall {
            validate_package_version("npm", version, NPM_VERSION_EXTRA_CHARACTERS)?;
        }
    }

    Ok(())
}

fn install_spec(request: &PackageRequest) -> anyhow::Result<String> {
    let id = &request.package.id.0;
    let version = request.package.version.as_deref();
    let spec = if let Some((local_name, target_name)) = alias_parts(id) {
        match version {
            Some(version) => format!("{local_name}@npm:{target_name}@{version}"),
            None => format!("{local_name}@npm:{target_name}"),
        }
    } else {
        match version {
            Some(version) => format!("{id}@{version}"),
            None => id.clone(),
        }
    };

    validate_script_value("package specifier", &spec)?;
    Ok(spec)
}

/// Accept a registry package name, or an alias `local:target` whose names are both registry names.
fn validate_npm_package_id(id: &str) -> anyhow::Result<()> {
    // The `npm.cmd` shim expands environment variable references.
    if id.contains('%') {
        bail!("npm package id cannot contain percent signs");
    }

    match alias_parts(id) {
        Some((local_name, target_name)) => {
            validate_npm_package_name("npm", &local_name)?;
            validate_npm_package_name("npm", &target_name)
        }
        None => validate_npm_package_name("npm", id),
    }
}

fn local_package_name(id: &str) -> String {
    alias_parts(id).map_or_else(|| id.to_owned(), |(local_name, _)| local_name)
}

fn alias_parts(id: &str) -> Option<(String, String)> {
    let colon_index = id.find(':')?;
    if colon_index == 0 {
        return None;
    }

    let local_name = id[..colon_index].to_owned();
    let target_spec = &id[colon_index + 1..];
    let target_name = target_spec
        .rfind('@')
        .filter(|at_index| *at_index > 0)
        .map_or(target_spec, |at_index| &target_spec[..at_index])
        .to_owned();

    Some((local_name, target_name))
}

fn append_raw(script: &mut String, value: &str) {
    script.push(' ');
    script.push_str(value);
}

fn append_value(script: &mut String, value: &str) {
    append_raw(script, &quote_powershell_literal(value));
}

fn validate_script_value(name: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        bail!("npm {name} cannot be empty");
    }
    if value.contains(['\0', '\r', '\n']) {
        bail!("npm {name} cannot contain control line separators");
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
            request_id: ResourceId::from("req-npm-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: ManagerName::Npm,
            source: RequestSource {
                name: "npm".to_owned(),
                url: None,
            },
            package: RequestPackage {
                id: PackageIdentifier::from("contoso-tool".to_owned()),
                version: Some(VersionString("1.2.3".to_owned())),
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
        assert_eq!(cmd[2], "-Command");
        cmd[3]
            .strip_prefix("$ErrorActionPreference = 'Stop'; ")
            .and_then(|script| script.strip_suffix("; exit $LASTEXITCODE"))
            .expect("npm script fails closed and forwards npm's exit code")
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn empty_source_is_accepted_for_update_and_uninstall_only() {
        for operation in [Operation::Update, Operation::Uninstall] {
            let mut request = make_request();
            request.operation = operation;
            request.source.name = String::new();
            build_npm_command(&request).expect("empty source");
        }

        let mut request = make_request();
        request.source.name = String::new();
        build_npm_command(&request).expect_err("install requires a named source");

        for operation in [Operation::Update, Operation::Uninstall] {
            let mut request = make_request();
            request.operation = operation;
            request.source.name = String::new();
            request.source.url = Some("https://example.test/".to_owned());
            build_npm_command(&request).expect_err("empty source cannot carry a URL");
        }
    }
    #[test]
    fn install_uses_npm_install_with_versioned_specifier() {
        let request = make_request();

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm.cmd install 'contoso-tool@1.2.3' --global");
    }

    #[test]
    fn update_uses_install_verb_with_requested_version() {
        let mut request = make_request();
        request.operation = Operation::Update;
        request.package.version = Some(VersionString("2.0.0".to_owned()));

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm.cmd install 'contoso-tool@2.0.0' --global");
    }

    #[test]
    fn install_without_version_omits_version_suffix() {
        let mut request = make_request();
        request.package.version = None;

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm.cmd install 'contoso-tool' --global");
    }

    #[test]
    fn update_reconstructs_alias_specifier() {
        let mut request = make_request();
        request.operation = Operation::Update;
        request.package.id = PackageIdentifier::from("babel-core-legacy:@babel/core@^7.20.0".to_owned());
        request.package.version = Some(VersionString("7.28.0".to_owned()));

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(
            script_of(&cmd),
            "npm.cmd install 'babel-core-legacy@npm:@babel/core@7.28.0' --global"
        );
    }

    #[test]
    fn uninstall_uses_alias_local_name_and_omits_version() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.package.id = PackageIdentifier::from("eslint-v9:eslint@^9.39.4".to_owned());

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm.cmd uninstall 'eslint-v9' --global");
    }

    #[test]
    fn neutral_architecture_is_accepted() {
        let mut request = make_request();
        request.package.architecture = Some(Architecture::Neutral);

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm.cmd install 'contoso-tool@1.2.3' --global");
    }

    #[test]
    fn concrete_architecture_is_rejected() {
        let mut request = make_request();
        request.package.architecture = Some(Architecture::X64);

        let error = build_npm_command(&request).expect_err("concrete architecture should fail");

        assert!(error.to_string().contains("architecture"));
    }

    #[test]
    fn pre_release_is_rejected() {
        let mut request = make_request();
        request.options.pre_release = true;

        let error = build_npm_command(&request).expect_err("prerelease should fail");

        assert!(error.to_string().contains("prerelease"));
    }

    #[test]
    fn elevated_requests_are_rejected() {
        let mut request = make_request();
        request.client.requested_elevation = Elevation::Elevated;

        let error = build_npm_command(&request).expect_err("elevated npm should fail");

        assert!(error.to_string().contains("elevated"));
    }

    #[test]
    fn machine_scope_requests_are_rejected() {
        let mut request = make_request();
        request.options.scope = Some(Scope::Machine);

        let error = build_npm_command(&request).expect_err("machine-scope npm should fail");

        assert!(error.to_string().contains("machine-scope"));
    }

    #[test]
    fn custom_parameters_are_rejected() {
        let mut request = make_request();
        request.options.custom_parameters = vec![CustomParameterString("--ignore-scripts".to_owned())];

        let error = build_npm_command(&request).expect_err("custom parameters should fail");

        assert!(error.to_string().contains("custom parameters"));
    }

    #[test]
    fn source_urls_are_rejected() {
        let mut request = make_request();
        request.source.url = Some("https://registry.npmjs.org/".parse().expect("URL"));

        let error = build_npm_command(&request).expect_err("source URL should fail");

        assert!(error.to_string().contains("sources with URLs"));
    }

    #[test]
    fn script_line_separators_are_rejected() {
        let mut request = make_request();
        request.package.id = PackageIdentifier::from("contoso\r\nnpm run unsafe".to_owned());

        let error = build_npm_command(&request).expect_err("line separator should fail");

        assert!(error.to_string().contains("control line separators"));
    }

    #[test]
    fn versions_with_unsupported_characters_are_rejected() {
        for version in ["1.0'", "1.0\u{2019}", "1.0&x", "^1.0", "1.0 || 2.0", "-1.0"] {
            let mut request = make_request();
            request.package.version = Some(VersionString(version.to_owned()));

            let error = build_npm_command(&request).expect_err("unsupported version should fail");

            assert!(error.to_string().contains("package version"), "{version}: {error:#}");
        }
    }

    #[test]
    fn uninstall_ignores_version_selectors() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.package.version = Some(VersionString("^1.0 || 2.x".to_owned()));

        let cmd = build_npm_command(&request).expect("uninstall ignores the version");

        assert_eq!(script_of(&cmd), "npm.cmd uninstall 'contoso-tool' --global");
    }

    #[test]
    fn package_ids_npm_resolves_outside_the_registry_are_rejected() {
        for id in [
            "user/repo",
            "github:user/repo",
            "git+https://example.test/repo.git",
            "https://example.test/pkg.tgz",
            "file:../pkg",
            "pkg.tgz",
            "./pkg",
            "../pkg",
            "/pkg",
            r"C:\pkg",
            "contoso%PATH%",
            "contoso'tool",
            "contoso\u{2019}tool",
            "alias:user/repo",
            "alias:file:../pkg",
        ] {
            let mut request = make_request();
            request.package.version = None;
            request.package.id = PackageIdentifier::from(id.to_owned());

            build_npm_command(&request).expect_err(id);
        }
    }

    #[test]
    fn script_syntax_in_package_ids_and_versions_is_rejected() {
        for value in [
            "tool'",
            "tool\"",
            "tool;calc",
            "$(calc)",
            "tool`calc",
            "tool\ncalc",
            "tool\r\ncalc",
            "tool&calc",
            "tool|calc",
        ] {
            let mut request = make_request();
            request.package.id = PackageIdentifier::from(value.to_owned());
            build_npm_command(&request).expect_err("package id with script syntax must be rejected");

            let mut request = make_request();
            request.package.version = Some(VersionString(value.to_owned()));
            build_npm_command(&request).expect_err("version with script syntax must be rejected");
        }
    }

    #[test]
    fn scoped_package_ids_are_accepted() {
        let mut request = make_request();
        request.package.version = None;
        request.package.id = PackageIdentifier::from("@contoso/tool".to_owned());

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm.cmd install '@contoso/tool' --global");
    }

    /// Runs the generated script under a `Restricted` execution policy for this process only, as on a default Windows client.
    #[cfg(windows)]
    fn under_restricted_policy(mut cmd: Vec<String>) -> Vec<String> {
        cmd.splice(2..2, ["-ExecutionPolicy".to_owned(), "Restricted".to_owned()]);
        cmd
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[cfg(windows)]
    #[test]
    fn generated_script_exits_with_npm_exit_code() {
        let fake_npm = tempfile::tempdir().expect("create temp dir");
        for operation in [Operation::Install, Operation::Update, Operation::Uninstall] {
            let mut request = make_request();
            request.operation = operation;
            let cmd = under_restricted_policy(build_npm_command(&request).expect("build command"));
            for code in [7, 0] {
                std::fs::write(fake_npm.path().join("npm.cmd"), format!("@exit /b {code}\r\n"))
                    .expect("write fake npm");
                // PowerShell prefers this shim over `npm.cmd` for a bare `npm`, and `Restricted` refuses to run it.
                std::fs::write(fake_npm.path().join("npm.ps1"), "exit 99\r\n").expect("write fake npm shim");
                assert_eq!(
                    crate::executor::run_prepared_for_test(&cmd, Some(fake_npm.path())),
                    Some(code),
                    "{operation:?}"
                );
            }
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[cfg(windows)]
    #[test]
    fn generated_script_fails_when_npm_cannot_be_found() {
        let empty_path = tempfile::tempdir().expect("create temp dir");
        let mut cmd = under_restricted_policy(build_npm_command(&make_request()).expect("build command"));
        let script = cmd.last_mut().expect("script");
        *script = script.replacen("npm.cmd ", "no-such-npm-xyz ", 1);
        assert_ne!(
            crate::executor::run_prepared_for_test(&cmd, Some(empty_path.path())),
            Some(0)
        );
    }
}
