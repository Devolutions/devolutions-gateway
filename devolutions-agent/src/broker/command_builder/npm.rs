//! npm command-line builder.
//!
//! UniGetUI runs npm through Windows PowerShell on Windows.
//! The broker follows the same shape so the Windows executor can materialize the
//! script through its protected PowerShell wrapper.
//!
//! Elevated npm operations are rejected because npm resolves through user PATH
//! and a `npm.cmd` shim.

use anyhow::bail;
use now_policy_api::{Elevation, Operation, PackageRequest, Scope};

/// Build an npm command from a validated request.
pub fn build_npm_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_npm_request(request)?;

    let mut script = String::from("npm");

    match request.operation {
        Operation::Install | Operation::Update => {
            append_raw(&mut script, "install");
            append_value(&mut script, &install_spec(request)?);
        }
        Operation::Uninstall => {
            append_raw(&mut script, "uninstall");
            append_value(&mut script, &local_package_name(&request.package.id.0));
        }
    }

    if request.options.pre_release {
        append_raw(&mut script, "--include");
        append_raw(&mut script, "dev");
    }

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
    if !request.source.name.eq_ignore_ascii_case("npm") {
        bail!("npm package source must be 'npm'");
    }
    if request.package.architecture.is_some() {
        bail!("npm package architecture selection is not supported by the broker");
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
    if let Some(version) = request.package.version.as_deref() {
        validate_script_value("package version", version)?;
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
    append_raw(script, &quote_ps(value));
}

fn quote_ps(value: &str) -> String {
    let escaped = value.replace('\'', "''");
    format!("'{escaped}'")
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
        &cmd[3]
    }

    #[test]
    fn install_uses_npm_install_with_versioned_specifier() {
        let request = make_request();

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm install 'contoso-tool@1.2.3'");
    }

    #[test]
    fn update_uses_install_verb_with_requested_version() {
        let mut request = make_request();
        request.operation = Operation::Update;
        request.package.version = Some(VersionString("2.0.0".to_owned()));

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm install 'contoso-tool@2.0.0'");
    }

    #[test]
    fn install_without_version_omits_version_suffix() {
        let mut request = make_request();
        request.package.version = None;

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm install 'contoso-tool'");
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
            "npm install 'babel-core-legacy@npm:@babel/core@7.28.0'"
        );
    }

    #[test]
    fn uninstall_uses_alias_local_name_and_omits_version() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.package.id = PackageIdentifier::from("eslint-v9:eslint@^9.39.4".to_owned());

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm uninstall 'eslint-v9'");
    }

    #[test]
    fn pre_release_matches_unigetui_include_dev_flag() {
        let mut request = make_request();
        request.options.pre_release = true;

        let cmd = build_npm_command(&request).expect("build command");

        assert_eq!(script_of(&cmd), "npm install 'contoso-tool@1.2.3' --include dev");
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
}
