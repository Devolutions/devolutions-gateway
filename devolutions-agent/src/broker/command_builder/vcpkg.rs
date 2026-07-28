//! vcpkg command-line builder.
//!
//! UniGetUI runs vcpkg package operations as:
//! - `vcpkg install <package[:triplet]>`
//! - `vcpkg upgrade <package[:triplet]> --no-dry-run`
//! - `vcpkg remove <package[:triplet]> --recurse`
//!
//! The broker maps the request source name to the vcpkg triplet and does not
//! accept command-line extensions that can redirect vcpkg to an arbitrary root,
//! overlay, registry, or script path.

use anyhow::bail;
use now_policy_api::{Elevation, Operation, PackageRequest, Scope};

/// Build the vcpkg command line from a validated request.
pub fn build_vcpkg_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_vcpkg_request(request)?;

    let operation = match request.operation {
        Operation::Install => "install",
        Operation::Update => "upgrade",
        Operation::Uninstall => "remove",
    };

    let mut command = vec!["vcpkg.exe".to_owned(), operation.to_owned(), package_spec(request)?];

    match request.operation {
        Operation::Install => {}
        Operation::Update => command.push("--no-dry-run".to_owned()),
        Operation::Uninstall => command.push("--recurse".to_owned()),
    }

    Ok(command)
}

fn validate_vcpkg_request(request: &PackageRequest) -> anyhow::Result<()> {
    if request.client.requested_elevation == Elevation::Elevated {
        bail!("vcpkg elevated operations are not supported by the broker");
    }
    if request.options.scope == Some(Scope::Machine) {
        bail!("vcpkg machine-scope operations are not supported by the broker");
    }
    if request.source.url.is_some() {
        bail!("vcpkg package sources with URLs are not supported by the broker");
    }
    if !is_valid_triplet(&request.source.name) {
        bail!("vcpkg package source name must be a triplet");
    }
    if request.package.version.is_some() {
        bail!("vcpkg package versions are not supported by the broker");
    }
    if request.package.architecture.is_some() {
        bail!("vcpkg package architecture is encoded by the triplet source");
    }
    if request.package.channel.is_some() {
        bail!("vcpkg package channels are not supported by the broker");
    }
    if request.options.interactive {
        bail!("vcpkg interactive operations are not supported by the broker");
    }
    if request.options.skip_hash_check {
        bail!("vcpkg skip-hash-check operations are not supported by the broker");
    }
    if request.options.pre_release {
        bail!("vcpkg prerelease operations are not supported by the broker");
    }
    if request.options.custom_install_location.is_some() {
        bail!("vcpkg custom install locations are not supported by the broker");
    }
    if let Some(param) = request.options.custom_parameters.iter().find(|param| !param.is_empty()) {
        bail!("vcpkg custom parameters are not supported by the broker: {}", param.0);
    }
    if request.options.uninstall_previous {
        bail!("vcpkg uninstall-previous operations are not supported by the broker");
    }
    if request.options.no_upgrade {
        bail!("vcpkg no-upgrade operations are not supported by the broker");
    }

    Ok(())
}

fn package_spec(request: &PackageRequest) -> anyhow::Result<String> {
    let triplet = request.source.name.trim();
    let package_id = request.package.id.0.trim();

    if package_id.is_empty() {
        bail!("vcpkg package id is required");
    }

    if let Some((port, package_triplet)) = package_id.split_once(':') {
        if port.is_empty() || package_triplet.is_empty() || package_triplet.contains(':') {
            bail!("vcpkg package id must be in the form '<port>[:<triplet>]'");
        }
        if package_triplet != triplet {
            bail!("vcpkg package triplet must match the request source");
        }
        Ok(package_id.to_owned())
    } else {
        Ok(format!("{package_id}:{triplet}"))
    }
}

fn is_valid_triplet(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
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
            request_id: ResourceId::from("req-vcpkg-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: ManagerName::Vcpkg,
            source: RequestSource {
                name: "x64-windows".to_owned(),
                url: None,
            },
            package: RequestPackage {
                id: PackageIdentifier::from("zlib".to_owned()),
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

    #[test]
    fn install_appends_source_triplet() {
        let request = make_request();
        let cmd = build_vcpkg_command(&request).expect("build command");

        assert_eq!(cmd, ["vcpkg.exe", "install", "zlib:x64-windows"]);
    }

    #[test]
    fn update_uses_unigetui_no_dry_run_semantics() {
        let mut request = make_request();
        request.operation = Operation::Update;
        request.package.id = PackageIdentifier::from("curl:x64-windows".to_owned());

        let cmd = build_vcpkg_command(&request).expect("build command");

        assert_eq!(cmd, ["vcpkg.exe", "upgrade", "curl:x64-windows", "--no-dry-run"]);
    }

    #[test]
    fn uninstall_uses_unigetui_recurse_semantics() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;
        request.package.id = PackageIdentifier::from("openssl:x64-windows".to_owned());

        let cmd = build_vcpkg_command(&request).expect("build command");

        assert_eq!(cmd, ["vcpkg.exe", "remove", "openssl:x64-windows", "--recurse"]);
    }

    #[test]
    fn package_triplet_must_match_source() {
        let mut request = make_request();
        request.package.id = PackageIdentifier::from("zlib:x86-windows".to_owned());

        let error = build_vcpkg_command(&request).expect_err("triplet mismatch should fail");

        assert!(error.to_string().contains("triplet"));
    }

    #[test]
    fn elevated_requests_are_rejected() {
        let mut request = make_request();
        request.client.requested_elevation = Elevation::Elevated;

        let error = build_vcpkg_command(&request).expect_err("elevated request should fail");

        assert!(error.to_string().contains("elevated"));
    }

    #[test]
    fn machine_scope_requests_are_rejected() {
        let mut request = make_request();
        request.options.scope = Some(Scope::Machine);

        let error = build_vcpkg_command(&request).expect_err("machine scope should fail");

        assert!(error.to_string().contains("machine-scope"));
    }

    #[test]
    fn custom_parameters_are_rejected() {
        let mut request = make_request();
        request.options.custom_parameters = vec![CustomParameterString(
            "--vcpkg-root=C:\\Users\\user\\checkout".to_owned(),
        )];

        let error = build_vcpkg_command(&request).expect_err("custom parameter should fail");

        assert!(error.to_string().contains("custom parameters"));
    }

    #[test]
    fn unsupported_options_are_rejected() {
        let mut request = make_request();
        request.options.custom_install_location = Some("C:\\libs".to_owned());
        assert!(
            build_vcpkg_command(&request)
                .expect_err("custom install location should fail")
                .to_string()
                .contains("custom install")
        );

        request = make_request();
        request.package.version = Some(VersionString("1.2.3".to_owned()));
        assert!(
            build_vcpkg_command(&request)
                .expect_err("version should fail")
                .to_string()
                .contains("versions")
        );
    }
}
