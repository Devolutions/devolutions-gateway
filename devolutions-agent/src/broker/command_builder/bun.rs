//! Bun command-line builder.
//!
//! UniGetUI models Bun package operations as direct `bun` invocations:
//! `bun add <package>@<version>` for install/update and `bun remove <package>`
//! for uninstall.
//! The broker only supports standard, per-user global Bun operations because
//! Bun is discovered from the user's PATH and there is no broker-trusted
//! elevated Bun executable location.

use anyhow::bail;
use now_policy_api::{Architecture, Elevation, Operation, PackageRequest, Scope};

const BUN_SOURCE_NAME: &str = "Bun";
const BUN_SOURCE_URL: &str = "https://www.npmjs.com";

/// Build the Bun command line from a validated request.
///
/// Returns the command as a list of arguments (first element is the executable).
pub fn build_bun_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    validate_bun_request(request)?;

    let operation = match request.operation {
        Operation::Install | Operation::Update => "add",
        Operation::Uninstall => "remove",
    };

    let package = match request.operation {
        Operation::Install | Operation::Update => {
            package_spec(&request.package.id.0, request.package.version.as_deref())
        }
        Operation::Uninstall => request.package.id.0.clone(),
    };

    Ok(vec![
        "bun".to_owned(),
        operation.to_owned(),
        package,
        "--global".to_owned(),
    ])
}

fn validate_bun_request(request: &PackageRequest) -> anyhow::Result<()> {
    if request.client.requested_elevation == Elevation::Elevated {
        bail!("elevated Bun package operations are not supported by the broker");
    }

    if request.options.scope == Some(Scope::Machine) {
        bail!("machine-scope Bun package operations are not supported by the broker");
    }

    if !request.source.name.eq_ignore_ascii_case(BUN_SOURCE_NAME)
        || request
            .source
            .url
            .as_ref()
            .is_some_and(|url| !is_default_bun_source_url(url))
    {
        bail!("custom Bun package sources are not supported by the broker");
    }

    if let Some(architecture) = request.package.architecture
        && architecture != Architecture::Neutral
    {
        bail!("Bun package architecture selection is not supported by the broker");
    }

    if request
        .package
        .channel
        .as_ref()
        .is_some_and(|channel| !channel.trim().is_empty())
    {
        bail!("Bun package channels are not supported by the broker");
    }

    if request.options.interactive {
        bail!("interactive Bun package operations are not supported by the broker");
    }

    if request.options.skip_hash_check {
        bail!("Bun hash-check bypass is not supported by the broker");
    }

    if request.options.pre_release {
        bail!("Bun pre-release selection is not supported by the broker");
    }

    if request
        .options
        .custom_install_location
        .as_ref()
        .is_some_and(|path| !path.trim().is_empty())
    {
        bail!("custom Bun install locations are not supported by the broker");
    }

    if let Some(param) = request.options.custom_parameters.iter().find(|param| !param.is_empty()) {
        bail!("Bun custom parameters are not supported by the broker: {}", param.0);
    }

    if request.options.uninstall_previous {
        bail!("Bun uninstall-previous operations are not supported by the broker");
    }

    if request.options.no_upgrade {
        bail!("Bun no-upgrade operations are not supported by the broker");
    }

    if let Some(version) = request.package.version.as_deref() {
        validate_bun_package_version(version)?;
    }

    Ok(())
}

fn package_spec(package_id: &str, version: Option<&str>) -> String {
    match version.filter(|version| !version.is_empty()) {
        Some(version) => format!("{package_id}@{version}"),
        None => package_id.to_owned(),
    }
}

fn is_default_bun_source_url(url: &str) -> bool {
    url.trim_end_matches('/').eq_ignore_ascii_case(BUN_SOURCE_URL)
}

fn validate_bun_package_version(version: &str) -> anyhow::Result<()> {
    if version.is_empty() {
        bail!("Bun package version must not be empty");
    }

    if semver::Version::parse(version).is_err() {
        bail!("Bun package version must be a valid semantic version: {version}");
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
            request_id: ResourceId::from("req-bun-1"),
            created_at: Utc::now(),
            operation: Operation::Install,
            manager: ManagerName::Bun,
            source: RequestSource {
                name: "Bun".to_owned(),
                url: None,
            },
            package: RequestPackage {
                id: PackageIdentifier::from("typescript".to_owned()),
                version: Some(VersionString("5.7.3".to_owned())),
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
    fn bun_install_uses_add_global_with_version() {
        let request = make_request();
        let command = build_bun_command(&request).expect("build command");

        assert_eq!(command, ["bun", "add", "typescript@5.7.3", "--global"]);
    }

    #[test]
    fn bun_update_uses_add_global_with_requested_version() {
        let mut request = make_request();
        request.operation = Operation::Update;
        request.package.version = Some(VersionString("5.8.0".to_owned()));

        let command = build_bun_command(&request).expect("build command");

        assert_eq!(command, ["bun", "add", "typescript@5.8.0", "--global"]);
    }

    #[test]
    fn bun_install_without_version_uses_plain_package_id() {
        let mut request = make_request();
        request.package.version = None;

        let command = build_bun_command(&request).expect("build command");

        assert_eq!(command, ["bun", "add", "typescript", "--global"]);
    }

    #[test]
    fn bun_install_accepts_scoped_package_identifiers() {
        let mut request = make_request();
        request.package.id = PackageIdentifier::from("@scope/package".to_owned());
        request.package.version = None;

        let command = build_bun_command(&request).expect("build command");

        assert_eq!(command, ["bun", "add", "@scope/package", "--global"]);
    }

    #[test]
    fn bun_accepts_semver_prerelease_and_build_versions() {
        let mut request = make_request();
        request.package.version = Some(VersionString("1.2.3-beta.1+build.5".to_owned()));

        let command = build_bun_command(&request).expect("build command");

        assert_eq!(command, ["bun", "add", "typescript@1.2.3-beta.1+build.5", "--global"]);
    }

    #[test]
    fn bun_accepts_default_source_url() {
        let mut request = make_request();
        request.source.url = Some("https://www.npmjs.com/".to_owned());

        let command = build_bun_command(&request).expect("build command");

        assert_eq!(command, ["bun", "add", "typescript@5.7.3", "--global"]);
    }

    #[test]
    fn bun_uninstall_uses_remove_and_omits_version() {
        let mut request = make_request();
        request.operation = Operation::Uninstall;

        let command = build_bun_command(&request).expect("build command");

        assert_eq!(command, ["bun", "remove", "typescript", "--global"]);
    }

    #[test]
    fn bun_rejects_elevated_execution() {
        let mut request = make_request();
        request.client.requested_elevation = Elevation::Elevated;

        let error = build_bun_command(&request).expect_err("elevation should fail");

        assert!(error.to_string().contains("elevated Bun"));
    }

    #[test]
    fn bun_rejects_machine_scope() {
        let mut request = make_request();
        request.options.scope = Some(Scope::Machine);

        let error = build_bun_command(&request).expect_err("machine scope should fail");

        assert!(error.to_string().contains("machine-scope Bun"));
    }

    #[test]
    fn bun_rejects_custom_source() {
        let mut request = make_request();
        request.source.name = "npmjs".to_owned();

        let error = build_bun_command(&request).expect_err("custom source should fail");

        assert!(error.to_string().contains("custom Bun package sources"));
    }

    #[test]
    fn bun_rejects_custom_source_url() {
        let mut request = make_request();
        request.source.url = Some("https://registry.npmjs.org".to_owned());

        let error = build_bun_command(&request).expect_err("custom source URL should fail");

        assert!(error.to_string().contains("custom Bun package sources"));
    }

    #[test]
    fn bun_rejects_custom_parameters() {
        let mut request = make_request();
        request.options.custom_parameters = vec![CustomParameterString("--cwd=C:\\temp".to_owned())];

        let error = build_bun_command(&request).expect_err("custom parameters should fail");

        assert!(error.to_string().contains("custom parameters"));
    }

    #[test]
    fn bun_rejects_security_sensitive_unsupported_options() {
        let mut request = make_request();
        request.options.skip_hash_check = true;

        let error = build_bun_command(&request).expect_err("skip hash check should fail");

        assert!(error.to_string().contains("hash-check bypass"));
    }

    #[test]
    fn bun_rejects_non_version_package_selectors() {
        for version in [
            "npm:unapproved-package",
            "https://registry.npmjs.org/typescript/-/typescript-5.7.3.tgz",
            "git+https://github.com/microsoft/TypeScript.git",
            "file:../typescript",
            "^5.7.3",
        ] {
            let mut request = make_request();
            request.package.version = Some(VersionString(version.to_owned()));

            let error = build_bun_command(&request).expect_err("non-version selector should fail");

            assert!(
                error.to_string().contains("valid semantic version"),
                "unexpected error for {version}: {error}"
            );
        }
    }
}
