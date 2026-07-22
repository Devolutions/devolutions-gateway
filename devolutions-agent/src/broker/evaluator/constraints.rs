//! Policy constraint checks.

use now_policy::PolicyConstraints;
use now_policy_api::PackageRequest;

use super::RequestFlags;
use super::wildcard::wildcard_any_vec;

pub(super) fn constraints_pass(
    constraints: &Option<PolicyConstraints>,
    request: &PackageRequest,
    flags: &RequestFlags,
) -> bool {
    let Some(c) = constraints else {
        return true;
    };

    if !c.allow_interactive && request.options.interactive {
        return false;
    }
    if !c.allow_skip_hash_check && request.options.skip_hash_check {
        return false;
    }
    if !c.allow_pre_release && request.options.pre_release {
        return false;
    }
    if !c.allow_custom_install_location && flags.has_custom_install_location {
        return false;
    }
    if !c.allow_custom_parameters && flags.has_custom_parameters {
        return false;
    }
    if !c.allow_pre_post_commands && flags.has_pre_post_commands {
        return false;
    }
    if !c.allow_kill_before_operation && flags.has_kill_before_operation {
        return false;
    }
    if !c.allow_uninstall_previous && flags.has_uninstall_previous {
        return false;
    }
    // `allow_upgrade` gates the request's `no_upgrade` flag (skip-upgrade-if-present).
    if !c.allow_upgrade && flags.no_upgrade {
        return false;
    }

    // Check install location patterns.
    if flags.has_custom_install_location
        && !c.allowed_install_location_patterns.is_empty()
        && !wildcard_any_vec(&flags.custom_install_location, &c.allowed_install_location_patterns)
    {
        return false;
    }

    // Check custom parameters.
    for param in &flags.custom_parameters {
        if !c.denied_custom_parameters.is_empty() && wildcard_any_vec(param, &c.denied_custom_parameters) {
            return false;
        }
        if !c.allowed_custom_parameters.is_empty() || !c.allowed_custom_parameter_patterns.is_empty() {
            let exact_allowed = c
                .allowed_custom_parameters
                .iter()
                .any(|v| v.eq_ignore_ascii_case(param));
            let pattern_allowed = wildcard_any_vec(param, &c.allowed_custom_parameter_patterns);
            if !exact_allowed && !pattern_allowed {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use now_policy::{CustomParameterString, StringPattern};
    use now_policy_api as api;

    use super::*;

    fn request() -> PackageRequest {
        PackageRequest {
            request_kind: api::PackageRequestKind,
            request_version: api::API_VERSION_STR.into(),
            request_id: api::ResourceId::from("req-1"),
            created_at: Utc::now(),
            operation: api::Operation::Install,
            manager: api::ManagerName::Winget,
            source: api::RequestSource {
                name: "winget".to_owned(),
                url: None,
            },
            package: api::RequestPackage {
                id: api::PackageIdentifier("Contoso.Tools".to_owned()),
                version: None,
                architecture: None,
                channel: None,
            },
            options: api::RequestOptions {
                scope: None,
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
            client: api::ClientContext {
                transport: api::Transport::HttpNamedPipe,
                requested_elevation: api::Elevation::Elevated,
                effective_user: "DOMAIN\\user".to_owned(),
                client_executable_path: "C:\\Program Files\\Devolutions\\Package Broker\\PackageBrokerClient.exe"
                    .to_owned(),
                client_version: "1.0.0".to_owned(),
            },
            include_command_preview: false,
            capture_output: false,
        }
    }

    fn flags() -> RequestFlags {
        RequestFlags {
            has_custom_parameters: false,
            has_custom_install_location: false,
            has_pre_post_commands: false,
            has_kill_before_operation: false,
            has_uninstall_previous: false,
            no_upgrade: false,
            custom_install_location: String::new(),
            custom_parameters: Vec::new(),
        }
    }

    #[test]
    fn missing_constraints_are_permissive() {
        assert!(constraints_pass(&None, &request(), &flags()));
    }

    #[test]
    fn boolean_risky_option_gates_are_enforced() {
        let mut request = request();
        request.options.interactive = true;

        let constraints = PolicyConstraints {
            allow_interactive: false,
            ..Default::default()
        };

        assert!(!constraints_pass(&Some(constraints), &request, &flags()));
    }

    #[test]
    fn install_location_must_match_allowed_patterns_when_present() {
        let constraints = PolicyConstraints {
            allowed_install_location_patterns: vec![StringPattern("C:\\Tools\\*".to_owned())],
            ..Default::default()
        };

        let mut matching_flags = flags();
        matching_flags.has_custom_install_location = true;
        matching_flags.custom_install_location = "C:\\Tools\\Contoso".to_owned();
        assert!(constraints_pass(
            &Some(constraints.clone()),
            &request(),
            &matching_flags
        ));

        let mut non_matching_flags = matching_flags;
        non_matching_flags.custom_install_location = "D:\\Temp\\Contoso".to_owned();
        assert!(!constraints_pass(&Some(constraints), &request(), &non_matching_flags));
    }

    #[test]
    fn denied_custom_parameter_takes_precedence() {
        let constraints = PolicyConstraints {
            allowed_custom_parameter_patterns: vec![CustomParameterString("--*".to_owned())],
            denied_custom_parameters: vec![CustomParameterString("--force".to_owned())],
            ..Default::default()
        };

        let mut flags = flags();
        flags.has_custom_parameters = true;
        flags.custom_parameters = vec!["--force".to_owned()];

        assert!(!constraints_pass(&Some(constraints), &request(), &flags));
    }

    #[test]
    fn custom_parameter_allowlist_accepts_exact_or_pattern_matches() {
        let constraints = PolicyConstraints {
            allowed_custom_parameters: vec![CustomParameterString("--silent".to_owned())],
            allowed_custom_parameter_patterns: vec![CustomParameterString("/log=*".to_owned())],
            ..Default::default()
        };

        let mut exact_flags = flags();
        exact_flags.has_custom_parameters = true;
        exact_flags.custom_parameters = vec!["--SILENT".to_owned()];
        assert!(constraints_pass(&Some(constraints.clone()), &request(), &exact_flags));

        let mut pattern_flags = flags();
        pattern_flags.has_custom_parameters = true;
        pattern_flags.custom_parameters = vec!["/log=C:\\Temp\\install.log".to_owned()];
        assert!(constraints_pass(&Some(constraints.clone()), &request(), &pattern_flags));

        let mut rejected_flags = flags();
        rejected_flags.has_custom_parameters = true;
        rejected_flags.custom_parameters = vec!["--force".to_owned()];
        assert!(!constraints_pass(&Some(constraints), &request(), &rejected_flags));
    }

    #[test]
    fn allow_upgrade_controls_no_upgrade_requests() {
        let constraints = PolicyConstraints {
            allow_upgrade: false,
            ..Default::default()
        };
        let mut flags = flags();
        flags.no_upgrade = true;

        assert!(!constraints_pass(&Some(constraints), &request(), &flags));
    }
}
