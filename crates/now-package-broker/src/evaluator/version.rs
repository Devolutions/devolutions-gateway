//! Request version matching helpers.

use std::cmp::Ordering;

use now_policy::{Decision, VersionCondition, VersionRange};
use now_policy_api::{CustomParameterString, ManagerName, Operation, PackageRequest};
use semver::{Prerelease, Version};

use super::identifier::identifier_may_select_version;

/// Returns the package version selected by the request, or `None` when it is unknown before execution.
///
/// The version is unknown when the request omits it, letting the package manager choose one;
/// for uninstall requests, which the package managers do not pin to the requested version;
/// and when custom parameters or a decorated package identifier may select a version on the
/// package manager command line.
pub(super) fn requested_version(request: &PackageRequest) -> Option<&str> {
    if request.operation == Operation::Uninstall
        || custom_parameters_may_select_version(request.manager, &request.options.custom_parameters)
        || identifier_may_select_version(&request.package.id.0)
    {
        return None;
    }

    request
        .package
        .version
        .as_ref()
        .map(|version| version.0.as_str())
        .filter(|version| !version.is_empty())
}

/// Whether a rule's version condition matches the requested version.
///
/// Both decisions fail closed when the version is in doubt.
/// An Allow rule does not match unknown or nonsemantic versions in ranges, and compares exact versions literally.
/// A Deny rule matches unknown and unparseable versions, equivalent spellings of exact versions
/// (`1.2.3`, `v1.2.3` and `1.2.3.0`), and pre-release versions within the range bounds.
pub(super) fn version_condition_matches(
    version: Option<&str>,
    condition: &VersionCondition,
    decision: Decision,
) -> bool {
    match decision {
        Decision::Allow => allow_version_matches(version, condition),
        Decision::Deny => deny_version_matches(version, condition),
    }
}

fn allow_version_matches(version: Option<&str>, condition: &VersionCondition) -> bool {
    let Some(version) = version else {
        return false;
    };

    match condition {
        VersionCondition::Exact(versions) => versions.iter().any(|expected| expected.0 == version),
        VersionCondition::Range(range) => version_range_matches(version, range),
    }
}

fn deny_version_matches(version: Option<&str>, condition: &VersionCondition) -> bool {
    let Some(version) = version else {
        return true;
    };
    let parsed = LenientVersion::parse(version);

    match condition {
        VersionCondition::Exact(versions) => versions.iter().any(|expected| {
            expected.0.eq_ignore_ascii_case(version)
                || parsed
                    .as_ref()
                    .is_none_or(|parsed| LenientVersion::parse(&expected.0).as_ref() == Some(parsed))
        }),
        VersionCondition::Range(range) => {
            let Some(parsed) = parsed else {
                return true;
            };
            let within = |bound: Option<&now_policy::SemanticVersion>, rejected: Ordering| {
                bound
                    .and_then(|bound| LenientVersion::parse(bound))
                    .is_none_or(|bound| parsed.cmp(&bound) != rejected)
            };
            within(range.min_version.as_ref(), Ordering::Less) && within(range.max_version.as_ref(), Ordering::Greater)
        }
    }
}

fn version_range_matches(version: &str, range: &VersionRange) -> bool {
    if version.is_empty() {
        return false;
    }
    let Ok(version) = Version::parse(version) else {
        return false;
    };

    if !version.pre.is_empty() && !range.include_prerelease {
        return false;
    }
    if let Some(min) = &range.min_version
        && !min.is_empty()
    {
        let Ok(min) = Version::parse(min) else {
            return false;
        };
        if version < min {
            return false;
        }
    }
    if let Some(max) = &range.max_version
        && !max.is_empty()
    {
        let Ok(max) = Version::parse(max) else {
            return false;
        };
        if version > max {
            return false;
        }
    }
    true
}

/// Whether custom parameters may select a package version on the package manager command line.
///
/// WinGet selects a version with `--version` (any letter case) or `-v`.
/// Scoop selects a version with a positional `app@version` argument.
/// The other managers reject custom parameters before execution, so any parameter is treated as version-selecting.
fn custom_parameters_may_select_version(manager: ManagerName, parameters: &[CustomParameterString]) -> bool {
    parameters
        .iter()
        .map(|parameter| parameter.0.trim())
        .filter(|parameter| !parameter.is_empty())
        .any(|parameter| match manager {
            ManagerName::Winget => winget_parameter_selects_version(parameter),
            ManagerName::Scoop => !parameter.starts_with('-') || parameter.contains('@'),
            _ => true,
        })
}

fn winget_parameter_selects_version(parameter: &str) -> bool {
    let Some(name) = parameter.strip_prefix('-') else {
        return false;
    };

    match name.strip_prefix('-') {
        Some(long) => long
            .split(['=', ':'])
            .next()
            .is_some_and(|long| long.eq_ignore_ascii_case("version")),
        None => name.starts_with(['v', 'V']),
    }
}

/// Package version parsed with the common numeric dotted form shared by package managers.
///
/// Accepts an optional `v` prefix, any number of numeric release components, an optional
/// semantic pre-release suffix and ignored build metadata.
/// Trailing zero release components are insignificant, so `1.2`, `1.2.0` and `1.2.0.0` are equal.
#[derive(Debug, PartialEq, Eq)]
struct LenientVersion {
    // INVARIANT: The last component is nonzero.
    release: Vec<u64>,
    pre: Prerelease,
}

impl LenientVersion {
    fn parse(version: &str) -> Option<Self> {
        let version = version.trim();
        let version = version.strip_prefix(['v', 'V']).unwrap_or(version);
        let version = version.split_once('+').map_or(version, |(version, _build)| version);
        let (release, pre) = match version.split_once('-') {
            Some((_, "")) => return None,
            Some((release, pre)) => (release, Prerelease::new(pre).ok()?),
            None => (version, Prerelease::EMPTY),
        };

        let mut release = release
            .split('.')
            .map(|component| {
                if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                component.parse::<u64>().ok()
            })
            .collect::<Option<Vec<_>>>()?;
        while release.last() == Some(&0) {
            release.pop();
        }

        Some(Self { release, pre })
    }
}

impl PartialOrd for LenientVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LenientVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lexicographic order on releases without trailing zeros equals zero-padded numeric order.
        self.release
            .cmp(&other.release)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn range(min: Option<&str>, max: Option<&str>, include_prerelease: bool) -> VersionRange {
        VersionRange {
            min_version: min
                .map(|version| now_policy::SemanticVersion::parse(version).expect("valid semantic version")),
            max_version: max
                .map(|version| now_policy::SemanticVersion::parse(version).expect("valid semantic version")),
            include_prerelease,
        }
    }

    fn exact(versions: &[&str]) -> VersionCondition {
        VersionCondition::Exact(
            versions
                .iter()
                .map(|version| now_policy::VersionString::parse(version).expect("valid version string"))
                .collect::<BTreeSet<_>>(),
        )
    }

    fn parameters(values: &[&str]) -> Vec<CustomParameterString> {
        values
            .iter()
            .map(|value| CustomParameterString((*value).to_owned()))
            .collect()
    }

    #[test]
    fn configured_range_rejects_missing_version() {
        assert!(!version_range_matches("", &range(Some("1.0.0"), None, false)));
    }

    #[test]
    fn inclusive_min_and_max_bounds_are_enforced() {
        let range = range(Some("1.2.0"), Some("1.4.0"), false);
        assert!(!version_range_matches("1.1.9", &range));
        assert!(version_range_matches("1.2.0", &range));
        assert!(version_range_matches("1.3.5", &range));
        assert!(version_range_matches("1.4.0", &range));
        assert!(!version_range_matches("1.4.1", &range));
    }

    #[test]
    fn prerelease_versions_require_explicit_opt_in() {
        assert!(!version_range_matches(
            "1.2.3-beta.1",
            &range(Some("1.0.0"), Some("2.0.0"), false)
        ));
        assert!(version_range_matches(
            "1.2.3-beta.1",
            &range(Some("1.0.0"), Some("2.0.0"), true)
        ));
    }

    #[test]
    fn semantic_prerelease_ordering_is_enforced() {
        assert!(!version_range_matches(
            "1.0.0-alpha.2",
            &range(Some("1.0.0-alpha.10"), None, true)
        ));
    }

    #[test]
    fn nonsemantic_requested_versions_fail_closed_when_range_is_configured() {
        assert!(!version_range_matches("1.2", &range(Some("1.0.0"), None, false)));
    }

    #[test]
    fn allow_conditions_require_a_known_matching_version() {
        let exact = exact(&["1.2.3"]);
        let range = VersionCondition::Range(range(Some("1.0.0"), Some("2.0.0"), false));

        assert!(version_condition_matches(Some("1.2.3"), &exact, Decision::Allow));
        assert!(!version_condition_matches(None, &exact, Decision::Allow));
        assert!(!version_condition_matches(Some("1.2.3.0"), &exact, Decision::Allow));
        assert!(!version_condition_matches(Some("v1.2.3"), &exact, Decision::Allow));

        assert!(version_condition_matches(Some("1.5.0"), &range, Decision::Allow));
        assert!(!version_condition_matches(None, &range, Decision::Allow));
        assert!(!version_condition_matches(Some("1.5"), &range, Decision::Allow));
        assert!(!version_condition_matches(Some("latest"), &range, Decision::Allow));
        assert!(!version_condition_matches(Some("1.5.0-beta"), &range, Decision::Allow));
    }

    #[test]
    fn deny_conditions_match_unknown_versions() {
        let exact = exact(&["1.2.3"]);
        let range = VersionCondition::Range(range(Some("1.0.0"), Some("2.0.0"), false));

        for version in [None, Some("latest"), Some("^1.0.0"), Some("1.2.x"), Some("1.2.3b1")] {
            assert!(
                version_condition_matches(version, &exact, Decision::Deny),
                "{version:?}"
            );
            assert!(
                version_condition_matches(version, &range, Decision::Deny),
                "{version:?}"
            );
        }
    }

    #[test]
    fn deny_exact_versions_match_equivalent_spellings() {
        let exact = exact(&["1.2.3"]);

        for version in ["1.2.3", "1.2.3.0", "v1.2.3", "V1.2.3.0.0", "1.2.3+build.7", " 1.2.3 "] {
            assert!(
                version_condition_matches(Some(version), &exact, Decision::Deny),
                "{version}"
            );
        }
        for version in ["1.2.4", "1.2.3.1", "1.2.3-beta", "1.2"] {
            assert!(
                !version_condition_matches(Some(version), &exact, Decision::Deny),
                "{version}"
            );
        }
    }

    #[test]
    fn deny_exact_nonsemantic_versions_compare_case_insensitively() {
        let exact = exact(&["2024.01-Build7"]);

        assert!(version_condition_matches(
            Some("2024.01-build7"),
            &exact,
            Decision::Deny
        ));
        assert!(!version_condition_matches(
            Some("2024.01-build7"),
            &exact,
            Decision::Allow
        ));
    }

    #[test]
    fn deny_ranges_match_numeric_versions_and_prereleases_within_bounds() {
        let range = VersionCondition::Range(range(Some("1.0.0"), Some("2.0.0"), false));

        for version in ["1.0", "1.5", "1.5.0.4", "v1.5.0", "1.5.0-beta", "2.0.0.0"] {
            assert!(
                version_condition_matches(Some(version), &range, Decision::Deny),
                "{version}"
            );
        }
        for version in ["0.9.9", "2.0.0.1", "2.0.1-beta", "1.0.0-rc.1"] {
            assert!(
                !version_condition_matches(Some(version), &range, Decision::Deny),
                "{version}"
            );
        }
    }

    #[test]
    fn lenient_versions_order_numerically() {
        let parse = |version| LenientVersion::parse(version).expect("valid lenient version");

        assert_eq!(parse("1.2"), parse("1.2.0.0"));
        assert!(parse("1.2.0.5") > parse("1.2"));
        assert!(parse("1.10") > parse("1.9.9"));
        assert!(parse("1.2.3-alpha") < parse("1.2.3"));
        assert!(parse("1.2.3-alpha.2") < parse("1.2.3-alpha.10"));
        assert!(LenientVersion::parse("1.2.3-").is_none());
        assert!(LenientVersion::parse("1..2").is_none());
    }

    #[test]
    fn winget_version_parameters_make_the_version_unknown() {
        for value in [
            "--version",
            "--VERSION",
            "--version=9.9.9",
            "-v",
            "-v=9.9.9",
            " --version",
        ] {
            assert!(
                custom_parameters_may_select_version(ManagerName::Winget, &parameters(&[value])),
                "{value}"
            );
        }
        for value in ["--silent", "--verbose-logs", "--override", "9.9.9", "--log=C:\\v.log"] {
            assert!(
                !custom_parameters_may_select_version(ManagerName::Winget, &parameters(&[value])),
                "{value}"
            );
        }
    }

    #[test]
    fn scoop_positional_or_versioned_parameters_make_the_version_unknown() {
        for value in ["app@1.2.3", "extras/app", "--arch@1"] {
            assert!(
                custom_parameters_may_select_version(ManagerName::Scoop, &parameters(&[value])),
                "{value}"
            );
        }
        assert!(!custom_parameters_may_select_version(
            ManagerName::Scoop,
            &parameters(&["--no-cache", "-k"])
        ));
    }

    #[test]
    fn custom_parameters_on_other_managers_make_the_version_unknown() {
        for manager in [
            ManagerName::PowerShell,
            ManagerName::PowerShell7,
            ManagerName::Chocolatey,
            ManagerName::Npm,
            ManagerName::Pip,
        ] {
            assert!(custom_parameters_may_select_version(
                manager,
                &parameters(&["-RequiredVersion"])
            ));
            assert!(!custom_parameters_may_select_version(manager, &[]));
        }
    }
}
