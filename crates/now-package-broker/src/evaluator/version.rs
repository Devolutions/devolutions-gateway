//! Request version matching helpers.

use now_policy::VersionRange;
use now_policy_api::PackageRequest;
use semver::Version;

pub(super) fn get_effective_version(request: &PackageRequest) -> String {
    match &request.package.version {
        Some(v) => v.0.clone(),
        None => String::new(),
    }
}

pub(super) fn version_range_matches(version: &str, range: &Option<VersionRange>) -> bool {
    let Some(range) = range else {
        return true;
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn range(min: Option<&str>, max: Option<&str>, include_prerelease: bool) -> Option<VersionRange> {
        Some(VersionRange {
            min_version: min.map(ToOwned::to_owned),
            max_version: max.map(ToOwned::to_owned),
            include_prerelease,
        })
    }

    #[test]
    fn absent_range_accepts_empty_or_present_versions() {
        assert!(version_range_matches("", &None));
        assert!(version_range_matches("1.2.3", &None));
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
    fn invalid_versions_fail_closed_when_range_is_configured() {
        assert!(!version_range_matches("1.2", &range(Some("1.0.0"), None, false)));
        assert!(!version_range_matches("1.2.3", &range(Some("1.0"), None, false)));
    }
}
