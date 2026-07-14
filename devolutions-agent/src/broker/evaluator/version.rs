//! Request version matching helpers.

use now_policy::VersionRange;
use now_policy_api::PackageRequest;

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
    if version.contains('-') && !range.include_prerelease {
        return false;
    }
    if let Some(min) = &range.min_version
        && !min.is_empty()
        && compare_versions(version, min) < 0
    {
        return false;
    }
    if let Some(max) = &range.max_version
        && !max.is_empty()
        && compare_versions(version, max) > 0
    {
        return false;
    }
    true
}

/// Simple numeric version comparison (e.g. "1.2.3" vs "1.2.4").
fn compare_versions(a: &str, b: &str) -> i32 {
    let parse = |s: &str| -> Vec<u64> {
        s.split(['.', '-', '+'])
            .filter_map(|part| part.parse::<u64>().ok())
            .collect()
    };

    let va = parse(a);
    let vb = parse(b);
    let len = va.len().max(vb.len());

    for i in 0..len {
        let pa = va.get(i).copied().unwrap_or(0);
        let pb = vb.get(i).copied().unwrap_or(0);
        if pa < pb {
            return -1;
        }
        if pa > pb {
            return 1;
        }
    }
    0
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
}
