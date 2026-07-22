//! Case-insensitive wildcard matching helpers.

use std::collections::BTreeSet;

pub(super) fn wildcard_any<S: AsRef<str>>(value: &str, patterns: &BTreeSet<S>) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| wildcard_match(value, pattern.as_ref()))
}

pub(super) fn wildcard_any_vec<S: AsRef<str>>(value: &str, patterns: &[S]) -> bool {
    patterns.iter().any(|pattern| wildcard_match(value, pattern.as_ref()))
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    // Convert glob pattern to regex: escape everything except *, which becomes .*
    let regex_pattern = format!("^{}$", regex::escape(pattern).replace(r"\*", ".*"));
    regex::RegexBuilder::new(&regex_pattern)
        .case_insensitive(true)
        .build()
        .is_ok_and(|re| re.is_match(value))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use now_policy::StringPattern;

    use super::*;

    #[test]
    fn empty_pattern_set_matches_everything() {
        assert!(wildcard_any(
            "Microsoft.VisualStudioCode",
            &BTreeSet::<StringPattern>::new()
        ));
    }

    #[test]
    fn wildcard_match_is_case_insensitive() {
        let patterns = BTreeSet::from([StringPattern("microsoft.*code".to_owned())]);
        assert!(wildcard_any("Microsoft.VisualStudioCode", &patterns));
    }

    #[test]
    fn wildcard_does_not_treat_regex_metacharacters_as_regex() {
        let patterns = BTreeSet::from([StringPattern("Contoso.Tools+".to_owned())]);
        assert!(wildcard_any("Contoso.Tools+", &patterns));
        assert!(!wildcard_any("Contoso.Toolss", &patterns));
    }
}
