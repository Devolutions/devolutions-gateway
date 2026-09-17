//! Case-insensitive wildcard matching helpers.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use unicode_normalization::UnicodeNormalization as _;
use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

static DEFAULT_IGNORABLE_CODE_POINT: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\p{Default_Ignorable_Code_Point}").expect("valid Unicode property regex"));

pub(super) fn wildcard_any<S: AsRef<str>>(value: &str, patterns: &BTreeSet<S>) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| wildcard_match(value, pattern.as_ref()))
}

pub(super) fn wildcard_any_vec<S: AsRef<str>>(value: &str, patterns: &[S]) -> bool {
    patterns.iter().any(|pattern| wildcard_match(value, pattern.as_ref()))
}

/// Match an exact source name using the PowerShell repository identity semantics.
///
/// PowerShell resolves repository names after canonical Unicode normalization with
/// ordinal case-insensitive comparison.
/// Source names are literals, so this deliberately does not apply wildcard semantics.
pub(super) fn literal_case_insensitive_match(value: &str, expected: &str) -> bool {
    let value: Vec<u16> = value.nfc().collect::<String>().encode_utf16().collect();
    let expected: Vec<u16> = expected.nfc().collect::<String>().encode_utf16().collect();

    // SAFETY: The binding marshals both valid UTF-8 strings as bounded UTF-16.
    unsafe { CompareStringOrdinal(&value, &expected, true) == CSTR_EQUAL }
}

/// Default-ignorable characters are rejected before matching and command building.
///
/// PowerShell repository lookup ignores them, while an opaque package request would
/// otherwise preserve them for `-Repository` and make policy identity ambiguous.
pub(super) fn has_default_ignorable_code_point(value: &str) -> bool {
    DEFAULT_IGNORABLE_CODE_POINT.is_match(value)
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

    #[test]
    fn literal_match_uses_unicode_case_insensitive_semantics() {
        assert!(literal_case_insensitive_match("CO\u{0308}RP", "CÖRP"));
        assert!(!literal_case_insensitive_match("P\u{017F}Gallery", "PSGallery"));
        assert!(!literal_case_insensitive_match("cörp", "CÖRP*"));
    }

    #[test]
    fn default_ignorable_source_characters_are_detected() {
        assert!(has_default_ignorable_code_point("PS\u{00AD}Gallery"));
        assert!(!has_default_ignorable_code_point("CÖRP"));
    }
}
