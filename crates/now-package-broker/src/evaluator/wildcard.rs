//! Case-insensitive wildcard matching helpers.

use std::sync::LazyLock;

use unicode_normalization::UnicodeNormalization as _;
use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

static DEFAULT_IGNORABLE_CODE_POINT: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\p{Default_Ignorable_Code_Point}").expect("valid Unicode property regex"));

pub(super) fn wildcard_any_vec<S: AsRef<str>>(value: &str, patterns: &[S]) -> bool {
    patterns.iter().any(|pattern| wildcard_match(value, pattern.as_ref()))
}

/// Match an exact source name using PowerShell repository identity semantics.
///
/// PowerShell compares literal repository names case-insensitively with the current
/// culture, which the broker pins to the invariant culture.
/// This approximates that comparison with canonical (NFC) normalization and ordinal
/// case-insensitive comparison.
/// Residual collation differences only involve repositories registered in the
/// requesting user's own repository store, which that user can already repoint.
/// Source names are literals, so this deliberately does not apply wildcard semantics.
pub(super) fn literal_case_insensitive_match(value: &str, expected: &str) -> bool {
    let value: Vec<u16> = value.nfc().collect::<String>().encode_utf16().collect();
    let expected: Vec<u16> = expected.nfc().collect::<String>().encode_utf16().collect();

    // SAFETY: Both slices contain valid, initialized UTF-16 code units.
    unsafe { CompareStringOrdinal(&value, &expected, true) == CSTR_EQUAL }
}

/// Default-ignorable characters are rejected before matching and command building.
///
/// PowerShell repository lookup ignores them, while an opaque package request would
/// otherwise preserve them for `-Repository` and make policy identity ambiguous.
pub(super) fn has_default_ignorable_code_point(value: &str) -> bool {
    DEFAULT_IGNORABLE_CODE_POINT.is_match(value)
}

/// Characters that PowerShell `WildcardPattern` interprets as wildcard or escape syntax.
pub(crate) fn has_powershell_wildcard_syntax(value: &str) -> bool {
    value.contains(['*', '?', '[', ']', '`'])
}

pub(super) fn wildcard_match(value: &str, pattern: &str) -> bool {
    wildcard_match_with_case(value, pattern, true)
}

/// Match `value` against a glob `pattern` where only `*` is special.
pub(super) fn wildcard_match_with_case(value: &str, pattern: &str, case_insensitive: bool) -> bool {
    // Convert glob pattern to regex: escape everything except *, which becomes .*
    let regex_pattern = format!("^{}$", regex::escape(pattern).replace(r"\*", ".*"));
    regex::RegexBuilder::new(&regex_pattern)
        .case_insensitive(case_insensitive)
        .build()
        .is_ok_and(|re| re.is_match(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_match_is_case_insensitive() {
        assert!(wildcard_match("Microsoft.VisualStudioCode", "microsoft.*code"));
    }

    #[test]
    fn case_sensitive_wildcard_match_preserves_case() {
        assert!(wildcard_match_with_case("JSONStream", "JSON*", false));
        assert!(!wildcard_match_with_case("jsonstream", "JSON*", false));
    }

    #[test]
    fn wildcard_does_not_treat_regex_metacharacters_as_regex() {
        assert!(wildcard_match("Contoso.Tools+", "Contoso.Tools+"));
        assert!(!wildcard_match("Contoso.Toolss", "Contoso.Tools+"));
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
