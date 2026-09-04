//! Case-insensitive wildcard matching helpers.

use std::collections::BTreeSet;

use regex::{Regex, RegexBuilder};

pub(super) fn wildcard_any<S: AsRef<str>>(value: &str, patterns: &BTreeSet<S>) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| wildcard_match(value, pattern.as_ref()))
}

pub(super) fn wildcard_any_vec<S: AsRef<str>>(value: &str, patterns: &[S]) -> bool {
    patterns.iter().any(|pattern| wildcard_match(value, pattern.as_ref()))
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    compile_pattern(pattern).is_some_and(|re| re.is_match(value))
}

/// Whether `pattern` compiles into the same evaluator-side matcher used at request-evaluation
/// time.
///
/// Every character is escaped except `*` (converted to `.*`), so a pattern can only fail to
/// compile once it grows large/complex enough to exceed the regex engine's default program
/// size limit; this is the same condition under which [`wildcard_match`] silently treats the
/// pattern as never matching, surfaced here as a validation finding instead of a silent no-op.
pub(crate) fn pattern_compiles(pattern: &str) -> bool {
    compile_pattern(pattern).is_some()
}

/// Convert a glob pattern (only `*` is special, converted to `.*`) into a compiled,
/// case-insensitive regex.
fn compile_pattern(pattern: &str) -> Option<Regex> {
    let regex_pattern = format!("^{}$", regex::escape(pattern).replace(r"\*", ".*"));
    RegexBuilder::new(&regex_pattern).case_insensitive(true).build().ok()
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
    fn ordinary_patterns_compile() {
        assert!(pattern_compiles("Microsoft.*"));
        assert!(pattern_compiles("Contoso.Tools+"));
        assert!(pattern_compiles("*"));
    }

    #[test]
    fn pathologically_large_pattern_fails_to_compile() {
        // Comfortably past regex's default 10MiB compiled-program size limit once escaped
        // and repeated; each `*` widens the resulting alternation-free `.*` chain.
        let huge = "a*".repeat(2_000_000);
        assert!(!pattern_compiles(&huge));
    }
}
