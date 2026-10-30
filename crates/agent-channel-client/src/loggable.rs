//! Text the authority chose, made safe to log.

/// The most characters [`loggable`] keeps, escapes included, before its truncation marker.
const MAX_LOGGED_CHARS: usize = 256;
/// The marker that ends a truncated text.
const TRUNCATED: &str = " [truncated]";

/// Returns `text` with each control character, backslash and other character that Rust's `Debug` escapes written as
/// that escape, cut before the first character that would take it past [`MAX_LOGGED_CHARS`] and then marked as
/// truncated.
///
/// The authority's text can't then start a forged log line or grow a log line without bound.
pub(crate) fn loggable(text: &str) -> String {
    let mut logged = String::new();
    let mut len = 0;
    for character in text.chars() {
        let start = logged.len();
        // Quotes need no escape inside a log field, and escaping them would only clutter the text.
        if matches!(character, '"' | '\'') {
            logged.push(character);
        } else {
            logged.extend(character.escape_debug());
        }
        len += logged[start..].chars().count();
        if MAX_LOGGED_CHARS < len {
            logged.truncate(start);
            logged.push_str(TRUNCATED);
            break;
        }
    }
    logged
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    #[rstest]
    #[case::carriage_return_and_line_feed("a\r\nb", r"a\r\nb")]
    #[case::escape("a\u{1b}[2Jb", r"a\u{1b}[2Jb")]
    #[case::delete("a\u{7f}b", r"a\u{7f}b")]
    #[case::c1_next_line("a\u{85}b", r"a\u{85}b")]
    #[case::nul_and_tab("a\0\tb", r"a\0\tb")]
    #[case::backslash(r"a\nb", r"a\\nb")]
    #[case::right_to_left_override("a\u{202e}b", r"a\u{202e}b")]
    #[case::printable_text_and_quotes("certificate \"rotated\" é", "certificate \"rotated\" é")]
    fn escapes_each_control_character(#[case] text: &str, #[case] logged: &str) {
        assert_eq!(loggable(text), logged);
    }

    // oracle: intent crates/agent-channel-client/INTENT.md §Connection
    #[rstest]
    #[case::at_the_bound("a".repeat(256), "a".repeat(256))]
    #[case::past_the_bound("a".repeat(257), format!("{} [truncated]", "a".repeat(256)))]
    #[case::multi_byte_character_at_the_bound("é".repeat(257), format!("{} [truncated]", "é".repeat(256)))]
    #[case::escape_across_the_bound(format!("{}\n", "a".repeat(255)), format!("{} [truncated]", "a".repeat(255)))]
    #[case::quote_past_the_bound(format!("{}\"", "a".repeat(256)), format!("{} [truncated]", "a".repeat(256)))]
    fn truncates_past_256_characters_without_splitting_one(#[case] text: String, #[case] logged: String) {
        assert_eq!(loggable(&text), logged);
    }
}
