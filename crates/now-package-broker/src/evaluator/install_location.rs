//! Custom install location normalization.

/// Normalized form of a custom install location, or `None` when it is not a plain local drive path.
///
/// Only absolute paths on a drive letter (`X:\...`) are accepted.
/// Relative, UNC and device paths are rejected, as are `.` and `..` segments, segments ending with
/// a dot or a space (which Windows trims), alternate data streams (`:` after the drive), wildcard
/// characters and control characters.
/// The result uses `\` separators without repeated or trailing separators and an uppercase drive letter.
pub(super) fn normalize_install_location(location: &str) -> Option<String> {
    let location = location.replace('/', "\\");
    let mut chars = location.chars();
    let drive = chars.next().filter(char::is_ascii_alphabetic)?;
    if chars.next() != Some(':') || chars.next() != Some('\\') {
        return None;
    }

    let rest = &location[3..];
    if rest
        .chars()
        .any(|character| character.is_control() || matches!(character, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return None;
    }

    let segments = rest
        .split('\\')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments
        .iter()
        .any(|segment| segment.ends_with(['.', ' ']) || segment.starts_with(' '))
    {
        return None;
    }

    Some(format!("{}:\\{}", drive.to_ascii_uppercase(), segments.join("\\")))
}

/// Pattern for matching against [`normalize_install_location`] output.
///
/// Uses `\` separators without repeated or trailing separators, except for a drive root.
pub(super) fn normalize_install_location_pattern(pattern: &str) -> String {
    let mut normalized = String::with_capacity(pattern.len());
    for character in pattern.chars() {
        let character = if character == '/' { '\\' } else { character };
        if !(character == '\\' && normalized.ends_with('\\')) {
            normalized.push(character);
        }
    }
    if normalized.ends_with('\\') && !normalized.ends_with(":\\") {
        normalized.pop();
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_drive_paths_are_normalized() {
        let cases = [
            (r"C:\Tools\Contoso", r"C:\Tools\Contoso"),
            (r"c:\Tools\Contoso\", r"C:\Tools\Contoso"),
            ("C:/Tools//Contoso/", r"C:\Tools\Contoso"),
            (r"C:\\Tools\\\Contoso", r"C:\Tools\Contoso"),
            (r"D:\", r"D:\"),
            (r"C:\Program Files\App v1.2", r"C:\Program Files\App v1.2"),
        ];

        for (location, expected) in cases {
            assert_eq!(
                normalize_install_location(location).as_deref(),
                Some(expected),
                "{location}"
            );
        }
    }

    #[test]
    fn unacceptable_locations_are_rejected() {
        for location in [
            r"C:\Tools\..\Windows\System32",
            "C:/Tools/../Windows/System32",
            r"C:\Tools\.\Contoso",
            r"C:\Tools\...",
            r"C:\Tools\Contoso.",
            r"C:\Tools\Contoso ",
            r"C:\Tools\ ..\Windows",
            r"C:\Tools\file.txt:stream",
            r"C:Tools",
            r"Tools\Contoso",
            r"\Tools",
            r"\\server\share\Tools",
            r"\\?\C:\Tools",
            r"\\.\C:\Tools",
            "C:\\Tools\nC:\\Windows",
            "C:\\Tools\u{0}",
            r"C:\Tools\*",
            "",
            "1:\\Tools",
        ] {
            assert_eq!(normalize_install_location(location), None, "{location:?}");
        }
    }

    #[test]
    fn patterns_use_the_same_separators() {
        assert_eq!(normalize_install_location_pattern("C:/Tools//*"), r"C:\Tools\*");
        assert_eq!(normalize_install_location_pattern(r"C:\Tools\"), r"C:\Tools");
        assert_eq!(normalize_install_location_pattern(r"C:\"), r"C:\");
    }
}
