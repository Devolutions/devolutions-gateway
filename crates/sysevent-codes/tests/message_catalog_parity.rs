//! Verifies that shared event codes and Windows message catalogs stay aligned.

use std::path::Path;

const MESSAGE_CATALOGS: &[&str] = &[
    "../../devolutions-gateway/devolutions-gateway.mc",
    "../../devolutions-agent/devolutions-agent.mc",
];

#[test]
fn every_event_code_is_defined_once_in_every_catalog() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_codes = declared_event_codes();

    for catalog in MESSAGE_CATALOGS {
        let path = manifest_dir.join(catalog);
        let content =
            std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

        for (name, code) in &event_codes {
            let expected_id = format!("MessageId={code}");
            let expected_name = format!("SymbolicName={name}");
            let positions: Vec<_> = content.match_indices(&expected_id).collect();
            assert_eq!(
                positions.len(),
                1,
                "{}: expected one {expected_id}, found {}",
                path.display(),
                positions.len()
            );

            let after_id = &content[positions[0].0..];
            let name_line = after_id.lines().nth(1).unwrap_or_default();
            assert_eq!(
                name_line.trim(),
                expected_name,
                "{}: {expected_id} must be followed by {expected_name}",
                path.display()
            );
        }
    }
}

#[test]
fn every_catalog_message_terminates_each_translation() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for catalog in MESSAGE_CATALOGS {
        let path = manifest_dir.join(catalog);
        let content = std::fs::read_to_string(&path).expect("read message catalog");
        assert!(
            content.starts_with('\u{feff}'),
            "{}: mc.exe requires a UTF-8 BOM to avoid decoding translations as ANSI",
            path.display()
        );
        for (_, code) in declared_event_codes() {
            let mut lines = message_block(&content, code).lines();
            let mut languages = Vec::new();
            while let Some(line) = lines.next() {
                let Some(language) = line.strip_prefix("Language=") else {
                    continue;
                };
                languages.push(language);
                let mut terminated = false;
                for text in lines.by_ref() {
                    if text == "." {
                        terminated = true;
                        break;
                    }
                    assert!(
                        !text.starts_with("Language="),
                        "{}: MessageId={code} {language} lacks a message terminator",
                        path.display()
                    );
                }
                assert!(
                    terminated,
                    "{}: MessageId={code} {language} lacks a message terminator",
                    path.display()
                );
            }
            languages.sort_unstable();
            assert_eq!(
                languages,
                ["English", "French", "German"],
                "{}: MessageId={code} must define each translation once",
                path.display()
            );
        }
    }
}

fn declared_event_codes() -> Vec<(&'static str, u32)> {
    include_str!("../src/lib.rs")
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub const "))
        .map(|declaration| {
            let (name, value) = declaration
                .split_once(": u32 = ")
                .unwrap_or_else(|| panic!("event code must use `pub const NAME: u32 = VALUE;`: {declaration}"));
            let value = value
                .split_once(';')
                .unwrap_or_else(|| panic!("event code must contain a semicolon: {declaration}"))
                .0
                .parse()
                .unwrap_or_else(|error| panic!("event code must be a decimal u32 in `{declaration}`: {error}"));
            (name, value)
        })
        .collect()
}

fn message_block(content: &str, code: u32) -> &str {
    let marker = format!("MessageId={code}");
    let start = content.find(&marker).unwrap_or_else(|| panic!("missing {marker}"));
    let after = &content[start + marker.len()..];
    let end = after.find("\nMessageId=").unwrap_or(after.len());
    &content[start..start + marker.len() + end]
}
