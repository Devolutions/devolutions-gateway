//! Verifies that shared event codes and Windows message catalogs stay aligned.

use std::path::Path;

const MESSAGE_CATALOGS: &[&str] = &[
    "../../devolutions-gateway/devolutions-gateway.mc",
    "../../devolutions-agent/devolutions-agent.mc",
];

const POLICY_INSERTION_COUNTS: &[(u32, usize)] = &[
    (sysevent_codes::POLICY_WRITE_ATTEMPTED, 5),
    (sysevent_codes::POLICY_WRITE_DENIED, 6),
    (sysevent_codes::POLICY_CREATE_FAILED, 8),
    (sysevent_codes::POLICY_CREATE_SUCCEEDED, 11),
    (sysevent_codes::POLICY_CHANGE_FAILED, 8),
    (sysevent_codes::POLICY_CHANGE_SUCCEEDED, 11),
    (sysevent_codes::POLICY_EXTERNAL_CHANGE_APPLIED, 4),
    (sysevent_codes::POLICY_EXTERNAL_CHANGE_REJECTED, 3),
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
fn policy_catalog_insertions_match_structured_field_order() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    for catalog in MESSAGE_CATALOGS {
        let path = manifest_dir.join(catalog);
        let content =
            std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

        for &(code, insertion_count) in POLICY_INSERTION_COUNTS {
            let block = message_block(&content, code);
            let messages: Vec<_> = block
                .lines()
                .enumerate()
                .filter(|(_, line)| line.starts_with("Language="))
                .map(|(index, _)| block.lines().nth(index + 1).unwrap_or_default())
                .collect();
            assert_eq!(messages.len(), 3, "{}: MessageId={code}", path.display());

            for message in messages {
                for insertion in 1..=insertion_count {
                    assert!(
                        message.contains(&format!("%{insertion}")),
                        "{}: MessageId={code} omits %{insertion}",
                        path.display()
                    );
                }
                assert!(
                    !message.contains(&format!("%{}", insertion_count + 1)),
                    "{}: MessageId={code} has an unexpected insertion",
                    path.display()
                );
            }
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
