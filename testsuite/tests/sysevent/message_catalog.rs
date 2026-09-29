//! Verifies that declared event codes and the Windows message catalogs stay aligned.

use std::path::{Path, PathBuf};

use sysevent::Entry;

const GATEWAY_CATALOG: &str = "devolutions-gateway/devolutions-gateway.mc";
const AGENT_CATALOG: &str = "devolutions-agent/devolutions-agent.mc";

/// A declared code set, with the catalogs that must define each of its codes.
struct DeclaredCodeSet {
    codes_crate: &'static str,
    codes: &'static [(&'static str, u32)],
    catalogs: &'static [&'static str],
}

const DECLARED_CODE_SETS: &[DeclaredCodeSet] = &[
    DeclaredCodeSet {
        codes_crate: "sysevent-codes",
        codes: sysevent_codes::DECLARED_CODES,
        catalogs: &[GATEWAY_CATALOG, AGENT_CATALOG],
    },
    DeclaredCodeSet {
        codes_crate: "agent-sysevent-codes",
        codes: agent_sysevent_codes::DECLARED_CODES,
        catalogs: &[AGENT_CATALOG],
    },
];

#[test]
fn every_event_code_is_defined_once_in_every_catalog() {
    for declared in DECLARED_CODE_SETS {
        let DeclaredCodeSet {
            codes_crate,
            codes,
            catalogs,
        } = declared;
        assert!(!codes.is_empty(), "{codes_crate} declares no event code");

        for catalog in *catalogs {
            let path = catalog_path(catalog);
            let content = read(&path);

            for (name, code) in *codes {
                let expected_id = format!("MessageId={code}");
                let expected_name = format!("SymbolicName={name}");
                let positions: Vec<_> = content.match_indices(&expected_id).collect();
                assert_eq!(
                    positions.len(),
                    1,
                    "{codes_crate}: {}: expected one {expected_id}, found {}",
                    path.display(),
                    positions.len()
                );

                let after_id = &content[positions[0].0..];
                let name_line = after_id.lines().nth(1).unwrap_or_default();
                assert_eq!(
                    name_line.trim(),
                    expected_name,
                    "{codes_crate}: {}: {expected_id} must be followed by {expected_name}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn every_catalog_message_terminates_each_translation() {
    for declared in DECLARED_CODE_SETS {
        let DeclaredCodeSet {
            codes_crate,
            codes,
            catalogs,
        } = declared;

        for catalog in *catalogs {
            let path = catalog_path(catalog);
            let content = read(&path);
            assert!(
                content.starts_with('\u{feff}'),
                "{}: mc.exe requires a UTF-8 BOM to avoid decoding translations as ANSI",
                path.display()
            );

            for (name, code) in *codes {
                let mut lines = message_block(&content, *code).lines();
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
                    "{codes_crate}: {}: MessageId={code} {name} must define each translation once",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn agent_policy_messages_insert_the_message_then_every_field() {
    let path = catalog_path(AGENT_CATALOG);
    let catalog = read(&path);

    for (code, entry) in agent_policy_events() {
        assert_eq!(
            entry.event_code,
            Some(code),
            "the builder for MessageId={code} must declare that event code"
        );

        // The Windows Event Log sink passes the message text as the first insertion string, then
        // one string per field, so a message needs exactly one insertion per field plus one.
        let count = u32::try_from(entry.fields.len() + 1).expect("the entry has few fields");
        let expected: Vec<u32> = (1..=count).collect();

        let messages = catalog_messages(&catalog, code);
        assert_eq!(messages.len(), 3, "{}: MessageId={code} translations", path.display());
        for message in messages {
            assert_eq!(
                insertions(message),
                expected,
                "{}: MessageId={code} must use %1 as the message and %2..%{count} as its fields: {message}",
                path.display()
            );
        }
    }
}

/// The Agent policy events, each paired with the entry its builder produces.
fn agent_policy_events() -> Vec<(u32, Entry)> {
    let path = Path::new("C:\\ProgramData\\Devolutions\\Agent\\policy.json");

    vec![
        (
            agent_sysevent_codes::POLICY_WRITE_ATTEMPTED,
            agent_sysevent_codes::policy_write_attempted("S-1-5-18", "devolutions-agent.exe", "policy_write", path),
        ),
        (
            agent_sysevent_codes::POLICY_WRITE_DENIED,
            agent_sysevent_codes::policy_write_denied(
                "S-1-5-18",
                "devolutions-agent.exe",
                "policy_write",
                path,
                "request_rejected",
            ),
        ),
        (
            agent_sysevent_codes::POLICY_CREATE_FAILED,
            agent_sysevent_codes::policy_write_failed(
                agent_sysevent_codes::POLICY_CREATE_FAILED,
                "Policy creation failed",
                "S-1-5-18",
                "devolutions-agent.exe",
                "policy_write",
                path,
                "create",
                "failed",
                "invalid_draft",
            ),
        ),
        (
            agent_sysevent_codes::POLICY_CREATE_SUCCEEDED,
            agent_sysevent_codes::policy_write_succeeded(
                agent_sysevent_codes::POLICY_CREATE_SUCCEEDED,
                "Policy creation succeeded",
                "S-1-5-18",
                "devolutions-agent.exe",
                path,
                "00000000-0000-0000-0000-000000000000",
                "0",
                "11111111-1111-1111-1111-111111111111",
                1,
                "policy_write",
                "create",
                "succeeded",
            ),
        ),
        (
            agent_sysevent_codes::POLICY_CHANGE_FAILED,
            agent_sysevent_codes::policy_write_failed(
                agent_sysevent_codes::POLICY_CHANGE_FAILED,
                "Policy change failed",
                "S-1-5-18",
                "devolutions-agent.exe",
                "policy_write",
                path,
                "change",
                "stale_conflict",
                "stale_store_token",
            ),
        ),
        (
            agent_sysevent_codes::POLICY_CHANGE_SUCCEEDED,
            agent_sysevent_codes::policy_write_succeeded(
                agent_sysevent_codes::POLICY_CHANGE_SUCCEEDED,
                "Policy change succeeded",
                "S-1-5-18",
                "devolutions-agent.exe",
                path,
                "11111111-1111-1111-1111-111111111111",
                "1",
                "22222222-2222-2222-2222-222222222222",
                2,
                "policy_write",
                "change",
                "succeeded",
            ),
        ),
        (
            agent_sysevent_codes::POLICY_EXTERNAL_CHANGE_APPLIED,
            agent_sysevent_codes::policy_external_change_applied(path, "22222222-2222-2222-2222-222222222222", 2),
        ),
        (
            agent_sysevent_codes::POLICY_EXTERNAL_CHANGE_REJECTED,
            agent_sysevent_codes::policy_external_change_rejected(path, "invalid"),
        ),
    ]
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn catalog_path(catalog: &str) -> PathBuf {
    // The testsuite sits at the repository root, next to the product crates holding the catalogs.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the testsuite sits in the repository root")
        .join(catalog)
}

/// The message of each translation inside the `MessageId=<code>` block.
fn catalog_messages(catalog: &str, code: u32) -> Vec<&str> {
    let mut messages = Vec::new();
    let mut lines = message_block(catalog, code).lines();
    while let Some(line) = lines.next() {
        if line.starts_with("Language=") {
            messages.push(lines.next().unwrap_or_default());
        }
    }
    messages
}

fn message_block(content: &str, code: u32) -> &str {
    let marker = format!("MessageId={code}");
    let start = content.find(&marker).unwrap_or_else(|| panic!("missing {marker}"));
    let after = &content[start + marker.len()..];
    let end = after.find("\nMessageId=").unwrap_or(after.len());
    &content[start..start + marker.len() + end]
}

/// Insertion indices (`%1`, `%2`, ...) referenced by a catalog message, in ascending order.
fn insertions(message: &str) -> Vec<u32> {
    let mut indices = Vec::new();
    let mut remaining = message;

    while let Some(percent) = remaining.find('%') {
        remaining = &remaining[percent + 1..];
        let trailing = remaining.trim_start_matches(|character: char| character.is_ascii_digit());
        if trailing.len() == remaining.len() {
            continue;
        }
        let (index, rest) = remaining.split_at(remaining.len() - trailing.len());
        indices.push(index.parse().expect("a catalog insertion index is a number"));
        remaining = rest;
    }

    indices.sort_unstable();
    indices
}
