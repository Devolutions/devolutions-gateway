//! Cross-checks that every event code declared in `sysevent-codes` has a matching
//! `MessageId`/`SymbolicName` entry in each product's Windows Event Log message catalog
//! (`.mc` file).
//!
//! Installer registration of an `EventMessageFile` alone is not enough: if the linked
//! binary's compiled message-table resource does not actually define an event ID, the
//! Windows Event Viewer shows "the description for Event ID ... cannot be found" for
//! every occurrence of that event. This test catches a code added to this crate without a
//! matching catalog update at CI time instead.

use std::path::Path;

/// Every `.mc` catalog must define every event code declared by `sysevent-codes`.
/// Both products link the complete shared catalog, including events they do not emit.
const MESSAGE_CATALOGS: &[&str] = &[
    "../../devolutions-gateway/devolutions-gateway.mc",
    "../../devolutions-agent/devolutions-agent.mc",
];

#[test]
fn every_event_code_is_defined_in_every_message_catalog() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_codes = declared_event_codes();

    for catalog in MESSAGE_CATALOGS {
        let path = manifest_dir.join(catalog);
        let content =
            std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

        for (name, code) in &event_codes {
            let expected_id = format!("MessageId={code}");
            let expected_name = format!("SymbolicName={name}");

            // A duplicate/missing `MessageId` is itself a bug (mc.exe would reject a
            // duplicate at build time), so fail fast here with a clearer message instead
            // of waiting for that far-less-obvious downstream failure.
            let id_positions: Vec<_> = content.match_indices(&expected_id).collect();
            assert_eq!(
                id_positions.len(),
                1,
                "{}: expected exactly one '{expected_id}' entry, found {}",
                path.display(),
                id_positions.len()
            );

            // `MessageId=N` must be immediately followed by `SymbolicName=NAME`, matching
            // every existing entry's layout: this is what actually binds the numeric
            // code emitted at runtime to this catalog's localized message text.
            let (id_offset, _) = id_positions[0];
            let after_id = &content[id_offset..];
            let next_line_start = after_id.find('\n').map_or(after_id.len(), |index| index + 1);
            let name_line = after_id[next_line_start..].lines().next().unwrap_or_default();
            assert_eq!(
                name_line.trim(),
                expected_name,
                "{}: '{expected_id}' must be immediately followed by '{expected_name}', found '{name_line}'",
                path.display()
            );
        }
    }

    fn declared_event_codes() -> Vec<(&'static str, u32)> {
        include_str!("../src/lib.rs")
            .lines()
            .filter(|line| line.trim().starts_with("pub const "))
            .map(|line| {
                let declaration = line
                    .trim()
                    .strip_prefix("pub const ")
                    .expect("filtered event-code declaration");
                let (name, value) = declaration.split_once(": u32 = ").unwrap_or_else(|| {
                    panic!("event-code declaration must use `pub const NAME: u32 = VALUE;`: {line}")
                });
                let (value, _) = value
                    .split_once(';')
                    .unwrap_or_else(|| panic!("event-code declaration must contain a semicolon: {line}"));
                let value = value.parse().unwrap_or_else(|error| {
                    panic!("event-code value must be a decimal u32 literal in `{line}`: {error}")
                });
                (name, value)
            })
            .collect()
    }
}
