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

/// (symbolic name as it appears in the `.mc` files, numeric event code) for every event
/// code declared in `sysevent-codes`. Deliberately explicit and manually maintained: this
/// makes adding a new event code a conscious two-step change (declare the constant in
/// `src/lib.rs`, list it here) that this test then verifies against every `.mc` catalog.
const EVENT_CODES: &[(&str, u32)] = &[
    ("SERVICE_STARTED", sysevent_codes::SERVICE_STARTED),
    ("SERVICE_STOPPING", sysevent_codes::SERVICE_STOPPING),
    ("CONFIG_INVALID", sysevent_codes::CONFIG_INVALID),
    ("START_FAILED", sysevent_codes::START_FAILED),
    ("BOOT_STACKTRACE_WRITTEN", sysevent_codes::BOOT_STACKTRACE_WRITTEN),
    ("LISTENER_STARTED", sysevent_codes::LISTENER_STARTED),
    ("LISTENER_BIND_FAILED", sysevent_codes::LISTENER_BIND_FAILED),
    ("LISTENER_STOPPED", sysevent_codes::LISTENER_STOPPED),
    ("TLS_CONFIGURED", sysevent_codes::TLS_CONFIGURED),
    ("TLS_VERIFY_STRICT_DISABLED", sysevent_codes::TLS_VERIFY_STRICT_DISABLED),
    ("TLS_CERTIFICATE_REJECTED", sysevent_codes::TLS_CERTIFICATE_REJECTED),
    ("SYSTEM_CERT_SELECTED", sysevent_codes::SYSTEM_CERT_SELECTED),
    ("TLS_KEY_LOAD_FAILED", sysevent_codes::TLS_KEY_LOAD_FAILED),
    (
        "TLS_CERTIFICATE_NAME_MISMATCH",
        sysevent_codes::TLS_CERTIFICATE_NAME_MISMATCH,
    ),
    (
        "TLS_NO_SUITABLE_CERTIFICATE",
        sysevent_codes::TLS_NO_SUITABLE_CERTIFICATE,
    ),
    ("SESSION_OPENED", sysevent_codes::SESSION_OPENED),
    ("SESSION_CLOSED", sysevent_codes::SESSION_CLOSED),
    ("TOKEN_PROVISIONED", sysevent_codes::TOKEN_PROVISIONED),
    ("TOKEN_REUSED", sysevent_codes::TOKEN_REUSED),
    ("TOKEN_REUSE_LIMIT_EXCEEDED", sysevent_codes::TOKEN_REUSE_LIMIT_EXCEEDED),
    ("RECORDING_STARTED", sysevent_codes::RECORDING_STARTED),
    ("RECORDING_STOPPED", sysevent_codes::RECORDING_STOPPED),
    ("RECORDING_ERROR", sysevent_codes::RECORDING_ERROR),
    ("JWT_REJECTED", sysevent_codes::JWT_REJECTED),
    ("JWT_ANOMALY", sysevent_codes::JWT_ANOMALY),
    ("AUTHORIZATION_DENIED", sysevent_codes::AUTHORIZATION_DENIED),
    ("AUTH_SUMMARY", sysevent_codes::AUTH_SUMMARY),
    (
        "USER_SESSION_PROCESS_STARTED",
        sysevent_codes::USER_SESSION_PROCESS_STARTED,
    ),
    (
        "USER_SESSION_PROCESS_TERMINATED",
        sysevent_codes::USER_SESSION_PROCESS_TERMINATED,
    ),
    ("UPDATER_TASK_ENABLED", sysevent_codes::UPDATER_TASK_ENABLED),
    ("UPDATER_ERROR", sysevent_codes::UPDATER_ERROR),
    ("PEDM_ENABLED", sysevent_codes::PEDM_ENABLED),
    ("RECORDING_STORAGE_LOW", sysevent_codes::RECORDING_STORAGE_LOW),
    ("POLICY_WRITE_ATTEMPTED", sysevent_codes::POLICY_WRITE_ATTEMPTED),
    ("POLICY_WRITE_DENIED", sysevent_codes::POLICY_WRITE_DENIED),
    ("POLICY_WRITE_CONFLICT", sysevent_codes::POLICY_WRITE_CONFLICT),
    (
        "POLICY_WRITE_CONFIRMED_OVERWRITE",
        sysevent_codes::POLICY_WRITE_CONFIRMED_OVERWRITE,
    ),
    ("POLICY_WRITE_FAILED", sysevent_codes::POLICY_WRITE_FAILED),
    ("POLICY_WRITE_SUCCEEDED", sysevent_codes::POLICY_WRITE_SUCCEEDED),
    (
        "POLICY_EXTERNAL_CHANGE_APPLIED",
        sysevent_codes::POLICY_EXTERNAL_CHANGE_APPLIED,
    ),
    (
        "POLICY_EXTERNAL_CHANGE_REJECTED",
        sysevent_codes::POLICY_EXTERNAL_CHANGE_REJECTED,
    ),
    ("DEBUG_OPTIONS_ENABLED", sysevent_codes::DEBUG_OPTIONS_ENABLED),
    ("XMF_NOT_FOUND", sysevent_codes::XMF_NOT_FOUND),
];

/// Every `.mc` catalog that must define the entire `EVENT_CODES` table above. Both
/// products link the full shared event-code catalog into their own message-table
/// resource, even for events the specific binary never itself emits (see each `.mc`
/// file's own header comment), so both are held to the exact same complete set.
const MESSAGE_CATALOGS: &[&str] = &[
    "../../devolutions-gateway/devolutions-gateway.mc",
    "../../devolutions-agent/devolutions-agent.mc",
];

#[test]
fn every_event_code_is_defined_in_every_message_catalog() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    for catalog in MESSAGE_CATALOGS {
        let path = manifest_dir.join(catalog);
        let content =
            std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

        for (name, code) in EVENT_CODES {
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
}
