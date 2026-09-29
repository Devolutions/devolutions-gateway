//! Verifies that each product's declared event codes and Windows message catalog stay aligned.

use std::path::{Path, PathBuf};

use sysevent::Entry;

const GATEWAY_CATALOG: &str = "devolutions-gateway/devolutions-gateway.mc";
const AGENT_CATALOG: &str = "devolutions-agent/devolutions-agent.mc";

/// A declared code set, the single catalog that must hold exactly its codes, and every builder of
/// those codes paired with the entry it produces.
struct DeclaredCodeSet {
    codes_crate: &'static str,
    codes: &'static [(&'static str, u32)],
    catalog: &'static str,
    events: fn() -> Vec<(u32, Entry)>,
}

/// The Gateway and the Agent own separate code tables, so each catalog holds the codes of its own
/// crate and nothing else. A code shared by both products is declared in both crates and appears in
/// both catalogs.
const DECLARED_CODE_SETS: &[DeclaredCodeSet] = &[
    DeclaredCodeSet {
        codes_crate: "sysevent-codes",
        codes: sysevent_codes::DECLARED_CODES,
        catalog: GATEWAY_CATALOG,
        events: gateway_events,
    },
    DeclaredCodeSet {
        codes_crate: "agent-sysevent-codes",
        codes: agent_sysevent_codes::DECLARED_CODES,
        catalog: AGENT_CATALOG,
        events: agent_events,
    },
];

#[test]
fn every_catalog_defines_exactly_its_declared_codes() {
    for declared in DECLARED_CODE_SETS {
        let DeclaredCodeSet {
            codes_crate,
            codes,
            catalog,
            ..
        } = declared;
        assert!(!codes.is_empty(), "{codes_crate} declares no event code");

        let path = catalog_path(catalog);
        let content = read(&path);
        let defined = catalog_codes(&content, &path);

        // The code is the value the runtime passes to ReportEventW, so a name bound to the wrong
        // number must fail here even though every declared name is present.
        let mut disagreements: Vec<String> = Vec::new();
        for (name, code) in codes.iter().copied() {
            match defined.iter().find(|(defined_name, _)| defined_name.as_str() == name) {
                None => disagreements.push(format!("{name} is missing")),
                Some((_, defined_code)) if *defined_code == code => {}
                Some((_, defined_code)) => disagreements.push(format!(
                    "{name} is MessageId={defined_code}, but {codes_crate} declares {code}"
                )),
            }
        }
        for (name, code) in &defined {
            if !codes.iter().any(|(declared_name, _)| *declared_name == name.as_str()) {
                disagreements.push(format!(
                    "{name} is MessageId={code}, which {codes_crate} does not declare; a catalog \
                     holds exactly the codes of its own product"
                ));
            }
        }
        assert!(
            disagreements.is_empty(),
            "{} and {codes_crate} disagree: {}",
            path.display(),
            disagreements.join("; ")
        );

        assert_eq!(
            defined.len(),
            codes.len(),
            "{} declares {} messages for {} {codes_crate} codes; each code needs exactly one \
             message",
            path.display(),
            defined.len(),
            codes.len()
        );
    }
}

#[test]
fn every_catalog_message_terminates_each_translation() {
    for declared in DECLARED_CODE_SETS {
        let DeclaredCodeSet { catalog, .. } = declared;
        let path = catalog_path(catalog);
        let content = read(&path);
        assert!(
            content.starts_with('\u{feff}'),
            "{}: mc.exe requires a UTF-8 BOM to avoid decoding translations as ANSI",
            path.display()
        );

        for (name, code) in catalog_codes(&content, &path) {
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
                "{}: MessageId={code} {name} must define each translation once",
                path.display()
            );
        }
    }
}

#[test]
fn every_code_builder_inserts_the_message_then_every_field() {
    for declared in DECLARED_CODE_SETS {
        let DeclaredCodeSet {
            codes_crate,
            codes,
            catalog,
            events,
        } = declared;
        let path = catalog_path(catalog);
        let catalog = read(&path);

        let events = events();
        let mut covered: Vec<u32> = events.iter().map(|(code, _)| *code).collect();
        covered.sort_unstable();
        let mut declared_codes: Vec<u32> = codes.iter().map(|(_, code)| *code).collect();
        declared_codes.sort_unstable();
        assert_eq!(
            covered, declared_codes,
            "every {codes_crate} code needs a builder here, so its insertion strings stay checked"
        );

        for (code, entry) in events {
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
}

/// Every declared Gateway event, each paired with the entry its builder produces.
fn gateway_events() -> Vec<(u32, Entry)> {
    let path = Path::new("C:\\ProgramData\\Devolutions\\Gateway\\gateway.json");

    let mut events = vec![
        (
            sysevent_codes::SERVICE_STARTED,
            sysevent_codes::service_started("2026.3.0"),
        ),
        (
            sysevent_codes::SERVICE_STOPPING,
            sysevent_codes::service_stopping("received stop control code"),
        ),
        (
            sysevent_codes::CONFIG_INVALID,
            sysevent_codes::config_invalid("invalid config", path),
        ),
        (
            sysevent_codes::START_FAILED,
            sysevent_codes::start_failed("failed to bind", "service_start"),
        ),
        (
            sysevent_codes::BOOT_STACKTRACE_WRITTEN,
            sysevent_codes::boot_stacktrace_written(path),
        ),
        (
            sysevent_codes::LISTENER_STARTED,
            sysevent_codes::listener_started("127.0.0.1:7171", "tcp"),
        ),
        (
            sysevent_codes::LISTENER_BIND_FAILED,
            sysevent_codes::listener_bind_failed("127.0.0.1:7171", "address in use"),
        ),
        (
            sysevent_codes::LISTENER_STOPPED,
            sysevent_codes::listener_stopped("127.0.0.1:7171", "shutdown"),
        ),
        (sysevent_codes::TLS_CONFIGURED, sysevent_codes::tls_configured("file")),
        (
            sysevent_codes::TLS_VERIFY_STRICT_DISABLED,
            sysevent_codes::tls_verify_strict_disabled("compat"),
        ),
        (
            sysevent_codes::TLS_CERTIFICATE_REJECTED,
            sysevent_codes::tls_certificate_rejected("CN=gateway", "missing_san"),
        ),
        (
            sysevent_codes::SYSTEM_CERT_SELECTED,
            sysevent_codes::system_cert_selected("<thumbprint>", "CN=gateway"),
        ),
        (
            sysevent_codes::TLS_KEY_LOAD_FAILED,
            sysevent_codes::tls_key_load_failed(path, "permission denied"),
        ),
        (
            sysevent_codes::TLS_CERTIFICATE_NAME_MISMATCH,
            sysevent_codes::tls_certificate_name_mismatch("gateway.example.com", "CN=gateway"),
        ),
        (
            sysevent_codes::TLS_NO_SUITABLE_CERTIFICATE,
            sysevent_codes::tls_no_suitable_certificate("no usable certificate", "expired"),
        ),
        (
            sysevent_codes::SESSION_OPENED,
            sysevent_codes::session_opened("RDP", "10.0.0.1", "srv01", "token_id"),
        ),
        (
            sysevent_codes::SESSION_CLOSED,
            sysevent_codes::session_closed(1000, 1024, 2048, "ok"),
        ),
        (
            sysevent_codes::TOKEN_PROVISIONED,
            sysevent_codes::token_provisioned("token_id"),
        ),
        (
            sysevent_codes::TOKEN_REUSED,
            sysevent_codes::token_reused("token_id", 1),
        ),
        (
            sysevent_codes::TOKEN_REUSE_LIMIT_EXCEEDED,
            sysevent_codes::token_reuse_limit_exceeded("token_id", 2),
        ),
        (
            sysevent_codes::RECORDING_STARTED,
            sysevent_codes::recording_started("C:\\recordings"),
        ),
        (
            sysevent_codes::RECORDING_STOPPED,
            sysevent_codes::recording_stopped(1024, 1),
        ),
        (
            sysevent_codes::RECORDING_ERROR,
            sysevent_codes::recording_error(path, "no space left"),
        ),
        (
            sysevent_codes::JWT_REJECTED,
            sysevent_codes::jwt_rejected("expired", "the token expired"),
        ),
        (
            sysevent_codes::JWT_ANOMALY,
            sysevent_codes::jwt_anomaly("issuer", "audience", "kid", "clock_skew", "detail"),
        ),
        (
            sysevent_codes::AUTHORIZATION_DENIED,
            sysevent_codes::authorization_denied("subject", "action", "resource", "rule"),
        ),
        (
            sysevent_codes::AUTH_SUMMARY,
            sysevent_codes::auth_summary(60, 10, 2, 1, "{}"),
        ),
        (
            sysevent_codes::RECORDING_STORAGE_LOW,
            sysevent_codes::recording_storage_low(1024, 4096),
        ),
        (
            sysevent_codes::DEBUG_OPTIONS_ENABLED,
            sysevent_codes::debug_options_enabled("verbose"),
        ),
        (
            sysevent_codes::XMF_NOT_FOUND,
            sysevent_codes::xmf_not_found(path, "not found"),
        ),
    ];

    events.sort_unstable_by_key(|(code, _)| *code);
    events
}

/// Every declared Agent event, each paired with the entry its builder produces.
fn agent_events() -> Vec<(u32, Entry)> {
    let path = Path::new("C:\\ProgramData\\Devolutions\\Agent\\policy.json");

    let mut events = vec![
        (
            agent_sysevent_codes::SERVICE_STARTED,
            agent_sysevent_codes::service_started("2026.3.0"),
        ),
        (
            agent_sysevent_codes::SERVICE_STOPPING,
            agent_sysevent_codes::service_stopping("received stop control code"),
        ),
        (
            agent_sysevent_codes::CONFIG_INVALID,
            agent_sysevent_codes::config_invalid("invalid config", path),
        ),
        (
            agent_sysevent_codes::START_FAILED,
            agent_sysevent_codes::start_failed("failed to bind", "service_start"),
        ),
        (
            agent_sysevent_codes::BOOT_STACKTRACE_WRITTEN,
            agent_sysevent_codes::boot_stacktrace_written(path),
        ),
        (
            agent_sysevent_codes::USER_SESSION_PROCESS_STARTED,
            agent_sysevent_codes::user_session_process_started(1, "console", "DevolutionsSession.exe"),
        ),
        (
            agent_sysevent_codes::USER_SESSION_PROCESS_TERMINATED,
            agent_sysevent_codes::user_session_process_terminated(1, 0, "user"),
        ),
        (
            agent_sysevent_codes::UPDATER_TASK_ENABLED,
            agent_sysevent_codes::updater_task_enabled(),
        ),
        (
            agent_sysevent_codes::UPDATER_ERROR,
            agent_sysevent_codes::updater_error("download", "invalid signature"),
        ),
        (agent_sysevent_codes::PEDM_ENABLED, agent_sysevent_codes::pedm_enabled()),
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
    ];

    events.sort_unstable_by_key(|(code, _)| *code);
    events
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

/// Every message of a catalog, as its symbolic name and message id, in file order.
fn catalog_codes(content: &str, path: &Path) -> Vec<(String, u32)> {
    let mut codes = Vec::new();
    let mut lines = content.lines();

    while let Some(line) = lines.next() {
        let Some(id) = line.strip_prefix("MessageId=") else {
            continue;
        };
        let id = id.trim();
        let name = lines
            .next()
            .unwrap_or_else(|| panic!("{}: MessageId={id} without a symbolic name", path.display()));
        let name = name.strip_prefix("SymbolicName=").unwrap_or_else(|| {
            panic!(
                "{}: MessageId={id} must be followed by its SymbolicName, found {name:?}",
                path.display()
            )
        });

        codes.push((
            name.trim().to_owned(),
            id.parse()
                .unwrap_or_else(|error| panic!("{}: MessageId={id} is not an event code: {error}", path.display())),
        ));
    }

    codes
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

/// The lines following `MessageId=<code>`, up to the next message. Each line is compared whole,
/// which keeps a code from matching a longer code such as `800` against `8001`, and the line ending
/// is trimmed so a catalog checked out with CRLF endings reads the same as one with LF.
fn message_block(content: &str, code: u32) -> &str {
    let marker = format!("MessageId={code}");
    let mut start = None;
    let mut end = content.len();
    let mut offset = 0;

    for line in content.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed == marker.as_str() {
            start = Some(offset + line.len());
        } else if start.is_some() && trimmed.starts_with("MessageId=") {
            end = offset;
            break;
        }
        offset += line.len();
    }

    match start {
        Some(start) => &content[start..end],
        None => panic!("missing MessageId={code}"),
    }
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
