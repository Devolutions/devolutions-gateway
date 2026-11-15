//! Converts a UniGetUI `GetInventorySnapshot` result into inventory messages.
//!
//! The snapshot is untrusted input.
//! Required data that is missing or malformed fails the whole conversion, and error messages never carry response content.
//! Source data that may expose local paths or credentials is omitted rather than reported.

use agent_channel_proto::{InstalledPackage, PackageManager, PackageSource};
use anyhow::{Context as _, bail};
use serde_json::{Map, Value};

use super::Snapshot;

type Object = Map<String, Value>;

pub(super) fn parse_snapshot(value: Value) -> anyhow::Result<Snapshot> {
    let Value::Object(snapshot) = value else {
        bail!("inventory snapshot is not an object");
    };

    let scan_completed_at = parse_timestamp(required_str(&snapshot, "completedAt")?).context("completedAt")?;

    let update_scan_completed_at = match snapshot.get("updateCompletedAt") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(parse_timestamp(text).context("updateCompletedAt")?),
        Some(_) => bail!("updateCompletedAt is not a string"),
    };

    let managers = required_array(&snapshot, "managers")?
        .iter()
        .map(parse_manager)
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut seen = std::collections::HashSet::new();
    if !managers.iter().all(|manager| seen.insert(manager.name.as_str())) {
        bail!("duplicate package manager");
    }

    let sources = required_array(&snapshot, "sources")?
        .iter()
        .map(parse_source)
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    let mut packages = required_array(&snapshot, "installedPackages")?
        .iter()
        .map(|item| parse_package(item).map(|package| package.installed))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Updates are advisory and only meaningful with a completed update scan.
    if update_scan_completed_at.is_some() {
        let updates = required_array(&snapshot, "updates")?
            .iter()
            .map(parse_package)
            .collect::<anyhow::Result<Vec<_>>>()?;
        merge_updates(&mut packages, updates);
    }

    Ok(Snapshot {
        packages,
        managers,
        sources,
        scan_completed_at,
        update_scan_completed_at,
    })
}

struct ParsedPackage {
    installed: InstalledPackage,
    new_version: String,
}

fn parse_package(item: &Value) -> anyhow::Result<ParsedPackage> {
    let item = item.as_object().context("package entry is not an object")?;

    let source = optional_str(item, "source")?.filter(|text| is_safe_text(text));
    let source_name = optional_str(item, "sourceName")?.filter(|text| is_safe_text(text));

    Ok(ParsedPackage {
        installed: InstalledPackage {
            manager: required_nonempty_str(item, "manager")?.to_owned(),
            source: source.unwrap_or_default().to_owned(),
            id: required_nonempty_str(item, "id")?.to_owned(),
            name: required_nonempty_str(item, "name")?.to_owned(),
            version: required_str(item, "version")?.to_owned(),
            available_version: String::new(),
            // No manager-specific ownership mapping exists, so ownership is never claimed.
            scope: "UNKNOWN".to_owned(),
            source_name: source_name.unwrap_or_default().to_owned(),
            reported_scope: optional_str(item, "reportedScope")?.unwrap_or_default().to_owned(),
        },
        new_version: optional_str(item, "newVersion")?.unwrap_or_default().to_owned(),
    })
}

fn parse_manager(item: &Value) -> anyhow::Result<PackageManager> {
    let item = item.as_object().context("manager entry is not an object")?;

    Ok(PackageManager {
        name: required_nonempty_str(item, "name")?.to_owned(),
        installed: required_bool(item, "ready")?,
        enabled: required_bool(item, "enabled")?,
        // UniGetUI IPC does not expose manager versions.
        version: String::new(),
    })
}

/// Returns `None` for a source whose identity cannot be reported safely.
fn parse_source(item: &Value) -> anyhow::Result<Option<PackageSource>> {
    let item = item.as_object().context("source entry is not an object")?;

    let manager = required_nonempty_str(item, "manager")?;
    let name = required_nonempty_str(item, "name")?;
    optional_str(item, "url")?;

    if !is_safe_text(manager) || !is_safe_text(name) {
        return Ok(None);
    }

    Ok(Some(PackageSource {
        manager: manager.to_owned(),
        name: name.to_owned(),
        url: String::new(),
    }))
}

/// Sets `available_version` only when exactly one installed package matches and all updates for it agree.
fn merge_updates(packages: &mut [InstalledPackage], updates: Vec<ParsedPackage>) {
    // `Some(None)` marks a package whose updates conflict.
    let mut merged: std::collections::HashMap<usize, Option<String>> = std::collections::HashMap::new();

    for update in updates.iter().filter(|update| !update.new_version.is_empty()) {
        let update = (&update.installed, &update.new_version);

        let mut candidates = packages
            .iter()
            .enumerate()
            .filter(|(_, package)| is_same_package(package, update.0));

        let (Some((index, _)), None) = (candidates.next(), candidates.next()) else {
            continue;
        };

        match merged.entry(index) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some(update.1.clone()));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().as_ref() != Some(update.1) {
                    entry.insert(None);
                }
            }
        }
    }

    for (index, version) in merged {
        if let Some(version) = version {
            packages[index].available_version = version;
        }
    }
}

fn is_same_package(installed: &InstalledPackage, update: &InstalledPackage) -> bool {
    let same_source = if installed.source_name.is_empty() || update.source_name.is_empty() {
        !installed.source.is_empty() && installed.source == update.source
    } else {
        installed.source_name == update.source_name
    };

    installed.manager == update.manager && installed.id == update.id && same_source
}

fn required_array<'a>(object: &'a Object, key: &str) -> anyhow::Result<&'a Vec<Value>> {
    object
        .get(key)
        .and_then(Value::as_array)
        .with_context(|| format!("{key} is missing or not an array"))
}

fn required_str<'a>(object: &'a Object, key: &str) -> anyhow::Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{key} is missing or not a string"))
}

fn required_nonempty_str<'a>(object: &'a Object, key: &str) -> anyhow::Result<&'a str> {
    let text = required_str(object, key)?;
    if text.is_empty() {
        bail!("{key} is empty");
    }
    Ok(text)
}

fn required_bool(object: &Object, key: &str) -> anyhow::Result<bool> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .with_context(|| format!("{key} is missing or not a boolean"))
}

fn optional_str<'a>(object: &'a Object, key: &str) -> anyhow::Result<Option<&'a str>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => bail!("{key} is not a string"),
    }
}

/// A conservative filter: a false positive only omits optional source data.
fn looks_sensitive(text: &str) -> bool {
    const MARKERS: [&str; 16] = [
        "\\",
        "@",
        "%",
        "file:",
        "/users/",
        "/home/",
        "password",
        "passwd",
        "pwd=",
        "token",
        "secret",
        "apikey",
        "api_key",
        "api-key",
        "credential",
        "bearer",
    ];

    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let has_drive = bytes.windows(3).enumerate().any(|(index, window)| {
        window[0].is_ascii_alphabetic()
            && window[1] == b':'
            && window[2] == b'/'
            && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric())
    });

    text.chars().any(char::is_control)
        || lower.starts_with(['/', '~'])
        || has_drive
        || lower.contains("key=")
        || lower.contains("authorization")
        || MARKERS.iter().any(|marker| lower.contains(marker))
}

fn is_safe_text(text: &str) -> bool {
    !text.is_empty()
        && !looks_sensitive(text)
        && text
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, ' ' | '-' | '_' | '.'))
}

/// Parses an RFC 3339 date-time without logging or returning the input.
fn parse_timestamp(text: &str) -> anyhow::Result<prost_types::Timestamp> {
    let fraction_len = text.split_once('.').map_or(0, |(_, fraction)| {
        fraction.bytes().take_while(u8::is_ascii_digit).count()
    });
    if !matches!(text.as_bytes().get(10), Some(b'T' | b't'))
        || 9 < fraction_len
        || text.as_bytes().get(17..19) == Some(b"60")
    {
        bail!("invalid RFC 3339 timestamp");
    }

    let timestamp = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .map_err(|_| anyhow::anyhow!("invalid RFC 3339 timestamp"))?;
    let seconds = timestamp.unix_timestamp();
    anyhow::ensure!(
        (-62_135_596_800..=253_402_300_799).contains(&seconds),
        "timestamp is outside the protobuf range"
    );
    Ok(prost_types::Timestamp {
        seconds,
        nanos: i32::try_from(timestamp.nanosecond()).expect("nanoseconds fit in i32"),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn package(extra: Value) -> Value {
        let mut value = json!({
            "name": "Example",
            "id": "example.id",
            "version": "1.0",
            "manager": "winget",
            "reportedScope": "Machine",
            "source": "winget",
            "sourceName": "winget",
        });
        value
            .as_object_mut()
            .expect("package fixture is an object")
            .extend(extra.as_object().expect("extra fields are an object").clone());
        value
    }

    fn snapshot(update_completed_at: Value, packages: Vec<Value>, updates: Vec<Value>) -> Value {
        json!({
            "completedAt": "2024-01-01T00:00:00Z",
            "updateCompletedAt": update_completed_at,
            "managers": [{ "name": "winget", "enabled": true, "ready": true }],
            "sources": [{ "manager": "winget", "name": "winget", "url": "https://cdn.winget.microsoft.com/cache" }],
            "installedPackages": packages,
            "updates": updates,
        })
    }

    #[test]
    fn timestamps_convert_to_unix_time() {
        let cases = [
            ("1970-01-01T00:00:00Z", 0, 0),
            ("2000-03-01T00:00:00Z", 951_868_800, 0),
            ("2024-02-29T12:00:00.5Z", 1_709_208_000, 500_000_000),
            ("2024-01-01T09:00:00+09:00", 1_704_067_200, 0),
            ("2023-12-31T19:00:00.000000001-05:00", 1_704_067_200, 1),
        ];
        for (text, seconds, nanos) in cases {
            assert_eq!(
                parse_timestamp(text).expect("timestamp is valid"),
                prost_types::Timestamp { seconds, nanos },
                "{text}"
            );
        }
    }

    #[test]
    fn invalid_timestamps_are_rejected() {
        for text in [
            "",
            "2024-01-01",
            "2024-01-01 00:00:00Z",
            "2024-01-01T00:00:00",
            "2023-02-29T00:00:00Z",
            "2024-13-01T00:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:00:60Z",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T00:00:00.1234567890Z",
            "2024-01-01T00:00:00+0900",
            "0000-01-01T00:00:00Z",
            "2024-01-01T00:00:00Zjunk",
        ] {
            assert!(parse_timestamp(text).is_err(), "{text}");
        }
    }

    #[test]
    fn installed_only_snapshot_keeps_timestamps_and_ignores_update_data() {
        let value = snapshot(
            Value::Null,
            vec![package(json!({ "newVersion": "9.9" }))],
            vec![package(json!({ "newVersion": "2.0" }))],
        );

        let snapshot = parse_snapshot(value).expect("snapshot is valid");

        assert_eq!(snapshot.scan_completed_at.seconds, 1_704_067_200);
        assert_eq!(snapshot.update_scan_completed_at, None);
        assert_eq!(
            snapshot.packages,
            vec![InstalledPackage {
                manager: "winget".to_owned(),
                source: "winget".to_owned(),
                id: "example.id".to_owned(),
                name: "Example".to_owned(),
                version: "1.0".to_owned(),
                available_version: String::new(),
                scope: "UNKNOWN".to_owned(),
                source_name: "winget".to_owned(),
                reported_scope: "Machine".to_owned(),
            }]
        );
        assert_eq!(
            snapshot.managers,
            vec![PackageManager {
                name: "winget".to_owned(),
                installed: true,
                enabled: true,
                version: String::new(),
            }]
        );
        assert_eq!(snapshot.sources.len(), 1);
    }

    #[test]
    fn empty_snapshot_is_valid_and_omitted_update_timestamp_is_none() {
        let mut value = snapshot(Value::Null, vec![], vec![]);
        let object = value.as_object_mut().expect("snapshot is an object");
        object.remove("updateCompletedAt");
        object.remove("updates");
        object.insert("managers".to_owned(), json!([]));
        object.insert("sources".to_owned(), json!([]));

        let snapshot = parse_snapshot(value).expect("empty snapshot is valid");

        assert!(snapshot.packages.is_empty() && snapshot.managers.is_empty() && snapshot.sources.is_empty());
        assert_eq!(snapshot.update_scan_completed_at, None);
    }

    #[test]
    fn update_scan_merges_unambiguous_versions_with_its_own_timestamp() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let value = json!({
            "completedAt": "2024-01-01T00:00:00Z",
            "updateCompletedAt": "2024-01-01T00:00:10Z",
            "managers": [],
            "sources": [],
            "installedPackages": [
                package(json!({})),
                package(json!({ "id": "other", "reportedScope": "User" })),
                package(json!({ "id": "other", "reportedScope": "Machine" })),
            ],
            "updates": [
                package(json!({ "newVersion": "2.0" })),
                package(json!({ "id": "other", "reportedScope": "User", "newVersion": "3.0" })),
                package(json!({ "id": "absent", "newVersion": "4.0" })),
            ],
        });

        let snapshot = parse_snapshot(value).expect("snapshot is valid");

        let versions: Vec<_> = snapshot.packages.iter().map(|p| p.available_version.as_str()).collect();
        assert_eq!(versions, ["2.0", "", ""]);
        assert_eq!(
            snapshot
                .update_scan_completed_at
                .expect("update timestamp is present")
                .seconds,
            1_704_067_210
        );
    }

    #[test]
    fn ambiguous_or_conflicting_updates_are_not_merged() {
        let duplicated_installed = snapshot(
            json!("2024-01-01T00:00:10Z"),
            vec![package(json!({})), package(json!({}))],
            vec![package(json!({ "newVersion": "2.0" }))],
        );
        let conflicting_updates = snapshot(
            json!("2024-01-01T00:00:10Z"),
            vec![package(json!({}))],
            vec![
                package(json!({ "newVersion": "2.0" })),
                package(json!({ "newVersion": "3.0" })),
            ],
        );
        let different_source = snapshot(
            json!("2024-01-01T00:00:10Z"),
            vec![package(json!({}))],
            vec![package(
                json!({ "newVersion": "2.0", "sourceName": "other", "source": "other" }),
            )],
        );

        for value in [duplicated_installed, conflicting_updates, different_source] {
            let snapshot = parse_snapshot(value).expect("snapshot is valid");
            assert!(snapshot.packages.iter().all(|p| p.available_version.is_empty()));
        }
    }

    #[test]
    fn reported_scope_is_preserved_but_never_becomes_ownership() {
        for reported in ["Machine", "Global", "User", "Local", ""] {
            let value = snapshot(Value::Null, vec![package(json!({ "reportedScope": reported }))], vec![]);
            let packages = parse_snapshot(value).expect("snapshot is valid").packages;
            assert_eq!(packages[0].reported_scope, reported);
            assert_eq!(packages[0].scope, "UNKNOWN");
        }
        let value = snapshot(Value::Null, vec![package(json!({ "reportedScope": null }))], vec![]);
        let packages = parse_snapshot(value).expect("snapshot is valid").packages;
        assert_eq!(packages[0].reported_scope, "");
        assert_eq!(packages[0].scope, "UNKNOWN");
    }

    #[test]
    fn unsafe_source_data_is_omitted() {
        let unsafe_values = [
            "C:\\Users\\me\\feed",
            "c:/feeds/local",
            "relative/feed",
            "\\\\server\\share",
            "/home/me/feed",
            "~/feed",
            "file:///feed",
            "https://user:pass@example.com/feed",
            "https://example.com/feed?token=abc",
            "https://example.com/feed#frag",
            "ftp://example.com/feed",
            "feed@example.com",
            "feed token",
            "line\nbreak",
        ];

        for text in unsafe_values {
            let value = snapshot(
                Value::Null,
                vec![package(json!({ "source": text, "sourceName": text }))],
                vec![],
            );
            let packages = parse_snapshot(value).expect("snapshot is valid").packages;
            assert_eq!(packages[0].source, "", "{text}");
            assert_eq!(packages[0].source_name, "", "{text}");

            let mut value = snapshot(Value::Null, vec![], vec![]);
            value["sources"] = json!([
                { "manager": "winget", "name": "winget", "url": text },
                { "manager": "winget", "name": text, "url": "https://example.com/feed" },
            ]);
            let sources = parse_snapshot(value).expect("snapshot is valid").sources;
            assert_eq!(
                sources,
                vec![PackageSource {
                    manager: "winget".to_owned(),
                    name: "winget".to_owned(),
                    url: String::new(),
                }],
                "{text}"
            );
        }
    }

    #[test]
    fn canonical_source_name_is_kept_without_exposing_a_url() {
        let value = snapshot(
            Value::Null,
            vec![package(
                json!({ "source": "https://community.chocolatey.org/api/v2/", "sourceName": "chocolatey" }),
            )],
            vec![],
        );
        let snapshot = parse_snapshot(value).expect("snapshot is valid");
        assert_eq!(snapshot.packages[0].source, "");
        assert_eq!(snapshot.packages[0].source_name, "chocolatey");
        assert_eq!(snapshot.sources[0].url, "");
    }

    #[test]
    fn malformed_required_data_fails_closed_without_echoing_input() {
        let mut cases = vec![
            json!([]),
            json!("snapshot"),
            snapshot(Value::Null, vec![package(json!({ "name": "" }))], vec![]),
            snapshot(Value::Null, vec![package(json!({ "version": 1 }))], vec![]),
            snapshot(Value::Null, vec![json!("SECRET-PACKAGE")], vec![]),
            snapshot(json!(5), vec![], vec![]),
            snapshot(json!("SECRET-TIME"), vec![], vec![]),
            snapshot(json!("2024-01-01T00:00:10Z"), vec![], vec![json!({})]),
        ];
        for key in ["completedAt", "managers", "sources", "installedPackages"] {
            let mut value = snapshot(Value::Null, vec![], vec![]);
            value.as_object_mut().expect("snapshot is an object").remove(key);
            cases.push(value);
        }
        let mut value = snapshot(Value::Null, vec![], vec![]);
        value["completedAt"] = json!("SECRET-TIME");
        cases.push(value);
        let mut value = snapshot(Value::Null, vec![], vec![]);
        value["managers"] = json!([{ "name": "winget", "enabled": true }]);
        cases.push(value);
        let mut value = snapshot(Value::Null, vec![], vec![]);
        value["managers"] = json!([
            { "name": "winget", "enabled": true, "ready": true },
            { "name": "winget", "enabled": false, "ready": false },
        ]);
        cases.push(value);
        let mut value = snapshot(json!("2024-01-01T00:00:10Z"), vec![], vec![]);
        value.as_object_mut().expect("snapshot is an object").remove("updates");
        cases.push(value);

        for value in cases {
            let error = format!("{:#}", parse_snapshot(value).expect_err("snapshot is invalid"));
            assert!(!error.contains("SECRET"), "{error}");
        }
    }
}
