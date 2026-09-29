use std::collections::BTreeMap;

use camino::Utf8Path;
use serde_json::Value;

pub type Metadata = BTreeMap<String, String>;

const REQUIRED: [&str; 5] = ["hostname", "os_name", "os_version", "arch", "agent_version"];
const OPTIONAL: [&str; 3] = ["fqdn", "domain", "machine_id"];

/// Collects fresh inventory information, applying any readable override at each call.
pub fn collect(agent_version: &str, override_path: Option<&Utf8Path>) -> Metadata {
    let mut values = Metadata::new();
    let hostname = hostname::get()
        .ok()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (hostname, fqdn, domain) = host_names(&hostname);
    values.insert("hostname".into(), hostname);
    values.insert("os_name".into(), sysinfo::System::name().unwrap_or_default());
    values.insert("os_version".into(), sysinfo::System::os_version().unwrap_or_default());
    values.insert("arch".into(), std::env::consts::ARCH.into());
    values.insert("agent_version".into(), agent_version.into());
    if let Some(fqdn) = fqdn {
        values.insert("fqdn".into(), fqdn);
    }
    if let Some(domain) = domain {
        values.insert("domain".into(), domain);
    }
    if let Some(machine_id) = machine_id() {
        values.insert("machine_id".into(), machine_id);
    }
    if let Some(overrides) = override_path
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.as_object().cloned())
    {
        for key in REQUIRED.into_iter().chain(OPTIONAL) {
            if let Some(value) = overrides.get(key).and_then(Value::as_str) {
                values.insert(key.into(), value.into());
            }
        }
    }
    sanitize(values)
}

fn sanitize(values: Metadata) -> Metadata {
    values
        .into_iter()
        .filter_map(|(key, value)| {
            let sanitized: String = value
                .chars()
                .filter(|ch| !matches!(ch, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
                .scan(0, |length, ch| {
                    *length += ch.len_utf8();
                    (*length <= 1024).then_some(ch)
                })
                .collect();
            if sanitized.is_empty() {
                REQUIRED.contains(&key.as_str()).then(|| (key, String::from("unknown")))
            } else {
                Some((key, sanitized))
            }
        })
        .collect()
}

fn host_names(raw: &str) -> (String, Option<String>, Option<String>) {
    let short = raw.split('.').next().unwrap_or_default().to_owned();
    let domain = raw.split_once('.').map(|(_, domain)| domain.to_owned());
    #[cfg(windows)]
    let domain = windows_host_name(windows::Win32::System::SystemInformation::ComputerNameDnsDomain).or(domain);
    #[cfg(windows)]
    let fqdn = windows_host_name(windows::Win32::System::SystemInformation::ComputerNameDnsFullyQualified)
        .filter(|name| name.contains('.'))
        .or_else(|| domain.as_ref().map(|domain| format!("{short}.{domain}")));
    #[cfg(unix)]
    let fqdn = domain.as_ref().map(|_| raw.to_owned()).or_else(unix_fqdn);
    #[cfg(unix)]
    let domain = fqdn
        .as_ref()
        .and_then(|name| name.split_once('.').map(|(_, domain)| domain.to_owned()));
    #[cfg(not(any(windows, unix)))]
    let fqdn = domain.as_ref().map(|_| raw.to_owned());
    (short, fqdn, domain)
}

#[cfg(unix)]
fn unix_fqdn() -> Option<String> {
    let output = std::process::Command::new("hostname").arg("-f").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let output = String::from_utf8(output.stdout).ok()?;
    let fqdn = output.trim().trim_end_matches('.');
    fqdn.contains('.').then(|| fqdn.to_owned())
}

#[cfg(windows)]
fn windows_host_name(format: windows::Win32::System::SystemInformation::COMPUTER_NAME_FORMAT) -> Option<String> {
    use windows::Win32::System::SystemInformation::GetComputerNameExW;
    use windows::core::PWSTR;

    let mut size = 0;
    // SAFETY: A null output buffer requests the required length.
    let _ = unsafe { GetComputerNameExW(format, None, &mut size) };
    let mut buffer = vec![0; usize::try_from(size).ok()?];
    // SAFETY: The buffer is writable and holds the reported number of UTF-16 code units.
    unsafe { GetComputerNameExW(format, Some(PWSTR(buffer.as_mut_ptr())), &mut size) }.ok()?;
    String::from_utf16(&buffer[..usize::try_from(size).ok()?]).ok()
}

#[cfg(target_os = "linux")]
fn machine_id() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|value| value.trim().to_owned())
}

#[cfg(target_os = "macos")]
fn machine_id() -> Option<String> {
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout
        .lines()
        .find(|line| line.contains("\"IOPlatformUUID\" = "))
        .and_then(|line| line.split('"').nth(3))
        .and_then(|uuid| uuid::Uuid::parse_str(uuid).ok())
        .map(|uuid| uuid.to_string())
}

#[cfg(windows)]
fn machine_id() -> Option<String> {
    use windows::Win32::System::SystemInformation::{FIRMWARE_TABLE_PROVIDER, GetSystemFirmwareTable};

    let provider = FIRMWARE_TABLE_PROVIDER(u32::from_be_bytes(*b"RSMB"));
    // SAFETY: A null output buffer requests the required firmware-table length.
    let length = unsafe { GetSystemFirmwareTable(provider, 0, None) };
    if !(32..=2_097_152).contains(&length) {
        return None;
    }
    let mut table = vec![0u8; usize::try_from(length).ok()?];
    // SAFETY: The mutable buffer is valid for `length` bytes.
    let written = unsafe { GetSystemFirmwareTable(provider, 0, Some(&mut table)) };
    if written != length {
        return None;
    }
    smbios_uuid(&table)
}

#[cfg(windows)]
fn smbios_uuid(raw: &[u8]) -> Option<String> {
    let table_size = usize::try_from(u32::from_le_bytes(raw.get(4..8)?.try_into().ok()?)).ok()?;
    let table = raw.get(8..8usize.checked_add(table_size)?)?;
    let mut cursor = 0;
    while cursor + 4 <= table.len() {
        let kind = table[cursor];
        let length = usize::from(table[cursor + 1]);
        if length < 4 || cursor.checked_add(length)? > table.len() {
            return None;
        }
        if kind == 1 && length >= 24 {
            let bytes: [u8; 16] = table.get(cursor + 8..cursor + 24)?.try_into().ok()?;
            if bytes == [0; 16] || bytes == [0xff; 16] {
                return None;
            }
            let uuid = if (raw[1], raw[2]) >= (2, 6) {
                uuid::Uuid::from_bytes_le(bytes)
            } else {
                uuid::Uuid::from_bytes(bytes)
            };
            return Some(uuid.to_string());
        }
        let strings = table.get(cursor + length..)?;
        cursor += length + strings.windows(2).position(|pair| pair == [0, 0])? + 2;
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn machine_id() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_all_values_with_utf8_limits_and_required_fallback() {
        let mut values = Metadata::new();
        values.insert("hostname".into(), "\u{1f}\u{7f}\u{80}".into());
        values.insert("fqdn".into(), "\u{1f}".into());
        values.insert("os_name".into(), "💻".repeat(300));
        for name in REQUIRED
            .iter()
            .copied()
            .filter(|key| *key != "hostname" && *key != "os_name")
        {
            values.insert(name.into(), "value".into());
        }
        let actual = sanitize(values);
        assert_eq!(actual["hostname"], "unknown");
        assert!(!actual.contains_key("fqdn"));
        assert_eq!(actual["os_name"], "💻".repeat(256));
        assert!(actual.values().all(|value| value.len() <= 1024));
        assert!(actual.values().all(|value| !value.chars().any(char::is_control)));
    }

    #[test]
    fn replaces_known_values_on_each_call() -> anyhow::Result<()> {
        let dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("metadata-tests")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("overrides.json");
        std::fs::write(
            &path,
            r#"{"hostname":"one","fqdn":"","agent_version":"override","unexpected":"ignored"}"#,
        )?;
        let first = collect("version", Some(&path));
        assert_eq!(first["hostname"], "one");
        assert_eq!(first["agent_version"], "override");
        assert!(!first.contains_key("fqdn"));
        assert!(!first.contains_key("unexpected"));
        std::fs::write(&path, r#"{"hostname":"two\u007f"}"#)?;
        let second = collect("version", Some(&path));
        assert_eq!(second["hostname"], "two");
        assert_eq!(second["agent_version"], "version");
        std::fs::remove_file(&path)?;
        assert_ne!(collect("version", Some(&path))["hostname"], "two");
        std::fs::remove_dir(dir)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn parses_the_smbios_system_uuid_in_canonical_byte_order() {
        let mut raw = vec![0, 2, 8, 0];
        raw.extend_from_slice(&26u32.to_le_bytes());
        raw.extend_from_slice(&[1, 24, 0, 0, 0, 0, 0, 0]);
        raw.extend_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ]);
        raw.extend_from_slice(&[0, 0]);
        assert_eq!(
            smbios_uuid(&raw).as_deref(),
            Some("12345678-9abc-def0-0123-456789abcdef")
        );
        assert!(smbios_uuid(&raw[..raw.len() - 1]).is_none());
    }
}
