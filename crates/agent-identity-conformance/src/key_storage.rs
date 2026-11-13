//! Key storage names ([contract] §5.7) and the key storage metadata the agent reports (§3.1).
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#key-storage

use anyhow::ensure;

pub(crate) const FILE: &str = "file";
pub(crate) const WINDOWS_SOFTWARE_PROVIDER: &str = "windows_software_provider";

/// A well-formed name outside the contract's table, which an agent counts as a key storage that isn't available.
pub(crate) const UNLISTED: &str = "zz_unlisted_storage";

/// Where the agent creates a key without a policy, and every enrollment key ([agent intent], "Key storage").
///
/// The agent ranks the Windows software provider before the file backend, and the suite runs on Windows only where the provider is available.
///
/// [agent intent]: ../../agent-identity/INTENT.md#key-storage
pub(crate) const fn builtin_default() -> &'static str {
    if cfg!(windows) { WINDOWS_SOFTWARE_PROVIDER } else { FILE }
}

/// A key storage that no agent can have available on this platform: the Windows software provider off Windows, which the contract table limits to Windows, and an unlisted name on Windows.
pub(crate) const fn unavailable() -> &'static str {
    if cfg!(windows) {
        UNLISTED
    } else {
        WINDOWS_SOFTWARE_PROVIDER
    }
}

/// Whether [`unavailable()`] is a key storage the agent knows, as opposed to a name it doesn't.
///
/// The agent logs an error for a key in a known key storage that isn't available ([agent intent], "Identities"); whether it logs one for a name it doesn't know is open.
///
/// [agent intent]: ../../agent-identity/INTENT.md#identities
pub(crate) const UNAVAILABLE_IS_KNOWN: bool = !cfg!(windows);

/// Whether `name` matches `^[a-z][a-z0-9_]{0,63}$`, the rule of a key storage name.
pub(crate) fn well_formed(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && name.len() <= 64
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// The names of a `key_storage_available` value, after checking that each is well-formed and that they are unique and in ascending byte order.
pub(crate) fn available_names(value: &str) -> anyhow::Result<Vec<&str>> {
    let names = value.split(',').collect::<Vec<_>>();
    for name in &names {
        ensure!(
            well_formed(name),
            "key_storage_available holds {name:?}, which is not a key storage name"
        );
    }
    ensure!(
        names.windows(2).all(|pair| pair[0].as_bytes() < pair[1].as_bytes()),
        "key_storage_available {value:?} is not unique names in ascending byte order"
    );
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_storage_names_follow_the_contract_rule() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
        let sixty_four = "a".repeat(64);
        let sixty_five = "a".repeat(65);
        let cases = [
            ("one letter", "a", true),
            ("table name", "windows_software_provider", true),
            ("64 characters", sixty_four.as_str(), true),
            ("65 characters", sixty_five.as_str(), false),
            ("empty", "", false),
            ("leading digit", "0a", false),
            ("leading underscore", "_a", false),
            ("upper case", "File", false),
            ("hyphen", "key-file", false),
            ("non-ASCII letter", "f\u{ef}le", false),
        ];
        for (case, name, expected) in cases {
            assert_eq!(well_formed(name), expected, "{case}");
        }
    }

    #[test]
    fn available_storages_are_unique_well_formed_names_in_ascending_byte_order() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
        let cases = [
            ("one name", "file", true),
            ("contract example", "file,windows_software_provider", true),
            ("three names", "file,tpm,windows_software_provider", true),
            ("descending", "windows_software_provider,file", false),
            ("repeated", "file,file", false),
            ("empty name", "file,", false),
            ("space after comma", "file, tpm", false),
            ("malformed name", "File", false),
        ];
        for (case, value, expected) in cases {
            assert_eq!(available_names(value).is_ok(), expected, "{case}");
        }
    }
}
