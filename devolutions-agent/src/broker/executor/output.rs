//! Output capture and exit-code helpers.

/// Maximum amount of captured process output retained (the tail is kept).
pub const MAX_CAPTURED_OUTPUT_BYTES: usize = 10 * 1024;

/// Outcome of executing a command plan: the main command's exit code and a
/// tail-truncated, UTF-8 capture of its combined stdout+stderr.
#[derive(Debug, Clone, Default)]
pub struct ExecutionOutput {
    pub exit_code: i32,
    pub stdout: String,
}

/// Keep the last [`MAX_CAPTURED_OUTPUT_BYTES`] of `bytes`, decoded lossily as UTF-8.
///
/// When truncated, a marker line is prepended so consumers can tell output was dropped.
pub fn tail_utf8(bytes: &[u8]) -> String {
    if bytes.len() <= MAX_CAPTURED_OUTPUT_BYTES {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let tail = &bytes[bytes.len() - MAX_CAPTURED_OUTPUT_BYTES..];
    format!(
        "[... output truncated to last {} KiB ...]\n{}",
        MAX_CAPTURED_OUTPUT_BYTES / 1024,
        String::from_utf8_lossy(tail)
    )
}

/// Official WinGet HRESULT messages from `AppInstallerErrors.h`.
const WINGET_EXIT_CODE_MESSAGES: &[(u32, &str)] = &[
    (0x8A15_0001, "WinGet: an internal error occurred"),
    (0x8A15_0002, "WinGet: invalid command-line arguments"),
    (0x8A15_0003, "WinGet: command failed"),
    (0x8A15_0004, "WinGet: failed to load the manifest"),
    (0x8A15_0005, "WinGet: operation was interrupted by a control signal"),
    (0x8A15_0006, "WinGet: shell execution install failed"),
    (0x8A15_0007, "WinGet: manifest version is not supported"),
    (0x8A15_0008, "WinGet: download failed"),
    (0x8A15_0009, "WinGet: cannot write to an older source index"),
    (0x8A15_000A, "WinGet: source index integrity is compromised"),
    (0x8A15_000B, "WinGet: sources are invalid"),
    (0x8A15_000C, "WinGet: source name already exists"),
    (0x8A15_000D, "WinGet: source type is invalid"),
    (0x8A15_000E, "WinGet: package is a bundle"),
    (0x8A15_000F, "WinGet: source data is missing"),
    (0x8A15_0010, "WinGet: no applicable installer found"),
    (0x8A15_0011, "WinGet: installer hash mismatch"),
    (0x8A15_0012, "WinGet: source name does not exist"),
    (0x8A15_0013, "WinGet: source argument already exists"),
    (0x8A15_0014, "WinGet: no package matched the query"),
    (0x8A15_0015, "WinGet: no sources are configured"),
    (0x8A15_0016, "WinGet: multiple packages matched the query"),
    (0x8A15_0017, "WinGet: no manifest found"),
    (0x8A15_0018, "WinGet: extension failed to provide package data"),
    (0x8A15_0019, "WinGet: command requires administrator privileges"),
    (0x8A15_001A, "WinGet: source is not secure"),
    (0x8A15_001B, "WinGet: Microsoft Store source is blocked by policy"),
    (0x8A15_001C, "WinGet: Microsoft Store app is blocked by policy"),
    (0x8A15_001D, "WinGet: experimental feature is disabled"),
    (0x8A15_001E, "WinGet: Microsoft Store install failed"),
    (0x8A15_001F, "WinGet: shell completion input was invalid"),
    (0x8A15_0020, "WinGet: failed to initialize YAML parser"),
    (0x8A15_0021, "WinGet: YAML contains an invalid mapping key"),
    (0x8A15_0022, "WinGet: YAML contains a duplicate mapping key"),
    (0x8A15_0023, "WinGet: YAML operation is invalid"),
    (0x8A15_0024, "WinGet: failed to build YAML document"),
    (0x8A15_0025, "WinGet: YAML emitter state is invalid"),
    (0x8A15_0026, "WinGet: YAML data is invalid"),
    (0x8A15_0027, "WinGet: YAML parser failed"),
    (0x8A15_0028, "WinGet: manifest validation reported warnings"),
    (0x8A15_0029, "WinGet: manifest validation failed"),
    (0x8A15_002A, "WinGet: manifest is invalid"),
    (0x8A15_002B, "WinGet: update is not applicable"),
    (0x8A15_002C, "WinGet: one or more updates failed"),
    (0x8A15_002D, "WinGet: installer security check failed"),
    (0x8A15_002E, "WinGet: downloaded file size does not match the manifest"),
    (0x8A15_002F, "WinGet: uninstall information was not found"),
    (0x8A15_0030, "WinGet: uninstall command failed"),
    (0x8A15_0031, "WinGet: ICU break iterator failed"),
    (0x8A15_0032, "WinGet: ICU case mapping failed"),
    (0x8A15_0033, "WinGet: ICU regular expression failed"),
    (0x8A15_0034, "WinGet: one or more imported packages failed to install"),
    (0x8A15_0035, "WinGet: not all requested packages were found"),
    (0x8A15_0036, "WinGet: JSON file is invalid"),
    (0x8A15_0037, "WinGet: source is not remote"),
    (0x8A15_0038, "WinGet: REST source is not supported"),
    (0x8A15_0039, "WinGet: REST source returned invalid data"),
    (0x8A15_003A, "WinGet: operation is blocked by policy"),
    (0x8A15_003B, "WinGet: REST API returned an internal error"),
    (0x8A15_003C, "WinGet: REST source URL is invalid"),
    (0x8A15_003D, "WinGet: REST API returned an unsupported MIME type"),
    (0x8A15_003E, "WinGet: REST source version is invalid"),
    (0x8A15_003F, "WinGet: source data integrity check failed"),
    (0x8A15_0040, "WinGet: failed to read stream data"),
    (0x8A15_0041, "WinGet: package agreements were not accepted"),
    (0x8A15_0042, "WinGet: failed to read prompt input"),
    (0x8A15_0043, "WinGet: source request is not supported"),
    (0x8A15_0044, "WinGet: REST API endpoint was not found"),
    (0x8A15_0045, "WinGet: failed to open source"),
    (0x8A15_0046, "WinGet: source agreements were not accepted"),
    (0x8A15_0047, "WinGet: custom header exceeds the maximum length"),
    (0x8A15_0048, "WinGet: resource file is missing"),
    (0x8A15_0049, "WinGet: MSI install failed"),
    (0x8A15_004A, "WinGet: msiexec argument is invalid"),
    (0x8A15_004B, "WinGet: failed to open all sources"),
    (0x8A15_004C, "WinGet: dependency validation failed"),
    (0x8A15_004D, "WinGet: package is missing"),
    (0x8A15_004E, "WinGet: table column is invalid"),
    (
        0x8A15_004F,
        "WinGet: upgrade version is not newer than the installed version",
    ),
    (0x8A15_0050, "WinGet: upgrade version is unknown"),
    (0x8A15_0051, "WinGet: ICU conversion failed"),
    (0x8A15_0052, "WinGet: portable install failed"),
    (0x8A15_0053, "WinGet: portable package does not support reparse points"),
    (0x8A15_0054, "WinGet: portable package already exists"),
    (0x8A15_0055, "WinGet: portable symlink path is a directory"),
    (0x8A15_0056, "WinGet: installer prohibits elevation"),
    (0x8A15_0057, "WinGet: portable uninstall failed"),
    (0x8A15_0058, "WinGet: installed version validation failed"),
    (0x8A15_0059, "WinGet: argument is not supported"),
    (0x8A15_005A, "WinGet: argument contains an embedded null character"),
    (0x8A15_005B, "WinGet: nested installer was not found"),
    (0x8A15_005C, "WinGet: failed to extract archive"),
    (0x8A15_005D, "WinGet: nested installer path is invalid"),
    (0x8A15_005E, "WinGet: pinned certificate does not match"),
    (0x8A15_005F, "WinGet: install location is required"),
    (0x8A15_0060, "WinGet: archive scan failed"),
    (0x8A15_0061, "WinGet: package is already installed"),
    (0x8A15_0062, "WinGet: pin already exists"),
    (0x8A15_0063, "WinGet: pin does not exist"),
    (0x8A15_0064, "WinGet: failed to open pinning index"),
    (0x8A15_0065, "WinGet: one or more installs failed"),
    (0x8A15_0066, "WinGet: one or more uninstalls failed"),
    (0x8A15_0067, "WinGet: not all single-package queries were found"),
    (0x8A15_0068, "WinGet: package is pinned"),
    (0x8A15_0069, "WinGet: package is a stub"),
    (0x8A15_006A, "WinGet: application termination signal was received"),
    (0x8A15_006B, "WinGet: failed to download dependencies"),
    (0x8A15_006C, "WinGet: download command is prohibited"),
    (0x8A15_006D, "WinGet: service is unavailable"),
    (0x8A15_006E, "WinGet: resume identifier was not found"),
    (0x8A15_006F, "WinGet: client version does not match the checkpoint"),
    (0x8A15_0070, "WinGet: resume state is invalid"),
    (0x8A15_0071, "WinGet: failed to open checkpoint index"),
    (0x8A15_0072, "WinGet: resume limit was exceeded"),
    (0x8A15_0073, "WinGet: authentication information is invalid"),
    (0x8A15_0074, "WinGet: authentication type is not supported"),
    (0x8A15_0075, "WinGet: authentication failed"),
    (0x8A15_0076, "WinGet: interactive authentication is required"),
    (0x8A15_0077, "WinGet: authentication was cancelled by the user"),
    (0x8A15_0078, "WinGet: authentication used the wrong account"),
    (0x8A15_0079, "WinGet: repair information was not found"),
    (0x8A15_007A, "WinGet: repair is not applicable"),
    (0x8A15_007B, "WinGet: repair command failed"),
    (0x8A15_007C, "WinGet: repair is not supported"),
    (0x8A15_007D, "WinGet: repair is prohibited in administrator context"),
    (0x8A15_007E, "WinGet: SQLite connection was terminated"),
    (0x8A15_007F, "WinGet: display catalog API failed"),
    (0x8A15_0080, "WinGet: no applicable display catalog package found"),
    (0x8A15_0081, "WinGet: SFS client API failed"),
    (0x8A15_0082, "WinGet: no applicable SFS client package found"),
    (0x8A15_0083, "WinGet: licensing API failed"),
    (0x8A15_0084, "WinGet: SFS client package is not supported"),
    (0x8A15_0085, "WinGet: licensing API returned forbidden"),
    (0x8A15_0086, "WinGet: installer file is empty"),
    (0x8A15_0087, "WinGet: font install failed"),
    (0x8A15_0088, "WinGet: font file is not supported"),
    (0x8A15_0089, "WinGet: font is already installed"),
    (0x8A15_008A, "WinGet: font file was not found"),
    (0x8A15_008B, "WinGet: font uninstall failed"),
    (0x8A15_008C, "WinGet: font validation failed"),
    (0x8A15_008D, "WinGet: font rollback failed"),
    (
        0x8A15_008E,
        "WinGet: installed package uses a different installer technology",
    ),
    (0x8A15_0101, "WinGet installer: package is currently in use"),
    (0x8A15_0102, "WinGet installer: another install is already in progress"),
    (0x8A15_0103, "WinGet installer: a required file is in use"),
    (0x8A15_0104, "WinGet installer: a dependency is missing"),
    (0x8A15_0105, "WinGet installer: disk is full"),
    (0x8A15_0106, "WinGet installer: memory is insufficient"),
    (0x8A15_0107, "WinGet installer: network is unavailable"),
    (0x8A15_0108, "WinGet installer: contact support"),
    (0x8A15_0109, "WinGet installer: reboot required to finish installation"),
    (0x8A15_010A, "WinGet installer: reboot required before installation"),
    (0x8A15_010B, "WinGet installer: reboot was initiated"),
    (0x8A15_010C, "WinGet installer: install was cancelled by the user"),
    (0x8A15_010D, "WinGet installer: package is already installed"),
    (0x8A15_010E, "WinGet installer: downgrade is not allowed"),
    (0x8A15_010F, "WinGet installer: install is blocked by policy"),
    (0x8A15_0110, "WinGet installer: dependency install failed"),
    (
        0x8A15_0111,
        "WinGet installer: package is in use by another application",
    ),
    (0x8A15_0112, "WinGet installer: invalid installer parameter"),
    (0x8A15_0113, "WinGet installer: system is not supported"),
    (0x8A15_0114, "WinGet installer: upgrade is not supported"),
    (0x8A15_0115, "WinGet installer: custom installer error"),
    (0x8A15_0201, "WinGet installed status: uninstall entry was not found"),
    (
        0x0A15_0202,
        "WinGet installed status: install location check is not applicable",
    ),
    (0x8A15_0203, "WinGet installed status: install location was not found"),
    (0x8A15_0204, "WinGet installed status: file hash mismatch"),
    (0x8A15_0205, "WinGet installed status: file was not found"),
    (
        0x0A15_0206,
        "WinGet installed status: file found but hash was not checked",
    ),
    (0x8A15_0207, "WinGet installed status: file access failed"),
    (0x8A15_C001, "WinGet configuration: configuration file is invalid"),
    (0x8A15_C002, "WinGet configuration: YAML is invalid"),
    (0x8A15_C003, "WinGet configuration: field type is invalid"),
    (0x8A15_C004, "WinGet configuration: file version is not supported"),
    (0x8A15_C005, "WinGet configuration: failed to apply configuration set"),
    (0x8A15_C006, "WinGet configuration: duplicate identifier"),
    (0x8A15_C007, "WinGet configuration: dependency is missing"),
    (0x8A15_C008, "WinGet configuration: dependency is unsatisfied"),
    (0x8A15_C009, "WinGet configuration: assertion failed"),
    (
        0x8A15_C00A,
        "WinGet configuration: configuration unit was manually skipped",
    ),
    (0x8A15_C00B, "WinGet configuration: warning was not accepted"),
    (0x8A15_C00C, "WinGet configuration: dependency cycle detected"),
    (0x8A15_C00D, "WinGet configuration: field value is invalid"),
    (0x8A15_C00E, "WinGet configuration: required field is missing"),
    (0x8A15_C00F, "WinGet configuration: configuration test failed"),
    (0x8A15_C010, "WinGet configuration: configuration test was not run"),
    (
        0x8A15_C011,
        "WinGet configuration: failed to get current configuration state",
    ),
    (0x8A15_C012, "WinGet configuration: history item was not found"),
    (
        0x8A15_C013,
        "WinGet configuration: parameter crossed an integrity boundary",
    ),
    (0x8A15_C101, "WinGet configuration unit: unit is not installed"),
    (
        0x8A15_C102,
        "WinGet configuration unit: unit was not found in the repository",
    ),
    (0x8A15_C103, "WinGet configuration unit: multiple units matched"),
    (0x8A15_C104, "WinGet configuration unit: failed to read current state"),
    (0x8A15_C105, "WinGet configuration unit: test operation failed"),
    (0x8A15_C106, "WinGet configuration unit: apply operation failed"),
    (0x8A15_C107, "WinGet configuration unit: module conflict"),
    (0x8A15_C108, "WinGet configuration unit: failed to import module"),
    (
        0x8A15_C109,
        "WinGet configuration unit: operation returned an invalid result",
    ),
    (
        0x8A15_C110,
        "WinGet configuration unit: failed to set configuration root",
    ),
    (
        0x8A15_C111,
        "WinGet configuration unit: module import requires administrator privileges",
    ),
    (0x8A15_C112, "WinGet configuration: processor is not supported"),
    (0x8A15_C113, "WinGet configuration: processor hash mismatch"),
];

/// Map a known WinGet or Windows Installer exit code to a short, human-readable
/// description, if recognized.
///
/// WinGet returns documented `HRESULT`-style codes in the `0x8A15_xxxx` and
/// `0x0A15_xxxx` ranges. Common MSI / Windows Installer codes are also
/// recognized. Returns `None` for codes that are not in the known set, so callers
/// can fall back to reporting the raw numeric code.
#[allow(clippy::cast_sign_loss)]
pub fn describe_exit_code(exit_code: i32) -> Option<String> {
    let code = exit_code as u32;
    if let Some((_, message)) = WINGET_EXIT_CODE_MESSAGES
        .iter()
        .find(|(known_code, _)| *known_code == code)
    {
        return Some((*message).to_owned());
    }

    let description = match code {
        // MSI / Windows Installer.
        1602 => "Windows Installer: the user cancelled the installation",
        1603 => "Windows Installer: a fatal error occurred during installation",
        1605 => "Windows Installer: the action is only valid for an installed product",
        1618 => "Windows Installer: another installation is already in progress",
        1619 => "Windows Installer: the installation package could not be opened",
        1620 => "Windows Installer: the installation package is invalid",
        1638 => "Windows Installer: another version of this product is already installed",
        1641 => "Windows Installer: a reboot was initiated to complete the installation",
        3010 => "Windows Installer: a reboot is required to complete the operation",
        _ => return None,
    };
    Some(description.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_utf8_keeps_short_output_verbatim() {
        let s = "hello world";
        assert_eq!(tail_utf8(s.as_bytes()), s);
    }

    #[test]
    fn tail_utf8_truncates_to_tail_with_marker() {
        let big = vec![b'a'; MAX_CAPTURED_OUTPUT_BYTES + 5000];
        let out = tail_utf8(&big);
        assert!(out.starts_with("[... output truncated"));
        // The retained tail is exactly MAX_CAPTURED_OUTPUT_BYTES of 'a's.
        assert!(out.ends_with(&"a".repeat(MAX_CAPTURED_OUTPUT_BYTES)));
        assert!(!out.ends_with(&"a".repeat(MAX_CAPTURED_OUTPUT_BYTES + 1)));
    }

    #[test]
    fn tail_utf8_handles_invalid_utf8_lossily() {
        let bytes = [0xff, 0xfe, b'h', b'i'];
        let out = tail_utf8(&bytes);
        assert!(out.ends_with("hi"));
    }

    #[test]
    fn describe_exit_code_recognizes_winget_cli_error() {
        // 0x8A150014 = APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND.
        assert_eq!(
            describe_exit_code(signed_hresult(0x8A15_0014)).as_deref(),
            Some("WinGet: no package matched the query")
        );
    }

    #[test]
    fn describe_exit_code_recognizes_signed_winget_hresult() {
        assert_eq!(
            describe_exit_code(-1_978_335_216).as_deref(),
            Some("WinGet: no applicable installer found")
        );
    }

    #[test]
    fn describe_exit_code_recognizes_winget_installer_error() {
        assert_eq!(
            describe_exit_code(signed_hresult(0x8A15_0109)).as_deref(),
            Some("WinGet installer: reboot required to finish installation")
        );
    }

    #[test]
    fn describe_exit_code_recognizes_winget_config_error() {
        assert_eq!(
            describe_exit_code(signed_hresult(0x8A15_C001)).as_deref(),
            Some("WinGet configuration: configuration file is invalid")
        );
    }

    #[test]
    fn describe_exit_code_recognizes_winget_config_test_failure() {
        assert_eq!(
            describe_exit_code(signed_hresult(0x8A15_C00F)).as_deref(),
            Some("WinGet configuration: configuration test failed")
        );
    }

    #[test]
    fn describe_exit_code_recognizes_winget_config_unit_error() {
        assert_eq!(
            describe_exit_code(signed_hresult(0x8A15_C104)).as_deref(),
            Some("WinGet configuration unit: failed to read current state")
        );
    }

    #[test]
    fn describe_exit_code_recognizes_winget_config_processor_error() {
        assert_eq!(
            describe_exit_code(signed_hresult(0x8A15_C112)).as_deref(),
            Some("WinGet configuration: processor is not supported")
        );
    }

    #[test]
    fn describe_exit_code_recognizes_winget_installed_status() {
        assert_eq!(
            describe_exit_code(signed_hresult(0x0A15_0206)).as_deref(),
            Some("WinGet installed status: file found but hash was not checked")
        );
    }

    #[test]
    fn describe_exit_code_recognizes_msi_reboot_required() {
        assert_eq!(
            describe_exit_code(3010).as_deref(),
            Some("Windows Installer: a reboot is required to complete the operation")
        );
    }

    #[test]
    fn describe_exit_code_returns_none_for_unknown() {
        assert_eq!(describe_exit_code(1), None);
        assert_eq!(describe_exit_code(0), None);
    }

    fn signed_hresult(code: u32) -> i32 {
        i32::from_ne_bytes(code.to_ne_bytes())
    }
}
