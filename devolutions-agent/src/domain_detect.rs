//! Auto-detection of the machine's DNS domain for agent tunnel domain advertisement.

/// Attempts to detect the DNS domain this machine belongs to.
///
/// Returns `None` if detection fails or the result is clearly not a valid domain
/// (e.g., ISP domain, empty string, single-label name).
pub fn detect_domain() -> Option<String> {
    let raw = detect_domain_raw()?;
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if is_plausible_domain(&trimmed) {
        Some(trimmed)
    } else {
        None
    }
}

/// Returns `true` if the detected domain looks like a legitimate internal domain
/// (not a TLD, has at least two labels, all labels non-empty).
fn is_plausible_domain(domain: &str) -> bool {
    let trimmed = domain.trim_end_matches('.');
    if trimmed.is_empty() {
        return false;
    }
    let mut parts = trimmed.split('.');
    parts.next().is_some_and(|l| !l.is_empty()) && parts.next().is_some_and(|l| !l.is_empty())
}

#[cfg(target_os = "windows")]
fn detect_domain_raw() -> Option<String> {
    // Try USERDNSDOMAIN first (available in user logon sessions)
    if let Ok(domain) = std::env::var("USERDNSDOMAIN")
        && !domain.is_empty()
    {
        return Some(domain);
    }

    // Fallback: GetComputerNameExW(ComputerNameDnsDomain)
    // This works in SYSTEM service context where USERDNSDOMAIN is empty.
    detect_domain_via_computer_name()
}

#[cfg(target_os = "windows")]
fn detect_domain_via_computer_name() -> Option<String> {
    use windows::Win32::System::SystemInformation::{ComputerNameDnsDomain, GetComputerNameExW};
    use windows::core::PWSTR;

    // First call: get required buffer size. Expected to fail with ERROR_MORE_DATA.
    let mut size = 0u32;

    // SAFETY: Passing null buffer with zero size to query required length.
    // GetComputerNameExW writes the required size to `size` and returns ERROR_MORE_DATA.
    let _ = unsafe { GetComputerNameExW(ComputerNameDnsDomain, None, &mut size) };

    if size == 0 {
        return None;
    }

    let mut buf = vec![0u16; size as usize];

    // SAFETY: `buf` is allocated with `size` elements. GetComputerNameExW writes at most
    // `size` wide chars and updates `size` to the actual length (excluding null terminator).
    let result = unsafe { GetComputerNameExW(ComputerNameDnsDomain, Some(PWSTR(buf.as_mut_ptr())), &mut size) };

    if result.is_err() {
        return None;
    }

    let domain = String::from_utf16_lossy(&buf[..size as usize]);

    if domain.is_empty() { None } else { Some(domain) }
}

#[cfg(not(target_os = "windows"))]
fn detect_domain_raw() -> Option<String> {
    let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("search ").or_else(|| line.strip_prefix("domain "))
            && let Some(domain) = rest.split_whitespace().next()
            && !domain.is_empty()
        {
            return Some(domain.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_domain_accepts_typical_ad_domain() {
        assert!(is_plausible_domain("contoso.local"));
        assert!(is_plausible_domain("corp.contoso.com"));
        assert!(is_plausible_domain("ad.it-help.ninja"));
    }

    #[test]
    fn plausible_domain_rejects_garbage() {
        assert!(!is_plausible_domain(""));
        assert!(!is_plausible_domain("local"));
        assert!(!is_plausible_domain("com"));
        assert!(!is_plausible_domain("."));
        assert!(!is_plausible_domain(".."));
    }

    #[test]
    fn plausible_domain_handles_trailing_dot() {
        assert!(is_plausible_domain("contoso.local."));
    }
}
