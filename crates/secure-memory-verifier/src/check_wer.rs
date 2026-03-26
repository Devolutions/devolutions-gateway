//! WER (Windows Error Reporting) dump-exclusion verification.
//!
//! ## What this proves
//!
//! `WerRegisterExcludedMemoryBlock` asks the WER subsystem to omit a specific
//! memory range from automatically-generated crash reports. This check:
//!
//! 1. Creates a `ProtectedBytes<32>` containing a known canary pattern.
//! 2. Registers the data page with `WerRegisterExcludedMemoryBlock`.
//! 3. Crashes the process intentionally so WER generates a dump.
//! 4. The parent process finds the dump and searches it for the canary.
//! 5. Absence of the canary confirms the exclusion worked.
//!
//! ## Prerequisites (WER LocalDumps must be pre-configured)
//!
//! WER only writes local dumps when the registry key is present. Configure it
//! before running this check:
//!
//! ```powershell
//! $key = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\secure-memory-verifier.exe"
//! New-Item $key -Force | Out-Null
//! Set-ItemProperty $key DumpType  2          # 2 = full dump
//! Set-ItemProperty $key DumpCount 5
//! Set-ItemProperty $key DumpFolder $env:TEMP
//! ```
//!
//! Administrator rights are required to create that key.
//!
//! ## What this does NOT prove
//!
//! - Third-party dump tools (ProcDump, WinDbg, procdump, …) honour
//!   `WerRegisterExcludedMemoryBlock`. They typically do not (e.g.: minidump)
//! - WER exclusion covers every possible dump format or WER version.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use secure_memory::ProtectedBytes;

use crate::{print_check, print_fail, print_info, print_pass};

/// Unique canary placed in the secret when testing WER exclusion.
/// 32 bytes, distinctive enough to be unlikely to collide with other data.
const WER_CANARY: [u8; 32] = [
    0xDE, 0xC0, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x57, 0xE8, 0x44, 0x20, 0xC1, 0x0C, 0xDB, 0x20, 0xFE, 0xDC, 0xBA,
    0x98, 0x76, 0x54, 0x32, 0x10, 0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE, 0x57, 0xE8,
];

// ── Parent side ───────────────────────────────────────────────────────────────

pub(crate) fn run() -> bool {
    print_check("wer-dump: verifying WerRegisterExcludedMemoryBlock excludes the secret from WER crash reports");

    let dump_folder = match find_wer_dump_folder() {
        Some(f) => f,
        None => {
            print_fail(
                "wer-dump: WER LocalDumps is not configured for this executable. \
                 Run the setup commands in the README and re-run this check.",
            );
            return false;
        }
    };

    print_info(&format!("wer-dump: WER dump folder: {}", dump_folder.display()));

    // Record the highest existing dump mtime before spawning, so we can identify the new dump.
    let baseline_time = newest_dump_mtime(&dump_folder);

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            print_fail(&format!("wer-dump: could not determine current executable: {e}"));
            return false;
        }
    };

    print_info("wer-dump: spawning child process to crash with WER exclusion registered...");
    let child_result = std::process::Command::new(&exe).args(["--child", "wer-crash"]).status();

    match child_result {
        Ok(s) if s.code() == Some(0) => {
            print_fail("wer-dump: child exited cleanly — it should have crashed");
            return false;
        }
        Err(e) => {
            print_fail(&format!("wer-dump: failed to spawn child: {e}"));
            return false;
        }
        Ok(_) => {} // non-zero exit code = expected crash
    }

    // Wait up to 30 s for WER to generate the dump.
    print_info("wer-dump: waiting for WER to write the crash dump (up to 30 s)...");
    let dump_path = match wait_for_new_dump(&dump_folder, baseline_time, Duration::from_secs(20)) {
        Some(p) => p,
        None => {
            print_fail(
                "wer-dump: no new dump appeared in the WER folder within 30 s. \
                 Ensure WER LocalDumps is configured and the service is running.",
            );
            return false;
        }
    };

    print_info(&format!("wer-dump: found dump: {}", dump_path.display()));

    let dump_bytes = match std::fs::read(&dump_path) {
        Ok(b) => b,
        Err(e) => {
            print_fail(&format!("wer-dump: could not read dump file: {e}"));
            return false;
        }
    };

    let canary_found = find_pattern(&dump_bytes, &WER_CANARY);

    if canary_found {
        print_fail("wer-dump: canary found in WER dump — WerRegisterExcludedMemoryBlock did NOT exclude the region");
        false
    } else {
        print_pass("wer-dump: canary absent from WER dump — the secret was excluded from the crash report");
        true
    }
}

// ── Child side ────────────────────────────────────────────────────────────────

/// Run in the child process. Creates a protected secret — `ProtectedBytes::new`
/// registers WER exclusion automatically — then crashes intentionally so WER
/// generates a dump for the parent to inspect.
pub(crate) fn child_crash() -> ! {
    let secret = ProtectedBytes::<32>::new(WER_CANARY);

    let status = secret.protection_status();
    if !status.dump_excluded {
        eprintln!(
            "child/wer-crash: WerRegisterExcludedMemoryBlock was not registered \
             (dump_excluded == false); dump may contain the canary"
        );
        // Continue anyway — the crash is still useful for the dump-existence check.
    }

    // Keep `secret` alive until the crash so its data page is in the dump.
    let _ = secret.expose_secret().as_ptr();

    // Crash the process. WER will generate a dump for the parent to inspect.
    // SAFETY: intentional null-pointer dereference to trigger STATUS_ACCESS_VIOLATION,
    //         causing WER to produce a crash dump that the parent verifier inspects.
    unsafe {
        let null: *const u8 = std::ptr::null();
        let _ = null.read_volatile();
    }

    unreachable!("process should have crashed")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Check the registry (read-only) for the WER LocalDumps folder configured for
/// this executable. Returns `None` if not configured.
fn find_wer_dump_folder() -> Option<PathBuf> {
    let exe_name = std::env::current_exe().ok()?;
    let exe_file = exe_name.file_name()?.to_string_lossy().into_owned();

    // Use `reg query` to avoid importing the full Win32 registry API.
    let key = format!(r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\{exe_file}");

    let output = std::process::Command::new("reg")
        .args(["query", &key, "/v", "DumpFolder"])
        .output()
        .ok()?;

    if !output.status.success() {
        // Also try the global LocalDumps key (no per-app key).
        let output2 = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps",
                "/v",
                "DumpFolder",
            ])
            .output()
            .ok()?;

        if !output2.status.success() {
            return None;
        }
        return parse_reg_sz_value(&output2.stdout);
    }

    parse_reg_sz_value(&output.stdout)
}

fn parse_reg_sz_value(reg_output: &[u8]) -> Option<PathBuf> {
    let text = str::from_utf8(reg_output).ok()?;
    // `reg query` output lines look like:
    //   DumpFolder    REG_EXPAND_SZ    C:\CrashDumps
    for line in text.lines() {
        if line.trim_start().starts_with("DumpFolder") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Some(PathBuf::from(parts[2..].join(" ")));
            }
        }
    }
    None
}

fn newest_dump_mtime(folder: &Path) -> Option<std::time::SystemTime> {
    std::fs::read_dir(folder)
        .ok()?
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x.eq_ignore_ascii_case("dmp"))
                .unwrap_or(false)
        })
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .max()
}

fn wait_for_new_dump(folder: &Path, baseline: Option<std::time::SystemTime>, timeout: Duration) -> Option<PathBuf> {
    let start = Instant::now();
    loop {
        if let Ok(entries) = std::fs::read_dir(folder) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.extension().map(|x| x.eq_ignore_ascii_case("dmp")).unwrap_or(false) {
                    continue;
                }
                if let Ok(mtime) = entry.metadata().and_then(|m| m.modified())
                    && baseline.map(|b| mtime > b).unwrap_or(true)
                {
                    return Some(path);
                }
            }
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn find_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
