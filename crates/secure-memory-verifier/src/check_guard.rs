//! Guard-page verification via child-process crash tests.
//!
//! ## Memory layout reminder
//!
//! ```text
//! ┌──────────────┬──────────────┬──────────────┐
//! │  guard page  │  data page   │  guard page  │
//! │ PAGE_NOACCESS│PAGE_READWRITE│ PAGE_NOACCESS│
//! └──────────────┴──────────────┴──────────────┘
//!  ^base           ^data          ^data + ps
//! ```
//!
//! `data` is page-aligned. Therefore:
//! - `data - 1`        is the last byte of the leading guard page.
//! - `data + page_size` is the first byte of the trailing guard page.
//!
//! ## Why child processes?
//!
//! Accessing a `PAGE_NOACCESS` page raises `STATUS_ACCESS_VIOLATION`
//! (0xC0000005). There is no in-process recovery path that would allow the
//! verifier itself to continue, so each probe runs in a fresh child process.
//! The parent asserts the child exited with the expected exception code.
//!
//! ## What this proves
//!
//! Any out-of-bounds byte store/load that crosses the page boundary adjacent
//! to the data page will fault at the OS level immediately, before the value
//! can be observed by attacker-controlled code in the same process.
//!
//! ## What this does NOT prove
//!
//! - Accesses that stay within the data page are caught (they are not).
//! - Protection holds in kernel mode or via DMA.

use std::mem;

use secure_memory::ProtectedBytes;
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use crate::{print_check, print_fail, print_info, print_pass};

/// Which guard page to probe.
#[derive(Clone, Copy)]
pub(crate) enum Side {
    /// Byte immediately before the data page (leading guard).
    Under,
    /// First byte of the trailing guard page.
    Over,
}

impl Side {
    fn name(self) -> &'static str {
        match self {
            Side::Under => "guard-underflow",
            Side::Over => "guard-overflow",
        }
    }

    fn child_arg(self) -> &'static str {
        match self {
            Side::Under => "guard-underflow",
            Side::Over => "guard-overflow",
        }
    }
}

// ── Parent (verifier) side ────────────────────────────────────────────────────

/// Run the guard-page check for the given side by spawning a child process.
pub(crate) fn run(side: Side) -> bool {
    let name = side.name();
    print_check(&format!("{name}: spawning child to probe {name}"));

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            print_fail(&format!("{name}: could not determine current executable: {e}"));
            return false;
        }
    };

    {
        // Check the protection status in order for information.

        let probe = ProtectedBytes::<32>::new(&mut [0xAAu8; 32]);
        let status = probe.protection_status();

        if !status.guard_pages {
            print_info(&format!(
                "{name}: guard pages were not established (protection_status.guard_pages == false); child crash may not occur"
            ));
        }
    }

    let child_result = std::process::Command::new(&exe)
        .args(["--child", side.child_arg()])
        .status();

    let exit_status = match child_result {
        Ok(s) => s,
        Err(e) => {
            print_fail(&format!("{name}: failed to spawn child process: {e}"));
            return false;
        }
    };

    // On Windows, a process killed by an unhandled exception exits with the
    // exception code as its exit code.
    // STATUS_ACCESS_VIOLATION = 0xC0000005 = -1073741819i32
    const ACCESS_VIOLATION: i32 = -1073741819i32;

    match exit_status.code() {
        Some(code) if code == ACCESS_VIOLATION => {
            print_pass(&format!(
                "{name}: child exited with STATUS_ACCESS_VIOLATION (0xC0000005) — guard page fired"
            ));
            true
        }
        Some(0) => {
            print_fail(&format!(
                "{name}: child exited cleanly (code 0) — guard page did NOT fire"
            ));
            false
        }
        Some(code) => {
            print_fail(&format!(
                "{name}: child exited with unexpected code {code:#010x} (expected STATUS_ACCESS_VIOLATION 0xC0000005)"
            ));
            false
        }
        None => {
            // On Unix this would mean signal-kill; on Windows code() is always Some.
            print_fail(&format!("{name}: child had no exit code"));
            false
        }
    }
}

// ── Child side ────────────────────────────────────────────────────────────────

/// Run inside the child process. Intentionally accesses a guard page, which
/// crashes with `STATUS_ACCESS_VIOLATION`. Never returns.
pub(crate) fn child(side: Side) -> ! {
    let secret = ProtectedBytes::<32>::new(&mut [0x42u8; 32]);
    let data_ptr = secret.expose_secret().as_ptr();

    let access_ptr: *const u8 = match side {
        Side::Under => {
            // `data_ptr` is page-aligned (= base + page_size).
            // Therefore `data_ptr - 1` is the last byte of the leading guard page.
            // SAFETY: arithmetic only; we do not dereference here.
            unsafe { data_ptr.sub(1) }
        }
        Side::Over => {
            let ps = system_page_size();
            // `data_ptr + page_size` is the first byte of the trailing guard page.
            // SAFETY: arithmetic only; we do not dereference here.
            unsafe { data_ptr.add(ps) }
        }
    };

    // Intentional access violation: read from a PAGE_NOACCESS guard page.
    // The OS raises STATUS_ACCESS_VIOLATION immediately, terminating this process.
    // This is the expected outcome; the parent process checks the exit code.
    //
    // SAFETY: this is deliberately unsafe — we are probing the guard page.
    //         The parent verifier spawns this child precisely to observe the crash.
    unsafe { access_ptr.read_volatile() };

    // Reaching here means the guard page did not fire, which is a failure.
    eprintln!("child: guard page did not cause access violation — unexpected");
    std::process::exit(99)
}

fn system_page_size() -> usize {
    // SAFETY: `mem::zeroed()` is valid for `SYSTEM_INFO` — it is a struct of
    //         plain integer and pointer fields with no invalid bit patterns.
    let mut info: SYSTEM_INFO = unsafe { mem::zeroed() };
    // SAFETY: `GetSystemInfo` writes to the provided struct; it is always safe to call.
    unsafe { GetSystemInfo(&mut info) };
    info.dwPageSize as usize
}
