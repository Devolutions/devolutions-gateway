//! Windows secure-allocation backend.
//!
//! ## Memory layout
//!
//! ```text
//! ┌──────────────┬──────────────┬──────────────┐
//! │  guard page  │  data page   │  guard page  │
//! │ PAGE_NOACCESS│PAGE_READWRITE│ PAGE_NOACCESS│
//! └──────────────┴──────────────┴──────────────┘
//!  ^base           ^data          ^data + page_size
//! ```
//!
//! The three pages are a single `VirtualAlloc` region.
//! Guard pages are set to `PAGE_NOACCESS` via `VirtualProtect`.
//!
//! ## Hardening steps (best-effort)
//!
//! 1. Guard pages via `VirtualProtect(PAGE_NOACCESS)`.
//! 2. RAM lock via `VirtualLock`.
//! 3. WER dump exclusion via `WerRegisterExcludedMemoryBlock`.
//!
//! ## Dump-exclusion on Windows
//!
//! Windows does not have a single universal per-region dump-exclusion API
//! equivalent to Linux's `madvise(MADV_DONTDUMP)`.  The protections that exist
//! are scoped:
//!
//! - **WER crash reports**: `WerRegisterExcludedMemoryBlock` tells the Windows
//!   Error Reporting subsystem to omit the registered range from automatically-
//!   generated crash dumps. This is the mechanism used here.
//!   `ProtectionStatus::dump_excluded` reflects whether this registration
//!   succeeded.
//!
//! - **Full-memory / forensic dumps** (`MiniDumpWithFullMemory`, kernel dumps,
//!   ProcDump `-ma`, …): no public callback API reliably excludes a page from
//!   these on current Windows versions. Applications that write their own
//!   dumps using `MiniDumpNormal` (the typical crash-reporter default) will
//!   not capture non-stack heap pages, but `MiniDumpWithFullMemory` captures
//!   everything regardless of WER registration or `IncludeVmRegionCallback`.
//!
//! `VirtualLock` prevents the secret from being written to the pagefile but
//! does **not** affect dump capture.

use std::ffi::c_void;
use std::ptr;
use std::sync::OnceLock;

use windows::Win32::System::ErrorReporting::{WerRegisterExcludedMemoryBlock, WerUnregisterExcludedMemoryBlock};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualAlloc,
    VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
};
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use crate::ProtectionStatus;

/// Page-based secure allocation for Windows.
pub(crate) struct SecureAlloc<const N: usize> {
    /// Start of the entire 3-page `VirtualAlloc` region (the first guard page).
    base: *mut u8,
    /// Start of the data page (`base + page_size`).
    data: *mut u8,
    /// Whether `VirtualLock` succeeded.
    locked: bool,
    /// Whether `WerRegisterExcludedMemoryBlock` succeeded for the data page.
    wer_excluded: bool,
    /// Marker: `SecureAlloc` logically owns a `[u8; N]`.
    _marker: std::marker::PhantomData<[u8; N]>,
}

// SAFETY: `SecureAlloc` has exclusive ownership of its `VirtualAlloc` region.
//         There is no shared mutable state and no aliasing.
unsafe impl<const N: usize> Send for SecureAlloc<N> {}

// SAFETY: `expose()` returns a shared reference to immutable bytes, which
//         is safe to hand out to multiple threads simultaneously.
unsafe impl<const N: usize> Sync for SecureAlloc<N> {}

impl<const N: usize> SecureAlloc<N> {
    pub(crate) fn new(src: &[u8; N]) -> (Self, ProtectionStatus) {
        let ps = page_size();
        assert!(
            N <= ps,
            "secure-memory: N ({N}) exceeds page size ({ps}); not supported"
        );

        let total = 3 * ps;

        // Allocate three contiguous committed pages (read/write).
        // SAFETY: `VirtualAlloc` with `None` address, `MEM_COMMIT | MEM_RESERVE`,
        //         and `PAGE_READWRITE` is the standard anonymous allocation idiom.
        let base_raw = unsafe { VirtualAlloc(None, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

        if base_raw.is_null() {
            panic!(
                "secure-memory: VirtualAlloc({total}) failed ({})",
                std::io::Error::last_os_error()
            );
        }

        let base = base_raw as *mut u8;

        // Data page starts at base + page_size.
        // SAFETY: `base` is a valid allocation of `total = 3 * ps` bytes;
        //         `base + ps` is within that range.
        let data = unsafe { base.add(ps) };

        // ── Guard page before the data (page 0) ─────────────────────────────
        let mut old_prot = PAGE_PROTECTION_FLAGS::default();
        // SAFETY: `base` is page-aligned and points to `ps` valid committed bytes.
        let r_guard_before = unsafe { VirtualProtect(base as *const c_void, ps, PAGE_NOACCESS, &mut old_prot) };

        // ── Guard page after the data (page 2) ──────────────────────────────
        // SAFETY: `base + 2 * ps` is within the allocation; page-aligned.
        let guard_after = unsafe { base.add(2 * ps) };
        // SAFETY: `guard_after` is page-aligned, `ps` committed bytes.
        let r_guard_after = unsafe { VirtualProtect(guard_after as *const c_void, ps, PAGE_NOACCESS, &mut old_prot) };

        let guard_pages = r_guard_before.is_ok() && r_guard_after.is_ok();
        if !guard_pages {
            tracing::debug!(
                "secure-memory: VirtualProtect for guard pages failed ({}); \
                 guard pages are not active",
                std::io::Error::last_os_error()
            );
        }

        // ── Lock the data page in RAM ────────────────────────────────────────
        // SAFETY: `data` is page-aligned; `ps` committed bytes within the allocation.
        let r_lock = unsafe { VirtualLock(data as *const c_void, ps) };
        let locked = r_lock.is_ok();
        if !locked {
            tracing::debug!(
                "secure-memory: VirtualLock failed ({}); \
                 secret may be paged to disk",
                std::io::Error::last_os_error()
            );
        }

        // ── Copy secret into the data page ──────────────────────────────────
        // SAFETY: `src` (caller stack) and `data` (VirtualAlloc region) are
        //         non-overlapping; both are valid for `N` bytes.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), data, N) };

        // ── Register the data page for WER dump exclusion ────────────────────
        // `WerRegisterExcludedMemoryBlock` asks the Windows Error Reporting
        // subsystem to omit this page from automatically-generated crash dumps.
        // Registration covers the full page, not just N bytes, because the
        // allocation model is page-based.

        // SAFETY: `data` is a valid, committed, page-aligned pointer; `ps` is
        //         exactly one page — the size passed to `VirtualAlloc`.
        let wer_hr = unsafe { WerRegisterExcludedMemoryBlock(data.cast::<c_void>(), ps as u32) };
        let wer_excluded = wer_hr.is_ok();
        if !wer_excluded {
            tracing::debug!(
                "secure-memory: WerRegisterExcludedMemoryBlock failed ({wer_hr:?}); \
                 the data page will not be excluded from WER crash reports"
            );
        }

        let alloc = SecureAlloc {
            base,
            data,
            locked,
            wer_excluded,
            _marker: std::marker::PhantomData,
        };
        let status = ProtectionStatus {
            locked,
            guard_pages,
            // On Windows, dump_excluded reflects WER exclusion only.
            // See module-level documentation for scope and limitations.
            dump_excluded: wer_excluded,
            fallback_backend: false,
        };

        (alloc, status)
    }

    pub(crate) fn expose(&self) -> &[u8; N] {
        // SAFETY: `self.data` is valid for `N` initialised bytes and is live
        //         for at least as long as `self`.
        unsafe { &*(self.data as *const [u8; N]) }
    }
}

impl<const N: usize> Drop for SecureAlloc<N> {
    fn drop(&mut self) {
        let ps = page_size();

        // Restore read+write on the data page so we can zeroize it.
        let mut old_prot = PAGE_PROTECTION_FLAGS::default();
        // SAFETY: `self.data` is page-aligned; `ps` committed bytes in our region.
        let _ = unsafe { VirtualProtect(self.data as *const c_void, ps, PAGE_READWRITE, &mut old_prot) };

        // Zeroize secret bytes using `zeroize` to defeat compiler optimisations.
        // SAFETY: `self.data` is valid for `N` bytes; align of `u8` is 1.
        let secret = unsafe { std::slice::from_raw_parts_mut(self.data, N) };
        zeroize::Zeroize::zeroize(secret);

        if self.locked {
            // SAFETY: `self.data` and `ps` are the values used in `VirtualLock`.
            let _ = unsafe { VirtualUnlock(self.data as *const c_void, ps) };
        }

        // Unregister WER exclusion before freeing the page.
        // Must happen before `VirtualFree` to avoid a dangling registration.
        if self.wer_excluded {
            // SAFETY: `self.data` is the same pointer passed to
            //         `WerRegisterExcludedMemoryBlock`; still valid here.
            let _ = unsafe { WerUnregisterExcludedMemoryBlock(self.data.cast::<c_void>()) };
        }

        // Release the entire three-page region.
        // SAFETY: `self.base` is the base of the allocation; `dwSize` must be 0
        //         when `dwFreeType` is `MEM_RELEASE` (Windows requirement).
        let _ = unsafe { VirtualFree(self.base as *mut c_void, 0, MEM_RELEASE) };
    }
}

/// Return the system page size, cached after the first call.
fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        let mut info = SYSTEM_INFO::default();
        // SAFETY: `GetSystemInfo` fills the provided struct; always safe to call.
        unsafe { GetSystemInfo(&mut info) };
        info.dwPageSize as usize
    })
}
