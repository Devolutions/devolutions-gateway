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
//!
//! ## Dump-exclusion limitation
//!
//! Windows does not expose a per-region public API equivalent to Linux's `MADV_DONTDUMP`.
//! `VirtualLock` prevents the pages from being written to the pagefile but crash dumps (WER, procdump, …) will still include them.
//! `dump_excluded` is always `false` on Windows.

use std::ffi::c_void;
use std::ptr;
use std::sync::OnceLock;

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
            "secret-memory: N ({N}) exceeds page size ({ps}); not supported"
        );

        let total = 3 * ps;

        // Allocate three contiguous committed pages (read/write).
        // SAFETY: `VirtualAlloc` with `None` address, `MEM_COMMIT | MEM_RESERVE`,
        //         and `PAGE_READWRITE` is the standard anonymous allocation idiom.
        let base_raw = unsafe { VirtualAlloc(None, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

        if base_raw.is_null() {
            panic!(
                "secret-memory: VirtualAlloc({total}) failed ({})",
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
                "secret-memory: VirtualProtect for guard pages failed ({}); \
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
                "secret-memory: VirtualLock failed ({}); \
                 secret may be paged to disk",
                std::io::Error::last_os_error()
            );
        }

        // ── Copy secret into the data page ──────────────────────────────────
        // SAFETY: `src` (caller stack) and `data` (VirtualAlloc region) are
        //         non-overlapping; both are valid for `N` bytes.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), data, N) };

        let alloc = SecureAlloc {
            base,
            data,
            locked,
            _marker: std::marker::PhantomData,
        };
        let status = ProtectionStatus {
            locked,
            guard_pages,
            dump_excluded: false, // no per-region dump exclusion on Windows
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
