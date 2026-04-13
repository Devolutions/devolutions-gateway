//! Unix (Linux / macOS) secure-allocation backend.
//!
//! ## Memory layout
//!
//! ```text
//! ┌──────────────┬──────────────┬──────────────┐
//! │  guard page  │  data page   │  guard page  │
//! │  PROT_NONE   │  PROT_READ   │  PROT_NONE   │
//! └──────────────┴──────────────┴──────────────┘
//!  ^base           ^data          ^data + page_size
//! ```
//!
//! The secret occupies the first `N` bytes of the data page; the rest is unused.
//! Guard pages are `PROT_NONE` so any out-of-bounds access faults immediately.
//! The data page is `PROT_READ|WRITE` only during construction (while the secret
//! is being written). It is demoted to `PROT_READ` before `new` returns.
//!
//! ## Hardening steps (best-effort)
//!
//! 1. Guard pages via `mprotect(PROT_NONE)`.
//! 2. RAM lock via `mlock` — may fail under tight `ulimit -l` limits.
//! 3. Core-dump exclusion via `madvise(MADV_DONTDUMP)` — Linux only.
//! 4. Data page demoted to `PROT_READ` after the secret is written.
//!
//! All four are best-effort: failure is logged and reflected in [`ProtectionStatus`] but does **not** abort the process.

use std::ptr;
use std::sync::OnceLock;

use crate::ProtectionStatus;

/// Page-based secure allocation for Unix.
pub(crate) struct SecureAlloc<const N: usize> {
    /// Start of the entire 3-page `mmap` region (the first guard page).
    base: *mut u8,
    /// Start of the data page (`base + page_size`).
    data: *mut u8,
    /// Whether `mlock` succeeded.
    locked: bool,
    /// Marker: `SecureAlloc` logically owns a `[u8; N]`.
    _marker: std::marker::PhantomData<[u8; N]>,
}

// SAFETY: `SecureAlloc` has exclusive ownership of its `mmap` allocation.
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

        // Allocate three contiguous anonymous private pages.
        // SAFETY: `MAP_ANON | MAP_PRIVATE` with `fd = -1`, `offset = 0` is the
        //         standard idiom for anonymous memory; no file backing, no aliases.
        let base_raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        if base_raw == libc::MAP_FAILED {
            panic!("secure-memory: mmap({total}) failed; process is out of address space");
        }

        let base = base_raw as *mut u8;

        // data page starts at base + page_size.
        // SAFETY: `base` is a valid allocation of `total = 3 * ps` bytes;
        //         `base + ps` is within that range.
        let data = unsafe { base.add(ps) };

        // ── Guard page before the data (page 0) ─────────────────────────────
        // SAFETY: `base` is page-aligned and points to `ps` valid bytes.
        let r_guard_before = unsafe { libc::mprotect(base as *mut libc::c_void, ps, libc::PROT_NONE) };

        // ── Guard page after the data (page 2) ──────────────────────────────
        // SAFETY: `base + 2 * ps` is within the allocation; page-aligned.
        let guard_after = unsafe { base.add(2 * ps) };
        // SAFETY: `guard_after` is page-aligned, `ps` bytes within the allocation.
        let r_guard_after = unsafe { libc::mprotect(guard_after as *mut libc::c_void, ps, libc::PROT_NONE) };

        let guard_pages = r_guard_before == 0 && r_guard_after == 0;
        if r_guard_before != 0 {
            tracing::debug!(
                "secure-memory: mprotect for leading guard page failed ({})",
                std::io::Error::last_os_error()
            );
        }
        if r_guard_after != 0 {
            tracing::debug!(
                "secure-memory: mprotect for trailing guard page failed ({})",
                std::io::Error::last_os_error()
            );
        }

        // ── Lock the data page in RAM ────────────────────────────────────────
        // SAFETY: `data` is page-aligned; `ps` bytes are within the allocation.
        let r_lock = unsafe { libc::mlock(data as *const libc::c_void, ps) };
        let locked = r_lock == 0;
        if !locked {
            tracing::debug!(
                "secure-memory: mlock failed ({}); \
                 secret may be paged to disk — consider raising `ulimit -l`",
                std::io::Error::last_os_error()
            );
        }

        // ── Exclude from core dumps (Linux ≥ 3.4 only) ──────────────────────
        #[cfg(target_os = "linux")]
        let dump_excluded = {
            // SAFETY: `data` is page-aligned; `ps` bytes are a valid mapping.
            let r = unsafe { libc::madvise(data as *mut libc::c_void, ps, libc::MADV_DONTDUMP) };
            if r != 0 {
                tracing::debug!(
                    "secure-memory: madvise(MADV_DONTDUMP) failed ({}); \
                     region may appear in core dumps",
                    std::io::Error::last_os_error()
                );
            }
            r == 0
        };
        // macOS and other Unixes: no equivalent to MADV_DONTDUMP.
        #[cfg(not(target_os = "linux"))]
        let dump_excluded = false;

        // ── Copy secret into the data page ──────────────────────────────────
        // SAFETY: `src` (caller stack) and `data` (mmap region) are
        //         non-overlapping; both are valid for `N` bytes.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), data, N) };

        // ── Demote data page to read-only ────────────────────────────────────
        // The secret is now in place and never needs to be modified in-place.
        // Removing write access prevents accidental overwrites.
        // SAFETY: `data` is page-aligned; `ps` bytes are within the allocation.
        let r_readonly = unsafe { libc::mprotect(data as *mut libc::c_void, ps, libc::PROT_READ) };
        let write_protected = r_readonly == 0;
        if !write_protected {
            tracing::debug!(
                "secure-memory: mprotect(PROT_READ) for data page failed ({}); \
                 data page remains writable",
                std::io::Error::last_os_error()
            );
        }

        let alloc = SecureAlloc {
            base,
            data,
            locked,
            _marker: std::marker::PhantomData,
        };
        let status = ProtectionStatus {
            locked,
            guard_pages,
            dump_excluded,
            write_protected,
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
        // The page was demoted to PROT_READ in new(); this re-enables writes.
        // SAFETY: `self.data` is page-aligned; `ps` bytes are within our mapping.
        let _ = unsafe { libc::mprotect(self.data as *mut libc::c_void, ps, libc::PROT_READ | libc::PROT_WRITE) };

        // Zeroize secret bytes using `zeroize` to defeat compiler optimisations.
        // SAFETY: `self.data` is valid for `N` bytes; align of `u8` is 1.
        let secret = unsafe { std::slice::from_raw_parts_mut(self.data, N) };
        zeroize::Zeroize::zeroize(secret);

        if self.locked {
            // SAFETY: `self.data` and `ps` are the values used in the matching `mlock`.
            let _ = unsafe { libc::munlock(self.data as *const libc::c_void, ps) };
        }

        // Unmap the full three-page region.
        // SAFETY: `self.base` is the start of the mapping of size `3 * ps`.
        let _ = unsafe { libc::munmap(self.base as *mut libc::c_void, 3 * ps) };
    }
}

/// Return the system page size, cached after the first call.
fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        // SAFETY: `sysconf` with `_SC_PAGESIZE` is always safe to call.
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(ps).unwrap_or(4096)
    })
}
