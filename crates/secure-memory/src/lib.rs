#![cfg_attr(doc, doc = include_str!("../README.md"))]

#[cfg(any(test, not(any(unix, windows))))]
mod fallback;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use core::fmt;

#[cfg(not(any(unix, windows)))]
use fallback as platform;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

/// The memory-protection features that were successfully activated for a
/// [`ProtectedBytes`] allocation.
///
/// All fields are `false` when the platform backend is not available
/// (`fallback_backend == true`).
///
/// For a quick pass/fail check, call [`ProtectionStatus::level`] instead of
/// inspecting individual fields.
#[derive(Debug, Clone, Copy)]
pub struct ProtectionStatus {
    /// The pages are locked in RAM (`mlock` / `VirtualLock`).
    ///
    /// When `false` the OS may page the secret to disk under memory pressure.
    pub locked: bool,

    /// Guard pages are installed immediately before and after the data page.
    ///
    /// Any out-of-bounds access into adjacent memory will fault at the OS level.
    pub guard_pages: bool,

    /// The page is registered for exclusion from crash dumps.
    ///
    /// - **Linux**: `madvise(MADV_DONTDUMP)` — excluded from kernel core dumps
    ///   and user-space tools that respect VMA flags.
    /// - **Windows**: `WerRegisterExcludedMemoryBlock` — excluded from the mini
    ///   dump embedded in WER crash reports sent to Microsoft Watson only.
    ///   Full-memory dumps (`MiniDumpWithFullMemory`, ProcDump `-ma`, kernel live
    ///   dumps) capture all committed pages regardless. `MiniDumpWriteDump`
    ///   callbacks (`RemoveMemoryCallback` / `IncludeVmRegionCallback`) can filter
    ///   regions but only for cooperating dump writers, not externally triggered
    ///   dumps.
    /// - **macOS**: always `false`; no equivalent API exists.
    pub dump_excluded: bool,

    /// The data page was successfully demoted to read-only after construction
    /// (`mprotect(PROT_READ)` / `VirtualProtect(PAGE_READONLY)`).
    ///
    /// When `false` the page remains writable, which means the "Removing write
    /// access prevents accidental overwrites" guarantee does not hold.
    pub write_protected: bool,

    /// No OS-level hardening is available; using plain heap allocation.
    ///
    /// The secret is still zeroized on drop but none of the other protections
    /// are active. A debug message is logged once at construction time.
    pub fallback_backend: bool,
}

impl ProtectionStatus {
    /// Return the overall protection level as a single summary value.
    ///
    /// Prefer this over checking individual fields when you only need to know
    /// whether the allocation is adequately protected. See [`ProtectionLevel`]
    /// for the exact definition of each variant.
    #[must_use]
    pub fn level(&self) -> ProtectionLevel {
        if self.fallback_backend {
            ProtectionLevel::Unprotected
        } else if self.guard_pages && self.locked && self.write_protected && self.dump_excluded {
            ProtectionLevel::Full
        } else {
            ProtectionLevel::Partial
        }
    }
}

/// Overall memory-protection level for a [`ProtectedBytes`] allocation.
///
/// Returned by [`ProtectionStatus::level`].
/// Individual protection flags are still accessible via [`ProtectionStatus`]
/// when finer-grained diagnostics are needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLevel {
    /// All core OS hardening is active: guard pages, RAM lock, read-only page
    /// protection, and crash-dump exclusion all succeeded.
    ///
    /// Note: on macOS `dump_excluded` is always `false` (no platform API
    /// exists), so `Full` is never reached on macOS — `Partial` is the best
    /// achievable level there.
    Full,

    /// The OS backend is active but at least one protection (`guard_pages`,
    /// `locked`, `write_protected`, or `dump_excluded`) failed at runtime
    /// (e.g. due to `ulimit` restrictions or platform limitations).
    Partial,

    /// No OS-level hardening is available. The allocation falls back to a plain
    /// heap allocation with zeroize-on-drop only.
    Unprotected,
}

/// A fixed-size, protected in-memory secret.
///
/// On supported platforms the backing storage is a dedicated page-based
/// allocation with guard pages, memory locking, read-only page protection after
/// construction, and (where available) exclusion from core dumps. On all
/// platforms the bytes are zeroized before the backing allocation is released.
///
/// - `Debug` emits `[REDACTED]`; `Display` is absent; not `Clone` or `Copy`.
/// - `new` takes a mutable reference and zeroizes exactly that buffer after
///   copying the secret into secure storage. Any earlier copies of the same
///   bytes elsewhere in the caller's frame (or in intermediate buffers) are
///   **not** zeroed by this crate.
/// - `mlock` / `VirtualLock` prevent paging to disk but do not prevent transient
///   exposure in registers or on the call stack during `expose_secret`.
pub struct ProtectedBytes<const N: usize> {
    inner: platform::SecureAlloc<N>,
    status: ProtectionStatus,
}

impl<const N: usize> ProtectedBytes<N> {
    /// Copy `bytes` into a new protected allocation and zeroize the source.
    ///
    /// The buffer pointed to by `bytes` is zeroized immediately after the
    /// secret has been transferred into secure storage. Any other copies of
    /// the same bytes — in earlier stack frames, intermediate buffers, or
    /// registers — are **not** zeroed by this crate.
    ///
    /// # Panics
    ///
    /// Panics if the underlying OS page allocation fails (equivalent to
    /// out-of-memory). Hardening steps that fail at runtime (mlock limits,
    /// unavailable `madvise` flags, …) do **not** panic; they are downgraded
    /// and reported via [`ProtectedBytes::protection_status`] and a
    /// `tracing::debug!`.
    pub fn new(bytes: &mut [u8; N]) -> Self {
        let (inner, status) = platform::SecureAlloc::new(bytes);
        // Zeroize the source buffer now that the secret lives in secure storage.
        zeroize::Zeroize::zeroize(bytes);
        Self { inner, status }
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        self.inner.expose()
    }

    /// Return the protection status achieved at construction time.
    #[must_use]
    pub fn protection_status(&self) -> &ProtectionStatus {
        &self.status
    }
}

impl<const N: usize> fmt::Debug for ProtectedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtectedBytes<{N}>([REDACTED])")
    }
}

// Intentionally absent: Display, Clone, Copy, Serialize, Deserialize.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_and_expose() {
        let secret = ProtectedBytes::new(&mut [0x42u8; 32]);
        assert_eq!(secret.expose_secret(), &[0x42u8; 32]);
    }

    #[test]
    fn redacted_debug_does_not_leak_bytes() {
        let secret = ProtectedBytes::new(&mut [0xFFu8; 32]);
        let s = format!("{secret:?}");
        assert!(s.contains("REDACTED"), "debug must say REDACTED, got: {s}");
        // Must not contain the byte value in decimal or hex.
        assert!(!s.contains("255"), "debug must not leak decimal value");
        assert!(!s.contains("ff"), "debug must not leak hex value");
        assert!(!s.contains("FF"), "debug must not leak hex value (upper)");
    }

    /// Verify that construction does not panic and that the status makes sense
    /// for the current platform.
    #[test]
    fn protection_status_coherent() {
        let secret = ProtectedBytes::new(&mut [1u8; 32]);
        let st = secret.protection_status();

        // fallback_backend is mutually exclusive with OS hardening.
        if st.fallback_backend {
            assert!(!st.locked);
            assert!(!st.guard_pages);
            assert!(!st.dump_excluded);
            assert!(!st.write_protected);
        }

        // dump_excluded without locked would be unusual; at minimum, if
        // dump_excluded is true then a real OS backend must be active.
        if st.dump_excluded {
            assert!(!st.fallback_backend);
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn os_backend_is_not_fallback() {
        let secret = ProtectedBytes::new(&mut [2u8; 32]);
        assert!(
            !secret.protection_status().fallback_backend,
            "expected OS backend on this platform"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn guard_pages_active() {
        let secret = ProtectedBytes::new(&mut [3u8; 32]);
        let st = secret.protection_status();
        assert!(st.guard_pages, "guard pages should be active");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn write_protected_active() {
        let secret = ProtectedBytes::new(&mut [4u8; 32]);
        let st = secret.protection_status();
        assert!(st.write_protected, "data page should be write-protected");
    }

    #[test]
    fn new_clears_source() {
        let mut raw = [0xABu8; 32];
        let secret = ProtectedBytes::new(&mut raw);
        assert_eq!(secret.expose_secret(), &[0xABu8; 32]);
        assert_eq!(raw, [0u8; 32], "source buffer must be zeroed after new");
    }

    // Test the fallback backend directly on all platforms.
    #[test]
    fn fallback_backend_constructs_correctly() {
        let (alloc, status) = fallback::SecureAlloc::<32>::new(&[0x99u8; 32]);
        assert_eq!(alloc.expose(), &[0x99u8; 32]);
        assert!(status.fallback_backend);
        assert!(!status.locked);
        assert!(!status.guard_pages);
        assert!(!status.dump_excluded);
        assert!(!status.write_protected);
        assert_eq!(status.level(), ProtectionLevel::Unprotected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn os_backend_is_full_protection() {
        let secret = ProtectedBytes::new(&mut [5u8; 32]);
        assert_eq!(
            secret.protection_status().level(),
            ProtectionLevel::Full,
            "expected Full protection on this platform"
        );
    }

    // On Windows, `WerRegisterExcludedMemoryBlock` is absent on some Windows Server 2016
    // (NT 10.0.14393) builds, so `dump_excluded` is best-effort and `Full` is not
    // guaranteed. `VirtualLock` is also best-effort (can fail under working-set limits).
    // Assert only the protections that are reliably available.
    #[cfg(windows)]
    #[test]
    fn os_backend_is_full_protection() {
        let secret = ProtectedBytes::new(&mut [5u8; 32]);
        let st = secret.protection_status();
        assert!(!st.fallback_backend, "OS backend should be active");
        assert!(st.guard_pages, "guard pages should be active");
        assert!(st.write_protected, "data page should be write-protected");
    }
}
