# secure-memory

A minimal, auditable in-memory secret store for a single fixed-size master key.

## Purpose

This crate provides exactly one type — `ProtectedBytes<N>` — whose sole job is
to hold a `[u8; N]` (e.g.: a master key) with the best available OS memory-hardening applied at runtime.

It is intentionally **not** a general-purpose secret library.

## Threat model

**Protected against:**
- Swapping the secret to disk (via `mlock` / `VirtualLock`).
- The secret appearing in Linux core dumps (`madvise(MADV_DONTDUMP)`) and
  Windows Error Reporting (WER) crash reports (`WerRegisterExcludedMemoryBlock`).
- Adjacent heap corruption reaching the secret (via guard pages).
- Accidental logging (redacted `Debug`, no `Display`).
- Residual bytes after the secret is dropped (zeroize-before-free).

**Not protected against:**
- A privileged process reading `/proc/<pid>/mem` or `ReadProcessMemory`.
- The OS itself (kernel, hypervisor).
- CPU microarchitectural side channels (Spectre, Meltdown, …).
- Transient register / stack copies during `expose_secret` calls — memory
  locking does **not** prevent the CPU from holding secret bytes in registers
  or on the call stack while the caller uses them.
- Stack residuals from passing the `[u8; N]` to `new` — the compiler may copy
  the array into `new`'s stack frame; only that local copy is zeroized.
  Any residual bytes in the caller's frame are not zeroed by this crate.
- Attackers with `ptrace` or equivalent capability.
- SGX / TPM / hardware-backed enclaves.

## Platform guarantees

| Feature         | Linux               | Windows             | Other              |
|-----------------|---------------------|---------------------|--------------------|
| Page allocation | `mmap(MAP_ANON)`    | `VirtualAlloc`      | `Box` heap         |
| Guard pages     | `mprotect(PROT_NONE)` | `VirtualProtect(PAGE_NOACCESS)` | ✗ |
| RAM lock        | `mlock`             | `VirtualLock`       | ✗                  |
| Write protect   | `mprotect(PROT_READ)` | `VirtualProtect(PAGE_READONLY)` | ✗ |
| Dump exclusion  | `MADV_DONTDUMP`     | `WerRegisterExcludedMemoryBlock` (see note) | ✗ |
| Zeroize on drop | ✓                   | ✓                   | ✓                  |

**Windows dump exclusion note:** `WerRegisterExcludedMemoryBlock` registers the
data page for exclusion from WER crash reports sent to Microsoft Watson.
`dump_excluded = true` means this registration succeeded. It does **not** imply
universal protection: full-memory dumps (`MiniDumpWithFullMemory`, ProcDump
`-ma`, LocalDumps `DumpType=2`, kernel dumps) capture all committed read/write
pages regardless. `MiniDumpWriteDump` callbacks can filter regions but only for
cooperating dump writers, not externally triggered dumps.

**macOS note:** The Unix backend compiles for macOS (mmap + guard pages + mlock),
but `MADV_DONTDUMP` is Linux-only, so `dump_excluded` is always `false` on macOS.
macOS support is not tested in CI.

## Fallback behavior

On platforms where neither the Unix nor Windows backend compiles, the crate falls
back to a plain `Box<[u8; N]>` with `zeroize`-on-drop. A debug message is
logged once at construction time. No feature flag is required; the crate always compiles
and runs.

## Usage

```rust
use secure_memory::{ProtectedBytes, ProtectionLevel};

let key = ProtectedBytes::new([0u8; 32]);

// Recommended: check the overall level first.
match key.protection_status().level() {
    ProtectionLevel::Full => {}
    ProtectionLevel::Partial => tracing::warn!("master key: some memory protections are inactive"),
    ProtectionLevel::Unprotected => tracing::warn!("master key: no OS memory hardening available"),
}

// Individual flags are still accessible for fine-grained diagnostics.
let status = key.protection_status();
if !status.locked {
    tracing::warn!("master key: mlock/VirtualLock failed; key may be paged to disk");
}

// Short-lived borrow:
let bytes: &[u8; 32] = key.expose_secret();
```
