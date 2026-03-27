# secure-memory-verifier

A Windows-only standalone binary that verifies the runtime behaviour of the
`secure-memory` crate's protection tracks.

Run it manually on a Windows machine to confirm the OS hardening is active.

## What it checks

| Subcommand | Track | Verification method |
|---|---|---|
| `lock` | RAM locking | `QueryWorkingSetEx` Locked bit |
| `guard-underflow` | Guard pages (leading) | Child process crashes on access before data |
| `guard-overflow` | Guard pages (trailing) | Child process crashes on access after data |

> **Note on WER dump exclusion:** `WerRegisterExcludedMemoryBlock` is called by
> `ProtectedBytes::new` but is not verified here. It registers the data page for
> exclusion from WER crash reports sent to Microsoft Watson only. Full-memory
> dumps (`MiniDumpWithFullMemory`, ProcDump `-ma`, LocalDumps `DumpType=2`,
> kernel dumps) capture all committed read/write pages regardless. No public
> Windows API reliably excludes a page from those.

## Prerequisites

- Windows 10 or later (Windows 11 recommended)
- Rust toolchain with `x86_64-pc-windows-msvc` or `aarch64-pc-windows-msvc` target
- `cargo build -p secure-memory-verifier` or `cargo run -p secure-memory-verifier`

## Running locally

```powershell
# Build first
cargo build -p secure-memory-verifier

# Individual checks
cargo run -p secure-memory-verifier -- lock
cargo run -p secure-memory-verifier -- guard-underflow
cargo run -p secure-memory-verifier -- guard-overflow

# All checks
cargo run -p secure-memory-verifier -- all
```

Exit code 0 = all checks passed. Exit code 1 = at least one check failed.
Exit code 2 = bad arguments.

## Exact guarantees proven by each check

### `lock` — RAM locking via QueryWorkingSetEx

**Proves:** The kernel has pinned the secret's data page to physical RAM.
The `Locked` bit in the working-set entry is set, meaning `VirtualLock`
succeeded and the OS has honoured the lock in the working-set database.

**Does not prove:**
- The secret was never transiently in registers or on the call stack while `expose_secret` was active.
- A kernel-mode driver cannot read the page.
- The lock holds under extreme memory pressure on all Windows editions.

### `guard-underflow` / `guard-overflow` — Guard pages via child-process crashes

**Proves:** Accessing one byte before or one byte after the secret's data page
immediately raises `STATUS_ACCESS_VIOLATION` (0xC0000005). The guard pages are
`PAGE_NOACCESS` — not `PAGE_GUARD` — so they are permanent (not one-shot).

**Method:** A child process is spawned that deliberately dereferences the
guard-page address. The parent asserts the child exited with exception code
0xC0000005.

**Does not prove:**
- Accesses that stay within the data page are detected.
- Protection is enforced in kernel mode or via DMA.
- The guard prevents attacks that skip the boundary (e.g. format-string bugs targeting arbitrary addresses).

## Non-guarantees (applies to all checks)

- **Transient exposure:** The secret briefly exists on the call stack and in CPU
  registers while `expose_secret()` is in use. No check here can prevent that.
- **Kernel-mode access:** Any kernel-mode component can read any user-mode page
  regardless of `PAGE_NOACCESS` or `VirtualLock`.
- **Suspend-and-read attacks:** Another process with `PROCESS_VM_READ` access
  can read the page between `VirtualProtect` calls during drop.
- **Hibernation / sleep:** `VirtualLock` prevents pagefile writes but does not
  prevent the RAM contents from being written to the hibernation file
  (`hiberfil.sys`).
- **Full-memory dumps:** `WerRegisterExcludedMemoryBlock` does not exclude the
  page from `MiniDumpWithFullMemory` or any locally-captured full dump.

## Common failure modes

| Symptom | Likely cause |
|---|---|
| `lock` FAIL — Locked bit not set | Process lacks `SeLockMemoryPrivilege`; increase the working-set limit |
| `guard-*` FAIL — child exits 0 | `VirtualProtect(PAGE_NOACCESS)` failed; guard pages not established |
| `guard-*` FAIL — unexpected exit code | Structured exception handler (SEH) in a DLL caught the AV; check for injected DLLs |
