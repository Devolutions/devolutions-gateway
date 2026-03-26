# secure-memory-verifier

A Windows-only standalone binary that verifies the runtime behaviour of the
`secret-memory` crate's four protection tracks independently.

## What it checks

| Subcommand | Track | Verification method | Automated? |
|---|---|---|---|
| `lock` | RAM locking | `QueryWorkingSetEx` Locked bit | Fully automated |
| `guard-underflow` | Guard pages (leading) | Child process crashes on access before data | Fully automated |
| `guard-overflow` | Guard pages (trailing) | Child process crashes on access after data | Fully automated |
| `wer-dump` | WER dump exclusion | `WerRegisterExcludedMemoryBlock` + crash child + scan dump | Requires WER pre-config (see below) |

## Prerequisites

- Windows 10 or later (Windows 11 recommended)
- Rust toolchain with `x86_64-pc-windows-msvc` or `aarch64-pc-windows-msvc` target
- `cargo build -p secure-memory-verifier` or `cargo run -p secure-memory-verifier`

### WER dump-exclusion check prerequisites

The `wer-dump` subcommand requires WER LocalDumps to be configured for the
verifier executable. This requires administrator rights.

```powershell
# Ensure WER is enabled and writes dumps immediately (required on CI runners).
$wer = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
Set-ItemProperty $wer -Name Disabled    -Value 0 -Type DWord -Force
Set-ItemProperty $wer -Name DontShowUI  -Value 1 -Type DWord -Force
Set-ItemProperty $wer -Name ForceQueue  -Value 0 -Type DWord -Force
Start-Service -Name WerSvc -ErrorAction SilentlyContinue

# Per-application LocalDumps configuration.
$key = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\secure-memory-verifier.exe"
New-Item $key -Force | Out-Null
Set-ItemProperty $key DumpType  2              # 2 = full dump
Set-ItemProperty $key DumpCount 5
Set-ItemProperty $key DumpFolder $env:TEMP     # or any writable folder
```

If the `LocalDumps` key is absent, `wer-dump` prints `[FAIL]` and exits 1.

## Running locally

```powershell
# Build first
cargo build -p secure-memory-verifier

# Individual checks
cargo run -p secure-memory-verifier -- lock
cargo run -p secure-memory-verifier -- guard-underflow
cargo run -p secure-memory-verifier -- guard-overflow
cargo run -p secure-memory-verifier -- wer-dump     # requires LocalDumps pre-config

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

### `wer-dump` — WER dump exclusion

**Proves:** When the secret's data page is registered with
`WerRegisterExcludedMemoryBlock` and a crash subsequently occurs, the
WER-generated full-memory dump does not contain the secret's canary pattern.
`ProtectedBytes::new` performs this registration automatically; the verifier
confirms it took effect end-to-end.

**Does not prove:**
- Third-party dump tools (ProcDump, WinDbg, Task Manager minidump, …) honour
  `WerRegisterExcludedMemoryBlock`. They typically do not.
- Every WER dump format or WER version behaves identically.
- Exclusion covers the full 3-page `VirtualAlloc` region (only the data page is registered).
- Full-memory dumps produced by `MiniDumpWithFullMemory` or kernel tools are excluded
  (no public Windows API reliably excludes a page from those).

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

## Common failure modes

| Symptom | Likely cause |
|---|---|
| `lock` FAIL — Locked bit not set | Process lacks `SeLockMemoryPrivilege`; increase the working-set limit |
| `guard-*` FAIL — child exits 0 | `VirtualProtect(PAGE_NOACCESS)` failed; guard pages not established |
| `guard-*` FAIL — unexpected exit code | Structured exception handler (SEH) in a DLL caught the AV; check for injected DLLs |
| `wer-dump` FAIL — not configured | WER LocalDumps registry key absent; run the setup PowerShell above |
| `wer-dump` FAIL — canary found | `WerRegisterExcludedMemoryBlock` not honoured; check WER service status |
