//! RAM-locking verification via `QueryWorkingSetEx`.
//!
//! ## What this proves
//!
//! `VirtualLock` returning success only means the OS *accepted* the locking
//! request. The working-set attribute is the authoritative runtime signal: the
//! kernel sets the `Locked` bit in the working-set entry only when the page is
//! genuinely pinned to physical RAM. Querying that bit via `QueryWorkingSetEx`
//! is the correct runtime verification primitive.
//!
//! ## What this does NOT prove
//!
//! - The secret value never existed in registers or on the call stack.
//! - The page cannot be read by a privileged process (e.g. a kernel-mode driver).
//! - The lock will hold under extreme memory pressure on all Windows editions.

use std::mem::{self, size_of};

use secure_memory::ProtectedBytes;
use windows::Win32::System::ProcessStatus::{PSAPI_WORKING_SET_EX_INFORMATION, QueryWorkingSetEx};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::{print_check, print_fail, print_info, print_pass};

/// Bit layout of `PSAPI_WORKING_SET_EX_BLOCK.Flags` (from Windows SDK):
///
/// ```text
/// bit  0      Valid         (page is in the working set)
/// bits 1–3    ShareCount
/// bits 4–14   Win32Protection
/// bit  15     Shared
/// bits 16–21  Node
/// bit  22     Locked        ← what we check
/// bit  23     LargePage
/// ```
const LOCKED_BIT: usize = 22;

pub(crate) fn run() -> bool {
    print_check("lock: verifying data page is locked in RAM via QueryWorkingSetEx");

    let secret = ProtectedBytes::<32>::new(&mut [0x5Au8; 32]);
    let status = secret.protection_status();

    if !status.locked {
        print_info(
            "VirtualLock was not achieved (protection_status.locked == false); QueryWorkingSetEx may still reflect this",
        );
    }

    let data_ptr = secret.expose_secret().as_ptr();

    // SAFETY: `mem::zeroed()` is valid for `PSAPI_WORKING_SET_EX_INFORMATION`
    //         because every bit pattern is a valid (if meaningless) representation
    //         of a struct of integers and pointers.
    let mut info: PSAPI_WORKING_SET_EX_INFORMATION = unsafe { mem::zeroed() };
    info.VirtualAddress = data_ptr as *mut _;

    // SAFETY: GetCurrentProcess() always returns the pseudo-handle (-1) for the
    //         current process; it is always valid for the current process's lifetime.
    let process = unsafe { GetCurrentProcess() };

    let struct_size = u32::try_from(size_of::<PSAPI_WORKING_SET_EX_INFORMATION>()).expect("struct fits in u32");

    // SAFETY: `info.VirtualAddress` is set to a page-aligned address inside our
    //         3-page VirtualAlloc region; `process` is the current-process pseudo-handle;
    //         `struct_size` exactly covers one `PSAPI_WORKING_SET_EX_INFORMATION` entry.
    let ok = unsafe { QueryWorkingSetEx(process, std::ptr::addr_of_mut!(info).cast(), struct_size) };

    if ok.is_err() {
        print_fail(&format!(
            "lock: QueryWorkingSetEx failed: {}",
            std::io::Error::last_os_error()
        ));
        return false;
    }

    // SAFETY: `Flags` is a plain `usize`-sized integer field of the union.
    //         Reading it as an integer is always defined behaviour.
    let flags: usize = unsafe { info.VirtualAttributes.Flags };
    let valid = (flags & 1) != 0;
    let locked = ((flags >> LOCKED_BIT) & 1) != 0;

    if !valid {
        print_fail("lock: QueryWorkingSetEx reports Valid==0; the page is not in the working set");
        return false;
    }

    if locked {
        print_pass("lock: Locked bit is set — page is pinned in physical RAM");
    } else {
        print_fail("lock: Locked bit is NOT set — page may be swapped to disk");
        if status.locked {
            print_info("lock: VirtualLock reported success but the kernel working-set entry disagrees");
        }
    }

    locked
}
