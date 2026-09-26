use std::collections::HashSet;
use std::ffi::{OsString, c_void};
use std::io::Write as _;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::FromRawHandle as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, ensure};
use windows::Win32::Foundation::{
    CloseHandle, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree, NTE_BAD_KEYSET, NTE_NO_MORE_ITEMS, NTE_NOT_FOUND,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, CERT_KEY_SPEC, CRYPT_INTEGER_BLOB,
    CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData, MS_KEY_STORAGE_PROVIDER,
    NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG,
    NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NCRYPT_PROV_HANDLE, NCRYPT_SECURITY_DESCR_PROPERTY, NCryptDeleteKey, NCryptEnumKeys,
    NCryptExportKey, NCryptFreeBuffer, NCryptFreeObject, NCryptGetProperty, NCryptKeyName, NCryptOpenKey,
    NCryptOpenStorageProvider,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

const ENTROPY: &[u8] = b"Devolutions.Agent.PendingEnrollment.v1";
const STILL_ACTIVE: u32 = 259;
const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);

#[link(name = "advapi32")]
unsafe extern "system" {
    fn CreateWellKnownSid(kind: i32, domain: *const c_void, sid: *mut c_void, length: *mut u32) -> i32;
    fn CheckTokenMembership(token: *mut c_void, sid: *const c_void, member: *mut i32) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn QueryFullProcessImageNameW(process: *mut c_void, flags: u32, name: *mut u16, length: *mut u32) -> i32;
    fn GetExitCodeProcess(process: *mut c_void, code: *mut u32) -> i32;
    fn TerminateProcess(process: *mut c_void, code: u32) -> i32;
    fn WaitForSingleObject(process: *mut c_void, milliseconds: u32) -> u32;
}

#[link(name = "psapi")]
unsafe extern "system" {
    fn EnumProcesses(process_ids: *mut u32, buffer_bytes: u32, needed_bytes: *mut u32) -> i32;
}

pub(crate) struct AgentJob(HANDLE);

// SAFETY: This wrapper owns the OS handle, and Windows job handles are valid across threads.
unsafe impl Send for AgentJob {}
// SAFETY: No operation mutates the handle through a shared reference.
unsafe impl Sync for AgentJob {}

impl AgentJob {
    pub(crate) fn attach(pid: u32) -> anyhow::Result<Self> {
        // SAFETY: A private, unnamed job has no borrowed security attributes or name.
        let job = Self(unsafe { CreateJobObjectW(None, None)? });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: The job and limits buffer are valid for this synchronous call.
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())?,
            )?
        };
        // SAFETY: The child PID came from the process just spawned by this test.
        let process = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, pid)? };
        // SAFETY: Both handles remain open until the assignment returns.
        let assigned = unsafe { AssignProcessToJobObject(job.0, process) };
        // SAFETY: OpenProcess returned an owned handle.
        unsafe { CloseHandle(process)? };
        assigned?;
        Ok(job)
    }
}

impl Drop for AgentJob {
    fn drop(&mut self) {
        // SAFETY: Closing our only job handle kills its entire process tree.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn blob(data: &[u8]) -> anyhow::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len())?,
        pbData: data.as_ptr().cast_mut(),
    })
}

fn protect(contents: &[u8], decrypt: bool, local_machine: bool) -> anyhow::Result<Vec<u8>> {
    let input = blob(contents)?;
    let entropy = blob(ENTROPY)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    if decrypt {
        // SAFETY: The input and entropy buffers remain live until CryptUnprotectData returns.
        unsafe { CryptUnprotectData(&input, None, Some(&entropy), None, None, 0, &mut output)? };
    } else {
        // SAFETY: The input and entropy buffers remain live until CryptProtectData returns.
        unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                Some(&entropy),
                None,
                None,
                if local_machine { CRYPTPROTECT_LOCAL_MACHINE } else { 0 },
                &mut output,
            )?
        };
    }
    // SAFETY: DPAPI allocated output.pbData for output.cbData bytes; LocalFree releases it.
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    // SAFETY: The buffer is allocated by CryptProtectData or CryptUnprotectData with LocalAlloc.
    unsafe { LocalFree(Some(HLOCAL(output.pbData.cast()))) };
    Ok(bytes)
}

pub(crate) fn unprotect_pending(contents: &[u8]) -> anyhow::Result<Vec<u8>> {
    protect(contents, true, false)
}

pub(crate) fn assert_machine_scope(contents: &[u8]) -> anyhow::Result<()> {
    // DPAPI's current blob header stores its scope flags at byte 40; reject unfamiliar formats.
    const PROVIDER: [u8; 16] = [
        0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb,
    ];
    ensure!(
        contents.len() >= 44 && contents[..4] == 1u32.to_le_bytes() && contents[4..20] == PROVIDER,
        "unsupported DPAPI blob header"
    );
    let flags = u32::from_le_bytes(contents[40..44].try_into()?);
    ensure!(
        flags & CRYPTPROTECT_LOCAL_MACHINE != 0,
        "pending file is not machine-scoped DPAPI"
    );
    Ok(())
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW allocated the descriptor.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn current_user_sid() -> anyhow::Result<String> {
    let output = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .context("look up current user SID")?;
    ensure!(output.status.success(), "could not look up current user SID");
    let text = String::from_utf8(output.stdout)?;
    let sid = text
        .trim()
        .rsplit_once(',')
        .context("missing current user SID")?
        .1
        .trim()
        .trim_matches('"');
    ensure!(
        sid.starts_with("S-1-") && sid.chars().all(|c| c.is_ascii_digit() || c == '-' || c == 'S'),
        "invalid SID"
    );
    Ok(sid.to_owned())
}

pub(crate) fn running_as_system() -> anyhow::Result<bool> {
    Ok(current_user_sid()? == "S-1-5-18")
}

pub(crate) fn running_as_elevated_administrator() -> anyhow::Result<bool> {
    const WIN_BUILTIN_ADMINISTRATORS_SID: i32 = 26;
    let mut sid = [0u8; 68];
    let mut length = u32::try_from(sid.len())?;
    ensure!(
        // SAFETY: The SID buffer has the maximum documented SID length and length is writable.
        unsafe {
            CreateWellKnownSid(
                WIN_BUILTIN_ADMINISTRATORS_SID,
                std::ptr::null(),
                sid.as_mut_ptr().cast(),
                &mut length,
            )
        } != 0,
        "create Administrators SID: {}",
        std::io::Error::last_os_error()
    );
    let mut member = 0;
    ensure!(
        // SAFETY: A null token checks this process's effective token against the valid SID above.
        unsafe { CheckTokenMembership(std::ptr::null_mut(), sid.as_ptr().cast(), &mut member) } != 0,
        "check effective administrator membership: {}",
        std::io::Error::last_os_error()
    );
    Ok(member != 0)
}

pub(crate) fn write_pending(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let encrypted = protect(contents, false, true)?;
    write_protected_file(path, &encrypted)
}

pub(crate) fn write_protected_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let current_user = current_user_sid()?;
    let sddl = if current_user == "S-1-5-18" {
        "D:P(A;;FA;;;SY)".to_owned()
    } else {
        format!("D:P(A;;FA;;;SY)(A;;FA;;;{current_user})")
    };
    let sddl = wide(std::ffi::OsStr::new(&sddl));
    let mut raw = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl is NUL-terminated and raw is an output pointer owned by this function.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut raw,
            None,
        )?
    };
    let descriptor = SecurityDescriptor(raw);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: BOOL(0),
    };
    let path = wide(path.as_os_str());
    // SAFETY: Both the NUL-terminated path and security descriptor remain live until CreateFileW returns.
    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(path.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            Some(&attributes),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?
    };
    // SAFETY: CreateFileW returned an owned handle, transferred to File for closing on drop.
    let mut file = unsafe { std::fs::File::from_raw_handle(handle.0) };
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: OpenProcess returned an owned handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn agent_pid(pid_file: &Path) -> anyhow::Result<Option<u32>> {
    let text = match std::fs::read_to_string(pid_file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(text.trim().parse().context("invalid SYSTEM agent PID file")?))
}

fn process_image(handle: &ProcessHandle) -> anyhow::Result<PathBuf> {
    let mut name = vec![0u16; 32_768];
    let mut length = u32::try_from(name.len())?;
    ensure!(
        // SAFETY: The handle is open with query permission, and name and length are writable.
        unsafe { QueryFullProcessImageNameW(handle.0.0, 0, name.as_mut_ptr(), &mut length) } != 0,
        "read SYSTEM agent image path: {}",
        std::io::Error::last_os_error()
    );
    Ok(PathBuf::from(OsString::from_wide(&name[..usize::try_from(length)?])))
}

fn process_running(handle: &ProcessHandle) -> anyhow::Result<bool> {
    let mut code = 0;
    ensure!(
        // SAFETY: The process handle remains valid while Windows writes its exit code.
        unsafe { GetExitCodeProcess(handle.0.0, &mut code) } != 0,
        "read SYSTEM agent exit code: {}",
        std::io::Error::last_os_error()
    );
    Ok(code == STILL_ACTIVE)
}

fn open_agent_process(pid: u32, agent_bin: &Path, terminate: bool) -> anyhow::Result<Option<(ProcessHandle, bool)>> {
    let access = if terminate {
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE
    } else {
        PROCESS_QUERY_LIMITED_INFORMATION
    };
    // SAFETY: The PID came from the fixture's PID file, and OpenProcess validates the requested rights.
    let handle = match unsafe { OpenProcess(access, false, pid) } {
        Ok(handle) => ProcessHandle(handle),
        Err(error) if error.code().0 == 0x8007_0057u32.cast_signed() => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let actual = std::fs::canonicalize(process_image(&handle)?)?;
    let expected = std::fs::canonicalize(agent_bin)?;
    ensure!(
        actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy()),
        "SYSTEM agent PID belongs to a different executable"
    );
    let running = process_running(&handle)?;
    Ok(Some((handle, running)))
}

fn process_ids() -> anyhow::Result<Vec<u32>> {
    let mut ids = vec![0u32; 4096];
    loop {
        let mut needed = 0;
        ensure!(
            // SAFETY: Windows writes at most the buffer's size and reports the byte count.
            unsafe {
                EnumProcesses(
                    ids.as_mut_ptr(),
                    u32::try_from(ids.len() * size_of::<u32>())?,
                    &mut needed,
                )
            } != 0,
            "enumerate processes for SYSTEM agent cleanup: {}",
            std::io::Error::last_os_error()
        );
        let count = usize::try_from(needed)? / size_of::<u32>();
        if count < ids.len() {
            ids.truncate(count);
            return Ok(ids);
        }
        ensure!(ids.len() < 65_536, "process enumeration exceeds 65536 entries");
        ids.resize(ids.len() * 2, 0);
    }
}

pub(crate) fn case_agent_processes(agent_bin: &Path) -> anyhow::Result<Vec<u32>> {
    let expected = std::fs::canonicalize(agent_bin)?;
    let mut matches = Vec::new();
    for pid in process_ids()? {
        if pid == 0 {
            continue;
        }
        // SAFETY: Each PID came from Windows; unrelated inaccessible processes are skipped.
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
            continue;
        };
        let handle = ProcessHandle(handle);
        let Ok(actual) = process_image(&handle).and_then(|path| std::fs::canonicalize(path).map_err(Into::into)) else {
            continue;
        };
        if actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy())
            && process_running(&handle)?
        {
            matches.push(pid);
        }
    }
    Ok(matches)
}

pub(crate) fn system_agent_running(pid_file: &Path, agent_bin: &Path) -> anyhow::Result<Option<bool>> {
    let Some(pid) = agent_pid(pid_file)? else {
        return Ok(None);
    };
    Ok(open_agent_process(pid, agent_bin, false)?.map(|(_, running)| running))
}

pub(crate) fn stop_system_agent(agent_bin: &Path) -> anyhow::Result<()> {
    for pid in case_agent_processes(agent_bin)? {
        if let Some((handle, true)) = open_agent_process(pid, agent_bin, true)? {
            ensure!(
                // SAFETY: The handle belongs to this fixture's uniquely copied agent executable.
                unsafe { TerminateProcess(handle.0.0, 1) } != 0,
                "terminate SYSTEM agent PID {pid}: {}",
                std::io::Error::last_os_error()
            );
            ensure!(
                // SAFETY: The owned process handle remains valid until the wait completes.
                unsafe { WaitForSingleObject(handle.0.0, 5_000) } == 0,
                "SYSTEM agent PID {pid} did not exit within five seconds"
            );
        }
    }
    ensure!(
        case_agent_processes(agent_bin)?.is_empty(),
        "fixture agent executable still has a running process"
    );
    Ok(())
}

pub(crate) fn pending_acl_is_protected(path: &Path) -> anyhow::Result<()> {
    let path = wide(path.as_os_str());
    let mut raw = PSECURITY_DESCRIPTOR::default();
    // SAFETY: path is NUL-terminated and raw receives an allocated security descriptor.
    let result = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut raw,
        )
    };
    ensure!(result.0 == 0, "could not read pending-file DACL ({})", result.0);
    let descriptor = SecurityDescriptor(raw);
    let acl = protected_dacl_sddl(descriptor.0)?;
    let user_sid = canonical_sddl_sid(&current_user_sid()?)?;
    let expected_aces = if user_sid == "SY" {
        "(A;;FA;;;SY)".to_owned()
    } else {
        format!("(A;;FA;;;SY)(A;;FA;;;{user_sid})")
    };
    ensure!(
        has_only_required_aces(&acl, &user_sid),
        "pending-file DACL grants access beyond SYSTEM and the current user: actual SDDL {acl}; expected ACEs {expected_aces}"
    );
    Ok(())
}

fn protected_dacl_sddl(descriptor: PSECURITY_DESCRIPTOR) -> anyhow::Result<String> {
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: The security descriptor remains live until the function returns.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision)? };
    ensure!(
        control & SE_DACL_PROTECTED.0 != 0,
        "security descriptor DACL is not protected"
    );
    dacl_sddl(descriptor)
}

fn dacl_sddl(descriptor: PSECURITY_DESCRIPTOR) -> anyhow::Result<String> {
    let mut sddl = PWSTR::null();
    // SAFETY: The descriptor is valid and the output string is owned until freed with LocalFree.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            None,
        )?
    };
    // SAFETY: The conversion returned a NUL-terminated string allocated for the caller.
    let acl = unsafe { sddl.to_string() };
    // SAFETY: LocalFree releases the SDDL string allocated by the conversion.
    unsafe { LocalFree(Some(HLOCAL(sddl.0.cast()))) };
    acl.map_err(Into::into)
}

/// Returns the SID as Windows writes it in SDDL, which uses aliases for some accounts
/// (for example `LA` for the RID 500 administrator that GitHub-hosted runners use).
fn canonical_sddl_sid(sid: &str) -> anyhow::Result<String> {
    let sddl = wide(std::ffi::OsStr::new(&format!("D:(A;;FA;;;{sid})")));
    let mut raw = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl is NUL-terminated and raw is an output pointer owned by this function.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut raw,
            None,
        )?
    };
    let descriptor = SecurityDescriptor(raw);
    let mut out = PWSTR::null();
    // SAFETY: The descriptor is valid and the output string is owned until freed with LocalFree.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut out,
            None,
        )?
    };
    // SAFETY: The conversion returned a NUL-terminated string allocated for the caller.
    let converted = unsafe { out.to_string() };
    // SAFETY: LocalFree releases the SDDL string allocated by the conversion.
    unsafe { LocalFree(Some(HLOCAL(out.0.cast()))) };
    let converted = converted?;
    converted
        .strip_prefix("D:(A;;FA;;;")
        .and_then(|rest| rest.strip_suffix(')'))
        .map(ToOwned::to_owned)
        .with_context(|| format!("unexpected SDDL round-trip for {sid}: {converted}"))
}

fn has_only_required_aces(sddl: &str, user_sid: &str) -> bool {
    if !sddl.starts_with("D:") {
        return false;
    }
    let Some(start) = sddl.find('(') else {
        return false;
    };
    let mut rest = &sddl[start..];
    let mut aces = Vec::new();
    while let Some(after_open) = rest.strip_prefix('(') {
        let Some(close) = after_open.find(')') else {
            return false;
        };
        aces.push(&after_open[..close]);
        rest = &after_open[close + 1..];
    }
    if !rest.is_empty() {
        return false;
    }
    aces.sort_unstable();
    let user_ace = format!("A;;FA;;;{user_sid}");
    let mut expected = vec!["A;;FA;;;SY"];
    if user_sid != "SY" {
        expected.push(&user_ace);
    }
    expected.sort_unstable();
    aces == expected
}

fn has_only_key_principals(sddl: &str, user_sid: &str, grant_current_user: bool) -> bool {
    if !sddl.starts_with("D:") {
        return false;
    }
    let Some(start) = sddl.find('(') else {
        return false;
    };
    let mut rest = &sddl[start..];
    let mut system = false;
    let mut user = false;
    while let Some(after_open) = rest.strip_prefix('(') {
        let Some(close) = after_open.find(')') else {
            return false;
        };
        let fields = after_open[..close].split(';').collect::<Vec<_>>();
        if fields.len() != 6 || fields[0] != "A" || fields[2].is_empty() {
            return false;
        }
        match fields[5] {
            "SY" => system = true,
            sid if grant_current_user && sid == user_sid => user = true,
            _ => return false,
        }
        rest = &after_open[close + 1..];
    }
    rest.is_empty() && system && (user || !grant_current_user || user_sid == "SY")
}

struct Provider(NCRYPT_PROV_HANDLE);

impl Provider {
    fn open() -> anyhow::Result<Self> {
        let mut handle = NCRYPT_PROV_HANDLE::default();
        // SAFETY: handle is writable and the provider name is a static NUL-terminated string.
        unsafe { NCryptOpenStorageProvider(&mut handle, MS_KEY_STORAGE_PROVIDER, 0)? };
        Ok(Self(handle))
    }

    fn key(&self, name: &str) -> anyhow::Result<Option<Key>> {
        let mut handle = NCRYPT_KEY_HANDLE::default();
        let name = wide(std::ffi::OsStr::new(name));
        // SAFETY: The key name is NUL-terminated and handle is writable.
        let result = unsafe {
            NCryptOpenKey(
                self.0,
                &mut handle,
                PCWSTR::from_raw(name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        match result {
            Ok(()) => Ok(Some(Key(handle))),
            Err(error) if matches!(error.code(), NTE_BAD_KEYSET | NTE_NOT_FOUND) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: The provider handle belongs to this wrapper.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

struct Key(NCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: The opened key handle belongs to this wrapper.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

pub(crate) fn machine_key_exists(name: &str) -> anyhow::Result<bool> {
    let provider = Provider::open()?;
    Ok(provider.key(name)?.is_some())
}

fn belongs_to_run(name: &str, prefix: &str) -> bool {
    name.starts_with(prefix)
}

pub(crate) fn machine_keys_with_prefix(prefix: &str) -> anyhow::Result<HashSet<String>> {
    ensure!(!prefix.is_empty(), "machine key run prefix is empty");
    struct EnumState(*mut c_void);
    impl Drop for EnumState {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: NCryptEnumKeys allocated the enumeration state for this provider.
                let _ = unsafe { NCryptFreeBuffer(self.0) };
            }
        }
    }
    struct KeyName(*mut NCryptKeyName);
    impl Drop for KeyName {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: NCryptEnumKeys allocated the returned key-name buffer.
                let _ = unsafe { NCryptFreeBuffer(self.0.cast()) };
            }
        }
    }

    let provider = Provider::open()?;
    let mut state = EnumState(std::ptr::null_mut());
    let mut names = HashSet::new();
    loop {
        let mut key = KeyName(std::ptr::null_mut());
        // SAFETY: Both output pointers are writable, and NCryptFreeBuffer releases their allocations.
        let result = unsafe {
            NCryptEnumKeys(
                provider.0,
                PCWSTR::null(),
                &mut key.0,
                &mut state.0,
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        match result {
            Ok(()) => {
                ensure!(!key.0.is_null(), "NCryptEnumKeys returned no key name");
                // SAFETY: NCryptEnumKeys returned a valid key-name structure.
                let pointer = unsafe { (*key.0).pszName };
                // SAFETY: The key-name pointer is NUL-terminated and lives until the buffer is freed.
                let name = unsafe { pointer.to_string()? };
                if belongs_to_run(&name, prefix) {
                    names.insert(name);
                }
            }
            Err(error) if error.code() == NTE_NO_MORE_ITEMS => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(names)
}

pub(crate) fn assert_non_exportable(name: &str) -> anyhow::Result<()> {
    let provider = Provider::open()?;
    let key = provider
        .key(name)?
        .context("machine key not found in Microsoft Software KSP")?;
    let mut policy = [0u8; 4];
    let mut used = 0;
    // SAFETY: NCryptGetProperty writes at most four bytes into policy and reports the count in used.
    unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            Some(&mut policy),
            &mut used,
            OBJECT_SECURITY_INFORMATION(0),
        )?
    };
    ensure!(
        used == 4 && u32::from_le_bytes(policy) == 0,
        "machine key permits export"
    );
    let mut buffer = [0u8; 4096];
    // SAFETY: The buffer is writable and the blob type is a NUL-terminated static string.
    let exported = unsafe {
        NCryptExportKey(
            key.0,
            None,
            NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
            None,
            Some(&mut buffer),
            &mut used,
            NCRYPT_FLAGS(0),
        )
    };
    buffer.fill(0);
    ensure!(exported.is_err(), "NCryptExportKey exported a private key");
    Ok(())
}

pub(crate) fn assert_machine_key_acl(name: &str, grant_current_user: bool) -> anyhow::Result<()> {
    let provider = Provider::open()?;
    let key = provider.key(name)?.context("machine key not found for ACL check")?;
    let mut needed = 0;
    // SAFETY: A null output buffer asks NCrypt for the security descriptor length.
    let _ = unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_SECURITY_DESCR_PROPERTY,
            None,
            &mut needed,
            DACL_SECURITY_INFORMATION,
        )
    };
    ensure!(needed > 0, "machine key has no readable security descriptor");
    let mut bytes = vec![0u8; usize::try_from(needed)?];
    // SAFETY: The writable buffer is at least the size NCrypt reported.
    unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key.0.0),
            NCRYPT_SECURITY_DESCR_PROPERTY,
            Some(&mut bytes),
            &mut needed,
            DACL_SECURITY_INFORMATION,
        )?
    };
    let acl = dacl_sddl(PSECURITY_DESCRIPTOR(bytes.as_mut_ptr().cast()))?;
    let user_sid = canonical_sddl_sid(&current_user_sid()?)?;
    ensure!(
        has_only_key_principals(&acl, &user_sid, grant_current_user),
        "machine-key DACL must grant SYSTEM{} and no other principal: actual SDDL {acl}",
        if grant_current_user {
            format!(" and current user {user_sid}")
        } else {
            String::new()
        }
    );
    Ok(())
}

pub(crate) fn machine_public_key(name: &str) -> anyhow::Result<Vec<u8>> {
    let provider = Provider::open()?;
    let key = provider
        .key(name)?
        .context("machine key not found for public-key check")?;
    let mut needed = 0;
    // SAFETY: A null output buffer asks NCrypt for the public blob length.
    let _ = unsafe {
        NCryptExportKey(
            key.0,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            None,
            &mut needed,
            NCRYPT_FLAGS(0),
        )
    };
    ensure!(needed >= 72, "machine key has no P-256 public blob");
    let mut bytes = vec![0u8; usize::try_from(needed)?];
    // SAFETY: The buffer has the length NCrypt requested for the public blob.
    unsafe {
        NCryptExportKey(
            key.0,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            Some(&mut bytes),
            &mut needed,
            NCRYPT_FLAGS(0),
        )?
    };
    let magic = u32::from_le_bytes(bytes[0..4].try_into()?);
    let coordinate_len = u32::from_le_bytes(bytes[4..8].try_into()?);
    ensure!(
        magic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC && coordinate_len == 32 && needed == 72,
        "machine key is not an ECDSA P-256 public key"
    );
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(4);
    sec1.extend_from_slice(&bytes[8..72]);
    Ok(sec1)
}

pub(crate) fn cleanup_machine_keys(prefix: &str) -> anyhow::Result<()> {
    let names = machine_keys_with_prefix(prefix)?;
    if names.is_empty() {
        return Ok(());
    }
    let provider = Provider::open()?;
    for name in names {
        let key = provider
            .key(&name)?
            .with_context(|| format!("run-owned machine key {name} disappeared before cleanup"))?;
        // SAFETY: The machine key handle was opened for this provider; on success NCryptDeleteKey frees it.
        unsafe { NCryptDeleteKey(key.0, 0) }.with_context(|| format!("delete run-owned machine key {name}"))?;
        std::mem::forget(key);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OwnedChild(std::process::Child);

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "spawned by the missing-PID cleanup test"]
    fn process_sentinel() {
        if std::env::var_os("AGENT_IDENTITY_PROCESS_SENTINEL").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    #[test]
    fn system_agent_cleanup_finds_process_without_published_pid() -> anyhow::Result<()> {
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-identity-windows-tests");
        std::fs::create_dir_all(&scratch)?;
        let dir = tempfile::Builder::new().prefix("system-process-").tempdir_in(scratch)?;
        let image = dir.path().join("case-agent.exe");
        std::fs::copy(std::env::current_exe()?, &image)?;
        let pid_file = dir.path().join("system-agent.pid");
        std::fs::write(&pid_file, b"")?;
        let mut child = OwnedChild(
            std::process::Command::new(&image)
                .args(["--ignored", "--exact", "windows::tests::process_sentinel"])
                .env("AGENT_IDENTITY_PROCESS_SENTINEL", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?,
        );
        let started = std::time::Instant::now();
        loop {
            if case_agent_processes(&image)?.contains(&child.0.id()) {
                break;
            }
            ensure!(
                child.0.try_wait()?.is_none(),
                "process sentinel exited before the cleanup test could observe it"
            );
            ensure!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "process sentinel did not become visible"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        ensure!(agent_pid(&pid_file)?.is_none(), "PID file must still be empty");
        stop_system_agent(&image)?;
        ensure!(
            child.0.wait()?.code() == Some(1) && case_agent_processes(&image)?.is_empty(),
            "case agent remained alive after image-based cleanup"
        );
        Ok(())
    }

    #[test]
    fn pending_file_dpapi_and_protected_acl() -> anyhow::Result<()> {
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-identity-windows-tests");
        std::fs::create_dir_all(&scratch)?;
        let dir = tempfile::Builder::new().prefix("pending-").tempdir_in(scratch)?;
        let path = dir.path().join("pending-enrollment.dat");
        let json = br#"{"version":1,"token":"test-only"}"#;
        write_pending(&path, json)?;
        pending_acl_is_protected(&path)?;
        let encrypted = std::fs::read(&path)?;
        assert_machine_scope(&encrypted)?;
        ensure!(
            unprotect_pending(&encrypted)? == json,
            "DPAPI pending file did not round-trip"
        );
        assert!(assert_machine_scope(&protect(json, false, false)?).is_err());
        Ok(())
    }

    #[test]
    fn pending_acl_rejects_extra_allow_ace() {
        let sid = "S-1-5-21-42";
        assert!(has_only_required_aces("D:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-42)", sid));
        assert!(has_only_required_aces("D:P(A;;FA;;;SY)(A;;FA;;;LA)", "LA"));
        assert!(has_only_required_aces("D:P(A;;FA;;;SY)", "SY"));
        assert!(!has_only_required_aces(
            "D:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-42)(A;;FA;;;WD)",
            sid
        ));
    }

    #[test]
    fn machine_key_acl_checks_principals_not_rights_or_ace_order() {
        let sid = "S-1-5-21-42";
        assert!(has_only_key_principals(
            "D:PAI(A;;0x10000;;;S-1-5-21-42)(A;;GR;;;SY)",
            sid,
            true
        ));
        assert!(has_only_key_principals("D:(A;;GR;;;SY)", sid, false));
        assert!(!has_only_key_principals(
            "D:(A;;GR;;;SY)(A;;GR;;;S-1-5-21-42)",
            sid,
            false
        ));
        assert!(!has_only_key_principals("D:(A;;GR;;;SY)", sid, true));
        assert!(!has_only_key_principals(
            "D:(A;;GR;;;SY)(A;;GR;;;S-1-5-21-42)(A;;GR;;;WD)",
            sid,
            true
        ));
    }

    #[test]
    fn canonical_sddl_sid_uses_windows_aliases() -> anyhow::Result<()> {
        assert_eq!(canonical_sddl_sid("S-1-5-18")?, "SY");
        assert_eq!(canonical_sddl_sid("S-1-5-32-544")?, "BA");
        let user = current_user_sid()?;
        let canonical = canonical_sddl_sid(&user)?;
        assert!(canonical == user || canonical.len() == 2, "{canonical}");
        assert_eq!(canonical_sddl_sid(&canonical)?, canonical);
        Ok(())
    }

    #[test]
    fn machine_key_cleanup_matches_only_the_run_prefix() {
        let prefix = format!("DevolutionsAgent-Identity-conformance-{}-", uuid::Uuid::new_v4());
        let own = format!("{prefix}{}", uuid::Uuid::new_v4());
        let other_run = format!("DevolutionsAgent-Identity-conformance-{}-", uuid::Uuid::new_v4());
        assert!(belongs_to_run(&own, &prefix));
        assert!(!belongs_to_run(
            &format!("{other_run}{}", uuid::Uuid::new_v4()),
            &prefix
        ));
        assert!(!belongs_to_run(
            &format!("DevolutionsAgent-Identity-{}", uuid::Uuid::new_v4()),
            &prefix
        ));
        assert!(!belongs_to_run(
            &format!("{prefix}other"),
            &format!("{prefix}{}", uuid::Uuid::new_v4())
        ));
    }
}
