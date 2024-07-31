//! Undocumented Windows API functions
use std::ffi::c_void;

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{BOOL, HANDLE, LUID, NTSTATUS, UNICODE_STRING},
        Security::{
            LOGON32_LOGON, LOGON32_PROVIDER, PSID, QUOTA_LIMITS, TOKEN_ACCESS_MASK, TOKEN_DEFAULT_DACL, TOKEN_GROUPS,
            TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, TOKEN_SOURCE, TOKEN_TYPE, TOKEN_USER,
        },
    },
};

use crate::win::module_symbol;

pub unsafe fn LogonUserExExW<P0, P1, P2>(
    lpszusername: P0,
    lpszdomain: P1,
    lpszpassword: P2,
    dwlogontype: LOGON32_LOGON,
    dwlogonprovider: LOGON32_PROVIDER,
    ptokenGroups: Option<*const TOKEN_GROUPS>,
    phtoken: Option<*mut HANDLE>,
    pplogonsid: Option<*mut PSID>,
    ppprofilebuffer: Option<*mut *mut core::ffi::c_void>,
    pdwprofilelength: Option<*mut u32>,
    pquotalimits: Option<*mut QUOTA_LIMITS>,
) -> windows::core::Result<()>
where
    P0: windows::core::Param<PCWSTR>,
    P1: windows::core::Param<PCWSTR>,
    P2: windows::core::Param<PCWSTR>,
{
    let LogonUserExExW = module_symbol::<
        unsafe extern "system" fn(
            PCWSTR,
            PCWSTR,
            PCWSTR,
            LOGON32_LOGON,
            LOGON32_PROVIDER,
            *const TOKEN_GROUPS,
            *mut HANDLE,
            *mut PSID,
            *mut *mut core::ffi::c_void,
            *mut u32,
            *mut QUOTA_LIMITS,
        ) -> BOOL,
    >("advapi32.dll", "LogonUserExExW")?;
    LogonUserExExW(
        lpszusername.param().abi(),
        lpszdomain.param().abi(),
        lpszpassword.param().abi(),
        dwlogontype,
        dwlogonprovider,
        ptokenGroups.unwrap_or(std::ptr::null_mut()),
        core::mem::transmute(phtoken.unwrap_or(std::ptr::null_mut())),
        core::mem::transmute(pplogonsid.unwrap_or(std::ptr::null_mut())),
        core::mem::transmute(ppprofilebuffer.unwrap_or(std::ptr::null_mut())),
        core::mem::transmute(pdwprofilelength.unwrap_or(std::ptr::null_mut())),
        core::mem::transmute(pquotalimits.unwrap_or(std::ptr::null_mut())),
    )
    .ok()
}

/// Argument to LsaManageSidNameMapping to add a mapping.
///
/// https://github.com/gtworek/PSBits/blob/5cdd1a8c03ee0c1c69d3abd20916cf347c9d7e47/VirtualAccounts/TrustedInstallerCmd2.c#L33
#[repr(C)]
#[derive(Default, Debug)]
pub struct LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT {
    pub DomainName: UNICODE_STRING,
    pub AccountName: UNICODE_STRING,
    pub Sid: PSID,
    pub Flags: u32,
}

/// Error codes for LsaManageSidNameMapping.
///
/// https://github.com/gtworek/PSBits/blob/5cdd1a8c03ee0c1c69d3abd20916cf347c9d7e47/VirtualAccounts/TrustedInstallerCmd2.c#L22
#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
pub struct LSA_SID_NAME_MAPPING_OPERATION_ERROR(pub i32);
pub const LsaSidNameMappingOperation_Success: LSA_SID_NAME_MAPPING_OPERATION_ERROR =
    LSA_SID_NAME_MAPPING_OPERATION_ERROR(0);
pub const LsaSidNameMappingOperation_NonMappingError: LSA_SID_NAME_MAPPING_OPERATION_ERROR =
    LSA_SID_NAME_MAPPING_OPERATION_ERROR(1);
pub const LsaSidNameMappingOperation_NameCollision: LSA_SID_NAME_MAPPING_OPERATION_ERROR =
    LSA_SID_NAME_MAPPING_OPERATION_ERROR(2);
pub const LsaSidNameMappingOperation_SidCollision: LSA_SID_NAME_MAPPING_OPERATION_ERROR =
    LSA_SID_NAME_MAPPING_OPERATION_ERROR(3);
pub const LsaSidNameMappingOperation_DomainNotFound: LSA_SID_NAME_MAPPING_OPERATION_ERROR =
    LSA_SID_NAME_MAPPING_OPERATION_ERROR(4);
pub const LsaSidNameMappingOperation_DomainSidPrefixMismatch: LSA_SID_NAME_MAPPING_OPERATION_ERROR =
    LSA_SID_NAME_MAPPING_OPERATION_ERROR(5);
pub const LsaSidNameMappingOperation_MappingNotFound: LSA_SID_NAME_MAPPING_OPERATION_ERROR =
    LSA_SID_NAME_MAPPING_OPERATION_ERROR(6);

/// Generic error code for LsaManageSidNameMapping.
///
/// From the reference document, every output type is a typedef to this type.
///
/// https://github.com/gtworek/PSBits/blob/5cdd1a8c03ee0c1c69d3abd20916cf347c9d7e47/VirtualAccounts/TrustedInstallerCmd2.c#L60
#[repr(C)]
#[derive(PartialEq, Eq, Copy, Clone, Default)]
pub struct LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT {
    pub ErrorCode: LSA_SID_NAME_MAPPING_OPERATION_ERROR,
}

/// Operation type for LsaManageSidNameMapping.
///
/// https://github.com/gtworek/PSBits/blob/5cdd1a8c03ee0c1c69d3abd20916cf347c9d7e47/VirtualAccounts/TrustedInstallerCmd2.c#L15
#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default)]
pub struct LSA_SID_NAME_MAPPING_OPERATION_TYPE(pub i32);
pub const LsaSidNameMappingOperation_Add: LSA_SID_NAME_MAPPING_OPERATION_TYPE = LSA_SID_NAME_MAPPING_OPERATION_TYPE(0);
pub const LsaSidNameMappingOperation_Remove: LSA_SID_NAME_MAPPING_OPERATION_TYPE =
    LSA_SID_NAME_MAPPING_OPERATION_TYPE(1);
pub const LsaSidNameMappingOperation_AddMultiple: LSA_SID_NAME_MAPPING_OPERATION_TYPE =
    LSA_SID_NAME_MAPPING_OPERATION_TYPE(2);

pub type LSA_SID_NAME_MAPPING_OPERATION_INPUT = c_void;

/// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/jj902653(v=vs.85)
pub unsafe fn LsaManageSidNameMapping(
    OpType: LSA_SID_NAME_MAPPING_OPERATION_TYPE,
    OpInput: *const LSA_SID_NAME_MAPPING_OPERATION_INPUT,
    OpOutput: *mut *mut LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT,
) -> windows::core::Result<()> {
    let LsaManageSidNameMapping = module_symbol::<
        unsafe extern "system" fn(
            LSA_SID_NAME_MAPPING_OPERATION_TYPE,
            *const LSA_SID_NAME_MAPPING_OPERATION_INPUT,
            *mut *mut LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT,
        ) -> NTSTATUS,
    >("advapi32.dll", "LsaManageSidNameMapping")?;

    LsaManageSidNameMapping(OpType, OpInput, OpOutput).ok()
}

/// https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/Storage/FileSystem/fn.RtlCreateVirtualAccountSid.html
pub unsafe fn RtlCreateVirtualAccountSid(
    Name: *const UNICODE_STRING,
    BaseSubAuthority: u32,
    Sid: PSID,
    SidLength: *mut u32,
) -> windows::core::Result<()> {
    let RtlCreateVirtualAccountSid = module_symbol::<
        unsafe extern "system" fn(*const UNICODE_STRING, u32, PSID, *mut u32) -> NTSTATUS,
    >("ntdll.dll", "RtlCreateVirtualAccountSid")?;

    RtlCreateVirtualAccountSid(Name, BaseSubAuthority, Sid, SidLength).ok()
}

pub const LOGON32_PROVIDER_VIRTUAL: LOGON32_PROVIDER = LOGON32_PROVIDER(4u32);

/// https://learn.microsoft.com/en-us/windows/win32/secbiomet/general-constants
/// Actually 68, we are generous
pub const SECURITY_MAX_SID_SIZE: u32 = 256;

#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default)]
pub struct PROCESSINFOCLASS(i32);
/// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
pub const ProcessBasicInformation: PROCESSINFOCLASS = PROCESSINFOCLASS(0);

/// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
pub unsafe fn NtQueryInformationProcess(
    ProcessHandle: HANDLE,
    ProcessInformationClass: PROCESSINFOCLASS,
    ProcessInformation: *mut c_void,
    ProcessInformationLength: u32,
    ReturnLength: Option<*mut u32>,
) -> windows::core::Result<()> {
    let NtQueryInformationProcess = module_symbol::<
        unsafe extern "system" fn(HANDLE, PROCESSINFOCLASS, *mut c_void, u32, *mut u32) -> NTSTATUS,
    >("ntdll.dll", "NtQueryInformationProcess")?;

    NtQueryInformationProcess(
        ProcessHandle,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationLength,
        ReturnLength.unwrap_or(std::ptr::null_mut()),
    )
    .ok()
}

#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default)]
pub struct THREADINFOCLASS(i32);
/// https://github.com/winsiderss/phnt/blob/2b70847be7f731126fba453568e2cfbf560614bf/ntpsapi.h#L288
pub const ThreadStrongerBadHandleChecks: THREADINFOCLASS = THREADINFOCLASS(0x35);

/// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationthread
pub unsafe fn NtSetInformationThread(
    ThreadHandle: HANDLE,
    ThreadInformationClass: THREADINFOCLASS,
    ThreadInformation: *mut c_void,
    ThreadInformationLength: u32,
) -> windows::core::Result<()> {
    let NtSetInformationThread = module_symbol::<
        unsafe extern "system" fn(HANDLE, THREADINFOCLASS, *mut c_void, u32) -> NTSTATUS,
    >("ntdll.dll", "NtSetInformationThread")?;

    NtSetInformationThread(
        ThreadHandle,
        ThreadInformationClass,
        ThreadInformation,
        ThreadInformationLength,
    )
    .ok()
}

/// https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/Foundation/struct.OBJECT_ATTRIBUTES.html
#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *const UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *const c_void,
    pub SecurityQualityOfService: *const c_void,
}

impl Default for OBJECT_ATTRIBUTES {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Manually creates a Windows token.
///
/// The caller must have the SeCreateTokenPrivilege privilege.
///
/// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FToken%2FNtCreateToken.html
pub unsafe fn NtCreateToken(
    TokenHandle: *mut HANDLE,
    DesiredAccess: TOKEN_ACCESS_MASK,
    ObjectAttributes: *const OBJECT_ATTRIBUTES,
    TokenType: TOKEN_TYPE,
    AuthenticationId: *const LUID,
    ExpirationTime: *const i64,
    TokenUser: *const TOKEN_USER,
    TokenGroups: *const TOKEN_GROUPS,
    TokenPrivileges: *const TOKEN_PRIVILEGES,
    TokenOwner: *const TOKEN_OWNER,
    TokenPrimaryGroup: *const TOKEN_PRIMARY_GROUP,
    TokenDefaultDacl: *const TOKEN_DEFAULT_DACL,
    TokenSource: *const TOKEN_SOURCE,
) -> windows::core::Result<()> {
    let NtCreateToken = module_symbol::<
        unsafe extern "system" fn(
            *mut HANDLE,
            TOKEN_ACCESS_MASK,
            *const OBJECT_ATTRIBUTES,
            TOKEN_TYPE,
            *const LUID,
            *const i64,
            *const TOKEN_USER,
            *const TOKEN_GROUPS,
            *const TOKEN_PRIVILEGES,
            *const TOKEN_OWNER,
            *const TOKEN_PRIMARY_GROUP,
            *const TOKEN_DEFAULT_DACL,
            *const TOKEN_SOURCE,
        ) -> NTSTATUS,
    >("ntdll.dll", "NtCreateToken")?;

    NtCreateToken(
        TokenHandle,
        DesiredAccess,
        ObjectAttributes,
        TokenType,
        AuthenticationId,
        ExpirationTime,
        TokenUser,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
    )
    .ok()
}

/// https://learn.microsoft.com/en-us/dotnet/api/system.io.pipes.pipeaccessrights?view=net-8.0
pub const PIPE_ACCESS_FULL_CONTROL: u32 = 0x1F019F;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/curdir.htm
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: HANDLE,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/rtl_user_process_parameters.htm
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: HANDLE,
    pub ConsoleFlags: u32,
    pub StandardInput: HANDLE,
    pub StandardOutput: HANDLE,
    pub StandardError: HANDLE,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: *mut c_void,
    pub StartingX: u32,
    pub StartingY: u32,
    pub CountX: u32,
    pub CountY: u32,
    pub CountCharsX: u32,
    pub CountCharsY: u32,
    pub FillAttribute: u32,
    pub WindowFlags: u32,
    pub ShowWindowFlags: u32,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
}
