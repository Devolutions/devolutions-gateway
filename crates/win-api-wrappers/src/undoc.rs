//! Undocumented Windows API functions

// Allowed since the goal is to replicate the Windows API crate so that it's familiar, which itself uses the raw names from the API.
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unsafe_op_in_unsafe_fn,
    clippy::too_many_arguments,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks
)]

use std::ffi::c_void;
use std::mem;

use windows::core::{BOOL, PCWSTR};
use windows::Win32::Foundation::{HANDLE, LUID, NTSTATUS, UNICODE_STRING};
use windows::Win32::Security::{
    LOGON32_LOGON, LOGON32_PROVIDER, PSID, QUOTA_LIMITS, TOKEN_ACCESS_MASK, TOKEN_DEFAULT_DACL, TOKEN_GROUPS,
    TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, TOKEN_SOURCE, TOKEN_TYPE, TOKEN_USER,
};

use crate::process::Module;

pub unsafe fn LogonUserExExW<P0, P1, P2>(
    lpszusername: P0,
    lpszdomain: P1,
    lpszpassword: P2,
    dwlogontype: LOGON32_LOGON,
    dwlogonprovider: LOGON32_PROVIDER,
    ptokenGroups: Option<*const TOKEN_GROUPS>,
    phtoken: Option<*mut HANDLE>,
    pplogonsid: Option<*mut PSID>,
    ppprofilebuffer: Option<*mut *mut c_void>,
    pdwprofilelength: Option<*mut u32>,
    pquotalimits: Option<*mut QUOTA_LIMITS>,
) -> windows::core::Result<()>
where
    P0: windows::core::Param<PCWSTR>,
    P1: windows::core::Param<PCWSTR>,
    P2: windows::core::Param<PCWSTR>,
{
    let LogonUserExExW = mem::transmute::<
        *const c_void,
        unsafe extern "system" fn(
            PCWSTR,
            PCWSTR,
            PCWSTR,
            LOGON32_LOGON,
            LOGON32_PROVIDER,
            *const TOKEN_GROUPS,
            *mut HANDLE,
            *mut PSID,
            *mut *mut c_void,
            *mut u32,
            *mut QUOTA_LIMITS,
        ) -> BOOL,
    >(Module::from_name("advapi32.dll")?.resolve_symbol("LogonUserExExW")?);
    LogonUserExExW(
        lpszusername.param().abi(),
        lpszdomain.param().abi(),
        lpszpassword.param().abi(),
        dwlogontype,
        dwlogonprovider,
        ptokenGroups.unwrap_or(std::ptr::null_mut()),
        phtoken.unwrap_or(std::ptr::null_mut()),
        pplogonsid.unwrap_or(std::ptr::null_mut()),
        ppprofilebuffer.unwrap_or(std::ptr::null_mut()),
        pdwprofilelength.unwrap_or(std::ptr::null_mut()),
        pquotalimits.unwrap_or(std::ptr::null_mut()),
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
    let LsaManageSidNameMapping = mem::transmute::<
        *const c_void,
        unsafe extern "system" fn(
            LSA_SID_NAME_MAPPING_OPERATION_TYPE,
            *const LSA_SID_NAME_MAPPING_OPERATION_INPUT,
            *mut *mut LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT,
        ) -> NTSTATUS,
    >(Module::from_name("advapi32.dll")?.resolve_symbol("LsaManageSidNameMapping")?);

    LsaManageSidNameMapping(OpType, OpInput, OpOutput).ok()
}

/// https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/Storage/FileSystem/fn.RtlCreateVirtualAccountSid.html
pub unsafe fn RtlCreateVirtualAccountSid(
    Name: *const UNICODE_STRING,
    BaseSubAuthority: u32,
    Sid: PSID,
    SidLength: *mut u32,
) -> windows::core::Result<()> {
    let RtlCreateVirtualAccountSid =
        mem::transmute::<
            *const c_void,
            unsafe extern "system" fn(*const UNICODE_STRING, u32, PSID, *mut u32) -> NTSTATUS,
        >(Module::from_name("ntdll.dll")?.resolve_symbol("RtlCreateVirtualAccountSid")?);

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
    let NtQueryInformationProcess = mem::transmute::<
        *const c_void,
        unsafe extern "system" fn(HANDLE, PROCESSINFOCLASS, *mut c_void, u32, *mut u32) -> NTSTATUS,
    >(Module::from_name("ntdll.dll")?.resolve_symbol("NtQueryInformationProcess")?);

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
    let NtSetInformationThread = mem::transmute::<
        *const c_void,
        unsafe extern "system" fn(HANDLE, THREADINFOCLASS, *mut c_void, u32) -> NTSTATUS,
    >(Module::from_name("ntdll.dll")?.resolve_symbol("NtSetInformationThread")?);

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
        unsafe { mem::zeroed() }
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
    let NtCreateToken = mem::transmute::<
        *const c_void,
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
    >(Module::from_name("ntdll.dll")?.resolve_symbol("NtCreateToken")?);

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

/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/curdir.htm
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: HANDLE,
}

/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/rtl_user_process_parameters.htm
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
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

/// Based on https://github.com/winsiderss/systeminformer/blob/7ad69bf13d31892a89be7230bdbd47ffde024a2b/phnt/include/ntseapi.h#L165.
/// It is a `u16` because of its usage in `TOKEN_SECURITY_ATTRIBUTE_V1`.
#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
pub struct TOKEN_SECURITY_ATTRIBUTE_TYPE(pub u16);

pub const TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID: TOKEN_SECURITY_ATTRIBUTE_TYPE = TOKEN_SECURITY_ATTRIBUTE_TYPE(0);
pub const TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64: TOKEN_SECURITY_ATTRIBUTE_TYPE = TOKEN_SECURITY_ATTRIBUTE_TYPE(1);
pub const TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64: TOKEN_SECURITY_ATTRIBUTE_TYPE = TOKEN_SECURITY_ATTRIBUTE_TYPE(2);
pub const TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING: TOKEN_SECURITY_ATTRIBUTE_TYPE = TOKEN_SECURITY_ATTRIBUTE_TYPE(3);
pub const TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN: TOKEN_SECURITY_ATTRIBUTE_TYPE = TOKEN_SECURITY_ATTRIBUTE_TYPE(4);
pub const TOKEN_SECURITY_ATTRIBUTE_TYPE_SID: TOKEN_SECURITY_ATTRIBUTE_TYPE = TOKEN_SECURITY_ATTRIBUTE_TYPE(5);
pub const TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN: TOKEN_SECURITY_ATTRIBUTE_TYPE = TOKEN_SECURITY_ATTRIBUTE_TYPE(6);
pub const TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING: TOKEN_SECURITY_ATTRIBUTE_TYPE = TOKEN_SECURITY_ATTRIBUTE_TYPE(16);

/// Based on https://github.com/winsiderss/systeminformer/blob/7ad69bf13d31892a89be7230bdbd47ffde024a2b/phnt/include/ntseapi.h#L176.
/// It is a `u32` because of its usage in `TOKEN_SECURITY_ATTRIBUTE_V1`.
#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
pub struct TOKEN_SECURITY_ATTRIBUTE_FLAG(pub u32);

pub const TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE: TOKEN_SECURITY_ATTRIBUTE_FLAG = TOKEN_SECURITY_ATTRIBUTE_FLAG(1);
pub const TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE: TOKEN_SECURITY_ATTRIBUTE_FLAG =
    TOKEN_SECURITY_ATTRIBUTE_FLAG(2);
pub const TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY: TOKEN_SECURITY_ATTRIBUTE_FLAG = TOKEN_SECURITY_ATTRIBUTE_FLAG(4);
pub const TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT: TOKEN_SECURITY_ATTRIBUTE_FLAG =
    TOKEN_SECURITY_ATTRIBUTE_FLAG(8);
pub const TOKEN_SECURITY_ATTRIBUTE_DISABLED: TOKEN_SECURITY_ATTRIBUTE_FLAG = TOKEN_SECURITY_ATTRIBUTE_FLAG(16);
pub const TOKEN_SECURITY_ATTRIBUTE_MANDATORY: TOKEN_SECURITY_ATTRIBUTE_FLAG = TOKEN_SECURITY_ATTRIBUTE_FLAG(32);
pub const TOKEN_SECURITY_ATTRIBUTE_COMPARE_IGNORE: TOKEN_SECURITY_ATTRIBUTE_FLAG = TOKEN_SECURITY_ATTRIBUTE_FLAG(64);

/// Based on https://github.com/winsiderss/systeminformer/blob/7ad69bf13d31892a89be7230bdbd47ffde024a2b/phnt/include/ntseapi.h#L197.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE {
    pub Version: u64,
    pub Name: UNICODE_STRING,
}

/// Based on https://github.com/winsiderss/systeminformer/blob/7ad69bf13d31892a89be7230bdbd47ffde024a2b/phnt/include/ntseapi.h#L204.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
    pub pValue: *const u8,
    pub ValueLength: u32,
}

/// Based on https://github.com/winsiderss/systeminformer/blob/7ad69bf13d31892a89be7230bdbd47ffde024a2b/phnt/include/ntseapi.h#L211.
#[repr(C)]
#[derive(Clone, Copy)]
pub union TOKEN_SECURITY_ATTRIBUTE_V1_VALUE {
    pub pGeneric: *const c_void,
    pub pInt64: *const i64,
    pub pUint64: *const u64,
    pub pString: *const UNICODE_STRING,
    pub pFqbn: *const TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE,
    pub pOctetString: *const TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE,
}

// Based on https://github.com/winsiderss/systeminformer/blob/7ad69bf13d31892a89be7230bdbd47ffde024a2b/phnt/include/ntseapi.h#L211.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TOKEN_SECURITY_ATTRIBUTE_V1 {
    pub Name: UNICODE_STRING,
    pub ValueType: TOKEN_SECURITY_ATTRIBUTE_TYPE,
    pub Reserved: u16,
    pub Flags: TOKEN_SECURITY_ATTRIBUTE_FLAG,
    pub ValueCount: u32,
    pub Values: TOKEN_SECURITY_ATTRIBUTE_V1_VALUE,
}

/// Based on https://github.com/winsiderss/systeminformer/blob/7ad69bf13d31892a89be7230bdbd47ffde024a2b/phnt/include/ntseapi.h#L229.
pub const TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1: u16 = 1;

/// Based on https://github.com/winsiderss/systeminformer/blob/7ad69bf13d31892a89be7230bdbd47ffde024a2b/phnt/include/ntseapi.h#L231.
pub const TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION: u16 = TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1;

/// Based on https://github.com/winsiderss/systeminformer/blob/7ad69bf13d31892a89be7230bdbd47ffde024a2b/phnt/include/ntseapi.h#L234.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TOKEN_SECURITY_ATTRIBUTES_INFORMATION {
    pub Version: u16,
    pub Reserved: u16,
    pub AttributeCount: u32,
    pub pAttributeV1: *const TOKEN_SECURITY_ATTRIBUTE_V1,
}

#[repr(C)]
pub enum TOKEN_SECURITY_ATTRIBUTE_OPERATION {
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_NONE,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_ADD,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_DELETE,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE,
}

pub struct TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION {
    pub Attributes: *const TOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    pub Operations: *const TOKEN_SECURITY_ATTRIBUTE_OPERATION,
}
