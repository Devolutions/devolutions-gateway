use std::{
    collections::HashMap,
    ffi::{c_void, CString, OsStr, OsString},
    fmt::{self, Debug},
    fs::File,
    hash::Hash,
    io::{Read, Write},
    mem::{self, MaybeUninit},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, BorrowedHandle, IntoRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr, slice,
    str::FromStr,
    sync::OnceLock,
};

use anyhow::{anyhow, bail, Result};

use crate::{
    error::Error,
    undoc::{
        LogonUserExExW, LsaManageSidNameMapping, LsaSidNameMappingOperation_Add, NtCreateToken,
        NtQueryInformationProcess, ProcessBasicInformation, RtlCreateVirtualAccountSid,
        LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT, LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT, OBJECT_ATTRIBUTES,
        RTL_USER_PROCESS_PARAMETERS, SECURITY_MAX_SID_SIZE,
    },
};
use windows::{
    core::{Interface, HRESULT, PCSTR, PWSTR},
    Win32::{
        Foundation::{
            DuplicateHandle, FreeLibrary, LocalFree, CRYPT_E_BAD_MSG, DUPLICATE_SAME_ACCESS, ERROR_ALREADY_EXISTS,
            ERROR_INCORRECT_SIZE, ERROR_INVALID_SID, ERROR_INVALID_VARIANT, ERROR_NO_TOKEN, ERROR_SUCCESS, HLOCAL,
            HWND, INVALID_HANDLE_VALUE, LUID, NTE_BAD_ALGID, S_OK, TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST,
            TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, UNICODE_STRING, WAIT_EVENT, WAIT_FAILED,
        },
        NetworkManagement::NetManagement::{
            NERR_Success, NERR_UserNotFound, NetApiBufferFree, NetUserGetInfo, USER_INFO_4,
        },
        Security::{
            AddAce, AdjustTokenPrivileges,
            Authentication::Identity::{GetUserNameExW, LsaFreeMemory, NameSamCompatible, EXTENDED_NAME_FORMAT},
            Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW, SetNamedSecurityInfoW, SE_OBJECT_TYPE},
            CreateWellKnownSid,
            Cryptography::{
                Catalog::{
                    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
                    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
                    CryptCATCatalogInfoFromContext, CATALOG_INFO,
                },
                CertGetEnhancedKeyUsage, CertNameToStrW, BCRYPT_SHA256_ALGORITHM, CERT_CONTEXT, CERT_EXTENSION,
                CERT_INFO, CERT_QUERY_ENCODING_TYPE, CERT_SIMPLE_NAME_STR, CERT_STRING_TYPE, CERT_V1, CERT_V2, CERT_V3,
                CMSG_SIGNER_INFO, CRYPT_ATTRIBUTE, CRYPT_INTEGER_BLOB, CTL_USAGE, PKCS_7_ASN_ENCODING,
                X509_ASN_ENCODING,
            },
            GetAce, GetLengthSid, GetSidSubAuthority, InitializeAcl, IsValidSid, LookupAccountSidW,
            LookupPrivilegeValueW, SecurityIdentification, SecurityImpersonation, SetTokenInformation,
            TokenElevationTypeDefault, TokenElevationTypeFull, TokenElevationTypeLimited, TokenPrimary,
            WinTrust::{
                WTHelperProvDataFromStateData, WinVerifyTrustEx, CRYPT_PROVIDER_CERT, CRYPT_PROVIDER_DATA,
                CRYPT_PROVIDER_SGNR, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
                WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
                WTD_DISABLE_MD2_MD4, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
                WTD_USE_DEFAULT_OSVER_CHECK,
            },
            ACE_FLAGS, ACE_HEADER, ACE_REVISION, ACL, ACL_REVISION, DACL_SECURITY_INFORMATION,
            GROUP_SECURITY_INFORMATION, LOGON32_LOGON, LOGON32_PROVIDER, LUID_AND_ATTRIBUTES,
            OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PROTECTED_SACL_SECURITY_INFORMATION, PSID, SACL_SECURITY_INFORMATION, SECURITY_DESCRIPTOR,
            SECURITY_DESCRIPTOR_CONTROL, SECURITY_DYNAMIC_TRACKING, SECURITY_NT_AUTHORITY, SECURITY_QUALITY_OF_SERVICE,
            SE_ASSIGNPRIMARYTOKEN_NAME, SE_BACKUP_NAME, SE_CHANGE_NOTIFY_NAME, SE_CREATE_GLOBAL_NAME,
            SE_CREATE_PAGEFILE_NAME, SE_CREATE_SYMBOLIC_LINK_NAME, SE_CREATE_TOKEN_NAME, SE_DACL_AUTO_INHERITED,
            SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_DEBUG_NAME,
            SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, SE_IMPERSONATE_NAME, SE_INCREASE_QUOTA_NAME,
            SE_INC_BASE_PRIORITY_NAME, SE_INC_WORKING_SET_NAME, SE_LOAD_DRIVER_NAME, SE_MANAGE_VOLUME_NAME,
            SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SE_PROF_SINGLE_PROCESS_NAME,
            SE_REMOTE_SHUTDOWN_NAME, SE_RESTORE_NAME, SE_SACL_AUTO_INHERITED, SE_SACL_DEFAULTED, SE_SACL_PRESENT,
            SE_SACL_PROTECTED, SE_SECURITY_NAME, SE_SHUTDOWN_NAME, SE_SYSTEMTIME_NAME, SE_SYSTEM_ENVIRONMENT_NAME,
            SE_SYSTEM_PROFILE_NAME, SE_TAKE_OWNERSHIP_NAME, SE_TIME_ZONE_NAME, SE_UNDOCK_NAME, SID, SID_AND_ATTRIBUTES,
            SID_IDENTIFIER_AUTHORITY, SID_NAME_USE, TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL, TOKEN_ELEVATION_TYPE,
            TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_POLICY, TOKEN_MANDATORY_POLICY_ID, TOKEN_OWNER,
            TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_SOURCE, TOKEN_STATISTICS,
            TOKEN_USER, UNPROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_SACL_SECURITY_INFORMATION,
            WELL_KNOWN_SID_TYPE,
        },
        Storage::FileSystem::{CreateDirectoryW, FlushFileBuffers, ReadFile, WriteFile},
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
                COINIT_MULTITHREADED, STGM_READ,
            },
            Diagnostics::{
                Debug::ReadProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32First, Process32Next, CREATE_TOOLHELP_SNAPSHOT_FLAGS,
                    PROCESSENTRY32, TH32CS_SNAPPROCESS,
                },
            },
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            GroupPolicy::PI_NOUI,
            LibraryLoader::{
                GetModuleFileNameW, GetModuleHandleA, GetModuleHandleExW, GetProcAddress,
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            },
            Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS},
            Pipes::{CreatePipe, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient, PeekNamedPipe},
            SystemServices::{ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION},
            Threading::{
                CreateProcessAsUserW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
                InitializeProcThreadAttributeList, OpenProcessToken, QueryFullProcessImageNameW, SetThreadToken,
                UpdateProcThreadAttribute, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
                LPPROC_THREAD_ATTRIBUTE_LIST, PEB, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, STARTUPINFOEXW, STARTUPINFOW,
                STARTUPINFOW_FLAGS, THREAD_ACCESS_RIGHTS,
            },
        },
        UI::{
            Controls::INFOTIPSIZE,
            Shell::{
                CommandLineToArgvW, CreateProfile, IShellLinkW, LoadUserProfileW, ShellLink, PROFILEINFOW,
                SLGP_SHORTPATH, SLR_NO_UI,
            },
        },
    },
};
use windows::{
    core::{PCWSTR, PSTR},
    Win32::{
        Foundation::{CloseHandle, E_HANDLE, E_INVALIDARG, E_POINTER, HANDLE, HMODULE, MAX_PATH, WAIT_OBJECT_0},
        Security::{
            AdjustTokenGroups, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser, RevertToSelf,
            SECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_ACCESS_MASK, TOKEN_TYPE,
        },
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE},
            Threading::{
                CreateRemoteThread, GetCurrentThread, OpenProcess, OpenThread, OpenThreadToken, ResumeThread,
                SuspendThread, WaitForSingleObject, INFINITE, LPTHREAD_START_ROUTINE, PROCESS_ACCESS_RIGHTS,
                PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_WIN32,
            },
        },
    },
};

#[derive(Debug, Clone)]
pub struct Handle {
    raw: HANDLE,
    owned: bool,
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    pub fn new(handle: HANDLE, owned: bool) -> Self {
        Self { raw: handle, owned }
    }

    pub fn raw(&self) -> HANDLE {
        self.raw
    }

    pub fn as_raw_ref(&self) -> &HANDLE {
        &self.raw
    }

    pub fn leak(&mut self) {
        self.owned = false;
    }

    fn try_clone(&self) -> Result<Self> {
        let current_process = unsafe { GetCurrentProcess() };
        let mut duplicated = HANDLE::default();

        unsafe {
            DuplicateHandle(
                current_process,
                self.raw(),
                current_process,
                &mut duplicated,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )?;
        }

        Ok(duplicated.into())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.owned {
            let _ = unsafe { CloseHandle(self.raw) };
        }
    }
}

impl From<HANDLE> for Handle {
    fn from(value: HANDLE) -> Self {
        Self::new(value, true)
    }
}

impl TryFrom<&BorrowedHandle<'_>> for Handle {
    type Error = anyhow::Error;

    fn try_from(value: &BorrowedHandle) -> Result<Self, Self::Error> {
        let handle = Handle {
            raw: HANDLE(value.as_raw_handle() as _),
            owned: false,
        };

        Ok(Self::try_clone(&handle)?)
    }
}

impl TryFrom<BorrowedHandle<'_>> for Handle {
    type Error = anyhow::Error;

    fn try_from(value: BorrowedHandle) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl From<OwnedHandle> for Handle {
    fn from(handle: OwnedHandle) -> Self {
        Self::from(HANDLE(handle.into_raw_handle() as _))
    }
}

pub struct Allocation<'a> {
    pub address: *mut c_void,
    pub process: &'a Process,
}

impl<'a> Allocation<'a> {
    pub fn try_new(process: &'a Process, size: usize) -> Result<Self> {
        let address = unsafe {
            VirtualAllocEx(
                process.handle.raw(),
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if address.is_null() {
            bail!(Error::last_error());
        }

        Ok(Allocation { address, process })
    }
}

impl<'a> Drop for Allocation<'a> {
    fn drop(&mut self) {
        let _ = unsafe { VirtualFreeEx(self.process.handle.raw(), self.address, 0, MEM_RELEASE) };
    }
}

#[derive(Debug)]
pub struct Process {
    pub handle: Handle,
}

impl Process {
    pub fn try_get_by_pid(pid: u32, desired_access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
        let handle = unsafe { OpenProcess(desired_access, false, pid) }?;

        Ok(Self { handle: handle.into() })
    }

    pub fn try_with_handle(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() {
            bail!(Error::from_hresult(E_HANDLE))
        } else {
            Ok(Self { handle: handle.into() })
        }
    }

    pub fn exe_path(&self) -> Result<PathBuf> {
        let mut path = Vec::with_capacity(MAX_PATH as _);

        let mut status;
        let mut length;
        loop {
            length = path.capacity() as u32;
            status = unsafe {
                QueryFullProcessImageNameW(
                    self.handle.raw(),
                    PROCESS_NAME_WIN32,
                    windows::core::PWSTR(path.as_mut_ptr()),
                    &mut length,
                )
            };

            if status.is_ok() || path.capacity() > u16::MAX as _ {
                break;
            }

            path.reserve(path.capacity());
        }

        status?;

        path.shrink_to(length as _);
        unsafe { path.set_len(path.capacity()) };

        Ok(OsString::from_wide(&path).into())
    }

    pub fn inject_dll(&self, path: &Path) -> Result<()> {
        let path = unsafe { CString::from_vec_unchecked(path.as_os_str().as_encoded_bytes().to_vec()) };
        let path_bytes = path.to_bytes_with_nul();

        let allocation = self.allocate(path_bytes.len())?;

        self.write_memory(path_bytes, allocation.address)?;

        let load_library =
            unsafe { module_symbol::<unsafe extern "system" fn(PCSTR) -> HMODULE>("kernel32.dll", "LoadLibraryA") }?;

        let thread = self.create_thread(Some(unsafe { mem::transmute(load_library) }), Some(allocation.address))?;

        thread.join()?;

        Ok(())
    }

    pub fn create_thread(
        &self,
        start_address: LPTHREAD_START_ROUTINE,
        parameter: Option<*const c_void>,
    ) -> Result<Thread> {
        let mut thread_id: u32 = 0;
        let handle = unsafe {
            CreateRemoteThread(
                self.handle.raw(),
                None,
                0,
                start_address,
                parameter,
                0,
                Some(&mut thread_id),
            )
        };

        Thread::try_with_handle(handle?)
    }

    pub fn allocate(&self, size: usize) -> Result<Allocation> {
        Allocation::try_new(self, size)
    }

    pub fn write_memory(&self, data: &[u8], address: *mut c_void) -> Result<()> {
        unsafe { WriteProcessMemory(self.handle.raw(), address, data.as_ptr() as _, data.len(), None) }?;

        Ok(())
    }

    pub fn current_process() -> Self {
        Self {
            handle: Handle::new(unsafe { GetCurrentProcess() }, false),
        }
    }

    pub fn token(&self, desired_access: TOKEN_ACCESS_MASK) -> Result<Token> {
        let mut handle = Default::default();

        unsafe { OpenProcessToken(self.handle.raw(), desired_access, &mut handle) }?;

        Token::try_with_handle(handle)
    }

    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<WAIT_EVENT> {
        let status = unsafe { WaitForSingleObject(self.handle.raw(), timeout_ms.unwrap_or(INFINITE)) };

        match status {
            WAIT_FAILED => bail!(Error::last_error()),
            w => Ok(w),
        }
    }

    pub fn exit_code(&self) -> Result<u32> {
        let mut exit_code = 0u32;
        unsafe { GetExitCodeProcess(self.handle.raw(), &mut exit_code) }?;

        Ok(exit_code)
    }

    pub fn query_basic_information(&self) -> Result<PROCESS_BASIC_INFORMATION> {
        let mut basic_info = PROCESS_BASIC_INFORMATION::default();
        unsafe {
            NtQueryInformationProcess(
                self.handle.raw(),
                ProcessBasicInformation,
                &mut basic_info as *mut _ as _,
                mem::size_of_val(&basic_info) as _,
                None,
            )?;
        }

        Ok(basic_info)
    }

    pub fn peb(&self) -> Result<Peb> {
        let basic_info = self.query_basic_information()?;

        Ok(Peb {
            process: self,
            address: basic_info.PebBaseAddress as _,
        })
    }

    pub fn read_memory(&self, address: usize, data: &mut [u8]) -> Result<usize> {
        let mut bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                self.handle.raw(),
                address as _,
                data.as_mut_ptr() as _,
                data.len(),
                Some(&mut bytes_read),
            )?;
        }

        Ok(bytes_read)
    }

    pub unsafe fn read_struct<T: Sized>(&self, address: usize) -> Result<T> {
        let mut buf = vec![0; mem::size_of::<T>()];

        let read = self.read_memory(address, buf.as_mut_slice())?;

        if buf.len() == read {
            Ok(buf.as_ptr().cast::<T>().read())
        } else {
            bail!(Error::from_win32(ERROR_INCORRECT_SIZE))
        }
    }

    pub unsafe fn read_array<T: Sized>(&self, count: usize, address: usize) -> Result<Vec<T>> {
        let mut buf = Vec::with_capacity(count);

        let read_bytes = self.read_memory(
            address,
            slice::from_raw_parts_mut(buf.as_mut_ptr() as _, buf.capacity() * mem::size_of::<T>()),
        )?;

        if count * mem::size_of::<T>() == read_bytes {
            buf.set_len(count);

            Ok(buf)
        } else {
            bail!(Error::from_win32(ERROR_INCORRECT_SIZE))
        }
    }
}

#[derive(Debug)]
pub struct Thread {
    pub handle: Handle,
}

impl Thread {
    pub fn try_with_handle(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() {
            bail!(Error::from_hresult(E_HANDLE))
        } else {
            Ok(Self { handle: handle.into() })
        }
    }

    pub fn try_get_by_id(id: u32, desired_access: THREAD_ACCESS_RIGHTS) -> Result<Self> {
        let handle = unsafe { OpenThread(desired_access, false, id) }?;

        Self::try_with_handle(handle)
    }

    pub fn current() -> Self {
        Self {
            handle: Handle::new(unsafe { GetCurrentThread() }, false),
        }
    }

    pub fn join(&self) -> Result<()> {
        let result = unsafe { WaitForSingleObject(self.handle.raw(), INFINITE) };
        match result {
            WAIT_OBJECT_0 => Ok(()),
            _ => bail!(Error::last_error()),
        }
    }

    pub fn suspend(&self) -> Result<()> {
        if unsafe { SuspendThread(self.handle.raw()) } == u32::MAX {
            bail!(Error::last_error())
        } else {
            Ok(())
        }
    }

    pub fn resume(&self) -> Result<()> {
        if unsafe { ResumeThread(self.handle.raw()) } == u32::MAX {
            bail!(Error::last_error())
        } else {
            Ok(())
        }
    }

    pub fn token(&self, desired_access: TOKEN_ACCESS_MASK, open_as_self: bool) -> Result<Token> {
        let mut handle = Default::default();

        unsafe { OpenThreadToken(self.handle.raw(), desired_access, open_as_self, &mut handle) }?;

        Token::try_with_handle(handle)
    }

    pub fn set_token(&self, token: &Token) -> Result<()> {
        unsafe {
            Ok(SetThreadToken(
                if self.handle.raw() == Thread::current().handle.raw() {
                    None
                } else {
                    Some(&self.handle.raw())
                },
                token.handle.raw(),
            )?)
        }
    }
}

#[derive(Debug)]
pub struct Token {
    handle: Handle,
}

impl Token {
    pub fn try_with_handle(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() {
            bail!(Error::from_hresult(E_HANDLE))
        } else {
            Ok(Self { handle: handle.into() })
        }
    }

    pub fn current_process_token() -> Self {
        Self {
            handle: Handle::new(HANDLE(-4 as _), false),
        }
    }
    pub fn create_token(
        authentication_id: &LUID,
        expiration_time: i64,
        user: &SidAndAttributes,
        groups: &TokenGroups,
        privileges: &TokenPrivileges,
        owner: &Sid,
        primary_group: &Sid,
        default_dacl: Option<&Acl>,
        source: &TOKEN_SOURCE,
    ) -> Result<Self> {
        // See https://github.com/decoder-it/CreateTokenExample/blob/master/StopZillaCreateToken.cpp#L344
        let sqos = SECURITY_QUALITY_OF_SERVICE {
            Length: mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as _,
            ImpersonationLevel: SecurityImpersonation,
            ContextTrackingMode: SECURITY_DYNAMIC_TRACKING.0,
            EffectiveOnly: false.into(),
        };

        let object_attributes = OBJECT_ATTRIBUTES {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as _,
            SecurityQualityOfService: &sqos as *const _ as _,
            ..Default::default()
        };

        let default_dacl = default_dacl.map(Acl::to_raw).transpose()?;
        let owner_sid = RawSid::from(owner);
        let groups = RawTokenGroups::from(groups);
        let privileges = RawTokenPrivileges::from(privileges);
        let primary_group = RawSid::from(primary_group);
        let user = RawSidAndAttributes::from(user);

        let mut priv_token = find_token_with_privilege(lookup_privilege_value(None, SE_CREATE_TOKEN_NAME)?)?
            .ok_or(Error::from_win32(ERROR_NO_TOKEN))?
            .duplicate_impersonation()?;

        priv_token.adjust_privileges(&TokenPrivilegesAdjustment::Enable(vec![
            lookup_privilege_value(None, SE_CREATE_TOKEN_NAME)?,
            lookup_privilege_value(None, SE_ASSIGNPRIMARYTOKEN_NAME)?,
        ]))?;

        let mut handle = HANDLE::default();
        priv_token.impersonate(|| unsafe {
            Ok(NtCreateToken(
                &mut handle,
                TOKEN_ALL_ACCESS,
                &object_attributes,
                TokenPrimary,
                authentication_id,
                &expiration_time,
                &TOKEN_USER { User: *user.as_raw() },
                groups.as_raw(),
                privileges.as_raw(),
                &TOKEN_OWNER {
                    Owner: PSID(owner_sid.as_raw() as *const _ as _),
                },
                &TOKEN_PRIMARY_GROUP {
                    PrimaryGroup: PSID(primary_group.as_raw() as *const _ as _),
                },
                &TOKEN_DEFAULT_DACL {
                    DefaultDacl: default_dacl
                        .as_ref()
                        .map(|x| x.as_ptr().cast_mut().cast())
                        .unwrap_or(ptr::null_mut()),
                },
                source,
            )?)
        })?;

        Ok(Self { handle: handle.into() })
    }

    pub fn duplicate(
        &self,
        desired_access: TOKEN_ACCESS_MASK,
        attributes: Option<&SECURITY_ATTRIBUTES>,
        impersonation_level: SECURITY_IMPERSONATION_LEVEL,
        token_type: TOKEN_TYPE,
    ) -> Result<Self> {
        let mut handle = Default::default();
        unsafe {
            DuplicateTokenEx(
                self.handle.raw(),
                desired_access,
                attributes.and_then(|x| Some(x as _)),
                impersonation_level,
                token_type,
                &mut handle,
            )
        }?;

        Self::try_with_handle(handle)
    }

    pub fn duplicate_impersonation(&self) -> Result<Self> {
        self.duplicate(TOKEN_ACCESS_MASK(0), None, SecurityImpersonation, TokenPrimary)
    }

    pub fn impersonate<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        unsafe { ImpersonateLoggedOnUser(self.handle.raw()) }?;

        let r = f();

        unsafe { RevertToSelf() }?;

        r
    }

    pub fn reset(&mut self) -> Result<()> {
        unsafe { AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None) }?;
        Ok(())
    }

    pub fn reset_groups(&mut self) -> Result<()> {
        unsafe { AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None) }?;
        Ok(())
    }

    fn information_var_size<S, D: for<'a> TryFrom<&'a S>>(&self, info_class: TOKEN_INFORMATION_CLASS) -> Result<D>
    where
        anyhow::Error: for<'a> From<<D as TryFrom<&'a S>>::Error>,
    {
        let mut required_size = 0u32;
        let _ = unsafe { GetTokenInformation(self.handle.raw(), info_class, None, 0, &mut required_size as _) };

        let mut buf: Vec<u8> = Vec::with_capacity(required_size as _);

        unsafe {
            GetTokenInformation(
                self.handle.raw(),
                info_class,
                Some(buf.as_mut_ptr() as _),
                buf.capacity() as _,
                &mut required_size as _,
            )
        }?;

        let raw_groups = unsafe { buf.as_ptr().cast::<S>().as_ref() };

        Ok(raw_groups.ok_or_else(|| Error::from_hresult(E_POINTER))?.try_into()?)
    }

    fn information_raw<T: Default + Sized>(&self, info_class: TOKEN_INFORMATION_CLASS) -> Result<T> {
        let mut info = T::default();
        let mut return_length = 0u32;

        unsafe {
            GetTokenInformation(
                self.handle.raw(),
                info_class,
                Some(&mut info as *mut _ as _),
                mem::size_of::<T>() as _,
                &mut return_length as _,
            )
        }?;

        Ok(info)
    }

    fn set_information_raw<T: Sized>(&self, info_class: TOKEN_INFORMATION_CLASS, value: &T) -> Result<()> {
        unsafe {
            SetTokenInformation(
                self.handle.raw(),
                info_class,
                value as *const _ as _,
                mem::size_of::<T>() as _,
            )?;
        }

        Ok(())
    }

    pub fn groups(&self) -> Result<TokenGroups> {
        self.information_var_size::<TOKEN_GROUPS, TokenGroups>(windows::Win32::Security::TokenGroups)
    }

    pub fn privileges(&self) -> Result<TokenPrivileges> {
        self.information_var_size::<TOKEN_PRIVILEGES, TokenPrivileges>(windows::Win32::Security::TokenPrivileges)
    }

    pub fn elevation_type(&self) -> Result<TokenElevationType> {
        self.information_raw::<TOKEN_ELEVATION_TYPE>(windows::Win32::Security::TokenElevationType)?
            .try_into()
    }

    pub fn is_elevated(&self) -> Result<bool> {
        Ok(self.information_raw::<i32>(windows::Win32::Security::TokenElevation)? != 0)
    }

    pub fn linked_token(&self) -> Result<Self> {
        Self::try_with_handle(self.information_raw::<HANDLE>(windows::Win32::Security::TokenLinkedToken)?)
    }

    pub fn username(&self, format: EXTENDED_NAME_FORMAT) -> Result<String> {
        let mut username = String::new();
        self.impersonate(|| {
            username = get_username(format)?;
            Ok(())
        })?;

        Ok(username)
    }

    pub fn logon(
        username: &str,
        domain: Option<&str>,
        password: Option<&str>,
        logon_type: LOGON32_LOGON,
        logon_provider: LOGON32_PROVIDER,
        groups: Option<&TokenGroups>,
    ) -> Result<Self> {
        let mut raw_token = HANDLE::default();

        let raw_groups = groups.map(RawTokenGroups::from);

        unsafe {
            LogonUserExExW(
                WideString::from(username).as_pcwstr(),
                domain.map(WideString::from).unwrap_or_default().as_pcwstr(),
                password.map(WideString::from).unwrap_or_default().as_pcwstr(),
                logon_type,
                logon_provider,
                raw_groups.as_ref().map(|x| x.as_raw() as _),
                Some(&mut raw_token as _),
                None,
                None,
                None,
                None,
            )?;
        }

        Token::try_with_handle(raw_token)
    }

    pub fn statistics(&self) -> Result<TOKEN_STATISTICS> {
        Ok(self.information_raw::<TOKEN_STATISTICS>(windows::Win32::Security::TokenStatistics)?)
    }

    pub fn sid_and_attributes(&self) -> Result<SidAndAttributes> {
        Ok(self
            .information_var_size::<TOKEN_USER, TokenUser>(windows::Win32::Security::TokenUser)?
            .user)
    }

    pub fn session_id(&self) -> Result<u32> {
        Ok(self.information_raw::<u32>(windows::Win32::Security::TokenSessionId)?)
    }

    pub fn set_session_id(&mut self, session_id: u32) -> Result<()> {
        self.set_information_raw(windows::Win32::Security::TokenSessionId, &session_id)
    }

    pub fn mandatory_policy(&self) -> Result<TOKEN_MANDATORY_POLICY_ID> {
        Ok(self
            .information_raw::<TOKEN_MANDATORY_POLICY>(windows::Win32::Security::TokenMandatoryPolicy)?
            .Policy)
    }

    pub fn set_mandatory_policy(&mut self, mandatory_policy: TOKEN_MANDATORY_POLICY_ID) -> Result<()> {
        self.set_information_raw(
            windows::Win32::Security::TokenMandatoryPolicy,
            &TOKEN_MANDATORY_POLICY {
                Policy: mandatory_policy,
            },
        )
    }

    pub fn load_profile(&self, username: &str) -> Result<ProfileInfo> {
        if let Err(err) = create_profile(&self.sid_and_attributes()?.sid, username) {
            match err.downcast::<windows::core::Error>() {
                Ok(err) => {
                    if err.code() != ERROR_ALREADY_EXISTS.to_hresult() {
                        bail!(err);
                    }
                }
                Err(err) => bail!(err),
            };
        }

        ProfileInfo::from_token(self, username)
    }

    pub fn adjust_groups(&mut self, adjustment: &TokenGroupAdjustment) -> Result<()> {
        match adjustment {
            TokenGroupAdjustment::ResetToDefaults => unsafe {
                AdjustTokenGroups(self.handle.raw(), true, None, 0, None, None)?;
            },
            TokenGroupAdjustment::Enable(groups) => {
                let raw_groups = RawTokenGroups::from(groups);
                unsafe {
                    AdjustTokenGroups(self.handle.raw(), false, Some(raw_groups.as_raw()), 0, None, None)?;
                }
            }
        }

        Ok(())
    }

    pub fn adjust_privileges(&mut self, adjustment: &TokenPrivilegesAdjustment) -> Result<()> {
        match adjustment {
            TokenPrivilegesAdjustment::DisableAllPrivileges => unsafe {
                AdjustTokenPrivileges(self.handle.raw(), true, None, 0, None, None)?;
            },
            TokenPrivilegesAdjustment::Enable(privs)
            | TokenPrivilegesAdjustment::Disable(privs)
            | TokenPrivilegesAdjustment::Remove(privs) => {
                let attr = match adjustment {
                    TokenPrivilegesAdjustment::Enable(_) => SE_PRIVILEGE_ENABLED,
                    TokenPrivilegesAdjustment::DisableAllPrivileges | TokenPrivilegesAdjustment::Disable(_) => {
                        TOKEN_PRIVILEGES_ATTRIBUTES(0)
                    }
                    TokenPrivilegesAdjustment::Remove(_) => SE_PRIVILEGE_REMOVED,
                };

                let privs = TokenPrivileges(
                    privs
                        .iter()
                        .map(|p| LUID_AND_ATTRIBUTES {
                            Luid: *p,
                            Attributes: attr,
                        })
                        .collect(),
                );

                let raw_privs = RawTokenPrivileges::from(&privs);

                unsafe {
                    AdjustTokenPrivileges(self.handle.raw(), false, Some(raw_privs.as_raw()), 0, None, None)?;
                }

                let last_err = Error::last_error();
                if last_err.code() != ERROR_SUCCESS.0 as _ {
                    bail!(last_err);
                }
            }
        }

        Ok(())
    }

    pub fn default_dacl(&self) -> Result<Option<Acl>> {
        Ok(self
            .information_var_size::<TOKEN_DEFAULT_DACL, TokenDefaultDacl>(windows::Win32::Security::TokenDefaultDacl)?
            .default_dacl)
    }

    pub fn primary_group(&self) -> Result<Sid> {
        Ok(self
            .information_var_size::<TOKEN_PRIMARY_GROUP, TokenPrimaryGroup>(
                windows::Win32::Security::TokenPrimaryGroup,
            )?
            .primary_group)
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            handle: self.handle.try_clone()?,
        })
    }
}

pub enum TokenGroupAdjustment {
    ResetToDefaults,
    Enable(TokenGroups),
}

pub enum TokenPrivilegesAdjustment {
    DisableAllPrivileges,
    Enable(Vec<LUID>),
    Disable(Vec<LUID>),
    Remove(Vec<LUID>),
}

pub unsafe fn module_symbol<T>(module: &str, symbol: &str) -> windows::core::Result<T> {
    let raw_module = CString::from_vec_unchecked(module.into());
    let module_handle = GetModuleHandleA(PCSTR::from_raw(raw_module.as_ptr() as _))?;

    let raw_symbol = CString::from_vec_unchecked(symbol.into());

    match GetProcAddress(module_handle, PCSTR::from_raw(raw_symbol.as_ptr() as _)) {
        Some(func) => Ok(mem::transmute_copy(&func)),
        None => Err(windows::core::Error::from_win32()),
    }
}

pub unsafe fn set_memory_protection(
    addr: *const (),
    size: usize,
    prot: PAGE_PROTECTION_FLAGS,
) -> Result<PAGE_PROTECTION_FLAGS> {
    let mut old_prot = Default::default();
    VirtualProtect(addr as _, size, prot, &mut old_prot)?;
    Ok(old_prot)
}

pub fn is_module_loaded(module: &str) -> bool {
    let raw_module = unsafe { CString::from_vec_unchecked(module.into()) };
    unsafe { GetModuleHandleA(PCSTR::from_raw(raw_module.as_ptr() as _)) }.is_ok()
}

pub fn serialize_environment(environment: &HashMap<String, String>) -> Result<Vec<u16>> {
    let mut serialized = Vec::new();

    for (k, v) in environment.iter() {
        if k.contains('=') {
            bail!(Error::from_hresult(E_INVALIDARG));
        }

        serialized.extend(k.encode_utf16());
        serialized.extend("=".encode_utf16());
        serialized.extend(v.encode_utf16());
        serialized.push(0);
    }

    serialized.push(0);

    Ok(serialized)
}

#[derive(Debug)]
pub struct ProcessInformation {
    pub process: Process,
    pub thread: Thread,
    pub process_id: u32,
    pub thread_id: u32,
}

pub fn create_process_as_user(
    token: Option<&Token>,
    application_name: Option<&Path>,
    command_line: Option<&str>,
    process_attributes: Option<&SecurityAttributes>,
    thread_attributes: Option<&SecurityAttributes>,
    inherit_handles: bool,
    creation_flags: PROCESS_CREATION_FLAGS,
    environment: Option<&HashMap<String, String>>,
    current_directory: Option<&Path>,
    startup_info: &mut StartupInfo,
) -> Result<ProcessInformation> {
    let application_name = application_name.map(WideString::from).unwrap_or_default();
    let current_directory = current_directory.map(WideString::from).unwrap_or_default();

    let environment = environment.map(serialize_environment).transpose()?;

    let mut command_line = command_line.map(WideString::from).unwrap_or_default();

    let mut creation_flags = creation_flags | CREATE_UNICODE_ENVIRONMENT;
    if startup_info.attribute_list.is_some() {
        creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    let mut raw_process_information = PROCESS_INFORMATION::default();

    let process_attributes = process_attributes.map(RawSecurityAttributes::try_from).transpose()?;
    let thread_attributes = thread_attributes.map(RawSecurityAttributes::try_from).transpose()?;

    unsafe {
        CreateProcessAsUserW(
            token.map(|x| x.handle.raw()).unwrap_or_default(),
            application_name.as_pcwstr(),
            command_line.as_pwstr(),
            process_attributes.as_ref().map(|x| x.raw() as _),
            thread_attributes.as_ref().map(|x| x.raw() as _),
            inherit_handles,
            creation_flags,
            environment.as_ref().map(|x| x.as_ptr() as _),
            current_directory.as_pcwstr(),
            &startup_info.as_raw().StartupInfo,
            &mut raw_process_information,
        )
    }?;

    Ok(ProcessInformation {
        process: Process::try_with_handle(raw_process_information.hProcess)?,
        thread: Thread::try_with_handle(raw_process_information.hThread)?,
        process_id: raw_process_information.dwProcessId,
        thread_id: raw_process_information.dwThreadId,
    })
}

pub fn environment_block(token: Option<&Token>, inherit: bool) -> Result<HashMap<String, String>> {
    let mut blocks = Vec::new();

    unsafe {
        let mut raw_blocks: *mut u16 = ptr::null_mut();

        CreateEnvironmentBlock(
            &mut raw_blocks as *mut _ as _,
            token.map(|x| x.handle.raw()).unwrap_or_default(),
            inherit,
        )?;

        let mut i = 0;
        while raw_blocks.add(i).read() != 0 {
            let mut block = Vec::new();

            loop {
                let cur_val = raw_blocks.add(i).read();
                i += 1;

                if cur_val == 0 {
                    break;
                }

                block.push(cur_val);
            }

            blocks.push(block);
        }

        DestroyEnvironmentBlock(raw_blocks as *mut _ as _)?;
    };

    let mut env_block = HashMap::new();

    for block in blocks.iter() {
        let block = String::from_utf16(block)?;

        let (k, v) = block.split_once('=').ok_or_else(|| Error::from_hresult(E_INVALIDARG))?;

        env_block.insert(k.to_owned(), v.to_owned());
    }

    Ok(env_block)
}

#[derive(Debug, Default)]
pub struct StartupInfo {
    pub reserved: WideString,
    pub desktop: WideString,
    pub title: WideString,
    pub x: u32,
    pub y: u32,
    pub x_size: u32,
    pub y_size: u32,
    pub x_count_chars: u32,
    pub y_count_chars: u32,
    pub fill_attribute: u32,
    pub flags: STARTUPINFOW_FLAGS,
    pub show_window: u16,
    pub reserved2: Option<Vec<u8>>,
    pub std_input: HANDLE,
    pub std_output: HANDLE,
    pub std_error: HANDLE,
    pub attribute_list: Option<Option<LPPROC_THREAD_ATTRIBUTE_LIST>>,
}

impl StartupInfo {
    pub unsafe fn as_raw(&mut self) -> STARTUPINFOEXW {
        STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: if self.attribute_list.is_some() {
                    mem::size_of::<STARTUPINFOEXW>()
                } else {
                    mem::size_of::<STARTUPINFOW>()
                } as _,
                lpReserved: self.reserved.as_pwstr(),
                lpDesktop: self.desktop.as_pwstr(),
                lpTitle: self.title.as_pwstr(),
                dwX: self.x,
                dwY: self.y,
                dwXSize: self.x_size,
                dwYSize: self.y_size,
                dwXCountChars: self.x_count_chars,
                dwYCountChars: self.y_count_chars,
                dwFillAttribute: self.fill_attribute,
                dwFlags: self.flags,
                wShowWindow: self.show_window,
                cbReserved2: self.reserved2.as_ref().map(|x| x.len()).unwrap_or(0) as _,
                lpReserved2: self
                    .reserved2
                    .as_ref()
                    .map(|x| x.as_ptr().cast_mut())
                    .unwrap_or(ptr::null_mut()),
                hStdInput: self.std_input,
                hStdOutput: self.std_output,
                hStdError: self.std_error,
            },
            lpAttributeList: self.attribute_list.unwrap_or_default().unwrap_or_default(),
        }
    }
}

pub trait SafeWindowsString {
    fn to_string_safe(&self) -> Result<String>;
    fn to_os_string_safe(&self) -> Result<OsString>;
    fn to_path_safe(&self) -> Result<PathBuf>;
}

macro_rules! impl_safe_win_string {
    ($t:ty) => {
        impl SafeWindowsString for $t {
            fn to_string_safe(&self) -> Result<String> {
                if self.is_null() {
                    bail!(Error::from_hresult(E_POINTER))
                } else {
                    unsafe { Ok(self.to_string()?) }
                }
            }

            fn to_os_string_safe(&self) -> Result<OsString> {
                self.to_string_safe().map(|s| s.into())
            }

            fn to_path_safe(&self) -> Result<PathBuf> {
                self.to_os_string_safe().map(|x| x.into())
            }
        }
    };
}

impl_safe_win_string!(PWSTR);
impl_safe_win_string!(PSTR);
impl_safe_win_string!(PCWSTR);
impl_safe_win_string!(PCSTR);

#[derive(Default)]
pub struct AnsiString(pub Option<Vec<u8>>);

impl AnsiString {
    pub fn as_pcstr(&self) -> PCSTR {
        self.0
            .as_ref()
            .map(|x| PCSTR::from_raw(x.as_ptr() as _))
            .unwrap_or_else(PCSTR::null)
    }

    pub fn as_pstr(&mut self) -> PSTR {
        self.0
            .as_ref()
            .map(|x| PSTR::from_raw(x.as_ptr() as _))
            .unwrap_or_else(PSTR::null)
    }
}

impl From<&str> for AnsiString {
    fn from(value: &str) -> Self {
        let mut buf = value.as_bytes().to_vec();
        buf.push(0);
        AnsiString(Some(buf))
    }
}

impl<T> From<Option<T>> for AnsiString
where
    T: for<'a> Into<&'a str>,
{
    fn from(value: Option<T>) -> Self {
        value.map(|x| AnsiString::from(x.into())).unwrap_or_default()
    }
}

#[derive(Default, Debug)]
pub struct WideString(pub Option<Vec<u16>>);

impl WideString {
    pub fn as_pcwstr(&self) -> PCWSTR {
        self.0
            .as_ref()
            .map(|x| PCWSTR::from_raw(x.as_ptr() as _))
            .unwrap_or_else(PCWSTR::null)
    }

    pub fn as_pwstr(&mut self) -> PWSTR {
        self.0
            .as_ref()
            .map(|x| PWSTR::from_raw(x.as_ptr() as _))
            .unwrap_or_else(PWSTR::null)
    }

    pub fn as_unicode_string(&self) -> UNICODE_STRING {
        UNICODE_STRING {
            Length: self
                .0
                .as_ref()
                .and_then(|x| x.split_last())
                .map(|x| mem::size_of_val(x.1))
                .unwrap_or(0) as _,
            MaximumLength: self.0.as_ref().map(|x| mem::size_of_val(x.as_slice())).unwrap_or(0) as _,
            Buffer: PWSTR(self.as_pcwstr().0.cast_mut()),
        }
    }
}

impl<T: ?Sized + AsRef<OsStr>> From<&T> for WideString {
    fn from(value: &T) -> Self {
        let mut buf = value.as_ref().encode_wide().collect::<Vec<_>>();
        buf.push(0);
        Self(Some(buf))
    }
}

impl FromStr for WideString {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let mut buf = s.encode_utf16().collect::<Vec<_>>();
        buf.push(0);
        Ok(Self(Some(buf)))
    }
}

impl From<String> for WideString {
    fn from(value: String) -> Self {
        Self::from(&value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sid {
    pub revision: u8,
    pub identifier_identity: SID_IDENTIFIER_AUTHORITY,
    pub sub_authority: Vec<u32>,
}

impl Hash for Sid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.revision.hash(state);
        self.identifier_identity.Value.hash(state);
        self.sub_authority.hash(state);
    }
}

impl Sid {
    pub fn virtual_account_sid(name: &str, base_sub_authority: u32) -> Result<Self> {
        let name = WideString::from(name);
        let mut buf: Vec<u8> = Vec::with_capacity(SECURITY_MAX_SID_SIZE as _);
        let mut out_size = buf.capacity() as u32;

        unsafe {
            RtlCreateVirtualAccountSid(
                &name.as_unicode_string(),
                base_sub_authority,
                PSID(buf.as_mut_ptr() as _),
                &mut out_size as _,
            )?;

            buf.set_len(out_size as _);
        }

        Ok(unsafe { &*buf.as_ptr().cast::<SID>() }.into())
    }

    pub fn from_well_known(sid_type: WELL_KNOWN_SID_TYPE, domain_sid: Option<&Self>) -> Result<Self> {
        let mut out_size = 0u32;

        let domain_sid = domain_sid.map(RawSid::from);

        let domain_sid_ptr = domain_sid.map(|x| x.as_raw() as *const _).unwrap_or_else(ptr::null);

        unsafe {
            let _ = CreateWellKnownSid(
                sid_type,
                PSID(domain_sid_ptr as _),
                PSID(ptr::null_mut()),
                &mut out_size as _,
            );
        }

        let mut buf: Vec<u8> = Vec::with_capacity(out_size as _);

        unsafe {
            CreateWellKnownSid(
                sid_type,
                PSID(domain_sid_ptr as _),
                PSID(buf.as_mut_ptr() as _),
                &mut out_size as _,
            )?;

            buf.set_len(out_size as _);
        }

        Ok(Self::from(unsafe { &*buf.as_ptr().cast::<SID>() }))
    }

    pub fn is_valid(&self) -> bool {
        RawSid::from(self).is_valid()
    }

    pub fn account(&self, system_name: Option<&str>) -> Result<Account> {
        let raw_sid = RawSid::from(self);
        let mut name_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_name_use = SID_NAME_USE::default();

        let mut account = Account::default();

        unsafe {
            let _ = LookupAccountSidW(
                system_name.map(WideString::from).unwrap_or_default().as_pcwstr(),
                PSID(raw_sid.as_raw() as *const _ as _),
                PWSTR::null(),
                &mut name_size,
                PWSTR::null(),
                &mut domain_size,
                &mut sid_name_use,
            );

            let mut name_buf = vec![0u16; name_size as _];
            let mut domain_buf = vec![0u16; domain_size as _];

            let name_buf_ptr = PWSTR::from_raw(name_buf.as_mut_ptr());
            let domain_buf_ptr = PWSTR::from_raw(domain_buf.as_mut_ptr());

            LookupAccountSidW(
                system_name.map(WideString::from).unwrap_or_default().as_pcwstr(),
                PSID(raw_sid.as_raw() as *const _ as _),
                name_buf_ptr,
                &mut name_size,
                domain_buf_ptr,
                &mut domain_size,
                &mut sid_name_use,
            )?;

            account.account_name = name_buf_ptr.to_string()?;
            account.domain_name = domain_buf_ptr.to_string()?;
        }

        account.account_sid = self.clone();
        account.domain_sid = self.clone();
        account.domain_sid.sub_authority.shrink_to(1);

        Ok(account)
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        RawSid::from(self).fmt(f)
    }
}

impl Default for Sid {
    fn default() -> Self {
        Self {
            revision: 1,
            identifier_identity: Default::default(),
            sub_authority: Default::default(),
        }
    }
}

pub struct RawSid(Vec<u8>);

impl RawSid {
    pub fn len(&self) -> usize {
        unsafe { GetLengthSid(PSID(self.as_raw() as *const _ as _)) as _ }
    }

    pub fn as_raw(&self) -> &SID {
        unsafe { &*self.0.as_ptr().cast::<SID>() }
    }

    pub fn is_valid(&self) -> bool {
        unsafe { IsValidSid(PSID(self.as_raw() as *const _ as _)) }.as_bool()
    }
}

impl fmt::Display for RawSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw_string_sid = PWSTR::null();
        unsafe {
            ConvertSidToStringSidW(PSID(self.as_raw() as *const _ as _), &mut raw_string_sid as _)
                .map_err(|_| fmt::Error)?;

            let res = (|| {
                f.write_str(&raw_string_sid.to_string_safe().map_err(|_| fmt::Error)?)?;
                Ok(())
            })();

            LocalFree(HLOCAL(raw_string_sid.0 as _));

            res
        }
    }
}

impl TryFrom<&str> for Sid {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = WideString::from(value);
        let mut sid_ptr = PSID::default();

        unsafe {
            ConvertStringSidToSidW(value.as_pcwstr(), &mut sid_ptr)?;
        }

        let sid = Self::from(unsafe {
            sid_ptr
                .0
                .cast::<SID>()
                .as_ref()
                .ok_or_else(|| Error::NullPointer("SID"))
        }?);

        unsafe {
            LocalFree(HLOCAL(sid_ptr.0));
        }

        Ok(sid)
    }
}

impl From<&Sid> for RawSid {
    fn from(value: &Sid) -> Self {
        let raw_sid_buf_size = mem::size_of::<SID>() // Size of the SID's header
            + (value.sub_authority.len() - 1) * mem::size_of::<u32>(); // Size of the SID's data part, minus the trailing VLA entry in the header
        let mut raw_sid_buf = vec![0u8; raw_sid_buf_size];

        let raw_sid = raw_sid_buf.as_mut_ptr().cast::<SID>();

        unsafe {
            ptr::addr_of_mut!((*raw_sid).IdentifierAuthority).write(value.identifier_identity);
            ptr::addr_of_mut!((*raw_sid).Revision).write(value.revision);
            ptr::addr_of_mut!((*raw_sid).SubAuthorityCount).write(value.sub_authority.len() as _);

            let sub_auth_ptr = ptr::addr_of_mut!((*raw_sid).SubAuthority).cast::<u32>();

            for (i, v) in value.sub_authority.iter().enumerate() {
                sub_auth_ptr.add(i).write(*v);
            }
        }

        Self(raw_sid_buf)
    }
}

impl TryFrom<PSID> for Sid {
    type Error = anyhow::Error;

    fn try_from(value: PSID) -> std::result::Result<Self, Self::Error> {
        let value = value.0.cast::<SID>();

        if value.is_null() {
            bail!(Error::from_hresult(E_POINTER));
        }

        Ok(Self::from(unsafe { &*value }))
    }
}

impl From<&SID> for Sid {
    fn from(sid: &SID) -> Self {
        let mut sub_authority = Vec::new();
        for i in 0..sid.SubAuthorityCount {
            unsafe {
                // Use just in case structure changes in the future
                let ptr = GetSidSubAuthority(PSID(sid as *const _ as _), i as _);

                // Doc says pointer is undefined if range is OOB.
                sub_authority.push(ptr.read());
            }
        }

        Self {
            revision: sid.Revision,
            identifier_identity: sid.IdentifierAuthority,
            sub_authority,
        }
    }
}

pub struct TokenUser {
    pub user: SidAndAttributes,
}

impl TryFrom<&TOKEN_USER> for TokenUser {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_USER) -> Result<Self, Self::Error> {
        Ok(Self {
            user: SidAndAttributes::try_from(&value.User)?,
        })
    }
}

pub struct SidAndAttributes {
    pub sid: Sid,
    pub attributes: u32,
}

pub struct RawSidAndAttributes {
    _sid: RawSid,
    raw: SID_AND_ATTRIBUTES,
}

impl RawSidAndAttributes {
    pub fn as_raw(&self) -> &SID_AND_ATTRIBUTES {
        &self.raw
    }
}

impl From<&SidAndAttributes> for RawSidAndAttributes {
    fn from(value: &SidAndAttributes) -> Self {
        let raw_sid = RawSid::from(&value.sid);

        let raw_sid_ptr = raw_sid.as_raw() as *const _;

        Self {
            _sid: raw_sid,
            raw: SID_AND_ATTRIBUTES {
                Sid: PSID(raw_sid_ptr as _),
                Attributes: value.attributes,
            },
        }
    }
}

impl TryFrom<&SID_AND_ATTRIBUTES> for SidAndAttributes {
    type Error = anyhow::Error;

    fn try_from(value: &SID_AND_ATTRIBUTES) -> Result<Self, Self::Error> {
        Ok(Self {
            sid: Sid::try_from(value.Sid)?,
            attributes: value.Attributes,
        })
    }
}

pub struct TokenGroups(pub Vec<SidAndAttributes>);

pub struct RawTokenGroups {
    buf: Vec<u8>,
    _sid_and_attributes: Vec<RawSidAndAttributes>,
}

impl RawTokenGroups {
    pub fn as_raw(&self) -> &TOKEN_GROUPS {
        unsafe { &*self.buf.as_ptr().cast::<TOKEN_GROUPS>() }
    }
}

impl From<&TokenGroups> for RawTokenGroups {
    fn from(value: &TokenGroups) -> Self {
        let mut raw_buf = vec![
            0u8;
            mem::size_of::<TOKEN_GROUPS>()
                + (value.0.len().saturating_sub(1)) * mem::size_of::<SID_AND_ATTRIBUTES>()
        ];

        let raw = raw_buf.as_mut_ptr().cast::<TOKEN_GROUPS>();

        let raw_sid_and_attributes = value.0.iter().map(RawSidAndAttributes::from).collect::<Vec<_>>();

        unsafe {
            ptr::addr_of_mut!((*raw).GroupCount).write(value.0.len() as _);

            let groups_ptr = ptr::addr_of_mut!((*raw).Groups).cast::<SID_AND_ATTRIBUTES>();

            for (i, v) in raw_sid_and_attributes.iter().enumerate() {
                groups_ptr.add(i).write(*v.as_raw());
            }
        }

        Self {
            buf: raw_buf,
            _sid_and_attributes: raw_sid_and_attributes,
        }
    }
}

impl TryFrom<&TOKEN_GROUPS> for TokenGroups {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_GROUPS) -> Result<Self> {
        let groups_slice = unsafe { slice::from_raw_parts(value.Groups.as_ptr(), value.GroupCount as _) };

        let mut groups = Vec::with_capacity(groups_slice.len());

        for group in groups_slice.iter() {
            groups.push(SidAndAttributes::try_from(group)?);
        }

        Ok(TokenGroups(groups))
    }
}

pub struct ThreadAttributeList(Vec<u8>);

impl<'a> ThreadAttributeList {
    pub fn with_count(count: u32) -> Result<ThreadAttributeList> {
        let mut out_size = 0;
        let _ = unsafe {
            InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST::default(), count, 0, &mut out_size)
        };

        let mut buf = vec![0; out_size];

        unsafe {
            InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as _),
                count,
                0,
                &mut out_size,
            )?;
        };

        Ok(ThreadAttributeList(buf))
    }

    pub unsafe fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.0.as_mut_ptr() as _)
    }

    pub fn update(&mut self, attribute: &'a ThreadAttributeType) -> Result<()> {
        unsafe {
            Ok(UpdateProcThreadAttribute(
                self.raw(),
                0,
                attribute.attribute() as _,
                Some(attribute.value()),
                attribute.size(),
                None,
                None,
            )?)
        }
    }
}

impl Drop for ThreadAttributeList {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.raw()) };
    }
}

pub enum ThreadAttributeType<'a> {
    ParentProcess(&'a Process),
    ExtendedFlags(u32),
    HandleList(Vec<HANDLE>),
}

impl<'a> ThreadAttributeType<'a> {
    pub fn attribute(&self) -> u32 {
        match self {
            ThreadAttributeType::ParentProcess(_) => PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            ThreadAttributeType::ExtendedFlags(_) => 0x60001,
            ThreadAttributeType::HandleList(_) => PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        }
    }

    pub fn value(&self) -> *const c_void {
        match self {
            ThreadAttributeType::ParentProcess(p) => p.handle.as_raw_ref() as *const _ as _,
            ThreadAttributeType::ExtendedFlags(v) => &v as *const _ as _,
            ThreadAttributeType::HandleList(h) => h.as_ptr() as _,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            ThreadAttributeType::ParentProcess(_) => mem::size_of::<HANDLE>(),
            ThreadAttributeType::ExtendedFlags(_) => mem::size_of::<u32>(),
            ThreadAttributeType::HandleList(h) => mem::size_of::<HANDLE>() * h.len(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenElevationType {
    Default = 1,
    Full = 2,
    Limited = 3,
}

impl TryFrom<TOKEN_ELEVATION_TYPE> for TokenElevationType {
    type Error = anyhow::Error;

    fn try_from(value: TOKEN_ELEVATION_TYPE) -> std::prelude::v1::Result<Self, Self::Error> {
        TokenElevationType::try_from(&value)
    }
}

impl TryFrom<&TOKEN_ELEVATION_TYPE> for TokenElevationType {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_ELEVATION_TYPE) -> std::prelude::v1::Result<Self, Self::Error> {
        if *value == TokenElevationTypeDefault {
            Ok(TokenElevationType::Default)
        } else if *value == TokenElevationTypeFull {
            Ok(TokenElevationType::Full)
        } else if *value == TokenElevationTypeLimited {
            Ok(TokenElevationType::Limited)
        } else {
            bail!(Error::from_win32(ERROR_INVALID_VARIANT))
        }
    }
}

pub fn get_username(format: EXTENDED_NAME_FORMAT) -> Result<String> {
    let mut required_size = 0u32;

    let _ = unsafe { GetUserNameExW(format, PWSTR::null(), &mut required_size as _) };

    let mut buf = vec![0u16; required_size as _];
    let mut tchars_copied = buf.len() as u32;
    let success = unsafe { GetUserNameExW(format, PWSTR::from_raw(buf.as_mut_ptr()), &mut tchars_copied as _) };

    if success.into() {
        Ok(String::from_utf16(&buf[..tchars_copied as _])?)
    } else {
        bail!(Error::last_error())
    }
}

pub fn is_username_valid(server_name: Option<&String>, username: &str) -> Result<bool> {
    let server_name = server_name.map(WideString::from).unwrap_or_default();
    let username = WideString::from(username);

    let status = unsafe {
        // 4 is arbitrary. consent.exe uses it so we do too
        let mut out = ptr::null_mut::<USER_INFO_4>();
        let status = NetUserGetInfo(
            server_name.as_pcwstr(),
            username.as_pcwstr(),
            4,
            &mut out as *mut _ as _,
        );

        NetApiBufferFree(Some(out as _));

        status
    };

    // TODO: Support other errors and hardcheck on NERR_UserNotFound
    if status == NERR_Success {
        Ok(true)
    } else if status == NERR_UserNotFound {
        Ok(false)
    } else {
        bail!(Error::from_hresult(HRESULT(status as _)))
    }
}

pub fn virtual_account_name(token: &Token) -> Result<String> {
    Ok(token.username(NameSamCompatible)?.replace("\\", "_"))
}

/// https://call4cloud.nl/wp-content/uploads/2023/05/flowcreateadmin.bmp
/// https://github.com/tyranid/setsidmapping/blob/main/SetSidMapping/Program.cs
pub fn create_virtual_identifier(domain_id: u32, domain_name: &str, token: Option<&Token>) -> Result<Sid> {
    let sid = {
        let mut sub_authority = vec![domain_id];
        if let Some(token) = token {
            let token_sid = token.sid_and_attributes()?.sid;

            sub_authority.extend(token_sid.sub_authority.iter().skip(1));
        }

        Sid {
            revision: 1,
            identifier_identity: SECURITY_NT_AUTHORITY,
            sub_authority,
        }
    };

    let raw_sid = RawSid::from(&sid);

    let domain_name = WideString::from(domain_name);
    let account_name = token
        .map(virtual_account_name)
        .transpose()?
        .map(WideString::from)
        .unwrap_or_default();

    // Just as intune?
    let input = LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT {
        DomainName: domain_name.as_unicode_string(),
        AccountName: account_name.as_unicode_string(),
        Sid: PSID(raw_sid.as_raw() as *const _ as _),
        ..Default::default()
    };

    let mut output = ptr::null_mut::<LSA_SID_NAME_MAPPING_OPERATION_GENERIC_OUTPUT>();

    unsafe {
        let _r = LsaManageSidNameMapping(
            LsaSidNameMappingOperation_Add,
            &input as *const _ as _,
            &mut output as _,
        );

        if !output.is_null() {
            LsaFreeMemory(Some(output as _)).ok()?;
        }
    }

    Ok(sid)
}

#[derive(Default, Debug, Hash, PartialEq, Eq, Clone)]
pub struct Account {
    pub domain_sid: Sid,
    pub domain_name: String,
    pub account_sid: Sid,
    pub account_name: String,
}

pub fn create_virtual_account(domain_id: u32, domain_name: &str, token: &Token) -> Result<Account> {
    let domain_sid = create_virtual_identifier(domain_id, domain_name, None)?;
    let account_sid = create_virtual_identifier(domain_id, domain_name, Some(token))?;

    if account_sid.is_valid() {
        Ok(Account {
            domain_sid,
            account_sid,
            account_name: virtual_account_name(token)?,
            domain_name: domain_name.to_owned(),
        })
    } else {
        bail!(Error::from_win32(ERROR_INVALID_SID))
    }
}

pub fn create_profile(account_sid: &Sid, account_name: &str) -> Result<String> {
    let mut buf: Vec<u16> = vec![0; MAX_PATH as _];

    unsafe {
        CreateProfile(
            WideString::from(&account_sid.to_string()).as_pcwstr(),
            WideString::from(account_name).as_pcwstr(),
            buf.as_mut_slice(),
        )?;
    }

    let raw_string = buf.into_iter().take_while(|x| *x != 0).collect::<Vec<_>>();

    Ok(String::from_utf16(&raw_string)?)
}

pub struct ProfileInfo<'a> {
    token: &'a Token,
    username: WideString,
    raw: PROFILEINFOW,
}

impl<'a> ProfileInfo<'a> {
    pub fn from_token(token: &'a Token, username: &str) -> Result<Self> {
        let mut profile_info = Self {
            token,
            username: WideString::from(username),
            raw: PROFILEINFOW {
                dwSize: mem::size_of::<PROFILEINFOW>() as _,
                dwFlags: PI_NOUI,
                ..Default::default()
            },
        };

        profile_info.raw.lpUserName = profile_info.username.as_pwstr();

        unsafe {
            LoadUserProfileW(profile_info.token.handle.raw(), &mut profile_info.raw)?;
        }

        Ok(profile_info)
    }
}

impl<'a> Drop for ProfileInfo<'a> {
    fn drop(&mut self) {
        // unsafe {
        // TODO unload
        // let _ = UnloadUserProfile(self.token.handle, self.raw.hProfile);
        // }
    }
}

pub struct Pipe {
    pub handle: Handle,
}

impl Pipe {
    /// Creates an anonymous pipe. Returns (rx, tx)
    pub fn new_anonymous(security_attributes: Option<&SECURITY_ATTRIBUTES>, size: u32) -> Result<(Self, Self)> {
        let (mut rx, mut tx) = (HANDLE::default(), HANDLE::default());
        unsafe { CreatePipe(&mut rx, &mut tx, security_attributes.map(|x| x as _), size) }?;
        Ok((Self { handle: rx.into() }, Self { handle: tx.into() }))
    }

    pub fn peek(&self, data: Option<&mut [u8]>) -> Result<u32> {
        let mut available = 0;
        let size = data.as_ref().map(|b| b.len() as _).unwrap_or_default();

        unsafe {
            PeekNamedPipe(
                self.handle.raw(),
                data.map(|b| b.as_mut_ptr() as _),
                size,
                None,
                Some(&mut available),
                None,
            )?;
        }

        Ok(available)
    }

    pub fn impersonate_client<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        unsafe { ImpersonateNamedPipeClient(self.handle.raw()) }?;

        let r = f();

        unsafe { RevertToSelf() }?;

        r
    }

    pub fn client_primary_token(&self) -> Result<Token> {
        let mut token = None;

        self.impersonate_client(|| {
            token = Some(Thread::current().token(TOKEN_ALL_ACCESS, true)?.duplicate(
                TOKEN_ACCESS_MASK(0),
                None,
                SecurityIdentification,
                TokenPrimary,
            )?);

            Ok(())
        })?;

        Ok(token.unwrap())
    }

    pub fn client_process_id(&self) -> Result<u32> {
        let mut pid = 0u32;
        unsafe {
            GetNamedPipeClientProcessId(self.handle.raw(), &mut pid)?;
        }

        Ok(pid)
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_bytes = 0;
        unsafe {
            ReadFile(self.handle.raw(), Some(buf), Some(&mut read_bytes), None)?;
        }

        Ok(read_bytes as _)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written_bytes = 0;
        unsafe {
            WriteFile(self.handle.raw(), Some(buf), Some(&mut written_bytes), None)?;
        }

        Ok(written_bytes as _)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        unsafe {
            FlushFileBuffers(self.handle.raw())?;
        }

        Ok(())
    }
}

pub fn parse_command_line(command_line: &str) -> Result<Vec<String>> {
    let command_line = WideString::from(command_line);
    let mut arg_count = 0i32;

    let raw_args = unsafe { CommandLineToArgvW(command_line.as_pcwstr(), &mut arg_count) };

    if raw_args.is_null() {
        bail!(Error::last_error());
    }

    let arg_count = arg_count as usize;

    let mut args = Vec::with_capacity(arg_count);
    for i in 0..arg_count {
        args.push(unsafe { raw_args.add(i).read().to_string() });
    }

    unsafe { LocalFree(HLOCAL(raw_args as _)) };

    Ok(args.into_iter().collect::<Result<_, _>>()?)
}

pub struct CatalogInfo {
    pub path: PathBuf,
    pub hash: Vec<u8>,
}

impl CatalogInfo {
    pub fn try_from_file(path: &Path) -> Result<Option<Self>> {
        let admin_ctx = CatalogAdminContext::try_new()?;

        let hash = admin_ctx.hash_file(path)?;

        let catalog_path = admin_ctx.catalogs_for_hash(&hash).next();

        Ok(catalog_path.map(|catalog_path| Self {
            hash,
            path: catalog_path,
        }))
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
/// https://stackoverflow.com/questions/68215779/getting-winverifytrust-to-work-with-catalog-signed-files-such-as-cmd-exe
/// https://github.com/dragokas/Verify-Signature-Cpp/blob/master/verify.cpp#L140
/// https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Security/CodeSigning/cpp/codesigning.cpp
pub fn win_verify_trust(path: &Path, catalog_info: Option<CatalogInfo>) -> Result<WinVerifyTrustResult> {
    let path = WideString::from(path);
    let catalog_info = catalog_info.map(|c| {
        (
            WideString::from(&c.path),
            WideString::from(base16ct::upper::encode_string(&c.hash)),
        )
    });

    #[derive(Debug)]
    enum WintrustInfo {
        Catalog(WINTRUST_CATALOG_INFO),
        File(WINTRUST_FILE_INFO),
    }

    let mut wintrust_info = match &catalog_info {
        Some((catalog_info_path, catalog_info_member)) => WintrustInfo::Catalog(WINTRUST_CATALOG_INFO {
            cbStruct: mem::size_of::<WINTRUST_CATALOG_INFO>() as _,
            pcwszCatalogFilePath: catalog_info_path.as_pcwstr(),
            pcwszMemberFilePath: path.as_pcwstr(),
            pcwszMemberTag: catalog_info_member.as_pcwstr(),
            ..Default::default()
        }),
        None => WintrustInfo::File(WINTRUST_FILE_INFO {
            cbStruct: mem::size_of::<WINTRUST_FILE_INFO>() as _,
            pcwszFilePath: path.as_pcwstr(),
            ..Default::default()
        }),
    };

    let mut win_trust_data = WINTRUST_DATA {
        cbStruct: mem::size_of::<WINTRUST_DATA>() as _,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: match &wintrust_info {
            WintrustInfo::Catalog(_) => WTD_CHOICE_CATALOG,
            WintrustInfo::File(_) => WTD_CHOICE_FILE,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        Anonymous: match &mut wintrust_info {
            WintrustInfo::Catalog(x) => WINTRUST_DATA_0 { pCatalog: x },
            WintrustInfo::File(x) => WINTRUST_DATA_0 { pFile: x },
        },
        dwProvFlags: WTD_USE_DEFAULT_OSVER_CHECK | WTD_DISABLE_MD2_MD4 | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };

    let mut guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe { WinVerifyTrustEx(HWND(INVALID_HANDLE_VALUE.0), &mut guid, &mut win_trust_data) };

    let result = AuthenticodeSignatureStatus::try_from(HRESULT(status));
    let provider = if win_trust_data.hWVTStateData.is_invalid() {
        None
    } else {
        unsafe {
            WTHelperProvDataFromStateData(win_trust_data.hWVTStateData)
                .as_ref()
                .map(CryptProviderData::try_from)
        }
    };

    win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;

    unsafe { WinVerifyTrustEx(HWND(INVALID_HANDLE_VALUE.0), &mut guid, &mut win_trust_data) };
    Ok(WinVerifyTrustResult {
        provider: provider.transpose()?,
        status: result.map_err(|x| x.ok().unwrap_err())?,
    })
}

#[derive(Debug)]
pub struct WinVerifyTrustResult {
    pub provider: Option<CryptProviderData>,
    pub status: AuthenticodeSignatureStatus,
}

pub fn authenticode_status(path: &Path) -> Result<WinVerifyTrustResult> {
    let catalog_info = CatalogInfo::try_from_file(path)?;

    win_verify_trust(path, catalog_info)
}

pub struct CatalogAdminContext {
    pub handle: HANDLE,
}

impl CatalogAdminContext {
    pub fn try_new() -> Result<Self> {
        let mut handle = HANDLE::default();

        // TODO add arguments
        unsafe { CryptCATAdminAcquireContext2(&mut handle.0 as *mut _ as _, None, BCRYPT_SHA256_ALGORITHM, None, 0) }?;

        Ok(Self { handle })
    }

    pub fn hash_file(&self, path: &Path) -> Result<Vec<u8>> {
        let file = File::open(path)?;
        let mut required_size = 0u32;

        unsafe {
            let _ = CryptCATAdminCalcHashFromFileHandle2(
                self.handle.0 as _,
                HANDLE(file.as_raw_handle() as _),
                &mut required_size,
                None,
                0,
            );

            let mut hash = Vec::with_capacity(required_size as _);

            CryptCATAdminCalcHashFromFileHandle2(
                self.handle.0 as _,
                HANDLE(file.as_raw_handle() as _),
                &mut required_size,
                Some(hash.as_mut_ptr()),
                0,
            )?;

            hash.set_len(required_size as _);

            Ok(hash)
        }
    }

    pub fn catalogs_for_hash<'a>(&'a self, hash: &'a [u8]) -> CatalogIterator<'a> {
        CatalogIterator::new(self, hash)
    }
}

impl Drop for CatalogAdminContext {
    fn drop(&mut self) {
        let _ = unsafe { CryptCATAdminReleaseContext(self.handle.0 as _, 0) };
    }
}

pub struct CatalogIterator<'a> {
    admin_ctx: &'a CatalogAdminContext,
    cur: Option<HANDLE>,
    hash: &'a [u8],
}

impl<'a> CatalogIterator<'a> {
    pub fn new(admin_ctx: &'a CatalogAdminContext, hash: &'a [u8]) -> Self {
        Self {
            admin_ctx,
            cur: None,
            hash,
        }
    }
}

impl Iterator for CatalogIterator<'_> {
    type Item = PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        let new_ctx = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                self.admin_ctx.handle.0 as _,
                &self.hash,
                0,
                self.cur.map(|mut x| &mut x.0 as *mut _ as _),
            )
        };

        if new_ctx == 0 {
            None
        } else {
            self.cur = Some(HANDLE(new_ctx as _));

            let mut info = CATALOG_INFO {
                cbStruct: mem::size_of::<CATALOG_INFO>() as _,
                ..Default::default()
            };

            unsafe { CryptCATCatalogInfoFromContext(new_ctx, &mut info, 0) }.ok()?;

            PCWSTR(info.wszCatalogFile.as_ptr()).to_path_safe().ok()
        }
    }
}

impl Drop for CatalogIterator<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.cur {
            let _ = unsafe { CryptCATAdminReleaseCatalogContext(self.admin_ctx.handle.0 as _, handle.0 as _, 0) };
        }
    }
}

pub struct Module {
    handle: HMODULE,
}

impl Module {
    pub fn from_ref<T>(address: &T) -> Result<Self> {
        let mut handle = HMODULE::default();
        unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                PCWSTR(address as *const _ as _),
                &mut handle,
            )?;
        }

        Ok(Self { handle })
    }

    pub fn current() -> Result<Self> {
        static VAL: u8 = 0;
        Self::from_ref(&VAL)
    }

    pub fn file_name(&self) -> Result<PathBuf> {
        let mut buf = vec![0; MAX_PATH as _];
        let size = unsafe { GetModuleFileNameW(self.handle, &mut buf) } as _;
        if size == 0 {
            bail!(Error::last_error());
        }

        unsafe {
            buf.set_len(size);
        }

        Ok(OsString::from_wide(&buf).into())
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        let _ = unsafe { FreeLibrary(self.handle) };
    }
}

pub struct Peb<'a> {
    pub process: &'a Process,
    pub address: usize,
}

impl Peb<'_> {
    pub unsafe fn raw(&self) -> Result<PEB> {
        self.process.read_struct::<PEB>(self.address)
    }

    pub unsafe fn user_process_parameters(&self) -> Result<UserProcessParameters> {
        let raw_peb = self.raw()?;

        let raw_params = self
            .process
            .read_struct::<RTL_USER_PROCESS_PARAMETERS>(raw_peb.ProcessParameters as _)?;

        let image_path_name = self.process.read_array::<u16>(
            raw_params.ImagePathName.Length as usize / mem::size_of::<u16>(),
            raw_params.ImagePathName.Buffer.as_ptr() as _,
        )?;

        let command_line = self.process.read_array::<u16>(
            raw_params.CommandLine.Length as usize / mem::size_of::<u16>(),
            raw_params.CommandLine.Buffer.as_ptr() as _,
        )?;

        let desktop = self.process.read_array::<u16>(
            raw_params.DesktopInfo.Length as usize / mem::size_of::<u16>(),
            raw_params.DesktopInfo.Buffer.as_ptr() as _,
        )?;

        let working_directory = self.process.read_array::<u16>(
            raw_params.CurrentDirectory.DosPath.Length as usize / mem::size_of::<u16>(),
            raw_params.CurrentDirectory.DosPath.Buffer.as_ptr() as _,
        )?;

        Ok(UserProcessParameters {
            image_path_name: OsString::from_wide(&image_path_name).into(),
            command_line: String::from_utf16(&command_line)?,
            desktop: String::from_utf16(&desktop)?,
            working_directory: OsString::from_wide(&working_directory).into(),
        })
    }
}

pub struct UserProcessParameters {
    pub image_path_name: PathBuf,
    pub command_line: String,
    pub desktop: String,
    pub working_directory: PathBuf,
}

/// https://github.com/PowerShell/PowerShell/blob/2018c16df04af03a8f1805849820b65f41eb7e29/src/System.Management.Automation/security/MshSignature.cs#L282
#[derive(Debug)]
pub enum AuthenticodeSignatureStatus {
    Valid,
    Incompatible,
    NotSigned,
    HashMismatch,
    NotSupportedFileFormat,
    NotTrusted,
}

impl TryFrom<HRESULT> for AuthenticodeSignatureStatus {
    type Error = HRESULT;

    fn try_from(value: HRESULT) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            S_OK => Ok(Self::Valid),
            NTE_BAD_ALGID => Ok(Self::Incompatible),
            TRUST_E_NOSIGNATURE => Ok(Self::NotSigned),
            TRUST_E_BAD_DIGEST | CRYPT_E_BAD_MSG => Ok(Self::HashMismatch),
            TRUST_E_PROVIDER_UNKNOWN => Ok(Self::NotSupportedFileFormat),
            TRUST_E_EXPLICIT_DISTRUST => Ok(Self::NotTrusted),
            err => Err(err),
        }
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_attribute
#[derive(Debug)]
pub struct CryptAttribute {
    pub oid: String,
    pub data: Vec<Vec<u8>>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_signer_info
#[derive(Debug)]
pub struct SignerInfo {
    pub issuer: String,
    pub serial_number: Vec<u8>,
    pub authenticated_attributes: Vec<CryptAttribute>,
    pub unauthenticated_attributes: Vec<CryptAttribute>,
}

#[derive(Debug)]
pub enum CertificateEncodingType {
    X509Asn,
    Pkcs7Asn,
}

#[derive(Debug)]
pub enum CertificateVersion {
    V1,
    V2,
    V3,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_extension
#[derive(Debug)]
pub struct CertificateExtension {
    pub oid: String,
    pub critical: bool,
    pub data: Vec<u8>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_info
#[derive(Debug)]
pub struct CertificateInfo {
    pub version: CertificateVersion,
    pub serial_number: Vec<u8>,
    pub issuer: String,
    pub subject: String,
    pub extensions: Vec<CertificateExtension>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context
#[derive(Debug)]
pub struct CertificateContext {
    pub encoding_type: CertificateEncodingType,
    pub encoded: Vec<u8>,
    pub info: CertificateInfo,
    pub eku: Vec<String>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_cert
#[derive(Debug)]
pub struct CryptProviderCertificate {
    pub cert: CertificateContext,
    pub commercial: bool,
    pub trusted_root: bool,
    pub self_signed: bool,
    pub test_cert: bool,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr
#[derive(Debug)]
pub struct CryptProviderSigner {
    pub signer: SignerInfo,
    pub cert_chain: Vec<CryptProviderCertificate>,
}

/// https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_data
#[derive(Debug)]
pub struct CryptProviderData {
    pub signers: Vec<CryptProviderSigner>,
}

impl TryFrom<&CRYPT_ATTRIBUTE> for CryptAttribute {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_ATTRIBUTE) -> Result<Self, Self::Error> {
        Ok(Self {
            oid: value.pszObjId.to_string_safe()?,
            data: unsafe {
                slice::from_raw_parts(value.rgValue, value.cValue as _)
                    .iter()
                    .map(|rg| slice::from_raw_parts(rg.pbData, rg.cbData as _).to_vec())
                    .collect()
            },
        })
    }
}

impl TryFrom<&CMSG_SIGNER_INFO> for SignerInfo {
    type Error = anyhow::Error;

    fn try_from(value: &CMSG_SIGNER_INFO) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: cert_name_blob_to_str(X509_ASN_ENCODING, &value.Issuer, CERT_SIMPLE_NAME_STR)?,
            serial_number: unsafe { slice::from_raw_parts(value.SerialNumber.pbData, value.SerialNumber.cbData as _) }
                .to_vec(),
            authenticated_attributes: unsafe {
                slice::from_raw_parts(value.AuthAttrs.rgAttr, value.AuthAttrs.cAttr as _)
                    .iter()
                    .map(CryptAttribute::try_from)
                    .collect::<Result<_>>()?
            },
            unauthenticated_attributes: unsafe {
                slice::from_raw_parts(value.UnauthAttrs.rgAttr, value.UnauthAttrs.cAttr as _)
                    .iter()
                    .map(CryptAttribute::try_from)
                    .collect::<Result<_>>()?
            },
        })
    }
}

impl TryFrom<&CERT_EXTENSION> for CertificateExtension {
    type Error = anyhow::Error;

    fn try_from(value: &CERT_EXTENSION) -> Result<Self, Self::Error> {
        Ok(Self {
            oid: value.pszObjId.to_string_safe()?,
            critical: value.fCritical.as_bool(),
            data: unsafe { slice::from_raw_parts(value.Value.pbData, value.Value.cbData as _) }.to_vec(),
        })
    }
}

impl TryFrom<&CERT_INFO> for CertificateInfo {
    type Error = anyhow::Error;

    fn try_from(value: &CERT_INFO) -> Result<Self, Self::Error> {
        Ok(Self {
            version: match value.dwVersion {
                CERT_V1 => Ok(CertificateVersion::V1),
                CERT_V2 => Ok(CertificateVersion::V2),
                CERT_V3 => Ok(CertificateVersion::V3),
                _ => Err(anyhow!(Error::from_win32(ERROR_INVALID_VARIANT))),
            }?,
            serial_number: unsafe {
                slice::from_raw_parts(value.SerialNumber.pbData, value.SerialNumber.cbData as _).to_vec()
            },
            issuer: cert_name_blob_to_str(X509_ASN_ENCODING, &value.Issuer, CERT_SIMPLE_NAME_STR)?,
            subject: cert_name_blob_to_str(X509_ASN_ENCODING, &value.Subject, CERT_SIMPLE_NAME_STR)?,
            extensions: unsafe { slice::from_raw_parts(value.rgExtension, value.cExtension as _) }
                .iter()
                .map(CertificateExtension::try_from)
                .collect::<Result<_>>()?,
        })
    }
}

impl TryFrom<&CERT_CONTEXT> for CertificateContext {
    type Error = anyhow::Error;

    fn try_from(value: &CERT_CONTEXT) -> Result<Self, Self::Error> {
        Ok(Self {
            encoding_type: match value.dwCertEncodingType {
                X509_ASN_ENCODING => Ok(CertificateEncodingType::X509Asn),
                PKCS_7_ASN_ENCODING => Ok(CertificateEncodingType::Pkcs7Asn),
                _ => Err(anyhow!(Error::from_win32(ERROR_INVALID_VARIANT))),
            }?,
            encoded: unsafe { slice::from_raw_parts(value.pbCertEncoded, value.cbCertEncoded as _).to_vec() },
            info: unsafe { value.pCertInfo.as_ref() }.map_or_else(
                || bail!(Error::NullPointer("pCertInfo")),
                |x| CertificateInfo::try_from(x),
            )?,
            eku: cert_ctx_eku(value)?,
        })
    }
}

impl TryFrom<&CRYPT_PROVIDER_CERT> for CryptProviderCertificate {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_PROVIDER_CERT) -> Result<Self, Self::Error> {
        Ok(Self {
            cert: unsafe { value.pCert.as_ref() }
                .ok_or_else(|| Error::NullPointer("pCert"))?
                .try_into()?,
            commercial: value.fCommercial.as_bool(),
            trusted_root: value.fTrustedRoot.as_bool(),
            self_signed: value.fSelfSigned.as_bool(),
            test_cert: value.fTestCert.as_bool(),
        })
    }
}

impl TryFrom<&CRYPT_PROVIDER_SGNR> for CryptProviderSigner {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_PROVIDER_SGNR) -> Result<Self, Self::Error> {
        Ok(Self {
            signer: unsafe { value.psSigner.as_ref() }
                .map_or_else(|| bail!(Error::NullPointer("psSigner")), |x| SignerInfo::try_from(x))?,
            cert_chain: unsafe {
                slice::from_raw_parts(value.pasCertChain, value.csCertChain as _)
                    .iter()
                    .map(CryptProviderCertificate::try_from)
                    .collect::<Result<_>>()?
            },
        })
    }
}

impl TryFrom<&CRYPT_PROVIDER_DATA> for CryptProviderData {
    type Error = anyhow::Error;

    fn try_from(value: &CRYPT_PROVIDER_DATA) -> Result<Self, Self::Error> {
        Ok(Self {
            signers: unsafe {
                slice::from_raw_parts(value.pasSigners, value.csSigners as _)
                    .iter()
                    .map(|x| CryptProviderSigner::try_from(x))
                    .collect::<Result<_>>()?
            },
        })
    }
}

pub fn cert_name_blob_to_str(
    encoding: CERT_QUERY_ENCODING_TYPE,
    value: &CRYPT_INTEGER_BLOB,
    string_type: CERT_STRING_TYPE,
) -> Result<String> {
    let required_size = unsafe { CertNameToStrW(encoding, value, string_type, None) };

    let mut buf = vec![0; required_size as _];
    unsafe {
        let converted_bytes = CertNameToStrW(X509_ASN_ENCODING, value, string_type, Some(buf.as_mut_slice()));

        if converted_bytes as usize != buf.len() || buf.len() < 1 {
            bail!(Error::from_win32(ERROR_INCORRECT_SIZE));
        }

        // Trailing null byte needs to be removed
        buf.set_len(buf.capacity() - 1)
    }

    Ok(String::from_utf16(&buf)?)
}

pub fn cert_ctx_eku(ctx: &CERT_CONTEXT) -> Result<Vec<String>> {
    let mut required_size = 0;

    unsafe {
        CertGetEnhancedKeyUsage(ctx, 0, None, &mut required_size)?;
    }

    let mut raw_buf = vec![0u8; required_size as _];

    unsafe {
        CertGetEnhancedKeyUsage(ctx, 0, Some(raw_buf.as_mut_ptr() as _), &mut required_size)?;

        let ctl_usage = raw_buf.as_ptr().cast::<CTL_USAGE>().read();

        Ok(
            slice::from_raw_parts(ctl_usage.rgpszUsageIdentifier, ctl_usage.cUsageIdentifier as _)
                .iter()
                .filter_map(|id| id.to_string_safe().ok())
                .collect(),
        )
    }
}

pub enum AceType {
    AccessAllowed(Sid),
}

impl AceType {
    pub fn kind(&self) -> u8 {
        match self {
            AceType::AccessAllowed(_) => ACCESS_ALLOWED_ACE_TYPE as _,
        }
    }

    pub fn to_raw(&self) -> Vec<u8> {
        match self {
            AceType::AccessAllowed(sid) => RawSid::from(sid).0,
        }
    }

    pub unsafe fn from_raw(kind: u8, buf: &[u8]) -> Result<Self> {
        Ok(match kind as _ {
            ACCESS_ALLOWED_ACE_TYPE => Self::AccessAllowed(Sid::try_from(PSID(buf.as_ptr().cast_mut().cast()))?),
            _ => bail!(Error::from_win32(ERROR_INVALID_VARIANT)),
        })
    }
}

pub struct Ace {
    pub flags: ACE_FLAGS,
    pub access_mask: u32,
    pub data: AceType,
}

impl Ace {
    pub fn to_raw(&self) -> Vec<u8> {
        let body = self.data.to_raw();

        let size = mem::size_of::<ACE_HEADER>() + mem::size_of::<u32>() + body.len();

        let header = ACE_HEADER {
            AceType: self.data.kind(),
            AceFlags: self.flags.0 as u8,
            AceSize: size as _,
        };

        let mut buf = vec![0; size];

        unsafe {
            let mut ptr = buf.as_mut_ptr();

            ptr.cast::<ACE_HEADER>().write(header);
            ptr = ptr.byte_add(mem::size_of::<ACE_HEADER>());

            ptr.cast::<u32>().write(self.access_mask);
            ptr = ptr.byte_add(mem::size_of::<u32>());

            ptr.copy_from(body.as_ptr(), body.len());
        }

        buf
    }

    pub unsafe fn from_ptr(mut ptr: *const c_void) -> Result<Self> {
        let header = ptr.cast::<ACE_HEADER>().read();
        ptr = ptr.byte_add(mem::size_of::<ACE_HEADER>());

        let access_mask = ptr.cast::<u32>().read();
        ptr = ptr.byte_add(mem::size_of::<u32>());

        let body_size = header.AceSize as usize - mem::size_of::<ACE_HEADER>() - mem::size_of::<u32>();
        let body = slice::from_raw_parts(ptr.cast::<u8>(), body_size);

        Ok(Self {
            flags: ACE_FLAGS(header.AceFlags as _),
            access_mask,
            data: AceType::from_raw(header.AceType, body)?,
        })
    }
}

pub struct Acl {
    pub revision: ACE_REVISION,
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn new() -> Self {
        Self {
            revision: ACL_REVISION,
            aces: vec![],
        }
    }

    pub fn with_aces(aces: Vec<Ace>) -> Self {
        Self {
            revision: ACL_REVISION,
            aces,
        }
    }

    pub fn to_raw(&self) -> Result<Vec<u8>> {
        let raw_aces = self.aces.iter().map(Ace::to_raw).collect::<Vec<_>>();
        let size = mem::size_of::<ACL>() + raw_aces.iter().map(Vec::len).sum::<usize>();

        // Align on u32 boundary
        let size = (size + mem::size_of::<u32>() - 1) & !3;

        let mut buf = vec![0; size];

        unsafe {
            InitializeAcl(buf.as_mut_ptr() as _, buf.len() as _, self.revision)?;

            for raw_ace in raw_aces {
                AddAce(
                    buf.as_mut_ptr().cast(),
                    self.revision,
                    0,
                    raw_ace.as_ptr().cast(),
                    raw_ace.len() as _,
                )?;
            }
        }

        Ok(buf)
    }
}

impl TryFrom<&ACL> for Acl {
    type Error = anyhow::Error;

    fn try_from(value: &ACL) -> Result<Self, Self::Error> {
        Ok(Self {
            revision: ACE_REVISION(value.AclRevision as _),
            aces: (0..value.AceCount as _)
                .map(|i| unsafe {
                    let mut ace = ptr::null_mut();
                    GetAce(value, i, &mut ace)?;

                    Ace::from_ptr(ace)
                })
                .collect::<Result<_>>()?,
        })
    }
}

pub struct TokenDefaultDacl {
    pub default_dacl: Option<Acl>,
}

impl TryFrom<&TOKEN_DEFAULT_DACL> for TokenDefaultDacl {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_DEFAULT_DACL) -> Result<Self, Self::Error> {
        Ok(Self {
            default_dacl: unsafe { value.DefaultDacl.as_ref() }.map(Acl::try_from).transpose()?,
        })
    }
}

pub struct TokenPrimaryGroup {
    pub primary_group: Sid,
}

impl TryFrom<&TOKEN_PRIMARY_GROUP> for TokenPrimaryGroup {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_PRIMARY_GROUP) -> Result<Self, Self::Error> {
        Ok(Self {
            primary_group: Sid::try_from(value.PrimaryGroup)?,
        })
    }
}

pub struct TokenPrivileges(pub Vec<LUID_AND_ATTRIBUTES>);

pub struct RawTokenPrivileges(Vec<u8>);

impl TryFrom<&TOKEN_PRIVILEGES> for TokenPrivileges {
    type Error = anyhow::Error;

    fn try_from(value: &TOKEN_PRIVILEGES) -> Result<Self, Self::Error> {
        let privs_slice = unsafe { slice::from_raw_parts(value.Privileges.as_ptr(), value.PrivilegeCount as _) };

        Ok(Self(privs_slice.iter().map(|x| x.clone()).collect()))
    }
}

impl RawTokenPrivileges {
    pub fn as_raw(&self) -> &TOKEN_PRIVILEGES {
        unsafe { &*self.0.as_ptr().cast::<TOKEN_PRIVILEGES>() }
    }
}

impl From<&TokenPrivileges> for RawTokenPrivileges {
    fn from(value: &TokenPrivileges) -> Self {
        let mut raw_buf = vec![
            0;
            mem::size_of::<TOKEN_PRIVILEGES>()
                + value.0.len().saturating_sub(1) * mem::size_of::<LUID_AND_ATTRIBUTES>()
        ];

        let raw = raw_buf.as_mut_ptr().cast::<TOKEN_PRIVILEGES>();

        unsafe {
            ptr::addr_of_mut!((*raw).PrivilegeCount).write(value.0.len() as _);

            let privs_ptr = ptr::addr_of_mut!((*raw).Privileges).cast::<LUID_AND_ATTRIBUTES>();

            for (i, v) in value.0.iter().enumerate() {
                privs_ptr.add(i).write(*v);
            }
        }

        Self(raw_buf)
    }
}

pub fn lookup_privilege_value(system_name: Option<PCWSTR>, name: PCWSTR) -> Result<LUID> {
    let mut luid = LUID::default();
    unsafe {
        LookupPrivilegeValueW(system_name.unwrap_or(PCWSTR::null()), name, &mut luid)?;
    }
    Ok(luid)
}

pub struct Snapshot {
    handle: HANDLE,
}

pub struct ProcessIdIterator<'a> {
    snapshot: &'a Snapshot,
    is_first: bool,
    entry: PROCESSENTRY32,
}

impl<'a> ProcessIdIterator<'a> {
    fn new(snapshot: &'a Snapshot) -> Self {
        Self {
            snapshot,
            is_first: true,
            entry: PROCESSENTRY32 {
                dwSize: mem::size_of::<PROCESSENTRY32>() as _,
                ..Default::default()
            },
        }
    }
}

impl Iterator for ProcessIdIterator<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let iter_fn = if self.is_first {
            self.is_first = false;
            Process32First
        } else {
            Process32Next
        };

        unsafe { iter_fn(self.snapshot.handle, &mut self.entry) }.ok()?;

        Some(self.entry.th32ProcessID)
    }
}

impl Snapshot {
    pub fn new(flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, process_id: Option<u32>) -> Result<Self> {
        Ok(Self {
            handle: unsafe { CreateToolhelp32Snapshot(flags, process_id.unwrap_or(0))? },
        })
    }

    pub fn process_ids(&self) -> ProcessIdIterator {
        ProcessIdIterator::new(self)
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.handle) };
        self.handle = HANDLE::default();
    }
}

pub fn find_token_with_privilege(privilege: LUID) -> Result<Option<Token>> {
    let snapshot = Snapshot::new(TH32CS_SNAPPROCESS, None)?;

    Ok(snapshot.process_ids().find_map(|pid| {
        let proc = Process::try_get_by_pid(pid, PROCESS_QUERY_INFORMATION).ok()?;
        let token = proc.token(TOKEN_ALL_ACCESS).ok()?;

        if token.privileges().ok()?.0.iter().any(|p| p.Luid == privilege) {
            Some(token)
        } else {
            None
        }
    }))
}

#[rustfmt::skip]
pub fn default_admin_privileges() -> &'static TokenPrivileges {
    static PRIVS: OnceLock<TokenPrivileges> = OnceLock::new();

    PRIVS.get_or_init(|| {
        let mut privs = vec![];

        macro_rules! add_priv {
            ($priv:ident, $name:expr, $state:expr) => {
                $priv.push(LUID_AND_ATTRIBUTES {
                    Luid: lookup_privilege_value(None, $name).unwrap(),
                    Attributes: $state,
                });
            };
        }

        add_priv!(privs, SE_INCREASE_QUOTA_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SECURITY_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_TAKE_OWNERSHIP_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_LOAD_DRIVER_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SYSTEM_PROFILE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SYSTEMTIME_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_PROF_SINGLE_PROCESS_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_INC_BASE_PRIORITY_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_CREATE_PAGEFILE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_BACKUP_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_RESTORE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SHUTDOWN_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_DEBUG_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_SYSTEM_ENVIRONMENT_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_REMOTE_SHUTDOWN_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_UNDOCK_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_MANAGE_VOLUME_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_INC_WORKING_SET_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_TIME_ZONE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_CREATE_SYMBOLIC_LINK_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));
        add_priv!(privs, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, TOKEN_PRIVILEGES_ATTRIBUTES(0));

        add_priv!(privs, SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        add_priv!(privs, SE_IMPERSONATE_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        add_priv!(privs, SE_CREATE_GLOBAL_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);

        TokenPrivileges(privs)
    })
}

pub fn com_call<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
    }

    let r = f();

    unsafe {
        CoUninitialize();
    }

    r
}

pub struct Link {
    path: PathBuf,
}

impl Link {
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_owned() }
    }

    fn with_instance<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&IShellLinkW) -> Result<T>,
    {
        com_call(|| unsafe {
            let inst: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            let mut persist_file = MaybeUninit::<IPersistFile>::zeroed();

            inst.query(&IPersistFile::IID, persist_file.as_mut_ptr() as _).ok()?;

            let persist_file = persist_file.assume_init();

            let raw_path = WideString::from(&self.path);
            persist_file.Load(raw_path.as_pcwstr(), STGM_READ)?;

            inst.Resolve(None, SLR_NO_UI.0 as _)?;

            f(&inst)
        })
    }

    pub fn target_path(&self) -> Result<PathBuf> {
        self.with_instance(|link| {
            let mut target = vec![0; MAX_PATH as _];
            unsafe { link.GetPath(target.as_mut_slice(), ptr::null_mut(), SLGP_SHORTPATH.0 as _) }?;

            if let Some(idx) = target
                .iter()
                .enumerate()
                .filter(|(_, x)| **x == 0)
                .map(|(i, _)| i)
                .next()
            {
                target.truncate(idx);
            }

            Ok(PathBuf::from(OsString::from_wide(&target)))
        })
    }

    pub fn target_args(&self) -> Result<String> {
        self.with_instance(|link| {
            let mut target = vec![0; std::cmp::max(INFOTIPSIZE as _, MAX_PATH as _)];
            unsafe { link.GetArguments(target.as_mut_slice()) }?;

            if let Some(idx) = target
                .iter()
                .enumerate()
                .filter(|(_, x)| **x == 0)
                .map(|(i, _)| i)
                .next()
            {
                target.truncate(idx);
            }

            Ok(String::from_utf16(&target)?)
        })
    }

    pub fn target_working_directory(&self) -> Result<PathBuf> {
        self.with_instance(|link| {
            let mut target = vec![0; MAX_PATH as _];
            unsafe { link.GetWorkingDirectory(target.as_mut_slice()) }?;

            if let Some(idx) = target
                .iter()
                .enumerate()
                .filter(|(_, x)| **x == 0)
                .map(|(i, _)| i)
                .next()
            {
                target.truncate(idx);
            }

            Ok(PathBuf::from(OsString::from_wide(&target)))
        })
    }
}

pub fn expand_environment(src: &str, environment: &HashMap<String, String>) -> String {
    let mut expanded = String::with_capacity(src.len());

    let mut last_replaced = false;
    let mut it = src.split('%').peekable();

    expanded.push_str(it.next().unwrap());

    while let Some(segment) = it.next() {
        let var_value = environment.get(segment);
        if !last_replaced && var_value.is_some() {
            expanded.push_str(var_value.unwrap());
            last_replaced = true;
        } else {
            if !last_replaced {
                expanded.push('%');
            }

            expanded.push_str(segment);
            last_replaced = false;
        }
    }

    expanded
}

pub fn expand_environment_path(src: &Path, environment: &HashMap<String, String>) -> Result<PathBuf> {
    Ok(PathBuf::from_str(&expand_environment(
        src.as_os_str()
            .to_str()
            .ok_or_else(|| Error::from_hresult(E_INVALIDARG))?,
        environment,
    ))?)
}

pub enum InheritableAclKind {
    Default,
    Protected,
    Inherit,
}

pub struct InheritableAcl {
    pub kind: InheritableAclKind,
    pub acl: Acl,
}

pub fn set_named_security_info(
    target: &str,
    object_type: SE_OBJECT_TYPE,
    owner: Option<&Sid>,
    group: Option<&Sid>,
    dacl: Option<&InheritableAcl>,
    sacl: Option<&InheritableAcl>,
) -> Result<()> {
    let target = WideString::from(target);

    let mut security_info = OBJECT_SECURITY_INFORMATION(0);
    if owner.is_some() {
        security_info |= OWNER_SECURITY_INFORMATION;
    }

    if group.is_some() {
        security_info |= GROUP_SECURITY_INFORMATION;
    }

    if let Some(dacl) = dacl {
        security_info |= DACL_SECURITY_INFORMATION;
        security_info |= match dacl.kind {
            InheritableAclKind::Protected => PROTECTED_DACL_SECURITY_INFORMATION,
            InheritableAclKind::Inherit | InheritableAclKind::Default => UNPROTECTED_DACL_SECURITY_INFORMATION,
        };
    }

    if let Some(sacl) = sacl {
        security_info |= SACL_SECURITY_INFORMATION;
        security_info |= match sacl.kind {
            InheritableAclKind::Protected => PROTECTED_SACL_SECURITY_INFORMATION,
            InheritableAclKind::Inherit | InheritableAclKind::Default => UNPROTECTED_SACL_SECURITY_INFORMATION,
        };
    }

    let owner = owner.map(RawSid::from);
    let group = group.map(RawSid::from);
    let dacl = dacl.map(|x| x.acl.to_raw()).transpose()?;
    let sacl = sacl.map(|x| x.acl.to_raw()).transpose()?;

    unsafe {
        SetNamedSecurityInfoW(
            target.as_pcwstr(),
            object_type,
            security_info,
            owner
                .as_ref()
                .map(|x| PSID(x.as_raw() as *const _ as _))
                .unwrap_or_default(),
            group
                .as_ref()
                .map(|x| PSID(x.as_raw() as *const _ as _))
                .unwrap_or_default(),
            dacl.as_ref().map(|x| x.as_ptr().cast()),
            sacl.as_ref().map(|x| x.as_ptr().cast()),
        )
        .ok()?
    };

    Ok(())
}

pub struct SecurityDescriptor {
    pub revision: u8,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub sacl: Option<InheritableAcl>,
    pub dacl: Option<InheritableAcl>,
}

impl Default for SecurityDescriptor {
    fn default() -> Self {
        Self {
            revision: SECURITY_DESCRIPTOR_REVISION as _,
            owner: None,
            group: None,
            sacl: None,
            dacl: None,
        }
    }
}

pub struct RawSecurityDescriptor {
    _owner: Option<RawSid>,
    _group: Option<RawSid>,
    _sacl: Option<Vec<u8>>,
    _dacl: Option<Vec<u8>>,
    raw: SECURITY_DESCRIPTOR,
}

impl RawSecurityDescriptor {
    pub fn raw(&self) -> &SECURITY_DESCRIPTOR {
        &self.raw
    }
}

impl TryFrom<&SecurityDescriptor> for RawSecurityDescriptor {
    type Error = anyhow::Error;

    fn try_from(value: &SecurityDescriptor) -> std::result::Result<Self, Self::Error> {
        let owner = value.owner.as_ref().map(RawSid::from);
        let group = value.group.as_ref().map(RawSid::from);
        let sacl = value.sacl.as_ref().map(|x| x.acl.to_raw()).transpose()?;
        let dacl = value.dacl.as_ref().map(|x| x.acl.to_raw()).transpose()?;

        let mut control = SECURITY_DESCRIPTOR_CONTROL(0);
        if sacl.is_some() {
            control |= SE_SACL_PRESENT;

            control |= match value.sacl.as_ref().unwrap().kind {
                InheritableAclKind::Protected => SE_SACL_PROTECTED,
                InheritableAclKind::Inherit => SE_SACL_AUTO_INHERITED,
                InheritableAclKind::Default => SE_SACL_DEFAULTED,
            };
        }

        if dacl.is_some() {
            control |= SE_DACL_PRESENT;

            control |= match value.dacl.as_ref().unwrap().kind {
                InheritableAclKind::Protected => SE_DACL_PROTECTED,
                InheritableAclKind::Inherit => SE_DACL_AUTO_INHERITED,
                InheritableAclKind::Default => SE_DACL_DEFAULTED,
            };
        }

        let raw = SECURITY_DESCRIPTOR {
            Revision: value.revision,
            Sbz1: 0,
            Control: control,
            Owner: PSID(
                owner
                    .as_ref()
                    .map_or_else(ptr::null_mut, |x| x.as_raw() as *const _ as _),
            ),
            Group: PSID(
                group
                    .as_ref()
                    .map_or_else(ptr::null_mut, |x| x.as_raw() as *const _ as _),
            ),
            Sacl: sacl
                .as_ref()
                .map_or_else(ptr::null_mut, |x| x.as_ptr().cast_mut().cast()),
            Dacl: dacl
                .as_ref()
                .map_or_else(ptr::null_mut, |x| x.as_ptr().cast_mut().cast()),
        };

        Ok(Self {
            _owner: owner,
            _group: group,
            _sacl: sacl,
            _dacl: dacl,
            raw,
        })
    }
}

impl TryFrom<&SECURITY_DESCRIPTOR> for SecurityDescriptor {
    type Error = anyhow::Error;

    fn try_from(value: &SECURITY_DESCRIPTOR) -> Result<Self, Self::Error> {
        let acl_conv = |field: *mut ACL, present, prot, inherited| {
            value
                .Control
                .contains(present)
                .then(|| {
                    Ok::<_, anyhow::Error>(InheritableAcl {
                        kind: if value.Control.contains(prot) {
                            InheritableAclKind::Protected
                        } else if value.Control.contains(inherited) {
                            InheritableAclKind::Inherit
                        } else {
                            InheritableAclKind::Default
                        },
                        acl: Acl::try_from(unsafe { field.as_ref() }.ok_or_else(|| Error::from_hresult(E_POINTER))?)?,
                    })
                })
                .transpose()
        };

        let sacl = acl_conv(value.Sacl, SE_SACL_PRESENT, SE_SACL_PROTECTED, SE_SACL_AUTO_INHERITED)?;
        let dacl = acl_conv(value.Dacl, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_DACL_AUTO_INHERITED)?;

        Ok(Self {
            revision: value.Revision,
            owner: unsafe { value.Owner.0.cast::<SID>().as_ref() }
                .map(Sid::try_from)
                .transpose()?,
            group: unsafe { value.Group.0.cast::<SID>().as_ref() }
                .map(Sid::try_from)
                .transpose()?,
            sacl,
            dacl,
        })
    }
}

pub struct SecurityAttributes {
    pub security_descriptor: Option<SecurityDescriptor>,
    pub inherit_handle: bool,
}

pub struct RawSecurityAttributes {
    _security_descriptor: Option<RawSecurityDescriptor>,
    raw: SECURITY_ATTRIBUTES,
}

impl RawSecurityAttributes {
    pub fn raw(&self) -> &SECURITY_ATTRIBUTES {
        &self.raw
    }
}

impl TryFrom<&SecurityAttributes> for RawSecurityAttributes {
    type Error = anyhow::Error;

    fn try_from(value: &SecurityAttributes) -> Result<Self, Self::Error> {
        let security_descriptor = value
            .security_descriptor
            .as_ref()
            .map(RawSecurityDescriptor::try_from)
            .transpose()?;

        let raw = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as _,
            lpSecurityDescriptor: security_descriptor
                .as_ref()
                .map_or_else(ptr::null_mut, |x| x.raw() as *const _ as _),
            bInheritHandle: value.inherit_handle.into(),
        };

        Ok(Self {
            _security_descriptor: security_descriptor,
            raw,
        })
    }
}

pub fn create_directory(path: &Path, security_attributes: &SecurityAttributes) -> Result<()> {
    let path = WideString::from(path);

    let security_attributes = RawSecurityAttributes::try_from(security_attributes)?;

    unsafe { CreateDirectoryW(path.as_pcwstr(), Some(security_attributes.raw())) }?;

    Ok(())
}
