use std::{
    any::Any,
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
        RTL_USER_PROCESS_PARAMETERS, SECURITY_MAX_SID_SIZE, TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION,
        TOKEN_SECURITY_ATTRIBUTES_INFORMATION, TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1,
        TOKEN_SECURITY_ATTRIBUTE_FLAG, TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE,
        TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, TOKEN_SECURITY_ATTRIBUTE_OPERATION, TOKEN_SECURITY_ATTRIBUTE_TYPE,
        TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN, TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64, TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID,
        TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING, TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING,
        TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64, TOKEN_SECURITY_ATTRIBUTE_V1, TOKEN_SECURITY_ATTRIBUTE_V1_VALUE,
    }, Token,
};
use windows::{
    core::{Interface, HRESULT, PCSTR, PWSTR},
    Win32::{
        Foundation::{
            DuplicateHandle, FreeLibrary, LocalFree, CRYPT_E_BAD_MSG, DUPLICATE_SAME_ACCESS, ERROR_ALREADY_EXISTS,
            ERROR_INCORRECT_SIZE, ERROR_INVALID_SECURITY_DESCR, ERROR_INVALID_SID, ERROR_INVALID_VARIANT,
            ERROR_NO_TOKEN, ERROR_SUCCESS, HLOCAL, HWND, INVALID_HANDLE_VALUE, LUID, NTE_BAD_ALGID, S_OK,
            TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN,
            UNICODE_STRING, WAIT_EVENT, WAIT_FAILED,
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
            TokenSecurityAttributes,
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
                COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, COINIT_MULTITHREADED, STGM_READ,
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
            SystemServices::{ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION, SE_GROUP_LOGON_ID},
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
                CommandLineToArgvW, CreateProfile, IShellLinkW, LoadUserProfileW, ShellExecuteExW, ShellLink,
                PROFILEINFOW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, SLGP_SHORTPATH, SLR_NO_UI,
            },
            WindowsAndMessaging::SHOW_WINDOW_CMD,
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