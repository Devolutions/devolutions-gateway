use std::fs::{self, File};
use std::io::{ErrorKind, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::MetadataExt as _;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use camino::Utf8Path;
use win_api_wrappers::identity::sid::{Sid, StringSid};
use win_api_wrappers::process::Process;
use win_api_wrappers::raw::Win32::Security::Authorization::GRANT_ACCESS;
use win_api_wrappers::raw::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use win_api_wrappers::raw::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
use win_api_wrappers::security::attributes::SecurityAttributesInit;
use win_api_wrappers::security::privilege;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
    LUID, LocalFree,
};
use windows::Win32::Security::Authorization::{
    AUTHZ_CLIENT_CONTEXT_HANDLE, AUTHZ_RESOURCE_MANAGER_HANDLE, AUTHZ_RM_FLAG_NO_AUDIT, AuthzContextInfoGroupsSids,
    AuthzFreeContext, AuthzFreeResourceManager, AuthzGetInformationFromContext, AuthzInitializeContextFromSid,
    AuthzInitializeResourceManager, GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::Win32::Security::{
    self, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_RENAME_INFO_0, FILE_SHARE_DELETE,
    FILE_SHARE_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, FileDispositionInfo, FileIdInfo,
    FileRenameInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, READ_CONTROL, SYNCHRONIZE,
    SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
};
use windows::core::{BOOL, PCWSTR};
use zeroize::{Zeroize as _, Zeroizing};

const ENTROPY: &[u8] = b"Devolutions.Agent.PendingEnrollment.v1";
const ENROLLMENT_DIRECTORY_NOT_READY: &str = "the Devolutions Agent service has not prepared the enrollment directory yet; start the Devolutions Agent service once, then retry";

fn user_sid() -> anyhow::Result<Sid> {
    Ok(Token::current_process_token()
        .sid_and_attributes()
        .context("get current user SID")?
        .sid)
}

fn system_sid() -> anyhow::Result<Sid> {
    Sid::from_well_known(Security::WinLocalSystemSid, None).context("get SYSTEM SID")
}

fn administrators_sid() -> anyhow::Result<Sid> {
    Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None).context("get Administrators SID")
}

fn owner_rights_sid() -> anyhow::Result<Sid> {
    StringSid::from_str("OW")?.to_sid().context("get OWNER RIGHTS SID")
}

fn allowed_principals(system: &Sid, user: &Sid, grant_current_user: bool) -> Vec<Sid> {
    let mut principals = vec![system.clone()];
    if grant_current_user && user != system {
        principals.push(user.clone());
    }
    principals
}

fn directory_aces(
    system: &Sid,
    user: &Sid,
    administrators: &Sid,
    grant_current_user: bool,
    pending_drop_box: bool,
) -> Vec<(Sid, u32, u32)> {
    let mut entries = expected_aces(
        &allowed_principals(system, user, grant_current_user),
        Security::CONTAINER_INHERIT_ACE | Security::OBJECT_INHERIT_ACE,
    );
    if pending_drop_box {
        entries.push((
            administrators.clone(),
            FILE_ADD_FILE.0 | SYNCHRONIZE.0,
            Security::NO_INHERITANCE.0,
        ));
    }
    entries
}

fn pending_base_aces(system: &Sid, user: &Sid, grant_current_user: bool) -> Vec<(Sid, u32, u32)> {
    expected_aces(
        &allowed_principals(system, user, grant_current_user),
        Security::NO_INHERITANCE,
    )
}

fn pending_file_aces(system: &Sid, user: &Sid, owner_rights: &Sid, grant_current_user: bool) -> Vec<(Sid, u32, u32)> {
    let mut entries = pending_base_aces(system, user, grant_current_user);
    entries.push((owner_rights.clone(), 0, Security::NO_INHERITANCE.0));
    entries
}

fn pending_aces_are_allowed(
    actual: &[(Sid, u32, u32)],
    system: &Sid,
    user: &Sid,
    owner_rights: &Sid,
    grant_current_user: bool,
    administrator_owner: bool,
) -> bool {
    let mut actual = actual.to_vec();
    actual.sort();
    let mut base = pending_base_aces(system, user, grant_current_user);
    base.sort();
    if !administrator_owner && actual == base {
        return true;
    }
    base.push((owner_rights.clone(), 0, Security::NO_INHERITANCE.0));
    base.sort();
    actual == base
}

pub(crate) fn is_system() -> anyhow::Result<bool> {
    Ok(user_sid()? == system_sid()?)
}

pub(crate) fn is_administrator_writer() -> anyhow::Result<bool> {
    Ok(!is_system()? && current_user_is_administrator()?)
}

fn current_user_is_administrator() -> anyhow::Result<bool> {
    let administrators = administrators_sid()?;
    let mut is_member = BOOL::default();
    // SAFETY: A null token selects the effective current token and the output pointer is writable.
    unsafe { Security::CheckTokenMembership(None, administrators.as_psid_const(), &mut is_member) }
        .context("check administrator group membership")?;
    Ok(is_member.as_bool())
}

pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

pub(crate) fn create_protected_directory(
    path: &Utf8Path,
    grant_current_user: bool,
    pending_drop_box: bool,
) -> anyhow::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;

    let system = system_sid()?;
    let user = user_sid()?;
    ensure!(
        grant_current_user || user == system,
        "identity directory must be created by SYSTEM"
    );
    let expected = directory_aces(
        &system,
        &user,
        &administrators_sid()?,
        grant_current_user,
        pending_drop_box,
    );
    if let Err(error) = fs::symlink_metadata(path)
        && error.kind() == ErrorKind::NotFound
    {
        let attributes = SecurityAttributesInit {
            owner: Some(user.clone()),
            dacl: Some(protected_dacl(&expected)?),
            ..Default::default()
        }
        .init();
        let parent = path.parent().context("identity directory has no parent")?;
        let name = path.file_name().context("identity directory has no name")?;
        let long_path = fs::canonicalize(parent)?.join(name);
        if let Err(error) = win_api_wrappers::fs::create_directory(&long_path, Some(&attributes))
            && fs::symlink_metadata(path).is_err()
        {
            return Err(error).context("create protected identity directory");
        }
    }
    let mut options = fs::OpenOptions::new();
    options
        .access_mode((FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER).0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0);
    let directory = options.open(path)?;
    let metadata = directory.metadata()?;
    ensure!(
        metadata.file_type().is_dir() && !is_reparse_point(&metadata),
        "identity directory is not a regular directory"
    );
    ensure_acl_volume(&directory)?;
    let (owner, descriptor) = owner_and_dacl(&directory)?;
    let owner_is_trusted = owner == system || owner == user;
    if !owner_is_trusted || verify_dacl(descriptor.0, expected.clone()).is_err() {
        // A foreign owner could widen its own DACL again, so repair ownership and access together.
        let dacl = protected_dacl(&expected)?;
        let mut security_info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        if !owner_is_trusted {
            security_info |= OWNER_SECURITY_INFORMATION;
        }
        // SAFETY: The directory handle, optional owner SID, and protected DACL remain live for the call.
        unsafe {
            SetSecurityInfo(
                HANDLE(directory.as_raw_handle()),
                SE_FILE_OBJECT,
                security_info,
                (!owner_is_trusted).then_some(user.as_psid_const()),
                None,
                Some(dacl.acl.as_ptr().cast()),
                None,
            )
            .ok()
        }
        .context("protect identity directory")?;
        let (repaired_owner, repaired) = owner_and_dacl(&directory)?;
        ensure!(
            repaired_owner == system || repaired_owner == user,
            "identity directory owner is not trusted"
        );
        verify_dacl(repaired.0, expected)?;
    }
    Ok(())
}

pub(crate) fn verify_protected_directory(
    file: &File,
    grant_current_user: bool,
    pending_drop_box: bool,
) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_dir() && !is_reparse_point(&metadata),
        "identity directory is not a regular directory"
    );
    ensure_acl_volume(file)?;
    let system = system_sid()?;
    let user = user_sid()?;
    let (owner, descriptor) = owner_and_dacl(file)?;
    ensure!(
        owner == system || owner == user,
        "identity directory owner is not trusted"
    );
    verify_dacl(
        descriptor.0,
        directory_aces(
            &system,
            &user,
            &administrators_sid()?,
            grant_current_user,
            pending_drop_box,
        ),
    )
}

pub(crate) fn create_private_file(
    path: &Utf8Path,
    grant_current_user: bool,
    pending_blob: bool,
) -> anyhow::Result<File> {
    let system = system_sid()?;
    let user = user_sid()?;
    ensure!(
        grant_current_user || user == system,
        "pending enrollment file must be written by SYSTEM"
    );
    let expected = if pending_blob {
        pending_base_aces(&system, &user, grant_current_user)
    } else {
        expected_aces(
            &allowed_principals(&system, &user, grant_current_user),
            Security::NO_INHERITANCE,
        )
    };
    let create_dacl = protected_dacl(&expected)?;
    let attributes = SecurityAttributesInit {
        owner: Some(user.clone()),
        dacl: Some(create_dacl),
        ..Default::default()
    }
    .init();
    let parent = path.parent().context("identity file has no parent directory")?;
    let name = path.file_name().context("identity file has no name")?;
    let long_path = fs::canonicalize(parent)?.join(name);
    use std::os::windows::io::FromRawHandle as _;

    let wide: Vec<_> = long_path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: The path and protected security attributes remain live until CreateFileW returns.
    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0 | WRITE_DAC.0 | DELETE.0,
            FILE_SHARE_DELETE,
            Some(attributes.as_ptr()),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .context("create protected identity file")?;
    // SAFETY: CreateFileW returned an owned handle that File now closes.
    let file = unsafe { File::from_raw_handle(handle.0) };
    ensure_acl_volume(&file)?;

    require_protected_dacl(&file, &user, expected)?;
    Ok(file)
}

pub(crate) fn submit_pending_as_administrator(
    data_dir: &Utf8Path,
    path: &Utf8Path,
    contents: &[u8],
) -> anyhow::Result<()> {
    let started = Instant::now();
    verify_system_provisioned_drop_box(data_dir, started)?;
    submit_pending_into_drop_box(data_dir, path, contents, started)
}

fn retry_sharing_violation<T>(started: Instant, mut operation: impl FnMut() -> anyhow::Result<T>) -> anyhow::Result<T> {
    loop {
        match operation() {
            Err(error) if is_sharing_violation(&error) => {
                let remaining = Duration::from_secs(10).saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(error);
                }
                std::thread::sleep(remaining.min(Duration::from_millis(100)));
            }
            result => return result,
        }
    }
}

fn is_sharing_violation(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|source| {
            source.raw_os_error().and_then(|code| u32::try_from(code).ok()) == Some(ERROR_SHARING_VIOLATION.0)
        }) || cause
            .downcast_ref::<windows::core::Error>()
            .is_some_and(|source| source.code() == ERROR_SHARING_VIOLATION.to_hresult())
    })
}

fn explain_unprepared_drop_box(error: anyhow::Error) -> anyhow::Error {
    if error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|source| matches!(source.kind(), ErrorKind::NotFound | ErrorKind::PermissionDenied))
    {
        error.context(ENROLLMENT_DIRECTORY_NOT_READY)
    } else {
        error
    }
}

fn verify_drop_box_directory(directory: &File, pending_drop_box: bool) -> anyhow::Result<()> {
    verify_protected_directory(directory, false, pending_drop_box)?;
    let (owner, _) = owner_and_dacl(directory)?;
    ensure!(owner == system_sid()?, "identity drop box is not SYSTEM-provisioned");
    Ok(())
}

fn verify_system_provisioned_drop_box(data_dir: &Utf8Path, started: Instant) -> anyhow::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    let metadata = fs::symlink_metadata(data_dir)
        .context("inspect identity data directory")
        .map_err(explain_unprepared_drop_box)?;
    ensure!(
        metadata.file_type().is_dir() && !is_reparse_point(&metadata),
        "identity data directory is not a regular directory"
    );
    let mut token = Process::current_process()
        .token(TOKEN_DUPLICATE | TOKEN_QUERY)
        .context("open administrator token")?
        .duplicate(
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
            None,
            SecurityImpersonation,
            Security::TokenImpersonation,
        )
        .context("duplicate administrator token")?;
    token
        .enable_privilege(privilege::SE_BACKUP_NAME)
        .context("enable administrator backup privilege")?;
    let _impersonation = token
        .impersonate()
        .context("impersonate administrator for ACL inspection")?;

    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .access_mode((FILE_READ_ATTRIBUTES | READ_CONTROL).0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0);
    let base = fs::canonicalize(data_dir)?;
    let data_directory = retry_sharing_violation(started, || {
        options.open(&base).context("inspect identity data directory")
    })?;
    ensure_acl_volume(&data_directory)?;
    let identity_path = base.join("identity");
    let identity = retry_sharing_violation(started, || {
        options
            .open(&identity_path)
            .context("inspect protected identity directory")
    })
    .map_err(explain_unprepared_drop_box)?;
    verify_drop_box_directory(&identity, false).context(ENROLLMENT_DIRECTORY_NOT_READY)?;
    let pending_path = identity_path.join("pending");
    let pending = retry_sharing_violation(started, || {
        options
            .open(&pending_path)
            .context("inspect protected pending drop box")
    })
    .map_err(explain_unprepared_drop_box)?;
    verify_drop_box_directory(&pending, true).context(ENROLLMENT_DIRECTORY_NOT_READY)?;
    for directory in [&identity, &pending] {
        ensure!(
            volume_serial(directory)? == volume_serial(&data_directory)?,
            "identity drop box resolves to another volume"
        );
    }
    Ok(())
}

fn submit_pending_into_drop_box(
    data_dir: &Utf8Path,
    path: &Utf8Path,
    contents: &[u8],
    started: Instant,
) -> anyhow::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;

    let metadata = fs::symlink_metadata(data_dir)?;
    ensure!(
        metadata.file_type().is_dir() && !is_reparse_point(&metadata),
        "identity data directory is not a regular directory"
    );
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0);
    let data_directory = retry_sharing_violation(started, || options.open(data_dir).map_err(Into::into))?;
    ensure_acl_volume(&data_directory)?;
    let pending_dir = data_dir.join("identity").join("pending");
    ensure!(
        path.parent() == Some(pending_dir.as_path()),
        "pending file is outside the drop box"
    );
    let name = path.file_name().context("pending file has no name")?;
    let long_dir = fs::canonicalize(data_dir)?.join("identity").join("pending");
    let (mut file, staging) = create_pending_staging(&long_dir, name, started)?;
    let published = (|| -> anyhow::Result<bool> {
        ensure_acl_volume(&file)?;
        verify_staging_destination(&data_directory, &file, &staging)?;
        file.write_all(contents).context("write pending enrollment")?;
        file.sync_all().context("sync pending enrollment")?;
        let published = publish_staged_pending(&file, &long_dir.join(name))?;
        if published {
            file.sync_all().context("sync published pending enrollment")?;
        }
        Ok(published)
    })();
    if !matches!(published, Ok(true)) {
        let discard = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: The handle has DELETE access and the disposition structure stays live for the call.
        let _ = unsafe {
            SetFileInformationByHandle(
                HANDLE(file.as_raw_handle()),
                FileDispositionInfo,
                (&raw const discard).cast(),
                u32::try_from(size_of::<FILE_DISPOSITION_INFO>())?,
            )
        };
    }
    published.map(|_| ())
}

fn create_pending_staging(
    long_dir: &std::path::Path,
    name: &str,
    started: Instant,
) -> anyhow::Result<(File, std::path::PathBuf)> {
    use std::os::windows::io::FromRawHandle as _;

    let staging = long_dir.join(format!(".{name}-{}.tmp", uuid::Uuid::new_v4()));
    let wide: Vec<_> = staging.as_os_str().encode_wide().chain(Some(0)).collect();

    let system = system_sid()?;
    let user = user_sid()?;
    let attributes = SecurityAttributesInit {
        owner: Some(user.clone()),
        dacl: Some(protected_dacl(&pending_file_aces(
            &system,
            &user,
            &owner_rights_sid()?,
            false,
        ))?),
        ..Default::default()
    }
    .init();
    let handle = retry_sharing_violation(started, || {
        // SAFETY: The path and protected security attributes remain live until CreateFileW returns.
        unsafe {
            CreateFileW(
                PCWSTR::from_raw(wide.as_ptr()),
                FILE_WRITE_DATA.0 | DELETE.0 | SYNCHRONIZE.0,
                FILE_SHARE_NONE,
                Some(attributes.as_ptr()),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(anyhow::Error::new)
    })
    .context("submit pending enrollment")?;
    // SAFETY: CreateFileW returned an owned handle transferred to File for closing.
    let file = unsafe { File::from_raw_handle(handle.0) };
    Ok((file, staging))
}

fn verify_staging_destination(data_directory: &File, staged: &File, expected: &std::path::Path) -> anyhow::Result<()> {
    use std::os::windows::io::AsRawHandle as _;

    ensure!(
        volume_serial(data_directory)? == volume_serial(staged)?,
        "pending drop box resolves to another volume"
    );

    let mut name = vec![0u16; 512];
    loop {
        // SAFETY: The staged file handle remains open and the UTF-16 output buffer is writable.
        let length =
            unsafe { GetFinalPathNameByHandleW(HANDLE(staged.as_raw_handle()), &mut name, FILE_NAME_NORMALIZED) };
        ensure!(length != 0, "inspect pending destination failed");
        let length = usize::try_from(length)?;
        if length < name.len() {
            let actual = String::from_utf16(&name[..length]).context("pending destination is not UTF-16")?;
            ensure!(
                expected.as_os_str().to_string_lossy().eq_ignore_ascii_case(&actual),
                "pending drop box resolves outside the data directory"
            );
            return Ok(());
        }
        name.resize(length + 1, 0);
    }
}

fn volume_serial(file: &File) -> anyhow::Result<u64> {
    use std::os::windows::io::AsRawHandle as _;

    let mut info = FILE_ID_INFO::default();
    // SAFETY: The live file handle and exact-size writable FILE_ID_INFO buffer are valid.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&raw mut info).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>())?,
        )
    }
    .context("inspect pending volume")?;
    Ok(info.VolumeSerialNumber)
}

#[expect(
    clippy::multiple_unsafe_ops_per_block,
    reason = "initializing one bounded variable-length FILE_RENAME_INFO is one logical operation"
)]
fn publish_staged_pending(file: &File, destination: &std::path::Path) -> anyhow::Result<bool> {
    use std::os::windows::io::AsRawHandle as _;

    let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .context("pending filename is too long")?;
    let name_offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = size_of::<FILE_RENAME_INFO>()
        .checked_add(name_bytes)
        .context("pending rename information is too large")?;
    let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: The aligned buffer fits the rename structure and its complete UTF-16 filename.
    unsafe {
        (*info).Anonymous = FILE_RENAME_INFO_0 { Flags: 0 };
        (*info).RootDirectory = HANDLE::default();
        (*info).FileNameLength = u32::try_from(name_bytes)?;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            buffer.as_mut_ptr().cast::<u8>().add(name_offset).cast(),
            name.len(),
        );
    }
    // SAFETY: The file and directory handles and initialized rename buffer remain live for the call.
    match unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileRenameInfo,
            buffer.as_ptr().cast(),
            u32::try_from(size)?,
        )
    } {
        Ok(()) => Ok(true),
        Err(error)
            if error.code() == ERROR_FILE_EXISTS.to_hresult() || error.code() == ERROR_ALREADY_EXISTS.to_hresult() =>
        {
            Ok(false)
        }
        Err(error) => Err(error).context("publish pending enrollment"),
    }
}

pub(crate) fn verify_installed_file(file: &File, grant_current_user: bool, pending_blob: bool) -> anyhow::Result<()> {
    let system = system_sid()?;
    let user = user_sid()?;
    let expected = if pending_blob {
        pending_base_aces(&system, &user, grant_current_user)
    } else {
        expected_aces(
            &allowed_principals(&system, &user, grant_current_user),
            Security::NO_INHERITANCE,
        )
    };
    require_protected_dacl(file, &user, expected)
}

pub(crate) fn verify_pending_read(file: &File, grant_current_user: bool) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file() && !is_reparse_point(&metadata),
        "pending enrollment path is not a regular file"
    );
    ensure_acl_volume(file)?;
    let (owner, descriptor) = owner_and_dacl(file)?;
    verify_pending_owner_and_dacl(&owner, descriptor.0, grant_current_user)
}

pub(crate) fn verify_pending_path(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && !is_reparse_point(&metadata),
        "pending enrollment path is not a regular file"
    );
    let (owner, descriptor) = named_owner_and_dacl(path)?;
    verify_pending_owner_and_dacl(&owner, descriptor.0, grant_current_user)
}

fn verify_pending_owner_and_dacl(
    owner: &Sid,
    descriptor: PSECURITY_DESCRIPTOR,
    grant_current_user: bool,
) -> anyhow::Result<()> {
    let system = system_sid()?;
    let user = user_sid()?;
    let owner_rights = owner_rights_sid()?;
    let administrator_owner = owner != &system && owner != &user && owner_is_administrator_member(owner)?;
    ensure!(
        pending_owner_is_allowed(&system, &user, owner, administrator_owner),
        "pending enrollment file owner is not trusted"
    );
    ensure!(
        pending_aces_are_allowed(
            &read_dacl(descriptor)?,
            &system,
            &user,
            &owner_rights,
            grant_current_user,
            administrator_owner
        ),
        "pending enrollment DACL grants unexpected access"
    );
    Ok(())
}

fn pending_owner_is_allowed(system: &Sid, user: &Sid, owner: &Sid, administrator_owner: bool) -> bool {
    owner == system || owner == user || administrator_owner
}

pub(crate) fn verify_trusted_state_file(file: &File) -> anyhow::Result<()> {
    ensure_acl_volume(file)?;
    let (owner, descriptor) = owner_and_dacl(file)?;
    verify_trusted_owner_and_dacl(&owner, descriptor.0)
}

pub(crate) fn verify_trusted_state_path(path: &Utf8Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && !is_reparse_point(&metadata),
        "identity state path is not a regular file"
    );
    let (owner, descriptor) = named_owner_and_dacl(path)?;
    verify_trusted_owner_and_dacl(&owner, descriptor.0)
}

fn verify_trusted_owner_and_dacl(owner: &Sid, descriptor: PSECURITY_DESCRIPTOR) -> anyhow::Result<()> {
    let system = system_sid()?;
    let user = user_sid()?;
    let owner_rights = owner_rights_sid()?;
    ensure!(
        owner == &system || owner == &user,
        "identity state file owner is not trusted"
    );
    ensure!(
        read_dacl(descriptor)?.iter().all(|(sid, mask, flags)| {
            *flags == Security::NO_INHERITANCE.0
                && (sid == &system || sid == &user || sid == &owner_rights && *mask == 0)
        }),
        "identity state file DACL grants access to another principal"
    );
    Ok(())
}

fn ensure_acl_volume(file: &File) -> anyhow::Result<()> {
    use std::os::windows::io::AsRawHandle as _;

    use win_api_wrappers::raw::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;

    let mut flags = 0;
    // SAFETY: The handle is live, and the volume-flags output pointer is writable.
    unsafe { GetVolumeInformationByHandleW(HANDLE(file.as_raw_handle()), None, None, None, Some(&mut flags), None) }
        .context("inspect identity file volume")?;
    ensure!(
        flags & FILE_PERSISTENT_ACLS != 0,
        "identity file volume does not enforce ACLs"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn assert_pending_protection(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    let file = crate::private_file::open_pending_read(path, grant_current_user)?;
    verify_installed_file(&file, grant_current_user, true)
}

#[cfg(test)]
pub(crate) fn set_test_directory_access(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    use win_api_wrappers::security::acl::set_named_security_info;
    use win_api_wrappers::str::U16CString;

    let parent = path.parent().context("test directory has no parent")?;
    let name = path.file_name().context("test directory has no name")?;
    let full_path = fs::canonicalize(parent)?.join(name);
    let wide = U16CString::from_os_str(full_path.as_os_str())?;
    let dacl = protected_dacl(&directory_aces(
        &system_sid()?,
        &user_sid()?,
        &administrators_sid()?,
        grant_current_user,
        false,
    ))?;
    set_named_security_info(&wide, SE_FILE_OBJECT, None, None, Some(&dacl), None)
}

pub(crate) fn replace_file(source: &Utf8Path, destination: &Utf8Path) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    let full_path = |path: &Utf8Path| -> anyhow::Result<Vec<u16>> {
        let parent = path.parent().context("identity file has no parent directory")?;
        let name = path.file_name().context("identity file has no name")?;
        Ok(fs::canonicalize(parent)?
            .join(name)
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect())
    };
    let source = full_path(source)?;
    let destination = full_path(destination)?;
    // SAFETY: Both extended-length paths are NUL-terminated and remain live for this call.
    unsafe {
        MoveFileExW(
            PCWSTR::from_raw(source.as_ptr()),
            PCWSTR::from_raw(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .context("atomically replace identity file")
}

fn protected_dacl(entries: &[(Sid, u32, u32)]) -> anyhow::Result<InheritableAcl> {
    let entries: Vec<_> = entries
        .iter()
        .map(|(sid, mask, flags)| ExplicitAccess {
            access_permissions: *mask,
            access_mode: GRANT_ACCESS,
            inheritance: Security::ACE_FLAGS(*flags),
            trustee: Trustee::Sid(sid.clone()),
        })
        .collect();
    Ok(InheritableAcl {
        kind: InheritableAclKind::Protected,
        acl: Acl::new()
            .and_then(|acl| acl.set_entries(&entries))
            .context("build protected identity DACL")?,
    })
}

fn expected_aces(principals: &[Sid], inheritance: Security::ACE_FLAGS) -> Vec<(Sid, u32, u32)> {
    principals
        .iter()
        .cloned()
        .map(|sid| (sid, FILE_ALL_ACCESS.0, inheritance.0))
        .collect()
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
            unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }
}

struct AuthzResourceManager(AUTHZ_RESOURCE_MANAGER_HANDLE);

impl Drop for AuthzResourceManager {
    fn drop(&mut self) {
        // SAFETY: AuthzInitializeResourceManager returned this owned handle.
        let _ = unsafe { AuthzFreeResourceManager(self.0) };
    }
}

struct AuthzContext(AUTHZ_CLIENT_CONTEXT_HANDLE);

impl Drop for AuthzContext {
    fn drop(&mut self) {
        // SAFETY: AuthzInitializeContextFromSid returned this owned handle.
        let _ = unsafe { AuthzFreeContext(self.0) };
    }
}

fn owner_is_administrator_member(owner: &Sid) -> anyhow::Result<bool> {
    let administrators = administrators_sid()?;
    if owner == &administrators {
        return Ok(true);
    }
    match authz_administrator_membership(owner, &administrators) {
        Ok(is_member) => Ok(is_member),
        Err(error) => {
            if win_api_wrappers::netmgmt::get_local_admin_group_members()
                .context("list local administrators")?
                .contains(owner)
            {
                Ok(true)
            } else {
                Err(error).context("verify pending owner administrator membership")
            }
        }
    }
}

fn authz_administrator_membership(owner: &Sid, administrators: &Sid) -> anyhow::Result<bool> {
    let mut manager = AUTHZ_RESOURCE_MANAGER_HANDLE::default();
    // SAFETY: The output pointer is writable and the callbacks and name are intentionally absent.
    unsafe { AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT.0, None, None, None, PCWSTR::null(), &mut manager) }
        .context("initialize administrator membership check")?;
    let manager = AuthzResourceManager(manager);

    let mut context = AUTHZ_CLIENT_CONTEXT_HANDLE::default();
    // SAFETY: The SID and resource manager stay live until the context has been freed.
    unsafe {
        AuthzInitializeContextFromSid(
            0,
            owner.as_psid_const(),
            manager.0,
            None,
            LUID::default(),
            None,
            &mut context,
        )
    }
    .context("resolve pending file owner groups")?;
    let context = AuthzContext(context);

    let mut required = 0;
    // SAFETY: The zero-length query writes only the required buffer size.
    let _ = unsafe {
        AuthzGetInformationFromContext(
            context.0,
            AuthzContextInfoGroupsSids,
            0,
            &mut required,
            std::ptr::null_mut(),
        )
    };
    let size = usize::try_from(required)?;
    ensure!(
        size >= size_of::<Security::TOKEN_GROUPS>(),
        "invalid administrator group list size"
    );
    let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
    // SAFETY: The word-aligned buffer has at least `required` writable bytes.
    unsafe {
        AuthzGetInformationFromContext(
            context.0,
            AuthzContextInfoGroupsSids,
            required,
            &mut required,
            buffer.as_mut_ptr().cast(),
        )
    }
    .context("read pending file owner groups")?;
    // SAFETY: AuthzGetInformationFromContext filled the aligned buffer with a TOKEN_GROUPS header.
    let groups = unsafe { &*buffer.as_ptr().cast::<Security::TOKEN_GROUPS>() };
    let count = usize::try_from(groups.GroupCount)?;
    let bytes = count
        .checked_mul(size_of::<Security::SID_AND_ATTRIBUTES>())
        .and_then(|bytes| bytes.checked_add(std::mem::offset_of!(Security::TOKEN_GROUPS, Groups)))
        .context("invalid administrator group list size")?;
    ensure!(bytes <= size, "invalid administrator group list size");
    // SAFETY: The verified count fits the Authz-allocated TOKEN_GROUPS buffer.
    let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) };
    for entry in entries {
        // SAFETY: AuthzGetInformationFromContext returned a valid SID in each group entry.
        if unsafe { Sid::from_psid(entry.Sid) }? == *administrators {
            return Ok(true);
        }
    }
    Ok(false)
}

fn require_protected_dacl(file: &File, expected_owner: &Sid, expected: Vec<(Sid, u32, u32)>) -> anyhow::Result<()> {
    let (owner, descriptor) = owner_and_dacl(file)?;
    ensure!(owner == *expected_owner, "identity file owner is not the expected user");
    verify_dacl(descriptor.0, expected)
}

fn named_owner_and_dacl(path: &Utf8Path) -> anyhow::Result<(Sid, SecurityDescriptor)> {
    let parent = path.parent().context("identity state path has no parent")?;
    let name = path.file_name().context("identity state path has no name")?;
    let full_path = fs::canonicalize(parent)?.join(name);
    let wide: Vec<_> = full_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = SecurityDescriptor(PSECURITY_DESCRIPTOR::default());
    let mut owner = Security::PSID::default();
    // SAFETY: The path is NUL-terminated and the security-descriptor outputs are writable.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut descriptor.0,
        )
    };
    status.ok().context("inspect identity state DACL")?;
    ensure!(!owner.0.is_null(), "identity state path has no owner");
    // SAFETY: The owner SID points into the descriptor retained until this function returns.
    let owner = unsafe { Sid::from_psid(owner) }.context("read identity state owner")?;
    Ok((owner, descriptor))
}

fn owner_and_dacl(file: &File) -> anyhow::Result<(Sid, SecurityDescriptor)> {
    use std::os::windows::io::AsRawHandle as _;

    let mut descriptor = SecurityDescriptor(PSECURITY_DESCRIPTOR::default());
    let mut owner = Security::PSID::default();
    // SAFETY: The file handle is live and both output pointers are writable.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor.0),
        )
    };
    status.ok().context("inspect identity file DACL")?;
    ensure!(!owner.0.is_null(), "identity file has no owner");
    // SAFETY: The owner SID points into the descriptor retained until this function returns.
    let owner = unsafe { Sid::from_psid(owner) }.context("read identity file owner")?;
    Ok((owner, descriptor))
}

fn verify_dacl(descriptor: PSECURITY_DESCRIPTOR, mut expected: Vec<(Sid, u32, u32)>) -> anyhow::Result<()> {
    let mut actual = read_dacl(descriptor)?;
    expected.sort();
    actual.sort();
    ensure!(actual == expected, "identity DACL grants unexpected access");
    Ok(())
}

fn read_dacl(descriptor: PSECURITY_DESCRIPTOR) -> anyhow::Result<Vec<(Sid, u32, u32)>> {
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: The descriptor remains live through this call.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }?;
    ensure!(
        control & SE_DACL_PROTECTED.0 != 0,
        "identity file DACL is not protected"
    );

    let mut present = BOOL::default();
    let mut defaulted = BOOL::default();
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: The descriptor remains live and output pointers are writable.
    unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }?;
    ensure!(present.as_bool() && !acl.is_null(), "identity file has no DACL");
    // SAFETY: GetSecurityDescriptorDacl returned a live ACL within the descriptor.
    let count = unsafe { (*acl).AceCount };
    let mut actual = Vec::new();
    for index in 0..u32::from(count) {
        let mut raw = std::ptr::null_mut();
        // SAFETY: The index is less than the ACL's ACE count.
        unsafe { GetAce(acl, index, &mut raw) }?;
        ensure!(!raw.is_null(), "identity file has an invalid ACE");
        // SAFETY: GetAce returned a live entry with an ACE_HEADER.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        ensure!(
            u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE,
            "identity file has an unexpected ACE type"
        );
        // SAFETY: This is an access-allowed ACE, so Mask and SidStart exist.
        let entry = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        // SAFETY: GetAce returned a live access-allowed ACE with a valid SID.
        let sid = unsafe { Sid::from_psid(Security::PSID(std::ptr::addr_of!(entry.SidStart).cast_mut().cast())) }?;
        actual.push((sid, entry.Mask, u32::from(header.AceFlags)));
    }
    Ok(actual)
}

fn blob(bytes: &[u8]) -> anyhow::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len())?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

struct LocalBlob(CRYPT_INTEGER_BLOB);

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: CryptProtectData/CryptUnprotectData allocated this buffer with LocalAlloc.
            unsafe { LocalFree(Some(HLOCAL(self.0.pbData.cast()))) };
        }
    }
}

pub(crate) fn protect(contents: &[u8]) -> anyhow::Result<Vec<u8>> {
    let input = blob(contents)?;
    let entropy = blob(ENTROPY)?;
    let mut output = LocalBlob(CRYPT_INTEGER_BLOB::default());
    // SAFETY: Input and entropy remain valid, and the output buffer is writable for this call.
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    }
    .context("encrypt pending enrollment")?;
    ensure!(
        !output.0.pbData.is_null(),
        "encryption produced an empty pending enrollment"
    );
    // SAFETY: DPAPI returned a live allocation of cbData bytes, retained by output.
    Ok(unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec() })
}

pub(crate) fn unprotect(contents: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let input = blob(contents)?;
    let entropy = blob(ENTROPY)?;
    let mut output = LocalBlob(CRYPT_INTEGER_BLOB::default());
    // SAFETY: Input and entropy remain valid, and the output buffer is writable for this call.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    }
    .context("decrypt pending enrollment")?;
    ensure!(
        !output.0.pbData.is_null(),
        "decryption produced an empty pending enrollment"
    );
    // SAFETY: DPAPI returned a live allocation of cbData bytes, retained by output.
    let plaintext =
        Zeroizing::new(unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec() });
    // SAFETY: The DPAPI allocation remains writable until LocalBlob drops it.
    unsafe { std::slice::from_raw_parts_mut(output.0.pbData, output.0.cbData as usize) }.zeroize();
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use win_api_wrappers::security::acl::set_named_security_info;
    use win_api_wrappers::str::U16CString;

    use super::*;

    #[test]
    fn directory_acl_policy_grants_only_system_and_optional_current_user() -> anyhow::Result<()> {
        let system = system_sid()?;
        let other = Sid::from_well_known(Security::WinBuiltinUsersSid, None)?;
        let administrators = administrators_sid()?;
        assert_eq!(allowed_principals(&system, &other, false), vec![system.clone()]);
        assert_eq!(
            allowed_principals(&system, &other, true),
            vec![system.clone(), other.clone()]
        );
        assert_eq!(allowed_principals(&system, &system, true), vec![system.clone()]);

        let inherited = (Security::CONTAINER_INHERIT_ACE | Security::OBJECT_INHERIT_ACE).0;
        let owner_only = directory_aces(&system, &other, &administrators, false, false);
        assert_eq!(owner_only, vec![(system.clone(), FILE_ALL_ACCESS.0, inherited)]);
        assert_eq!(
            directory_aces(&system, &other, &administrators, false, true),
            vec![
                (system.clone(), FILE_ALL_ACCESS.0, inherited),
                (
                    administrators.clone(),
                    FILE_ADD_FILE.0 | SYNCHRONIZE.0,
                    Security::NO_INHERITANCE.0
                )
            ]
        );
        assert_eq!(
            directory_aces(&system, &other, &administrators, true, true),
            vec![
                (system, FILE_ALL_ACCESS.0, inherited),
                (other, FILE_ALL_ACCESS.0, inherited),
                (
                    administrators,
                    FILE_ADD_FILE.0 | SYNCHRONIZE.0,
                    Security::NO_INHERITANCE.0
                )
            ]
        );
        Ok(())
    }

    #[test]
    fn pending_file_acl_denies_implicit_owner_access() -> anyhow::Result<()> {
        let system = system_sid()?;
        let user = Sid::from_well_known(Security::WinBuiltinUsersSid, None)?;
        let owner_rights = owner_rights_sid()?;
        assert_eq!(
            pending_file_aces(&system, &user, &owner_rights, false),
            vec![
                (system.clone(), FILE_ALL_ACCESS.0, Security::NO_INHERITANCE.0),
                (owner_rights.clone(), 0, Security::NO_INHERITANCE.0)
            ]
        );
        assert_eq!(
            pending_file_aces(&system, &user, &owner_rights, true),
            vec![
                (system, FILE_ALL_ACCESS.0, Security::NO_INHERITANCE.0),
                (user, FILE_ALL_ACCESS.0, Security::NO_INHERITANCE.0),
                (owner_rights, 0, Security::NO_INHERITANCE.0)
            ]
        );
        Ok(())
    }

    #[test]
    fn drop_box_writer_cannot_reopen_its_file_and_replays_succeed() -> anyhow::Result<()> {
        use std::os::windows::fs::OpenOptionsExt as _;

        let data_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("drop-box-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&data_dir)?;
        crate::private_file::prepare_directories(&data_dir, true)?;
        let path = data_dir
            .join("identity")
            .join("pending")
            .join(format!("{}.dat", "a".repeat(64)));
        let lock = crate::state_lock::acquire(&data_dir, true)?;
        submit_pending_into_drop_box(&data_dir, &path, b"test payload", Instant::now())?;
        drop(lock);
        assert!(fs::symlink_metadata(&path)?.file_type().is_file());
        assert!(File::open(&path).is_err());
        assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::OpenOptions::new().access_mode(WRITE_DAC.0).open(&path).is_err());
        submit_pending_into_drop_box(&data_dir, &path, b"different payload", Instant::now())?;
        fs::remove_file(path)?;
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }

    #[test]
    fn interrupted_staging_does_not_block_a_replayed_enrollment() -> anyhow::Result<()> {
        let data_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("drop-box-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&data_dir)?;
        crate::private_file::prepare_directories(&data_dir, true)?;
        let name = format!("{}.dat", "e".repeat(64));
        let long_dir = fs::canonicalize(&data_dir)?.join("identity").join("pending");
        let (mut interrupted, staging) = create_pending_staging(&long_dir, &name, Instant::now())?;
        interrupted.write_all(b"incomplete DPAPI blob")?;
        drop(interrupted);
        assert!(fs::symlink_metadata(&staging)?.file_type().is_file());

        let pending = data_dir.join("identity").join("pending").join(name);
        submit_pending_into_drop_box(&data_dir, &pending, b"complete DPAPI blob", Instant::now())?;
        assert!(fs::symlink_metadata(&pending)?.file_type().is_file());
        fs::remove_file(staging)?;
        fs::remove_file(pending)?;
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }

    #[test]
    fn drop_box_writer_can_traverse_an_identity_directory_without_read_access() -> anyhow::Result<()> {
        let data_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("drop-box-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&data_dir)?;
        crate::private_file::prepare_directories(&data_dir, true)?;
        let identity = data_dir.join("identity");
        let pending = identity.join("pending");
        let identity_name = U16CString::from_os_str(fs::canonicalize(&identity)?.as_os_str())?;
        let pending_name = U16CString::from_os_str(fs::canonicalize(&pending)?.as_os_str())?;
        let system = system_sid()?;
        let user = user_sid()?;
        let administrators = administrators_sid()?;
        let identity_private = protected_dacl(&directory_aces(&system, &user, &administrators, false, false))?;
        let pending_add_only = protected_dacl(&[
            (
                system.clone(),
                FILE_ALL_ACCESS.0,
                (Security::CONTAINER_INHERIT_ACE | Security::OBJECT_INHERIT_ACE).0,
            ),
            (
                user.clone(),
                FILE_ADD_FILE.0 | SYNCHRONIZE.0,
                Security::NO_INHERITANCE.0,
            ),
        ])?;
        set_named_security_info(&pending_name, SE_FILE_OBJECT, None, None, Some(&pending_add_only), None)?;
        set_named_security_info(
            &identity_name,
            SE_FILE_OBJECT,
            None,
            None,
            Some(&identity_private),
            None,
        )?;

        assert!(fs::read_dir(&identity).is_err());
        assert!(fs::read_dir(&pending).is_err());
        let path = pending.join(format!("{}.dat", "b".repeat(64)));
        submit_pending_into_drop_box(&data_dir, &path, b"test payload", Instant::now())?;
        submit_pending_into_drop_box(&data_dir, &path, b"different payload", Instant::now())?;

        let pending_debug = protected_dacl(&directory_aces(&system, &user, &administrators, true, true))?;
        let identity_debug = protected_dacl(&directory_aces(&system, &user, &administrators, true, false))?;
        set_named_security_info(&pending_name, SE_FILE_OBJECT, None, None, Some(&pending_debug), None)?;
        set_named_security_info(&identity_name, SE_FILE_OBJECT, None, None, Some(&identity_debug), None)?;
        assert_eq!(fs::read_dir(&pending)?.count(), 1);
        fs::remove_file(path)?;
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }

    #[test]
    fn drop_box_denies_a_token_without_administrators_membership() -> anyhow::Result<()> {
        if current_user_is_administrator()? {
            return Ok(());
        }
        let data_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("drop-box-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&data_dir)?;
        crate::private_file::prepare_directories(&data_dir, true)?;
        let pending = data_dir.join("identity").join("pending");
        let name = U16CString::from_os_str(fs::canonicalize(&pending)?.as_os_str())?;
        let system = system_sid()?;
        let user = user_sid()?;
        let administrators = administrators_sid()?;
        let add_only = protected_dacl(&directory_aces(&system, &user, &administrators, false, true))?;
        set_named_security_info(&name, SE_FILE_OBJECT, None, None, Some(&add_only), None)?;

        let path = pending.join(format!("{}.dat", "c".repeat(64)));
        assert!(submit_pending_into_drop_box(&data_dir, &path, b"test payload", Instant::now()).is_err());
        assert!(!path.exists());

        let debug_dacl = protected_dacl(&directory_aces(&system, &user, &administrators, true, true))?;
        set_named_security_info(&name, SE_FILE_OBJECT, None, None, Some(&debug_dacl), None)?;
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }

    #[test]
    fn drop_box_rejects_reparse_redirects_before_writing() -> anyhow::Result<()> {
        use std::os::windows::fs::symlink_dir;

        let data_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("drop-box-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&data_dir)?;
        crate::private_file::prepare_directories(&data_dir, true)?;
        let pending = data_dir.join("identity").join("pending");
        fs::remove_dir(&pending)?;
        let redirected = data_dir.join("redirected");
        fs::create_dir(&redirected)?;
        if let Err(error) = symlink_dir(&redirected, &pending) {
            if error.kind() == ErrorKind::PermissionDenied {
                fs::remove_dir_all(data_dir)?;
                return Ok(());
            }
            return Err(error).context("create test reparse point");
        }

        let path = pending.join(format!("{}.dat", "d".repeat(64)));
        let error = submit_pending_into_drop_box(&data_dir, &path, b"test payload", Instant::now())
            .expect_err("redirected drop box accepted a pending enrollment");
        assert!(format!("{error:#}").contains("resolves outside the data directory"));
        assert!(fs::read_dir(&redirected)?.next().is_none());
        fs::remove_dir(&pending)?;
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }

    #[test]
    fn administrator_writer_requires_system_provisioned_directories() -> anyhow::Result<()> {
        let data_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("drop-box-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&data_dir)?;
        let missing = verify_system_provisioned_drop_box(&data_dir, Instant::now())
            .expect_err("missing identity directory was accepted");
        assert_eq!(missing.to_string(), ENROLLMENT_DIRECTORY_NOT_READY);
        assert!(
            format!("{missing:#}").contains("inspect protected identity directory"),
            "{missing:#}"
        );
        crate::private_file::prepare_directories(&data_dir, true)?;
        let untrusted = verify_system_provisioned_drop_box(&data_dir, Instant::now())
            .expect_err("debug directory was SYSTEM-trusted");
        assert_eq!(untrusted.to_string(), ENROLLMENT_DIRECTORY_NOT_READY);
        assert!(format!("{untrusted:#}").contains("unexpected access"), "{untrusted:#}");
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }

    #[test]
    fn retries_only_sharing_violations() -> anyhow::Result<()> {
        let sharing = anyhow::Error::new(std::io::Error::from_raw_os_error(i32::try_from(
            ERROR_SHARING_VIOLATION.0,
        )?))
        .context("inspect protected identity directory");
        assert!(is_sharing_violation(&sharing));

        let mut attempts = 0;
        retry_sharing_violation(Instant::now(), || {
            attempts += 1;
            if attempts == 1 {
                Err(windows::core::Error::from_hresult(ERROR_SHARING_VIOLATION.to_hresult()).into())
            } else {
                Ok(())
            }
        })?;
        assert_eq!(attempts, 2);

        let other = windows::core::Error::from_hresult(windows::Win32::Foundation::ERROR_ACCESS_DENIED.to_hresult());
        assert!(!is_sharing_violation(&anyhow::Error::new(other)));
        let inaccessible = explain_unprepared_drop_box(
            anyhow::Error::new(std::io::Error::from(ErrorKind::PermissionDenied))
                .context("inspect protected pending drop box"),
        );
        assert_eq!(inaccessible.to_string(), ENROLLMENT_DIRECTORY_NOT_READY);
        assert!(
            format!("{inaccessible:#}").contains("inspect protected pending drop box"),
            "{inaccessible:#}"
        );
        let mut attempts = 0;
        let result: anyhow::Result<()> = retry_sharing_violation(Instant::now(), || {
            attempts += 1;
            Err(std::io::Error::from(ErrorKind::PermissionDenied).into())
        });
        assert!(result.is_err());
        assert_eq!(attempts, 1);
        Ok(())
    }

    #[test]
    fn pending_reader_accepts_only_the_two_exact_acl_forms() -> anyhow::Result<()> {
        let system = system_sid()?;
        let user = Sid::from_well_known(Security::WinBuiltinUsersSid, None)?;
        let other = Sid::from_well_known(Security::WinBuiltinGuestsSid, None)?;
        let owner_rights = owner_rights_sid()?;
        assert!(pending_owner_is_allowed(&system, &user, &system, false));
        assert!(pending_owner_is_allowed(&system, &user, &user, false));
        assert!(pending_owner_is_allowed(&system, &system, &user, true));
        assert!(!pending_owner_is_allowed(&system, &user, &other, false));
        for grant in [false, true] {
            let base = pending_base_aces(&system, &user, grant);
            let with_owner_rights = pending_file_aces(&system, &user, &owner_rights, grant);
            assert!(pending_aces_are_allowed(
                &base,
                &system,
                &user,
                &owner_rights,
                grant,
                false
            ));
            assert!(!pending_aces_are_allowed(
                &base,
                &system,
                &user,
                &owner_rights,
                grant,
                true
            ));
            assert!(pending_aces_are_allowed(
                &with_owner_rights,
                &system,
                &user,
                &owner_rights,
                grant,
                true
            ));
            assert!(pending_aces_are_allowed(
                &with_owner_rights,
                &system,
                &user,
                &owner_rights,
                grant,
                false
            ));
            for unexpected in [
                (other.clone(), FILE_ALL_ACCESS.0, Security::NO_INHERITANCE.0),
                (owner_rights.clone(), FILE_ALL_ACCESS.0, Security::NO_INHERITANCE.0),
                (owner_rights.clone(), 0, Security::OBJECT_INHERIT_ACE.0),
            ] {
                let mut extra = base.clone();
                extra.push(unexpected);
                assert!(!pending_aces_are_allowed(
                    &extra,
                    &system,
                    &user,
                    &owner_rights,
                    grant,
                    false
                ));
                assert!(!pending_aces_are_allowed(
                    &extra,
                    &system,
                    &user,
                    &owner_rights,
                    grant,
                    true
                ));
            }
            let mut duplicate = with_owner_rights;
            duplicate.push((owner_rights.clone(), 0, Security::NO_INHERITANCE.0));
            assert!(!pending_aces_are_allowed(
                &duplicate,
                &system,
                &user,
                &owner_rights,
                grant,
                true
            ));
        }
        Ok(())
    }

    #[test]
    fn distinct_administrator_owner_requires_zero_access_owner_rights() -> anyhow::Result<()> {
        let system = system_sid()?;
        let administrator = administrators_sid()?;
        let current = user_sid()?;
        let owner_rights = owner_rights_sid()?;
        let base = SecurityAttributesInit {
            owner: Some(administrator.clone()),
            dacl: Some(protected_dacl(&pending_base_aces(&system, &current, false))?),
            ..Default::default()
        }
        .init();
        // SAFETY: The security attributes and their descriptor remain live through verification.
        let descriptor = PSECURITY_DESCRIPTOR(unsafe { (*base.as_ptr()).lpSecurityDescriptor });
        assert!(verify_pending_owner_and_dacl(&administrator, descriptor, false).is_err());

        let protected = SecurityAttributesInit {
            owner: Some(administrator.clone()),
            dacl: Some(protected_dacl(&pending_file_aces(
                &system,
                &current,
                &owner_rights,
                false,
            ))?),
            ..Default::default()
        }
        .init();
        // SAFETY: The security attributes and their descriptor remain live through verification.
        let descriptor = PSECURITY_DESCRIPTOR(unsafe { (*protected.as_ptr()).lpSecurityDescriptor });
        verify_pending_owner_and_dacl(&administrator, descriptor, false)?;
        Ok(())
    }

    #[test]
    fn system_style_pending_file_without_owner_rights_is_readable() -> anyhow::Result<()> {
        let data_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("pending-acl-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&data_dir)?;
        crate::private_file::prepare_directories(&data_dir, true)?;
        let path = data_dir
            .join("identity")
            .join("pending")
            .join(format!("{}.dat", "a".repeat(64)));
        let mut file = create_private_file(&path, true, false)?;
        file.write_all(&protect(b"invalid pending JSON")?)?;
        file.sync_all()?;
        drop(file);
        assert!(matches!(
            crate::pending::read(&path, true)?,
            crate::pending::PendingRead::Malformed(_)
        ));
        fs::remove_file(path)?;
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }

    #[test]
    fn owner_membership_distinguishes_administrators_from_local_service() -> anyhow::Result<()> {
        let administrators = administrators_sid()?;
        assert!(owner_is_administrator_member(&administrators)?);
        let local_service = Sid::from_well_known(Security::WinLocalServiceSid, None)?;
        assert!(!owner_is_administrator_member(&local_service)?);
        Ok(())
    }

    #[test]
    fn repairs_a_directory_with_an_extra_allow_principal() -> anyhow::Result<()> {
        let data_dir = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("identity-acl-tests")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&data_dir)?;
        let directory = data_dir.join("identity");
        fs::create_dir(&directory)?;
        let system = system_sid()?;
        let user = user_sid()?;
        let mut broad = allowed_principals(&system, &user, true);
        let users = Sid::from_well_known(Security::WinBuiltinUsersSid, None)?;
        broad.push(users);
        let inheritance = Security::CONTAINER_INHERIT_ACE | Security::OBJECT_INHERIT_ACE;
        let name = U16CString::from_os_str(fs::canonicalize(&directory)?.as_os_str())?;
        let dacl = protected_dacl(&expected_aces(&broad, inheritance))?;
        set_named_security_info(&name, SE_FILE_OBJECT, None, None, Some(&dacl), None)?;

        create_protected_directory(&directory, true, false)?;
        let (owner, descriptor) = named_owner_and_dacl(&directory)?;
        assert!(owner == system || owner == user);
        verify_dacl(
            descriptor.0,
            expected_aces(&allowed_principals(&system, &user, true), inheritance),
        )?;
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }
}
