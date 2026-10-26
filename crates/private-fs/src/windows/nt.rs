//! Handle operations: opening and creating relative to a directory handle, and reading and changing what a handle
//! refers to.

use std::ffi::OsString;
use std::io;
use std::mem::offset_of;
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle};

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_DISPOSITION_DELETE, FILE_DISPOSITION_POSIX_SEMANTICS, FILE_INFORMATION_CLASS, FILE_RENAME_INFORMATION,
    FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS, FileDispositionInformation,
    FileDispositionInformationEx, FileFsDeviceInformation, FileRenameInformation, FileRenameInformationEx,
    NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS, NtCreateFile, NtQueryVolumeInformationFile,
    NtSetInformationFile,
};
use windows::Win32::Foundation::{
    ERROR_NO_MORE_FILES, HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_NOT_SUPPORTED, UNICODE_STRING,
};
use windows::Win32::Security::SECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_NAME_NORMALIZED, FILE_SHARE_MODE,
    FILE_STANDARD_INFO, FileAttributeTagInfo, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, FileIdInfo,
    FileStandardInfo, FlushFileBuffers, GETFINALPATHNAMEBYHANDLE_FLAGS, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, VOLUME_NAME_DOS, VOLUME_NAME_NONE,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;
use windows::core::PWSTR;

/// What [`create`] asks `NtCreateFile` for.
pub(super) struct Request<'a> {
    pub(super) access: FILE_ACCESS_RIGHTS,
    pub(super) share: FILE_SHARE_MODE,
    pub(super) disposition: NTCREATEFILE_CREATE_DISPOSITION,
    pub(super) options: NTCREATEFILE_CREATE_OPTIONS,
    pub(super) attributes: FILE_FLAGS_AND_ATTRIBUTES,
    /// The security descriptor a created file or directory gets.
    pub(super) descriptor: Option<&'a SECURITY_DESCRIPTOR>,
}

pub(super) fn raw(handle: BorrowedHandle<'_>) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

/// Converts a failed `NTSTATUS` to the Win32 error it maps to, so that callers see the same error codes and kinds as
/// from the Win32 functions.
pub(super) fn status_error(status: NTSTATUS) -> io::Error {
    // SAFETY: RtlNtStatusToDosError only maps a value.
    let code = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(code.cast_signed())
}

/// Converts an error of the `windows` crate to the Win32 error it carries.
///
/// The `windows` crate converts to an `io::Error` holding the whole HRESULT, whose kind std can't decode.
pub(super) fn win32_error(error: windows::core::Error) -> io::Error {
    let code = error.code().0.cast_unsigned();
    // An HRESULT made from a Win32 error code has the severity bit, the facility FACILITY_WIN32 (7) and the code in
    // its low word.
    if code & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((code & 0xFFFF).cast_signed())
    } else {
        io::Error::from_raw_os_error(code.cast_signed())
    }
}

/// Opens or creates the entry `name` of the directory `root`, without resolving any path but `name`.
pub(super) fn create(root: BorrowedHandle<'_>, name: &str, request: &Request<'_>) -> io::Result<OwnedHandle> {
    create_in(raw(root), name, request)
}

/// Opens or creates the object at the NT path `path`, such as `\??\C:\Users`.
pub(super) fn create_absolute(path: &str, request: &Request<'_>) -> io::Result<OwnedHandle> {
    create_in(HANDLE::default(), path, request)
}

fn create_in(root: HANDLE, name: &str, request: &Request<'_>) -> io::Result<OwnedHandle> {
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let length = wide
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidFilename))?;
    let object_name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: PWSTR(wide.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).expect("OBJECT_ATTRIBUTES is a few dozen bytes"),
        RootDirectory: root,
        ObjectName: &raw const object_name,
        // Win32 file names are case-insensitive, and so are the names private-fs opens.
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: request.descriptor.map_or(std::ptr::null(), std::ptr::from_ref),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: The name, its buffer, the object attributes and the security descriptor stay live for the call, the root
    // handle is open or null, and the handle and status block outputs are writable.
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            request.access,
            &raw const attributes,
            &raw mut status_block,
            None,
            request.attributes,
            request.share,
            request.disposition,
            request.options,
            None,
            0,
        )
    };
    // NT_SUCCESS: success and informational codes are not negative; warnings and errors are.
    if status.0 < 0 {
        return Err(status_error(status));
    }
    // SAFETY: NtCreateFile succeeded, so the handle is open and nothing else owns it.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
}

/// Reads one fixed-size information class of `handle`.
fn information<T: Default>(handle: BorrowedHandle<'_>, class: FILE_INFO_BY_HANDLE_CLASS) -> io::Result<T> {
    let mut info = T::default();
    // SAFETY: The handle is open, and the output is a writable `T` of the size passed, which callers pair with the
    // structure that `class` fills.
    unsafe {
        GetFileInformationByHandleEx(
            raw(handle),
            class,
            (&raw mut info).cast(),
            u32::try_from(size_of::<T>()).expect("file information structures are a few dozen bytes"),
        )
    }
    .map_err(win32_error)?;
    Ok(info)
}

/// Returns the file attributes, such as `FILE_ATTRIBUTE_DIRECTORY` and `FILE_ATTRIBUTE_REPARSE_POINT`, and the reparse
/// tag, which is meaningful only with `FILE_ATTRIBUTE_REPARSE_POINT`.
pub(super) fn attributes_and_tag(handle: BorrowedHandle<'_>) -> io::Result<(u32, u32)> {
    let info = information::<FILE_ATTRIBUTE_TAG_INFO>(handle, FileAttributeTagInfo)?;
    Ok((info.FileAttributes, info.ReparseTag))
}

/// Reports whether a reparse tag makes its file or directory stand for another name, as symbolic links, junctions and
/// volume mount points do, rather than only change how its content is stored, as cloud placeholders and deduplicated
/// files do.
pub(super) fn is_name_surrogate(tag: u32) -> bool {
    // IsReparseTagNameSurrogate: the name surrogate bit of a reparse tag.
    tag & 0x2000_0000 != 0
}

pub(super) fn link_count(handle: BorrowedHandle<'_>) -> io::Result<u32> {
    Ok(information::<FILE_STANDARD_INFO>(handle, FileStandardInfo)?.NumberOfLinks)
}

/// Returns the volume serial number and the file ID, which together identify a file.
pub(super) fn file_id(handle: BorrowedHandle<'_>) -> io::Result<(u64, [u8; 16])> {
    let info = information::<FILE_ID_INFO>(handle, FileIdInfo)?;
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

/// Reports whether the volume holding `handle` keeps and enforces access control lists.
///
/// UNTESTED: a FAT or exFAT volume reports `false`, and an NTFS or ReFS volume `true`.
/// Tests run on NTFS only, and a FAT volume needs a removable disk or a mounted image; when changing this, check both,
/// because on a volume without ACLs every DACL private-fs sets is silently dropped and every check would read none.
pub(super) fn persistent_acls(handle: BorrowedHandle<'_>) -> io::Result<bool> {
    let mut flags = 0u32;
    // SAFETY: The handle is open, the flags output is writable, and the other outputs are not requested.
    unsafe { GetVolumeInformationByHandleW(raw(handle), None, None, None, Some(&raw mut flags), None) }
        .map_err(win32_error)?;
    Ok(flags & FILE_PERSISTENT_ACLS != 0)
}

/// Reports whether the volume holding `handle` is remote, such as an SMB share, whose server decides access with its own
/// accounts rather than by the DACLs this computer reads.
///
/// UNTESTED: a file on a mapped or UNC SMB share reports `true`, and one on a local disk `false`.
/// Tests have no share to mount; when changing this, check both, because a share keeps ACLs and would otherwise pass the
/// volume check.
pub(super) fn is_remote(handle: BorrowedHandle<'_>) -> io::Result<bool> {
    // FILE_FS_DEVICE_INFORMATION: DeviceType, then Characteristics.
    // The windows crate's FILE_FS_DEVICE_INFORMATION and FILE_REMOTE_DEVICE need its Wdk_System_SystemServices feature,
    // which nothing else here needs, so the two fields are read as they are laid out.
    let mut information = [0u32; 2];
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: The handle is open, and the information and status block outputs are writable for their sizes.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            raw(handle),
            &raw mut status_block,
            information.as_mut_ptr().cast(),
            4 /* DeviceType */ + 4, /* Characteristics */
            FileFsDeviceInformation,
        )
    };
    if status.0 < 0 {
        return Err(status_error(status));
    }
    // FILE_REMOTE_DEVICE.
    Ok(information[1] & 0x10 != 0)
}

/// Returns the normalized path of `handle` with its DOS volume name, such as `\\?\C:\Users`.
pub(super) fn final_path(handle: BorrowedHandle<'_>) -> io::Result<String> {
    final_path_with(handle, VOLUME_NAME_DOS)
}

/// Returns the normalized path of `handle` within its volume, such as `\Users`, or `\` for the volume's root.
pub(super) fn path_in_volume(handle: BorrowedHandle<'_>) -> io::Result<String> {
    final_path_with(handle, VOLUME_NAME_NONE)
}

fn final_path_with(handle: BorrowedHandle<'_>, volume: GETFINALPATHNAMEBYHANDLE_FLAGS) -> io::Result<String> {
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: The handle is open and the buffer is writable for its length.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                raw(handle),
                &mut buffer,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | volume.0),
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        let length = usize::try_from(length).expect("a path length fits in usize");
        // INVARIANT: A length less than the buffer is the path's, without the terminating NUL; otherwise it is the
        // buffer size needed, with it.
        if length < buffer.len() {
            buffer.truncate(length);
            return String::from_utf16(&buffer).map_err(|_| io::Error::from(io::ErrorKind::InvalidData));
        }
        buffer.resize(length, 0);
    }
}

pub(super) fn flush(handle: BorrowedHandle<'_>) -> io::Result<()> {
    // SAFETY: The handle is open.
    unsafe { FlushFileBuffers(raw(handle)) }.map_err(win32_error)
}

/// Renames the file or directory `handle` refers to, to the entry `name` of the directory `root`.
///
/// With POSIX semantics, a replaced destination that another process holds open, sharing deletion, doesn't make the
/// rename fail.
/// The handle needs `DELETE` access.
pub(super) fn rename(
    handle: BorrowedHandle<'_>,
    root: BorrowedHandle<'_>,
    name: &str,
    replace: bool,
) -> io::Result<()> {
    let mut flags = FILE_RENAME_POSIX_SEMANTICS;
    if replace {
        flags |= FILE_RENAME_REPLACE_IF_EXISTS;
    }
    let mut status = set_rename(handle, root, name, flags, FileRenameInformationEx)?;
    // UNTESTED: where the file system lacks the extended class, the legacy class renames, with or without replacing.
    // Tests run on NTFS of a Windows that has it; when changing this, check on FAT or an older Windows, or force the
    // fallback, that every rename test still passes.
    if needs_legacy_class(status) {
        // The legacy class reads ReplaceIfExists, a BOOLEAN, from the first byte of the same field.
        status = set_rename(handle, root, name, u32::from(replace), FileRenameInformation)?;
    }
    if status.0 < 0 {
        return Err(status_error(status));
    }
    Ok(())
}

/// Reports whether a failure of an extended information class means the file system knows only the legacy class, as
/// before Windows 10 1709 or on FAT.
fn needs_legacy_class(status: NTSTATUS) -> bool {
    [
        STATUS_INVALID_PARAMETER,
        STATUS_NOT_SUPPORTED,
        STATUS_INVALID_INFO_CLASS,
        STATUS_INVALID_DEVICE_REQUEST,
        STATUS_NOT_IMPLEMENTED,
    ]
    .contains(&status)
}

fn set_rename(
    handle: BorrowedHandle<'_>,
    root: BorrowedHandle<'_>,
    name: &str,
    flags: u32,
    class: FILE_INFORMATION_CLASS,
) -> io::Result<NTSTATUS> {
    let invalid_name = || io::Error::from(io::ErrorKind::InvalidFilename);
    let wide: Vec<u16> = name.encode_utf16().collect();
    let name_bytes = wide.len().checked_mul(size_of::<u16>()).ok_or_else(invalid_name)?;
    let name_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
    let size = size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name_bytes)
        .ok_or_else(invalid_name)?;
    // A u64 buffer is aligned for FILE_RENAME_INFORMATION, whose largest field is a handle.
    let mut buffer = vec![0u64; size.div_ceil(size_of::<u64>())];
    {
        // The fields are written as bytes, so that every byte of the buffer, padding included, stays initialized.
        // SAFETY: The buffer is initialized, and u8 has no alignment requirement and no invalid values.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), buffer.len() * size_of::<u64>())
        };
        let mut put = |offset: usize, value: &[u8]| bytes[offset..][..value.len()].copy_from_slice(value);
        put(offset_of!(FILE_RENAME_INFORMATION, Anonymous), &flags.to_le_bytes());
        put(
            offset_of!(FILE_RENAME_INFORMATION, RootDirectory),
            &raw(root).0.addr().to_ne_bytes(),
        );
        put(
            offset_of!(FILE_RENAME_INFORMATION, FileNameLength),
            &u32::try_from(name_bytes).map_err(|_| invalid_name())?.to_ne_bytes(),
        );
        for (index, unit) in wide.iter().enumerate() {
            put(name_offset + index * size_of::<u16>(), &unit.to_ne_bytes());
        }
    }
    let size = u32::try_from(size).map_err(|_| invalid_name())?;
    // NtSetInformationFile takes the name relative to RootDirectory, which SetFileInformationByHandle refuses.
    // SAFETY: The rename structure, with its root handle and name, stays live for the call and is `size` bytes long.
    Ok(unsafe { set_information(handle, buffer.as_ptr().cast(), size, class) })
}

/// Deletes the file `handle` refers to.
///
/// With POSIX semantics its name goes at once, even while other handles to it stay open, so the name can be created
/// again; with the legacy semantics of older systems and FAT, it goes once every handle to it is closed.
/// The handle needs `DELETE` access.
pub(super) fn delete(handle: BorrowedHandle<'_>) -> io::Result<()> {
    let flags = FILE_DISPOSITION_DELETE.0 | FILE_DISPOSITION_POSIX_SEMANTICS.0;
    // SAFETY: The flags, a FILE_DISPOSITION_INFORMATION_EX, stay live for the call.
    let mut status = unsafe {
        set_information(
            handle,
            (&raw const flags).cast(),
            4, /* Flags */
            FileDispositionInformationEx,
        )
    };
    // UNTESTED: where the file system lacks the extended class, the legacy class deletes once every handle is closed.
    // Tests run on NTFS of a Windows that has it; when changing this, check on FAT or an older Windows, or force the
    // fallback, that every removal test but the one needing POSIX semantics still passes.
    if needs_legacy_class(status) {
        let delete_file = 1u8;
        // SAFETY: The BOOLEAN DeleteFile, a FILE_DISPOSITION_INFORMATION, stays live for the call.
        status = unsafe {
            set_information(
                handle,
                (&raw const delete_file).cast(),
                1, /* DeleteFile */
                FileDispositionInformation,
            )
        };
    }
    if status.0 < 0 {
        return Err(status_error(status));
    }
    Ok(())
}

/// # Safety
///
/// `information` points to `length` bytes, live for the call, holding the structure `class` takes.
unsafe fn set_information(
    handle: BorrowedHandle<'_>,
    information: *const core::ffi::c_void,
    length: u32,
    class: FILE_INFORMATION_CLASS,
) -> NTSTATUS {
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: The handle is open, the status block is writable, and per the function's contract the information is
    // valid for the call.
    unsafe { NtSetInformationFile(raw(handle), &raw mut status_block, information, length, class) }
}

/// Lists the entries of the directory `handle` refers to, with their file attributes and reparse tags, without `.`
/// and `..`.
///
/// The listing moves the handle's enumeration cursor, so callers pass a handle that nothing else lists through.
pub(super) fn list(handle: BorrowedHandle<'_>) -> io::Result<Vec<(OsString, u32, u32)>> {
    // A u64 buffer is aligned for FILE_ID_BOTH_DIR_INFO, whose largest fields are 64-bit.
    let mut buffer = vec![0u64; 8 * 1024];
    let byte_length = buffer.len() * size_of::<u64>();
    let mut entries = Vec::new();
    // The restart class rewinds the handle's listing, which an earlier call on the same handle may have left at its end.
    let mut class = FileIdBothDirectoryRestartInfo;
    loop {
        buffer.fill(0);
        // SAFETY: The handle is open and the buffer is writable for the length passed.
        let listed = unsafe {
            GetFileInformationByHandleEx(
                raw(handle),
                class,
                buffer.as_mut_ptr().cast(),
                u32::try_from(byte_length).expect("the listing buffer is 64 KiB"),
            )
        };
        match listed {
            Ok(()) => {}
            Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => return Ok(entries),
            Err(error) => return Err(win32_error(error)),
        }
        class = FileIdBothDirectoryInfo;
        // SAFETY: The buffer is initialized, and u8 has no alignment requirement and no invalid values.
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), byte_length) };
        parse_listing(bytes, &mut entries)?;
    }
}

/// Appends the entries of one buffer of `FILE_ID_BOTH_DIR_INFO` records to `entries`.
fn parse_listing(bytes: &[u8], entries: &mut Vec<(OsString, u32, u32)>) -> io::Result<()> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed directory listing");
    let mut offset = 0usize;
    loop {
        let field = |at: usize| -> io::Result<u32> {
            let start = offset.checked_add(at).ok_or_else(invalid)?;
            let field = bytes.get(start..start + size_of::<u32>()).ok_or_else(invalid)?;
            Ok(u32::from_le_bytes(field.try_into().map_err(|_| invalid())?))
        };
        let next = field(offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset))?;
        let attributes = field(offset_of!(FILE_ID_BOTH_DIR_INFO, FileAttributes))?;
        // A reparse point's entry holds its reparse tag in EaSize, per [MS-FSCC] "FileIdBothDirectoryInformation",
        // EaSize.
        let tag = if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            field(offset_of!(FILE_ID_BOTH_DIR_INFO, EaSize))?
        } else {
            0
        };
        let name_length =
            usize::try_from(field(offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength))?).map_err(|_| invalid())?;
        let start = offset + offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
        let name = bytes
            .get(start..start.checked_add(name_length).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        let units: Vec<u16> = name
            .chunks_exact(size_of::<u16>())
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect();
        let name = OsString::from_wide(&units);
        if name != "." && name != ".." {
            entries.push((name, attributes, tag));
        }
        if next == 0 {
            return Ok(());
        }
        offset = offset
            .checked_add(usize::try_from(next).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
    }
}
