use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;

use anyhow::Context as _;
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::Storage::FileSystem;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

use crate::security::attributes::SecurityAttributes;
use crate::str::{U16CStrExt as _, U16CString};

pub fn create_directory(path: &Path, security_attributes: Option<&SecurityAttributes>) -> anyhow::Result<()> {
    let path = U16CString::from_os_str(path.as_os_str()).context("invalid path")?;

    // SAFETY: FFI call with no outstanding preconditions.
    unsafe { FileSystem::CreateDirectoryW(path.as_pcwstr(), security_attributes.map(|x| x.as_ptr())) }?;

    Ok(())
}

pub fn get_system32_path() -> anyhow::Result<String> {
    let mut buffer = [0u16; MAX_PATH as usize];

    // SAFETY:
    // - `buffer.as_mut_ptr()` gives a valid writable pointer for MAX_PATH u16s.
    // - `GetSystemDirectoryW` expects a valid mutable wide string buffer.
    let len = {
        // SAFETY: We construct a valid slice from the buffer.
        let slice = unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr(), buffer.len()) };
        // SAFETY: slice is a valid mutable wide string buffer.
        unsafe { GetSystemDirectoryW(Some(slice)) }
    };

    if len == 0 {
        anyhow::bail!("GetSystemDirectoryW failed");
    }

    if len as usize >= buffer.len() {
        anyhow::bail!("buffer too small for system directory path");
    }

    Ok(OsString::from_wide(&buffer[..len as usize])
        .to_string_lossy()
        .into_owned())
}
