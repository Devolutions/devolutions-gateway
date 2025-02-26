use std::path::Path;

use anyhow::Context as _;
use windows::Win32::Storage::FileSystem;

use crate::security::attributes::SecurityAttributes;
use crate::str::{U16CStrExt as _, U16CString};

pub fn create_directory(path: &Path, security_attributes: Option<&SecurityAttributes>) -> anyhow::Result<()> {
    let path = U16CString::from_os_str(path.as_os_str()).context("invalid path")?;

    // SAFETY: FFI call with no outstanding preconditions.
    unsafe { FileSystem::CreateDirectoryW(path.as_pcwstr(), security_attributes.map(|x| x.as_ptr())) }?;

    Ok(())
}
