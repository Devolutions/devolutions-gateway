use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use uuid::Uuid;

use super::protocol::{CatalogSync, catalog_sync};

pub(super) fn apply(identity_id: Uuid, request: CatalogSync) -> anyhow::Result<()> {
    if request.revision <= 0 {
        bail!("invalid software catalog revision");
    }

    let directory = catalog_directory()?;
    #[cfg(any(windows, target_os = "macos"))]
    prepare_directory(directory.parent().context("catalog directory has no parent")?)?;
    prepare_directory(&directory)?;
    let revision_path = directory.join(format!(".devolutions-catalog-{identity_id}.revision"));
    match fs::symlink_metadata(&revision_path) {
        Ok(metadata) if !metadata.is_file() || is_link(&metadata) => {
            bail!("stored catalog revision is not a regular file");
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect stored catalog revision"),
    }
    let applied = match fs::read_to_string(&revision_path) {
        Ok(value) => value.trim().parse::<i64>().context("invalid stored catalog revision")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error).context("read stored catalog revision"),
    };

    // UNTESTED: Revisions survive restarts so a delayed snapshot cannot replace a newer catalog; check restart and replay.
    if request.revision < applied {
        return Ok(());
    }

    let destination = directory.join("SoftwareCatalog.json");
    match request.content.context("catalog synchronization has no content")? {
        catalog_sync::Content::Document(document) => {
            let parsed: serde_json::Value = serde_json::from_str(&document).context("invalid catalog JSON")?;
            if parsed["version"].as_u64() != Some(1) || !parsed["catalogs"].is_array() {
                bail!("unsupported software catalog document");
            }
            atomic_write(&destination, document.as_bytes())?;
        }
        catalog_sync::Content::Delete(true) => match fs::remove_file(&destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("delete software catalog"),
        },
        catalog_sync::Content::Delete(false) => bail!("invalid software catalog delete request"),
    }

    atomic_write(&revision_path, request.revision.to_string().as_bytes())?;
    debug!(revision = request.revision, "Applied software catalog snapshot");
    Ok(())
}

fn catalog_directory() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    {
        let program_data = std::env::var_os("ProgramData").context("ProgramData is not set")?;
        Ok(PathBuf::from(program_data).join("Devolutions").join("UniGetUI"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(PathBuf::from("/Library/Application Support/Devolutions/UniGetUI"))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from("/etc/UniGetUI"))
    }
}

fn prepare_directory(path: &Path) -> anyhow::Result<()> {
    for ancestor in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor).context("inspect software catalog directory ancestor")?;
        if !metadata.is_dir() || is_link(&metadata) {
            bail!("software catalog directory ancestor is not a regular directory");
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_dir() || is_link(&metadata) => {
            bail!("catalog directory is not a regular directory");
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).context("create software catalog directory")?;
        }
        Err(error) => return Err(error).context("inspect software catalog directory"),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = fs::metadata(path).context("inspect software catalog directory owner")?;
        if metadata.uid() != 0 {
            bail!("software catalog directory is not owned by root");
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).context("protect software catalog directory")?;
    }
    #[cfg(windows)]
    {
        use win_api_wrappers::identity::sid::Sid;
        use win_api_wrappers::raw::Win32::Security::Authorization::SE_FILE_OBJECT;
        use win_api_wrappers::raw::Win32::Security::{WinBuiltinAdministratorsSid, WinLocalSystemSid};
        use win_api_wrappers::security::descriptor::SecurityDescriptor;
        use win_api_wrappers::str::U16CString;

        let wide_path = U16CString::from_os_str(path.as_os_str()).context("invalid catalog directory path")?;
        let descriptor = SecurityDescriptor::of_path(&wide_path, SE_FILE_OBJECT)
            .context("inspect software catalog directory owner")?;
        let owner = descriptor.owner()?.context("software catalog directory has no owner")?;
        let system = Sid::from_well_known(WinLocalSystemSid, None).context("get SYSTEM SID")?;
        let administrators =
            Sid::from_well_known(WinBuiltinAdministratorsSid, None).context("get Administrators SID")?;
        if owner != system && owner != administrators {
            bail!("software catalog directory is not owned by SYSTEM or Administrators");
        }
        let path = camino::Utf8Path::from_path(path).context("catalog directory is not UTF-8")?;
        crate::updater::set_file_dacl(path, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
            .context("protect software catalog directory")?;
    }
    Ok(())
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(unix)]
    {
        metadata.file_type().is_symlink()
    }
}

fn atomic_write(destination: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = destination.parent().context("catalog path has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).context("create temporary catalog file")?;
    temporary.write_all(contents).context("write temporary catalog file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))
            .context("set catalog read permissions")?;
    }
    #[cfg(windows)]
    {
        let path = camino::Utf8Path::from_path(temporary.path()).context("temporary catalog path is not UTF-8")?;
        crate::updater::set_file_dacl(path, "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
            .context("set catalog read permissions")?;
    }
    temporary.as_file().sync_all().context("flush temporary catalog file")?;
    // UNTESTED: Persist replaces the file atomically on each OS; check readers see only complete JSON during deployment.
    temporary
        .persist(destination)
        .context("replace software catalog file")?;
    #[cfg(unix)]
    fs::File::open(parent)?
        .sync_all()
        .context("flush software catalog directory")?;
    Ok(())
}
