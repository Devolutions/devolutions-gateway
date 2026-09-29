use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write as _};

use anyhow::{Context as _, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use tracing::warn;
use uuid::Uuid;

#[derive(Debug)]
struct UntrustedStateFile;

impl fmt::Display for UntrustedStateFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("untrusted identity state file")
    }
}

impl Error for UntrustedStateFile {}

pub(crate) fn is_untrusted(error: &anyhow::Error) -> bool {
    error.is::<UntrustedStateFile>()
}

fn untrusted() -> anyhow::Error {
    warn!("Ignore untrusted identity state file");
    anyhow::Error::new(UntrustedStateFile)
}

struct TemporaryFile(Utf8PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub(crate) fn create_directory(path: &Utf8Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        let mut missing = Vec::new();
        let mut current = path;
        loop {
            match fs::symlink_metadata(current) {
                Ok(metadata) => {
                    ensure!(metadata.file_type().is_dir(), "identity path is not a directory");
                    break;
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    missing.push(current.to_owned());
                    current = current
                        .parent()
                        .filter(|parent| !parent.as_str().is_empty())
                        .unwrap_or_else(|| Utf8Path::new("."));
                }
                Err(error) => return Err(error).context("inspect identity directory"),
            }
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        for directory in missing.iter().rev() {
            match builder.create(directory) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::AlreadyExists && fs::symlink_metadata(directory)?.is_dir() => {
                }
                Err(error) => return Err(error).context("create identity directory"),
            }
            sync_directory(directory)?;
            sync_directory(
                directory
                    .parent()
                    .filter(|parent| !parent.as_str().is_empty())
                    .unwrap_or_else(|| Utf8Path::new(".")),
            )?;
        }
        #[cfg(target_os = "macos")]
        crate::macos_acl::ensure_private_directory(&File::open(path)?)?;
        ensure!(
            fs::symlink_metadata(path)?.permissions().mode() & 0o022 == 0,
            "identity directory is writable by other users"
        );
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path).context("create identity directory")?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(metadata.file_type().is_dir(), "identity path is not a directory");
    #[cfg(windows)]
    ensure!(
        !crate::windows::is_reparse_point(&metadata),
        "identity directory is a reparse point"
    );
    Ok(())
}

pub(crate) fn prepare_directories(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    create_directory(data_dir)?;
    let identity = data_dir.join("identity");
    create_owned_directory(&identity, grant_current_user)?;
    for name in ["authorities", "keys", "pending", "rejected"] {
        create_owned_directory(&identity.join(name), grant_current_user)?;
    }
    Ok(())
}

pub(crate) fn protect_authority_directories(data_dir: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    let authorities = data_dir.join("identity").join("authorities");
    for entry in fs::read_dir(&authorities)? {
        let entry = entry?;
        let name = entry.file_name();
        if name
            .to_str()
            .and_then(|name| Uuid::parse_str(name).ok().filter(|uuid| uuid.to_string() == name))
            .is_some()
        {
            let path =
                Utf8PathBuf::from_path_buf(entry.path()).map_err(|_| anyhow::anyhow!("non-UTF-8 identity path"))?;
            let _ = check_owned_directory(&path, grant_current_user)?;
        }
    }
    Ok(())
}

pub(crate) fn check_owned_directory(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect identity directory"),
    };
    if !metadata.file_type().is_dir() {
        warn!("Ignore untrusted identity directory");
        return Ok(false);
    }
    #[cfg(windows)]
    if crate::windows::is_reparse_point(&metadata) {
        warn!("Ignore untrusted identity directory");
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        // SAFETY: Reading the process's effective UID has no preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } {
            warn!("Ignore untrusted identity directory");
            return Ok(false);
        }
    }
    create_owned_directory(path, grant_current_user).context("protect identity directory")?;
    Ok(true)
}

fn create_owned_directory(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

        let _ = grant_current_user;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        if let Err(error) = builder.create(path)
            && error.kind() != ErrorKind::AlreadyExists
        {
            return Err(error).context("create identity directory");
        }
        let metadata = fs::symlink_metadata(path)?;
        ensure!(metadata.file_type().is_dir(), "identity path is not a directory");
        // SAFETY: Reading the process's effective UID has no preconditions.
        let user = unsafe { libc::geteuid() };
        ensure!(
            metadata.uid() == user,
            "identity directory owner is not the process user"
        );
        if metadata.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).context("protect identity directory")?;
        }
        ensure!(
            fs::symlink_metadata(path)?.permissions().mode() & 0o777 == 0o700,
            "identity directory is not owner-only"
        );
        #[cfg(target_os = "macos")]
        crate::macos_acl::ensure_private_directory(&File::open(path)?)?;
        sync_directory(path)?;
        sync_directory(path.parent().context("identity directory has no parent")?)?;
    }
    #[cfg(windows)]
    crate::windows::create_protected_directory(
        path,
        grant_current_user,
        path.file_name() == Some("pending") && path.parent().and_then(Utf8Path::file_name) == Some("identity"),
    )?;
    Ok(())
}

pub(crate) fn write_atomic(
    data_dir: &Utf8Path,
    path: &Utf8Path,
    bytes: &[u8],
    grant_current_user: bool,
) -> anyhow::Result<()> {
    let parent = path.parent().context("identity file has no parent directory")?;
    let identity = data_dir.join("identity");
    let authorities = identity.join("authorities");
    if parent.parent() == Some(authorities.as_path()) {
        create_owned_directory(parent, grant_current_user)?;
    } else {
        ensure!(
            parent == identity.join("pending") || parent == identity.join("rejected"),
            "identity file is outside its state directories"
        );
    }
    let name = path.file_name().context("identity file has no name")?;
    let temporary = TemporaryFile(parent.join(format!(".{name}-{}.tmp", Uuid::new_v4())));
    #[cfg(windows)]
    let pending_blob = parent == identity.join("pending") && path.extension() == Some("dat");
    #[cfg(not(windows))]
    let pending_blob = false;
    let mut file = create_private_file(&temporary.0, grant_current_user, pending_blob)?;
    file.write_all(bytes).context("write identity file")?;
    file.sync_all().context("sync identity file")?;
    #[cfg(windows)]
    {
        crate::windows::verify_installed_file(&file, grant_current_user, pending_blob)?;
        drop(file);
        crate::windows::replace_file(&temporary.0, path).context("install identity file")?;
        let installed = open_read(path)?;
        crate::windows::verify_installed_file(&installed, grant_current_user, pending_blob)?;
    }
    #[cfg(unix)]
    {
        drop(file);
        replace(&temporary.0, path).context("install identity file")?;
        sync_directory(parent)?;
    }
    Ok(())
}

pub(crate) fn open_read(path: &Utf8Path) -> anyhow::Result<File> {
    open_read_with_policy(path, None)
}

pub(crate) fn open_pending_read(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<File> {
    open_read_with_policy(path, Some(grant_current_user))
}

fn open_read_with_policy(path: &Utf8Path, pending_grant: Option<bool>) -> anyhow::Result<File> {
    let metadata = fs::symlink_metadata(path).context("inspect identity file")?;
    if !metadata.file_type().is_file() {
        return Err(untrusted());
    }
    #[cfg(windows)]
    if crate::windows::is_reparse_point(&metadata) {
        return Err(untrusted());
    }
    #[cfg(windows)]
    match pending_grant {
        Some(grant) => crate::windows::verify_pending_path(path, grant).map_err(|_| untrusted())?,
        None => verify_state_path(path)?,
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    }
    let file = options.open(path).map_err(|error| {
        if error.kind() == ErrorKind::PermissionDenied {
            untrusted()
        } else {
            anyhow::Error::new(error).context("open identity file")
        }
    })?;
    #[cfg(windows)]
    if let Some(grant) = pending_grant {
        crate::windows::verify_pending_read(&file, grant).map_err(|_| untrusted())?;
    } else {
        verify_open_file(&file)?;
    }
    #[cfg(unix)]
    if pending_grant.is_some() {
        verify_open_pending_file(&file)?;
    } else {
        verify_open_file(&file)?;
    }
    Ok(file)
}

#[cfg(unix)]
fn verify_unix_file_permissions(
    mode: u32,
    actual_owner: libc::uid_t,
    required_owner: Option<libc::uid_t>,
) -> anyhow::Result<()> {
    if let Some(owner) = required_owner {
        ensure!(actual_owner == owner, "identity file owner is not the process user");
    }
    ensure!(mode & 0o077 == 0, "identity file is not owner-only");
    Ok(())
}

#[cfg(unix)]
fn verify_open_pending_file(file: &File) -> anyhow::Result<()> {
    let protection = || -> anyhow::Result<()> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = file.metadata()?;
        ensure!(metadata.file_type().is_file(), "identity path is not a regular file");
        verify_unix_file_permissions(metadata.permissions().mode(), metadata.uid(), None)?;
        #[cfg(target_os = "macos")]
        crate::macos_acl::ensure_private_pending_file(file)?;
        Ok(())
    };
    protection().map_err(|_| untrusted())
}

pub(crate) fn verify_open_file(file: &File) -> anyhow::Result<()> {
    let protection = || -> anyhow::Result<()> {
        let metadata = file.metadata()?;
        ensure!(metadata.file_type().is_file(), "identity path is not a regular file");
        #[cfg(windows)]
        ensure!(
            !crate::windows::is_reparse_point(&metadata),
            "identity path is a reparse point"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

            // SAFETY: Reading the process's effective UID has no preconditions.
            let user = unsafe { libc::geteuid() };
            verify_unix_file_permissions(metadata.permissions().mode(), metadata.uid(), Some(user))?;
            #[cfg(target_os = "macos")]
            crate::macos_acl::ensure_private_file(file)?;
        }
        #[cfg(windows)]
        crate::windows::verify_trusted_state_file(file)?;
        Ok(())
    };
    protection().map_err(|_| untrusted())
}

#[cfg(windows)]
pub(crate) fn verify_state_path(path: &Utf8Path) -> anyhow::Result<()> {
    crate::windows::verify_trusted_state_path(path).map_err(|_| untrusted())
}

pub(crate) fn remove_file(path: &Utf8Path) -> anyhow::Result<()> {
    remove_checked_file(path, open_read)
}

pub(crate) fn remove_pending_file(path: &Utf8Path, grant_current_user: bool) -> anyhow::Result<()> {
    remove_checked_file(path, |path| open_pending_read(path, grant_current_user))
}

fn remove_checked_file(path: &Utf8Path, open: impl FnOnce(&Utf8Path) -> anyhow::Result<File>) -> anyhow::Result<()> {
    match open(path) {
        Ok(file) => drop(file),
        Err(error)
            if is_untrusted(&error)
                || error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == ErrorKind::NotFound) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    }
    match fs::remove_file(path) {
        Ok(()) => {
            #[cfg(unix)]
            sync_directory(path.parent().context("identity file has no parent directory")?)?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove identity file"),
    }
}

pub(crate) fn cleanup_temporary_files(
    directory: &Utf8Path,
    matches_stem: impl Fn(&str) -> bool,
    remove: impl Fn(&Utf8Path, &str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("list identity directory"),
    };
    for entry in entries {
        let entry = entry.context("read identity directory entry")?;
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(temporary_stem) else {
            continue;
        };
        if matches_stem(stem) && entry.file_type()?.is_file() {
            remove(
                &Utf8PathBuf::from_path_buf(entry.path()).map_err(|_| anyhow::anyhow!("non-UTF-8 identity path"))?,
                stem,
            )?;
        }
    }
    Ok(())
}

fn temporary_stem(name: &str) -> Option<&str> {
    let name = name.strip_suffix(".tmp")?;
    let (stem, suffix) = name.split_at_checked(name.len().checked_sub(36)?)?;
    let stem = stem.strip_suffix('-')?;
    let uuid = Uuid::parse_str(suffix).ok()?;
    (uuid.get_version_num() == 4 && uuid.to_string() == suffix).then_some(stem)
}

#[cfg(unix)]
fn create_private_file(path: &Utf8Path, _grant_current_user: bool, _pending_blob: bool) -> anyhow::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("create identity file")?;
    ensure!(
        file.metadata()?.permissions().mode() & 0o077 == 0,
        "identity file volume does not enforce owner-only permissions"
    );
    #[cfg(target_os = "macos")]
    crate::macos_acl::ensure_private_file(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn create_private_file(path: &Utf8Path, grant_current_user: bool, pending_blob: bool) -> anyhow::Result<File> {
    crate::windows::create_private_file(path, grant_current_user, pending_blob)
}

#[cfg(unix)]
fn replace(from: &Utf8Path, to: &Utf8Path) -> anyhow::Result<()> {
    fs::rename(from, to).context("atomically replace identity file")
}

#[cfg(unix)]
fn sync_directory(path: &Utf8Path) -> anyhow::Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .context("sync identity directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn pending_files_do_not_require_service_ownership() {
        // SAFETY: Reading the process's effective UID has no preconditions.
        let service_user = unsafe { libc::geteuid() };
        let other_owner = service_user.wrapping_add(1);
        assert!(verify_unix_file_permissions(0o600, other_owner, None).is_ok());
        assert!(verify_unix_file_permissions(0o600, other_owner, Some(service_user)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pending_files_still_require_owner_only_permissions() {
        for mode in [0o640, 0o604, 0o644] {
            assert!(verify_unix_file_permissions(mode, 1, None).is_err());
        }
        assert!(verify_unix_file_permissions(0o600, 1, None).is_ok());
    }

    #[test]
    fn recognizes_only_own_temporary_file_names() {
        let uuid = Uuid::new_v4();
        assert_eq!(
            temporary_stem(&format!(".identity.json-{uuid}.tmp")),
            Some(".identity.json")
        );
        assert_eq!(temporary_stem(".identity.json-not-a-uuid.tmp"), None);
        assert_eq!(temporary_stem(&format!(".identity.json-{uuid}.backup")), None);
        assert_eq!(temporary_stem(&format!(".x-é{}.tmp", "a".repeat(35))), None);
    }
}
