use std::fs::File;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use anyhow::{Context as _, ensure};
use private_fs::ExtendedAclError;

fn ensure_private_volume(file: &File) -> anyhow::Result<()> {
    let ignores_ownership = private_fs::volume_ignores_ownership(file).context("inspect identity volume")?;
    ensure!(!ignores_ownership, "identity volume ignores ownership");
    Ok(())
}

fn ensure_no_extended_acl(file: &File) -> anyhow::Result<()> {
    let has_entries = private_fs::has_extended_acl(file).map_err(|error| match error {
        ExtendedAclError::Inspect(error) => anyhow::Error::new(error).context("inspect identity ACL"),
        ExtendedAclError::Validate(error) => anyhow::Error::new(error).context("validate identity ACL"),
        ExtendedAclError::ReadEntries(error) => anyhow::Error::new(error).context("read identity ACL entries"),
    })?;
    ensure!(!has_entries, "identity path has extended ACL entries");
    Ok(())
}

pub(crate) fn ensure_private_file(file: &File) -> anyhow::Result<()> {
    ensure_private_volume(file)?;
    let user = private_fs::effective_uid();
    ensure!(
        file.metadata()?.uid() == user,
        "identity file owner is not the process user"
    );
    ensure_no_extended_acl(file)
}

pub(crate) fn ensure_private_pending_file(file: &File) -> anyhow::Result<()> {
    ensure_private_volume(file)?;
    ensure_no_extended_acl(file)
}

pub(crate) fn ensure_private_directory(file: &File) -> anyhow::Result<()> {
    ensure_private_volume(file)?;
    let metadata = file.metadata()?;
    let user = private_fs::effective_uid();
    ensure!(
        metadata.uid() == user,
        "identity directory owner is not the process user"
    );
    ensure!(
        metadata.permissions().mode() & 0o022 == 0,
        "identity directory is writable by other users"
    );
    ensure_no_extended_acl(file)
}
