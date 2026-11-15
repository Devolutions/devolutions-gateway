use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use agent_channel_proto::{CatalogSync, catalog_sync};
use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(super) fn apply(identity_id: Uuid, request: CatalogSync) -> anyhow::Result<()> {
    let revision = request.revision;
    let directory = catalog_directory()?;
    #[cfg(any(windows, target_os = "macos"))]
    prepare_directory(directory.parent().context("catalog directory has no parent")?)?;
    prepare_directory(&directory)?;
    apply_in_directory(&directory, identity_id, request)?;
    debug!(revision, "Applied software catalog snapshot");
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct CatalogTransaction {
    revision: i64,
    content: Option<String>,
}

fn apply_in_directory(directory: &Path, identity_id: Uuid, request: CatalogSync) -> anyhow::Result<()> {
    // INVARIANT: Recover a durable transaction before comparing revisions so a stale snapshot cannot replace it.
    recover_pending_transaction(directory, identity_id)?;

    if request.revision <= 0 {
        bail!("invalid software catalog revision");
    }

    let revision_path = revision_path(directory, identity_id);
    let applied = read_revision(&revision_path)?;
    if request.revision < applied {
        return Ok(());
    }

    let content = match request.content.context("catalog synchronization has no content")? {
        catalog_sync::Content::Document(document) => {
            validate_document(&document)?;
            Some(document)
        }
        catalog_sync::Content::Delete(true) => None,
        catalog_sync::Content::Delete(false) => bail!("invalid software catalog delete request"),
    };
    let transaction = CatalogTransaction {
        revision: request.revision,
        content,
    };
    let transaction_path = transaction_path(directory, identity_id);
    let serialized = serde_json::to_vec(&transaction).context("serialize catalog transaction")?;
    atomic_write(&transaction_path, &serialized)?;
    commit_transaction(directory, identity_id, transaction)
}

fn recover_pending_transaction(directory: &Path, identity_id: Uuid) -> anyhow::Result<()> {
    let path = transaction_path(directory, identity_id);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_file() || is_link(&metadata) => {
            bail!("stored catalog transaction is not a regular file");
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect stored catalog transaction"),
    }

    let serialized = fs::read(&path).context("read stored catalog transaction")?;
    let transaction: CatalogTransaction =
        serde_json::from_slice(&serialized).context("invalid stored catalog transaction")?;
    if transaction.revision <= 0 {
        bail!("stored catalog transaction has an invalid revision");
    }
    if let Some(document) = &transaction.content {
        validate_document(document)?;
    }

    commit_transaction(directory, identity_id, transaction)
}

fn commit_transaction(directory: &Path, identity_id: Uuid, transaction: CatalogTransaction) -> anyhow::Result<()> {
    let destination = directory.join("SoftwareCatalog.json");
    match transaction.content {
        Some(document) => atomic_write(&destination, document.as_bytes())?,
        None => match fs::remove_file(&destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("delete software catalog"),
        },
    }

    atomic_write(
        &revision_path(directory, identity_id),
        transaction.revision.to_string().as_bytes(),
    )?;
    let path = transaction_path(directory, identity_id);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove stored catalog transaction"),
    }
    Ok(())
}

fn read_revision(path: &Path) -> anyhow::Result<i64> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || is_link(&metadata) => {
            bail!("stored catalog revision is not a regular file");
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).context("inspect stored catalog revision"),
    }

    let value = fs::read_to_string(path).context("read stored catalog revision")?;
    value.trim().parse::<i64>().context("invalid stored catalog revision")
}

fn validate_document(document: &str) -> anyhow::Result<()> {
    let parsed: serde_json::Value = serde_json::from_str(document).context("invalid catalog JSON")?;
    if parsed["version"].as_u64() != Some(1) || !parsed["catalogs"].is_array() {
        bail!("unsupported software catalog document");
    }
    Ok(())
}

fn revision_path(directory: &Path, identity_id: Uuid) -> PathBuf {
    directory.join(format!(".devolutions-catalog-{identity_id}.revision"))
}

fn transaction_path(directory: &Path, identity_id: Uuid) -> PathBuf {
    directory.join(format!(".devolutions-catalog-{identity_id}.transaction"))
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
        // UNTESTED: The directory ACL must preserve the catalog's service and reader access without allowing replacement.
        // Verify the effective Windows permissions if changing this ACL.
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
    #[cfg(all(windows, not(test)))]
    {
        // UNTESTED: Catalog files must remain writable only by SYSTEM and Administrators.
        // Verify the effective Windows permissions if changing this ACL.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_catalog_transaction_recovers_before_stale_snapshot() {
        // oracle: regression #2194
        let directory = tempfile::tempdir().expect("create catalog test directory");
        let identity_id = Uuid::new_v4();
        let old_document = r#"{"version":1,"catalogs":[{"name":"old"}]}"#;
        let new_document = r#"{"version":1,"catalogs":[{"name":"new"}]}"#;

        fs::write(revision_path(directory.path(), identity_id), "4").expect("write previous revision");
        fs::write(directory.path().join("SoftwareCatalog.json"), new_document).expect("write new catalog");
        fs::write(
            transaction_path(directory.path(), identity_id),
            serde_json::to_vec(&CatalogTransaction {
                revision: 5,
                content: Some(new_document.to_owned()),
            })
            .expect("serialize pending transaction"),
        )
        .expect("write pending transaction");

        apply_in_directory(
            directory.path(),
            identity_id,
            CatalogSync {
                revision: 4,
                content: Some(catalog_sync::Content::Document(old_document.to_owned())),
            },
        )
        .expect("recover pending transaction and ignore stale snapshot");

        assert_eq!(
            fs::read_to_string(revision_path(directory.path(), identity_id)).expect("read revision"),
            "5"
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("SoftwareCatalog.json")).expect("read catalog"),
            new_document
        );
        assert!(!transaction_path(directory.path(), identity_id).exists());
    }

    #[test]
    fn pending_catalog_deletion_prevents_stale_snapshot_resurrection() {
        // oracle: regression #2194
        let directory = tempfile::tempdir().expect("create catalog test directory");
        let identity_id = Uuid::new_v4();
        let old_document = r#"{"version":1,"catalogs":[{"name":"old"}]}"#;

        fs::write(revision_path(directory.path(), identity_id), "4").expect("write previous revision");
        fs::write(
            transaction_path(directory.path(), identity_id),
            serde_json::to_vec(&CatalogTransaction {
                revision: 5,
                content: None,
            })
            .expect("serialize pending deletion"),
        )
        .expect("write pending deletion");

        apply_in_directory(
            directory.path(),
            identity_id,
            CatalogSync {
                revision: 4,
                content: Some(catalog_sync::Content::Document(old_document.to_owned())),
            },
        )
        .expect("recover pending deletion and ignore stale snapshot");

        assert_eq!(
            fs::read_to_string(revision_path(directory.path(), identity_id)).expect("read revision"),
            "5"
        );
        assert!(!directory.path().join("SoftwareCatalog.json").exists());
        assert!(!transaction_path(directory.path(), identity_id).exists());
    }
}
