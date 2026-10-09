use anyhow::Context as _;
use camino::Utf8Path;

pub fn write_restricted_file_atomic(path: &Utf8Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write as _;

    let parent = path.parent().context("restricted file requires a parent directory")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".identity-")
        .make_in(parent, |candidate| {
            let candidate = Utf8Path::from_path(candidate)
                .ok_or_else(|| std::io::Error::other("non-UTF-8 restricted file path"))?;
            create_restricted_file(candidate).map_err(std::io::Error::other)
        })
        .context("create restricted temporary file")?;
    temporary
        .write_all(contents.as_bytes())
        .context("write restricted temporary file")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync restricted temporary file")?;
    temporary
        .into_temp_path()
        .persist(path)
        .map_err(|error| error.error)
        .context("replace restricted file")?;
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("sync restricted file directory")?;
    Ok(())
}

pub fn create_restricted_directory(path: &Utf8Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create restricted directory parent")?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "restricted directory must be a real directory"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect restricted directory"),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        if !path.exists() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .context("create restricted directory")?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .context("restrict directory permissions")?;
    }
    #[cfg(windows)]
    {
        use win_api_wrappers::raw::Win32::Security::Authorization::SE_FILE_OBJECT;
        use win_api_wrappers::security::acl::set_named_security_info;
        use win_api_wrappers::str::U16CString;
        let attributes = restricted_attributes(true)?;
        if !path.exists() {
            win_api_wrappers::fs::create_directory(path.as_std_path(), Some(&attributes))
                .context("create restricted directory")?;
        }
        let name = U16CString::from_str(path.as_str()).context("encode restricted directory path")?;
        let dacl = restricted_dacl(true)?;
        set_named_security_info(&name, SE_FILE_OBJECT, None, None, Some(&dacl), None)
            .context("restrict directory permissions")?;
    }
    Ok(())
}

pub fn write_restricted_file(path: &Utf8Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write as _;

    let _ = std::fs::remove_file(path);

    let mut file = create_restricted_file(path)?;

    file.write_all(contents.as_bytes())
        .with_context(|| format!("write to {path}"))
}

#[cfg(not(windows))]
fn create_restricted_file(path: &Utf8Path) -> anyhow::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    options.open(path).with_context(|| format!("create file {path}"))
}

#[cfg(windows)]
fn create_restricted_file(path: &Utf8Path) -> anyhow::Result<std::fs::File> {
    let attributes = restricted_attributes(false)?;
    win_api_wrappers::fs::create_file(path.as_std_path(), Some(&attributes))
        .with_context(|| format!("create file {path}"))
}

#[cfg(windows)]
fn restricted_dacl(inherit: bool) -> anyhow::Result<win_api_wrappers::security::acl::InheritableAcl> {
    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::raw::Win32::Security;
    use win_api_wrappers::raw::Win32::Security::Authorization::GRANT_ACCESS;
    use win_api_wrappers::raw::Win32::Storage::FileSystem::{
        DELETE, FILE_ALL_ACCESS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
    use win_api_wrappers::token::Token;

    let modify = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0;

    let entry = |access_permissions, sid| ExplicitAccess {
        access_permissions,
        access_mode: GRANT_ACCESS,
        inheritance: if inherit {
            Security::OBJECT_INHERIT_ACE | Security::CONTAINER_INHERIT_ACE
        } else {
            Security::NO_INHERITANCE
        },
        trustee: Trustee::Sid(sid),
    };

    let well_known = |sid_type| Sid::from_well_known(sid_type, None).context("get well-known SID");

    let entries = [
        entry(FILE_ALL_ACCESS.0, well_known(Security::WinLocalSystemSid)?),
        entry(FILE_ALL_ACCESS.0, well_known(Security::WinBuiltinAdministratorsSid)?),
        entry(modify, well_known(Security::WinNetworkServiceSid)?),
        entry(
            modify,
            Token::current_process_token()
                .sid_and_attributes()
                .context("get current process token user")?
                .sid,
        ),
    ];

    Ok(InheritableAcl {
        kind: InheritableAclKind::Protected,
        acl: Acl::new()
            .and_then(|acl| acl.set_entries(&entries))
            .context("build restricted DACL")?,
    })
}

#[cfg(windows)]
fn restricted_attributes(inherit: bool) -> anyhow::Result<win_api_wrappers::security::attributes::SecurityAttributes> {
    use win_api_wrappers::security::attributes::SecurityAttributesInit;

    Ok(SecurityAttributesInit {
        dacl: Some(restricted_dacl(inherit)?),
        ..Default::default()
    }
    .init())
}
