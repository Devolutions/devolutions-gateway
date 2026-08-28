use anyhow::Context as _;
use camino::Utf8Path;

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
    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::raw::Win32::Security;
    use win_api_wrappers::raw::Win32::Security::Authorization::GRANT_ACCESS;
    use win_api_wrappers::raw::Win32::Storage::FileSystem::{
        DELETE, FILE_ALL_ACCESS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
    use win_api_wrappers::security::attributes::SecurityAttributesInit;
    use win_api_wrappers::token::Token;

    let modify = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0;

    let entry = |access_permissions, sid| ExplicitAccess {
        access_permissions,
        access_mode: GRANT_ACCESS,
        inheritance: Security::NO_INHERITANCE,
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

    let dacl = InheritableAcl {
        kind: InheritableAclKind::Protected,
        acl: Acl::new()
            .and_then(|acl| acl.set_entries(&entries))
            .context("build restricted DACL")?,
    };

    let attributes = SecurityAttributesInit {
        dacl: Some(dacl),
        ..Default::default()
    }
    .init();

    win_api_wrappers::fs::create_file(path.as_std_path(), Some(&attributes))
        .with_context(|| format!("create file {path}"))
}
