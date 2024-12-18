use devolutions_pedm_shared::policy::{Hash, User};
use digest::Update;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::info;
use win_api_wrappers::identity::account::Account;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::netmgmt::get_local_admin_group_members;
use win_api_wrappers::process::{create_process_as_user, ProcessInformation, StartupInfo};
use win_api_wrappers::raw::Win32::System::Threading::PROCESS_CREATION_FLAGS;
use win_api_wrappers::token::Token;
use win_api_wrappers::utils::{create_directory, CommandLine};

// WinAPI's functions have many arguments, we wrap the same way.
#[expect(clippy::too_many_arguments)]
pub(crate) fn start_process(
    token: &Token,
    executable_path: Option<&Path>,
    command_line: Option<&CommandLine>,
    inherit_handles: bool,
    creation_flags: PROCESS_CREATION_FLAGS,
    environment: Option<&HashMap<String, String>>,
    current_directory: Option<&Path>,
    startup_info: &mut StartupInfo,
) -> anyhow::Result<ProcessInformation> {
    let token = token.duplicate_impersonation()?;
    let account = token.sid_and_attributes()?.sid.account(None)?;

    info!(
        ?executable_path,
        ?command_line,
        account.account_name,
        "Starting process"
    );

    let _ctx = token.impersonate()?;

    create_process_as_user(
        Some(&token),
        executable_path,
        command_line,
        None,
        None,
        inherit_handles,
        creation_flags,
        environment,
        current_directory,
        startup_info,
    )
}

fn is_member_of_administrators_group_directly(user_sid: &Sid) -> anyhow::Result<bool> {
    Ok(get_local_admin_group_members()?.contains(user_sid))
}

fn is_member_of_administrators(user_token: &Token) -> anyhow::Result<bool> {
    if is_member_of_administrators_group_directly(&user_token.sid_and_attributes()?.sid)? {
        return Ok(true);
    }

    let local_admin_sids = get_local_admin_group_members()?;
    let group_sids_and_attributes = user_token.groups()?.0;

    for user_group_sid_and_attributes in group_sids_and_attributes {
        for admin_sid in &local_admin_sids {
            if admin_sid == &user_group_sid_and_attributes.sid {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

#[derive(Default)]
pub(crate) struct MultiHasher {
    sha1: Sha1,
    sha256: Sha256,
}

impl MultiHasher {
    pub(crate) fn chain_update(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    pub(crate) fn finalize(self) -> Hash {
        let sha1 = self.sha1.finalize();
        let sha256 = self.sha256.finalize();

        Hash {
            sha1: base16ct::lower::encode_string(&sha1),
            sha256: base16ct::lower::encode_string(&sha256),
        }
    }
}

impl Update for MultiHasher {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.sha1, data);
        Update::update(&mut self.sha256, data);
    }
}

pub(crate) fn file_hash(path: &Path) -> anyhow::Result<Hash> {
    let data = fs::read(path)?;

    let mut hasher = MultiHasher::default();
    hasher.update(&data);
    Ok(hasher.finalize())
}

pub(crate) fn ensure_protected_directory(dir: &Path, _readers: Vec<Sid>) -> anyhow::Result<()> {
    // FIXME: Underlying behaviour of security primitives must be corrected before this can work
    // let owner = Sid::from_well_known(WinLocalSystemSid, None)?;

    // let mut aces = vec![Ace {
    //     flags: OBJECT_INHERIT_ACE,
    //     access_mask: GENERIC_ALL.0,
    //     data: AceType::AccessAllowed(owner.clone()),
    // }];

    // aces.extend(readers.into_iter().map(|sid| Ace {
    //     flags: OBJECT_INHERIT_ACE,
    //     access_mask: GENERIC_READ.0,
    //     data: AceType::AccessAllowed(sid),
    // }));

    // let dacl = InheritableAcl {
    //     kind: InheritableAclKind::Protected,
    //     acl: Acl::with_aces(aces),
    // };

    // if dir.exists() {
    //     set_named_security_info(
    //         &dir.to_string_lossy(),
    //         SE_FILE_OBJECT,
    //         Some(&owner),
    //         None,
    //         Some(&dacl),
    //         None,
    //     )?;
    // } else {
    //     create_directory_with_security_attributes(
    //         dir,
    //         &SecurityAttributes {
    //             security_descriptor: Some(SecurityDescriptor {
    //                 owner: Some(owner),
    //                 dacl: Some(dacl),
    //                 ..Default::default()
    //             }),
    //             inherit_handle: false,
    //         },
    //     )?;
    // }

    if !dir.exists() {
        create_directory(dir)?;
    }

    Ok(())
}

pub(crate) trait AccountExt {
    fn to_user(self) -> User;
}

impl AccountExt for Account {
    fn to_user(self) -> User {
        User {
            account_name: self.account_name,
            domain_name: self.domain_name,
            account_sid: self.account_sid.to_string(),
            domain_sid: self.domain_sid.to_string(),
        }
    }
}
