#![allow(clippy::print_stdout)]

use anyhow::Context as _;
use win_api_wrappers::identity::account::{enumerate_account_rights, get_username, lookup_account_by_name};
use win_api_wrappers::identity::sid::{Sid, SidAndAttributes};
use win_api_wrappers::process::Process;
use win_api_wrappers::raw::Win32::Foundation::LUID;
use win_api_wrappers::raw::Win32::Security;
use win_api_wrappers::raw::Win32::System::SystemServices;
use win_api_wrappers::raw::core::HRESULT;
use win_api_wrappers::security::privilege;
use win_api_wrappers::str::u16cstr;
use win_api_wrappers::token::{Token, TokenPrivilegesAdjustment};

pub(super) fn main() -> anyhow::Result<()> {
    // -- Configuration -- //

    let expect_elevation = std::env::var("PEDM_SIMULATOR_EXPECT_ELEVATION").is_ok();

    // -- Parameters -- //

    // Obtain a token handle from the current process.
    // We just need TOKEN_ADJUST_PRIVILEGES and TOKEN_QUERY accesses.
    let mut token = Process::current_process()
        .token(Security::TOKEN_ADJUST_PRIVILEGES | Security::TOKEN_QUERY)
        .context("open current process token")?;

    // Verify that the current account is assigned with the SE_CREATE_TOKEN_NAME privilege.
    println!("Retrieve the current account name...");
    let account_username =
        get_username(Security::Authentication::Identity::NameSamCompatible).context("retrieve account username")?;
    println!("Account name: {account_username:?}");

    match lookup_account_by_name(&account_username) {
        Ok(account) => {
            // Verify that the current account is assigned with the SE_CREATE_TOKEN_NAME privilege.
            println!(
                "Attempting to verify whether the current account is assigned with the SE_CREATE_TOKEN_NAME privilege"
            );

            let rights = enumerate_account_rights(&account.sid)
                .with_context(|| format!("enumerate account rights for {account_username:?}"))?;
            let has_create_token_right = rights.iter().any(|right| right == u16cstr!("SeCreateTokenPrivilege"));
            println!("Has SeCreateTokenPrivilege right? {has_create_token_right}");

            if expect_elevation {
                assert!(has_create_token_right);
                println!("Current user is assigned the SeCreateTokenPrivilege right. Enabling it...");

                // SE_CREATE_TOKEN_NAME is required for performing the elevation.
                let se_create_token_name_luid =
                    privilege::lookup_privilege_value(None, privilege::SE_CREATE_TOKEN_NAME)
                        .context("lookup SE_CREATE_TOKEN_NAME privilege")?;
                token
                    .adjust_privileges(&TokenPrivilegesAdjustment::Enable(vec![se_create_token_name_luid]))
                    .context("enable SE_CREATE_TOKEN_NAME privilege")?;

                // Verify the SE_CREATE_TOKEN_NAME privilege is actually enabled.
                let se_create_token_name_is_enabled = token
                    .privileges()
                    .context("list token privileges")?
                    .as_slice()
                    .iter()
                    .any(|privilege| privilege.Luid == se_create_token_name_luid);

                assert!(se_create_token_name_is_enabled);
            }
        }
        Err(e) => {
            println!("Failed to look up account for {account_username:?}: {e}");

            // Possible issue when running this program using psexec -s, under `NT AUTHORITY\SYSTEM` (LocalSystem):
            // - There is no direct domain credentials by default, unless the machine is domain joined and has a line-of-sight to the DC.
            // - This context may not be able to see the same network resources or DC that the interactive user.
            // Causing LookupAccountNameW to fail with a "no mapping" error.
            // Let’s just go ahead with the elevation in this case, assuming LocalSystem is enough for all intents and purposes at this point.
            #[expect(clippy::cast_possible_wrap)]
            if e.code() == HRESULT(0x80070534u32 as i32) {
                println!("Got the 'no mapping' error; continuing...")
            } else {
                return Err(anyhow::Error::new(e).context(format!(
                    "unexpected error when looking up the account for {account_username:?}"
                )));
            }
        }
    }

    let token_source = build_token_source(LADM_SRC_NAME, LADM_SRC_LUID);

    // -- Relevant snippet from local_admin_elevator.rs -- //

    let stats = token.statistics().context("fetch token status")?;

    let owner_sid = Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None)?;

    let mut groups = token.groups().context("fetch token groups")?;

    groups.push(SidAndAttributes {
        sid: Sid::from_well_known(Security::WinLocalAccountAndAdministratorSid, None)?,
        attributes: (SystemServices::SE_GROUP_ENABLED
            | SystemServices::SE_GROUP_ENABLED_BY_DEFAULT
            | SystemServices::SE_GROUP_MANDATORY) as u32,
    });

    groups.push(SidAndAttributes {
        sid: owner_sid.clone(),
        attributes: (SystemServices::SE_GROUP_ENABLED
            | SystemServices::SE_GROUP_ENABLED_BY_DEFAULT
            | SystemServices::SE_GROUP_MANDATORY
            | SystemServices::SE_GROUP_OWNER) as u32,
    });

    groups.push(SidAndAttributes {
        sid: Sid::from_well_known(Security::WinHighLabelSid, None)?,
        attributes: (SystemServices::SE_GROUP_ENABLED
            | SystemServices::SE_GROUP_ENABLED_BY_DEFAULT
            | SystemServices::SE_GROUP_MANDATORY) as u32,
    });

    let res = Token::create_token(
        &stats.AuthenticationId,
        stats.ExpirationTime,
        &token.sid_and_attributes()?,
        &groups,
        &privilege::DEFAULT_ADMIN_PRIVILEGES,
        &owner_sid,
        &token.primary_group()?,
        token.default_dacl()?.as_ref(),
        &token_source,
    );

    if expect_elevation {
        match res {
            Ok(mut admin_token) => {
                admin_token
                    .set_session_id(token.session_id()?)
                    .context("set session ID on admin token")?;

                admin_token
                    .set_mandatory_policy(token.mandatory_policy()?)
                    .context("set mandatory policy on admin token")?;

                // Verify the admin token is elevated.
                let admin_token_is_elevated = admin_token.is_elevated().context("is_elevated")?;
                assert!(admin_token_is_elevated);

                println!("Successfully created an elevated, admin token.")
            }
            Err(e) => return Err(e.context("failed to create admin token")),
        }
    } else {
        match res {
            Ok(_) => {
                anyhow::bail!("admin token creation succeded, but this was not expected")
            }
            Err(e) => {
                assert_eq!(e.to_string(), "no token found for SE_CREATE_TOKEN_NAME privilege");
                println!("As expected, we couldn’t get an elevated, admin token.")
            }
        }
    }

    println!("OK.");

    Ok(())
}

const LADM_SRC_NAME: &[u8; 8] = b"DevoPEDM";

const LADM_SRC_LUID: LUID = LUID {
    HighPart: 0,
    LowPart: 0x1337,
};

fn build_token_source(source_name: &[u8; 8], source_identifier: LUID) -> Security::TOKEN_SOURCE {
    let mut source = Security::TOKEN_SOURCE {
        SourceIdentifier: source_identifier,
        ..Default::default()
    };

    // Wrapping is what we want.
    #[expect(clippy::cast_possible_wrap)]
    source
        .SourceName
        .iter_mut()
        .zip(source_name.iter())
        .for_each(|(x, y)| *x = *y as i8);

    source
}
