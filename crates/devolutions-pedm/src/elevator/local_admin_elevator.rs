//! Elevator in charge of local admin elevation.
//!
//! This works without ever adding the target user to the administrator group.
//! A token is manually created using `NtCreateToken`, and the administrator group is specified.
//! This has the advantage of granting the user a token for admin purposes we can control without a timespan where the user
//! is free to do what they want in the admin group.

use anyhow::Context as _;

use win_api_wrappers::identity::sid::{Sid, SidAndAttributes};
use win_api_wrappers::raw::Win32::Foundation::LUID;
use win_api_wrappers::raw::Win32::Security;
use win_api_wrappers::raw::Win32::System::SystemServices;
use win_api_wrappers::security::privilege::DEFAULT_ADMIN_PRIVILEGES;
use win_api_wrappers::token::Token;

use crate::elevator::Elevator;

pub(crate) struct LocalAdminElevator {
    source: Security::TOKEN_SOURCE,
}

impl LocalAdminElevator {
    pub(crate) fn new(source_name: &[u8; 8], source_identifier: LUID) -> Self {
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

        Self { source }
    }
}

impl Elevator for LocalAdminElevator {
    fn elevate_token(&self, token: &Token) -> anyhow::Result<Token> {
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

        let mut admin_token = Token::create_token(
            &stats.AuthenticationId,
            stats.ExpirationTime,
            &token.sid_and_attributes()?,
            &groups,
            &DEFAULT_ADMIN_PRIVILEGES,
            &owner_sid,
            &token.primary_group()?,
            token.default_dacl()?.as_ref(),
            &self.source,
        )
        .context("create token")?;

        admin_token
            .set_session_id(token.session_id()?)
            .context("set session ID on admin token")?;

        admin_token
            .set_mandatory_policy(token.mandatory_policy()?)
            .context("set mandatory policy on admin token")?;

        Ok(admin_token)
    }
}
