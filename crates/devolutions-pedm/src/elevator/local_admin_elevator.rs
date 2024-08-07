//! Elevator in charge of local admin elevation.
//!
//! This works without ever adding the target user to the administrator group.
//! A token is manually created using `NtCreateToken`, and the administrator group is specified.
//! This has the advantage of granting the user a token for admin purposes we can control without a timespan where the user
//! is free to do what they want in the admin group.
use anyhow::Result;
use win_api_wrappers::identity::sid::{Sid, SidAndAttributes};
use win_api_wrappers::raw::Win32::Foundation::LUID;
use win_api_wrappers::raw::Win32::Security::{
    WinBuiltinAdministratorsSid, WinHighLabelSid, WinLocalAccountAndAdministratorSid, TOKEN_SOURCE,
};
use win_api_wrappers::raw::Win32::System::SystemServices::{
    SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY, SE_GROUP_OWNER,
};
use win_api_wrappers::security::privilege::default_admin_privileges;
use win_api_wrappers::token::Token;

use super::Elevator;

pub(crate) struct LocalAdminElevator {
    source: TOKEN_SOURCE,
}

impl LocalAdminElevator {
    pub(crate) fn new(source_name: &[u8; 8], source_identifier: LUID) -> Self {
        let mut source = TOKEN_SOURCE {
            SourceIdentifier: source_identifier,
            ..Default::default()
        };

        // Wrapping is what we want.
        #[allow(clippy::cast_possible_wrap)]
        source
            .SourceName
            .iter_mut()
            .zip(source_name.iter())
            .for_each(|(x, y)| *x = *y as i8);

        Self { source }
    }
}

impl Elevator for LocalAdminElevator {
    fn elevate_token(&self, token: &Token) -> Result<Token> {
        let stats = token.statistics()?;

        let owner_sid = Sid::from_well_known(WinBuiltinAdministratorsSid, None)?;

        let mut groups = token.groups()?;
        groups.0.push(SidAndAttributes {
            sid: Sid::from_well_known(WinLocalAccountAndAdministratorSid, None)?,
            #[allow(clippy::cast_sign_loss)]
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as u32,
        });

        groups.0.push(SidAndAttributes {
            sid: owner_sid.clone(),
            #[allow(clippy::cast_sign_loss)]
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY | SE_GROUP_OWNER) as u32,
        });

        groups.0.push(SidAndAttributes {
            sid: Sid::from_well_known(WinHighLabelSid, None)?,
            #[allow(clippy::cast_sign_loss)]
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as u32,
        });

        let mut admin_token = Token::create_token(
            &stats.AuthenticationId,
            stats.ExpirationTime,
            &token.sid_and_attributes()?,
            &groups,
            default_admin_privileges(),
            &owner_sid,
            &token.primary_group()?,
            token.default_dacl()?.as_ref(),
            &self.source,
        )?;

        admin_token.set_session_id(token.session_id()?)?;
        admin_token.set_mandatory_policy(token.mandatory_policy()?)?;

        Ok(admin_token)
    }
}
