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

pub struct LocalAdminElevator {
    source: TOKEN_SOURCE,
}

impl LocalAdminElevator {
    pub fn new(source_name: &[u8; 8], source_identifier: LUID) -> Self {
        let mut source = TOKEN_SOURCE::default();
        source.SourceIdentifier = source_identifier;
        source
            .SourceName
            .iter_mut()
            .zip(source_name.iter())
            .for_each(|(x, y)| *x = *y as _);

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
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as _,
        });

        groups.0.push(SidAndAttributes {
            sid: owner_sid.clone(),
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY | SE_GROUP_OWNER) as _,
        });

        groups.0.push(SidAndAttributes {
            sid: Sid::from_well_known(WinHighLabelSid, None)?,
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as _,
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
