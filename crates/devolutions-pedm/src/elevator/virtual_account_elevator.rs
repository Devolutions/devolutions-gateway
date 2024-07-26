use anyhow::Result;
use win_api_wrappers::{
    raw::Win32::{
        Security::{WinBuiltinAdministratorsSid, WinLocalSid, LOGON32_LOGON_INTERACTIVE, SECURITY_NT_AUTHORITY},
        System::SystemServices::{
            SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_LOGON_ID, SE_GROUP_MANDATORY, SE_GROUP_OWNER,
        },
    },
    undoc::LOGON32_PROVIDER_VIRTUAL,
    win::{create_virtual_account, Sid, SidAndAttributes, Token, TokenGroups},
};

use super::Elevator;

pub struct VirtualAccountElevator {
    pub domain: String,
    pub rid: u32,
}

impl Elevator for VirtualAccountElevator {
    /// https://call4cloud.nl/2023/05/the-virtual-account-that-rocks-the-epm/
    /// https://posts.specterops.io/getting-intune-with-bugs-and-tokens-a-journey-through-epm-013b431e7f49
    /// consent.exe!CuipCreateAutomaticAdminAccount
    fn elevate_token(&self, token: &Token) -> Result<Token> {
        let virtual_account = create_virtual_account(self.rid, &self.domain, &token)?;

        let luid = token.statistics()?.TokenId;

        let mut groups = Vec::new();

        groups.push(SidAndAttributes {
            sid: Sid {
                identifier_identity: SECURITY_NT_AUTHORITY,
                sub_authority: vec![5, luid.HighPart as _, luid.LowPart],
                ..Default::default()
            },
            attributes: (SE_GROUP_LOGON_ID | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as _, // 0xc0000007
        });

        groups.push(SidAndAttributes {
            sid: Sid::from_well_known(WinLocalSid, None)?, // S-1-2-0
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as _, // 0x7
        });

        groups.push(SidAndAttributes {
            sid: Sid::from_well_known(WinBuiltinAdministratorsSid, None)?, // S-1-5-32-544
            attributes: (SE_GROUP_OWNER | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as _, // 0xf
        });

        groups.push(SidAndAttributes {
            sid: virtual_account.domain_sid,
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as _, // 0x7
        });

        let base_token = Token::logon(
            &virtual_account.account_name,
            Some(&self.domain),
            None,
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_VIRTUAL,
            Some(&TokenGroups(groups)),
        )?;

        let session_id = token.session_id()?;

        base_token.load_profile(&virtual_account.account_name)?;

        let mut admin_token = base_token.linked_token()?.duplicate_impersonation()?;
        admin_token.set_session_id(session_id)?;

        Ok(admin_token)
    }
}
