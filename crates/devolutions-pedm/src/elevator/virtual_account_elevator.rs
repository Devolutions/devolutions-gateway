//! Elevator in charge of virtual account elevation.
//!
//! Virtual account elevation works by creating a virtual SID name mapping using `LsaManageSidNameMapping`,
//! and then logging into the account using `LogonUserExExW` with the undocumented `LOGON32_PROVIDER_VIRTUAL` provider.
//! Then we add the logon ID of the logged in user to the virtual user's groups so that it has access to the user's desktop.
//! This way, we can start processes with administrator privileges on the user's desktop without it being their account.
//!
//! This method can however lead to isses when doing remote authentication etc. since sometimes it can expect a user, which
//! is not the virtual user.

use std::collections::HashMap;

use anyhow::Context as _;
use parking_lot::RwLock;
use win_api_wrappers::Error;
use win_api_wrappers::identity::account::{ProfileInfo, create_virtual_account};
use win_api_wrappers::identity::sid::{Sid, SidAndAttributes};
use win_api_wrappers::raw::Win32::Foundation::ERROR_ACCOUNT_EXPIRED;
use win_api_wrappers::raw::Win32::Security::{LOGON32_LOGON_INTERACTIVE, WinBuiltinAdministratorsSid, WinLocalSid};
use win_api_wrappers::raw::Win32::System::SystemServices::{
    SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_LOGON_ID, SE_GROUP_MANDATORY, SE_GROUP_OWNER,
};
use win_api_wrappers::str::U16CString;
use win_api_wrappers::token::Token;
use win_api_wrappers::token_groups::TokenGroups;
use win_api_wrappers::undoc::LOGON32_PROVIDER_VIRTUAL;

use super::Elevator;

struct VirtualAccountElevation {
    _base_token: Token,
    elevated_token: Token,
    _profile: ProfileInfo,
}

// SAFETY: `*mut u16` from `profile` not used.
unsafe impl Sync for VirtualAccountElevation {}

// SAFETY: `*mut u16` from `profile` not used.
unsafe impl Send for VirtualAccountElevation {}

pub(crate) struct VirtualAccountElevator {
    domain: String,
    rid: u32,
    tokens: RwLock<HashMap<Sid, VirtualAccountElevation>>,
}

impl VirtualAccountElevator {
    pub(crate) fn new(domain: String, rid: u32) -> Self {
        Self {
            domain,
            rid,
            tokens: RwLock::new(HashMap::new()),
        }
    }

    fn create_token(&self, token: &Token) -> anyhow::Result<()> {
        let domain = U16CString::from_str(&self.domain)?;

        let virtual_account = create_virtual_account(self.rid, &domain, token).context("create virtual account")?;

        let mut groups = TokenGroups::new(
            // Needed for the virtual account to access the user's desktop and window station.
            SidAndAttributes {
                sid: token.logon_sid()?,
                #[expect(clippy::cast_sign_loss)]
                attributes: (SE_GROUP_LOGON_ID | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY)
                    as u32, // 0xc0000007
            },
        );

        groups.push(SidAndAttributes {
            sid: Sid::from_well_known(WinLocalSid, None)?, // S-1-2-0
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as u32, // 0x7
        });

        groups.push(SidAndAttributes {
            sid: Sid::from_well_known(WinBuiltinAdministratorsSid, None)?, // S-1-5-32-544
            attributes: (SE_GROUP_OWNER | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as u32, // 0xf
        });

        groups.push(SidAndAttributes {
            sid: virtual_account.domain_sid,
            attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as u32, // 0x7
        });

        let base_token = Token::logon(
            &virtual_account.name,
            Some(&domain),
            None,
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_VIRTUAL,
            Some(&groups),
        )
        .context("logon virtual account")?;

        let profile = base_token
            .load_profile(virtual_account.name)
            .context("load virtual account profile")?;

        let elevated_token = base_token.linked_token()?;

        self.tokens.write().insert(
            token.sid_and_attributes()?.sid,
            VirtualAccountElevation {
                _base_token: base_token,
                elevated_token,
                _profile: profile,
            },
        );

        Ok(())
    }
}

impl Elevator for VirtualAccountElevator {
    /// https://call4cloud.nl/2023/05/the-virtual-account-that-rocks-the-epm/
    /// https://posts.specterops.io/getting-intune-with-bugs-and-tokens-a-journey-through-epm-013b431e7f49
    /// consent.exe!CuipCreateAutomaticAdminAccount
    fn elevate_token(&self, token: &Token) -> anyhow::Result<Token> {
        let sid = token.sid_and_attributes()?.sid;

        if !self.tokens.read().contains_key(&sid) {
            self.create_token(token).context("create virtual account token")?;
        }

        self.tokens
            .read()
            .get(&sid)
            .ok_or_else(|| anyhow::anyhow!(Error::from_win32(ERROR_ACCOUNT_EXPIRED)))
            .and_then(|vtoken| {
                let mut vtoken = vtoken
                    .elevated_token
                    .duplicate_impersonation()
                    .context("duplicate virtual elevated token")?;

                vtoken
                    .set_session_id(token.session_id()?)
                    .context("set virtual token session id")?;

                Ok(vtoken)
            })
    }
}
