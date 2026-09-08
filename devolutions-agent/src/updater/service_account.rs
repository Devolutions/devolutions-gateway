//! Identity of the account the Devolutions Gateway service logs on as.
//!
//! The Gateway historically ran as NETWORK SERVICE, but its installer accepts a custom
//! service account (a managed service account, the service's virtual account, or a regular
//! user). The agent needs to know that account for two reasons:
//!
//! - the update channel files (`update.json`, `update_status.json`) must grant it access;
//! - an account that logs on with a password cannot be carried across an MSI upgrade
//!   without that password, so unattended Gateway updates are not possible for it.

use anyhow::Context as _;
use win_api_wrappers::identity::account::lookup_account_by_name;
use win_api_wrappers::identity::sid::StringSid;
use win_api_wrappers::service::ServiceManager;
use win_api_wrappers::utils::WideString;

/// Service name of the Devolutions Gateway Windows service.
pub(crate) const GATEWAY_SERVICE_NAME: &str = "DevolutionsGateway";

/// String SID of NT AUTHORITY\NetworkService, the account the Gateway runs as by default.
pub(crate) const NETWORK_SERVICE_SID: &str = "S-1-5-20";

/// The account the Gateway service is configured to log on as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatewayServiceAccount {
    /// Account name as recorded by the service control manager, e.g. `NT AUTHORITY\NetworkService`
    /// or `CONTOSO\gateway$`.
    pub(crate) name: String,
    /// String SID of the account.
    pub(crate) sid: String,
}

impl GatewayServiceAccount {
    /// Query the service control manager for the Gateway service account and resolve its SID.
    ///
    /// Returns `Ok(None)` when the Gateway service is not installed on this host.
    pub(crate) fn query() -> anyhow::Result<Option<Self>> {
        let service_manager = ServiceManager::open_read().context("open service control manager")?;

        let service = match service_manager.open_service_read(GATEWAY_SERVICE_NAME) {
            Ok(service) => service,
            Err(error) => {
                debug!(%error, "Gateway service not found");
                return Ok(None);
            }
        };

        let name = service
            .account_name()
            .context("query Gateway service account name")?
            .unwrap_or_else(|| "LocalSystem".to_owned());

        let sid = resolve_sid(&name).with_context(|| format!("resolve SID of service account `{name}`"))?;

        Ok(Some(Self { name, sid }))
    }

    /// Whether the account logs on without a password that the installer would need to be given.
    pub(crate) fn is_passwordless(&self) -> bool {
        is_passwordless_account(&self.name, &self.sid)
    }
}

fn resolve_sid(account_name: &str) -> anyhow::Result<String> {
    let wide_name = WideString::from(account_name);
    let wide_name = wide_name.0.as_deref().context("empty account name")?;
    let wide_name =
        widestring::U16CStr::from_slice_truncate(wide_name).context("account name is not a valid wide string")?;

    let account = lookup_account_by_name(wide_name).context("LookupAccountNameW")?;
    let sid = StringSid::from_sid(&account.sid).context("convert SID to string")?;

    Ok(sid.to_string())
}

/// Classify a service account by the conventions the Gateway installer uses.
///
/// Passwordless accounts are the well-known service accounts, virtual accounts
/// (`NT SERVICE\...`, SID prefix `S-1-5-80`), and standalone or group managed service
/// accounts, whose SAM account names end with `$`. Everything else is a regular user that
/// logs on with a password.
pub(crate) fn is_passwordless_account(name: &str, sid: &str) -> bool {
    const WELL_KNOWN_SERVICE_SIDS: [&str; 3] = [
        "S-1-5-18", // LocalSystem
        "S-1-5-19", // NT AUTHORITY\LocalService
        NETWORK_SERVICE_SID,
    ];

    if WELL_KNOWN_SERVICE_SIDS.contains(&sid) {
        return true;
    }

    if sid.starts_with("S-1-5-80-") {
        return true;
    }

    let sam_account_name = name.rsplit_once('\\').map_or(name, |(_, sam)| sam);
    let sam_account_name = sam_account_name
        .split_once('@')
        .map_or(sam_account_name, |(sam, _)| sam);

    sam_account_name.ends_with('$')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_service_accounts_are_passwordless() {
        assert!(is_passwordless_account("NT AUTHORITY\\NetworkService", "S-1-5-20"));
        assert!(is_passwordless_account("NT AUTHORITY\\LocalService", "S-1-5-19"));
        assert!(is_passwordless_account("LocalSystem", "S-1-5-18"));
    }

    #[test]
    fn virtual_accounts_are_passwordless() {
        assert!(is_passwordless_account(
            "NT SERVICE\\DevolutionsGateway",
            "S-1-5-80-1234567890-1234567890-1234567890-1234567890-1234567890"
        ));
    }

    #[test]
    fn managed_service_accounts_are_passwordless() {
        assert!(is_passwordless_account(
            "CONTOSO\\gateway$",
            "S-1-5-21-1111111111-2222222222-3333333333-1105"
        ));
        assert!(is_passwordless_account(
            "gateway$@contoso.com",
            "S-1-5-21-1111111111-2222222222-3333333333-1105"
        ));
    }

    #[test]
    fn user_accounts_require_a_password() {
        assert!(!is_passwordless_account(
            "CONTOSO\\svc-gateway",
            "S-1-5-21-1111111111-2222222222-3333333333-1106"
        ));
        assert!(!is_passwordless_account(
            "svc-gateway@contoso.com",
            "S-1-5-21-1111111111-2222222222-3333333333-1106"
        ));
        assert!(!is_passwordless_account(
            ".\\gateway",
            "S-1-5-21-4444444444-5555555555-6666666666-1001"
        ));
    }
}
