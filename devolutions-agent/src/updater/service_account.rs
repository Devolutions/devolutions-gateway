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
use win_api_wrappers::identity::account::{is_managed_service_account, lookup_account_by_name};
use win_api_wrappers::identity::sid::StringSid;
use win_api_wrappers::service::{ServiceError, ServiceManager};
use win_api_wrappers::str::U16CString;
use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;

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
    passwordless: bool,
}

impl GatewayServiceAccount {
    /// Query the service control manager for the Gateway service account and resolve its SID.
    ///
    /// Returns `Ok(None)` when the Gateway service is not installed on this host.
    pub(crate) fn query() -> anyhow::Result<Option<Self>> {
        let service_manager = ServiceManager::open_read().context("open service control manager")?;

        let service = match service_manager.open_service_read(GATEWAY_SERVICE_NAME) {
            Ok(service) => service,
            Err(ServiceError::WinAPI(error)) if error.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => {
                return Ok(None);
            }
            Err(error) => return Err(error).context("open Gateway service"),
        };

        let mut name = service
            .account_name()
            .context("query Gateway service account name")?
            .unwrap_or_else(|| "LocalSystem".to_owned());
        if let Some(local_name) = name.strip_prefix(".\\") {
            name = format!(
                "{}\\{local_name}",
                std::env::var("COMPUTERNAME").context("resolve local computer name")?
            );
        }

        let sid = resolve_sid(&name).with_context(|| format!("resolve SID of service account `{name}`"))?;
        let passwordless = match sid.as_str() {
            NETWORK_SERVICE_SID => true,
            "S-1-5-18" | "S-1-5-19" => anyhow::bail!("unsupported Gateway service account `{name}`"),
            _ if sid.starts_with("S-1-5-80-") => {
                anyhow::ensure!(
                    name.eq_ignore_ascii_case("NT SERVICE\\DevolutionsGateway"),
                    "virtual account `{name}` does not belong to Gateway"
                );
                true
            }
            _ => {
                let sam_name = name.rsplit_once('\\').map_or(name.as_str(), |(_, sam)| sam);
                let local_prefix = format!(
                    "{}\\",
                    std::env::var("COMPUTERNAME").context("resolve local computer name")?
                );
                if !sam_name.ends_with('$') || name.to_uppercase().starts_with(&local_prefix.to_uppercase()) {
                    false
                } else {
                    let account_name = U16CString::from_str(&name).context("invalid managed account name")?;
                    is_managed_service_account(&account_name).context("query managed service account registration")?
                }
            }
        };

        Ok(Some(Self {
            name,
            sid,
            passwordless,
        }))
    }

    /// Whether the account logs on without a password that the installer would need to be given.
    pub(crate) fn is_passwordless(&self) -> bool {
        self.passwordless
    }
}

fn resolve_sid(account_name: &str) -> anyhow::Result<String> {
    let wide_name = U16CString::from_str(account_name).context("account name contains a null character")?;
    let account = lookup_account_by_name(&wide_name).context("LookupAccountNameW")?;
    let sid = StringSid::from_sid(&account.sid).context("convert SID to string")?;

    Ok(sid.to_string())
}
