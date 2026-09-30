use win_api_wrappers::identity::account::{get_username, is_managed_service_account, lookup_account_by_name};
use win_api_wrappers::service::ServiceManager;
use win_api_wrappers::str::U16CString;
use windows::Win32::Security::Authentication::Identity::NameSamCompatible;

#[test]
#[ignore = "requires a running local Netlogon service; run explicitly on a configured account-lab host"]
fn unknown_dollar_suffix_is_not_a_managed_service_account() {
    let name = format!("gw{}$", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let name = U16CString::from_str(name).unwrap();
    assert!(!is_managed_service_account(&name).unwrap());
}

#[test]
fn unknown_account_lookup_returns_an_error() {
    for suffix in ["", "$"] {
        let name = U16CString::from_str(format!("gateway-{}{suffix}", uuid::Uuid::new_v4())).unwrap();
        assert!(lookup_account_by_name(&name).is_err());
    }
}

#[test]
#[ignore = "requires a running local Netlogon service and an ordinary user; run explicitly on a configured account-lab host"]
fn ordinary_user_is_not_a_managed_service_account() {
    let user = get_username(NameSamCompatible).unwrap().to_string().unwrap();
    let sam_name = user.rsplit('\\').next().unwrap();
    assert!(!sam_name.ends_with('$'), "run this test as an ordinary user");
    let sam_name = U16CString::from_str(sam_name).unwrap();
    assert!(!is_managed_service_account(&sam_name).unwrap());
}

#[test]
fn service_configuration_exposes_account_name() {
    let scm = ServiceManager::open_read().unwrap();
    let event_log = scm.open_service_read("EventLog").unwrap();
    assert!(!event_log.account_name().unwrap().unwrap().is_empty());
}
