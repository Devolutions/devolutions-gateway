//! Compiled as Devolutions Agent unit tests via `#[path]`, not as part of the `testsuite` crate.

use crate::updater::should_refresh_update_status;

#[test]
fn gateway_failure_with_agent_success_refreshes_status() {
    assert!(should_refresh_update_status(true, true, true));
}

#[test]
fn agent_only_success_defers_status_refresh() {
    assert!(!should_refresh_update_status(true, false, true));
}

#[test]
fn ordinary_product_success_or_failure_refreshes_status() {
    assert!(should_refresh_update_status(true, false, false));
    assert!(should_refresh_update_status(false, true, false));
    assert!(should_refresh_update_status(true, true, false));
}

#[test]
fn no_updates_do_not_refresh_status() {
    assert!(!should_refresh_update_status(false, false, false));
}
