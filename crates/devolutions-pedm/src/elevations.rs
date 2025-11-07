//! Module in charge of handling elevated sessions.
//!
//! This includes session elevations that do not expire until the user manually revokes them or temporary based elevations.
//! Note that temporary elevations will not kill processes launched and will just deny creations after the expiration period.
use devolutions_pedm_shared::policy::User;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[expect(dead_code, reason = "work in progress feature")]
#[derive(Clone)]
pub(crate) enum Elevation {
    Temporary(Instant),
    Session,
}

#[expect(dead_code, reason = "work in progress feature")]
fn elevations() -> &'static RwLock<HashMap<User, Elevation>> {
    static ELEVATIONS: OnceLock<RwLock<HashMap<User, Elevation>>> = OnceLock::new();
    ELEVATIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

#[expect(dead_code, reason = "work in progress feature")]
pub(crate) fn elevation_time_left_secs(user: &User) -> Option<u64> {
    elevations().read().get(user).and_then(|x| {
        if let Elevation::Temporary(i) = x {
            Some((*i - Instant::now()).as_secs())
        } else {
            None
        }
    })
}

#[expect(dead_code, reason = "work in progress feature")]
pub(crate) fn is_elevated(user: &User) -> bool {
    elevations().read().get(user).is_some_and(|elev| match elev {
        Elevation::Temporary(i) => Instant::now() < *i,
        Elevation::Session => true,
    })
}

#[expect(dead_code, reason = "work in progress feature")]
pub(crate) fn elevate_session(user: User) {
    elevations().write().insert(user, Elevation::Session);
}

#[expect(dead_code, reason = "work in progress feature")]
pub(crate) fn elevate_temporary(user: User, duration: &Duration) {
    elevations()
        .write()
        .insert(user, Elevation::Temporary(Instant::now() + *duration));
}

#[expect(dead_code, reason = "work in progress feature")]
pub(crate) fn revoke(user: &User) {
    elevations().write().remove(user);
}
