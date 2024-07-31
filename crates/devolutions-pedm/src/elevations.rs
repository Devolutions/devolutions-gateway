use devolutions_pedm_shared::policy::User;
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::OnceLock,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub enum Elevation {
    Temporary(Instant),
    Session,
}

fn elevations() -> &'static RwLock<HashMap<User, Elevation>> {
    static ELEVATIONS: OnceLock<RwLock<HashMap<User, Elevation>>> = OnceLock::new();
    ELEVATIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn elevation_time_left_secs(user: &User) -> Option<u64> {
    elevations().read().get(user).and_then(|x| {
        if let Elevation::Temporary(i) = x {
            Some((*i - Instant::now()).as_secs())
        } else {
            None
        }
    })
}

pub fn is_elevated(user: &User) -> bool {
    elevations().read().get(user).is_some_and(|elev| match elev {
        Elevation::Temporary(i) => Instant::now() < *i,
        Elevation::Session => true,
    })
}

pub fn elevate_session(user: User) {
    elevations().write().insert(user, Elevation::Session);
}

pub fn elevate_temporary(user: User, duration: &Duration) {
    elevations()
        .write()
        .insert(user, Elevation::Temporary(Instant::now() + *duration));
}

pub fn revoke(user: &User) {
    elevations().write().remove(user);
}
