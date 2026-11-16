//! Live registered endpoints, keyed by user SID and session.
//!
//! See "Liveness and duplicates" in the package-management contract.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use win_api_wrappers::identity::sid::Sid;

use super::dispatch::{Command, ConnectionHandle, RequestError};

/// Connections accepted for one user SID.
pub(super) const MAX_CONNECTIONS_PER_USER: usize = 4;

/// Connections accepted in total.
pub(super) const MAX_CONNECTIONS: usize = 64;

/// A UniGetUI endpoint that holds an authenticated registration connection.
///
/// The user SID is for the Agent's own mapping and must not be sent to the Authority.
/// Requests go only to the connection this endpoint was taken from.
#[derive(Clone, Debug)]
pub struct RegisteredEndpoint {
    user_sid: Sid,
    session_id: u32,
    display_name: Option<String>,
    connection: Arc<ConnectionHandle>,
}

impl RegisteredEndpoint {
    /// Returns the user SID taken from the authenticated client, never from the client's own report.
    pub fn user_sid(&self) -> &Sid {
        &self.user_sid
    }

    /// Returns the logged-on session of the authenticated client.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Returns the account name resolved by the Agent, when it could be resolved.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Sends a `Request` over this endpoint's retained connection and returns the `result` of its correlated `Response`.
    ///
    /// `arguments` must be a JSON object.
    /// The request is never sent on another connection, even when this one is closed.
    /// The error is a [`RequestError`](super::RequestError), which tells whether the request may have reached UniGetUI.
    /// Neither the arguments nor the response are logged.
    /// `RescanInventory` goes through [`Self::rescan_inventory`], which keeps at most one outstanding on the connection.
    pub async fn request(&self, command: &str, arguments: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        Ok(self.connection.request(command, arguments).await?)
    }

    /// Asks UniGetUI to reload its installed-package and available-update lists and waits for its answer.
    ///
    /// `Ok` means that both scans completed.
    /// The answer comes from a `RescanInventory` written to this endpoint's connection after this call, never from an earlier one.
    /// The connection has at most one such request outstanding, so the call may first wait for that one to end.
    /// Dropping the returned future abandons the wait but not a written request.
    /// The only bound on the wait is the connection's own deadline for the request, so a caller that needs a shorter one applies it.
    pub async fn rescan_inventory(&self) -> Result<(), RequestError> {
        self.connection.rescan_inventory().await
    }
}

/// Registration is not being served, so the registered set is not known to be complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistrationUnavailable;

impl fmt::Display for RegistrationUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UniGetUI registration is unavailable")
    }
}

impl std::error::Error for RegistrationUnavailable {}

/// Cloneable handle on the live registered endpoints.
#[derive(Clone, Debug)]
pub struct RegistrationHandle {
    registry: Arc<Registry>,
}

impl RegistrationHandle {
    pub(crate) fn new() -> Self {
        Self {
            registry: Arc::new(Registry::default()),
        }
    }

    /// Returns one endpoint per registered user SID and session whose client process is still running.
    ///
    /// Fails while the registration pipe is not being served.
    pub fn snapshot(&self) -> Result<Vec<RegisteredEndpoint>, RegistrationUnavailable> {
        self.registry.snapshot()
    }

    pub(super) fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }
}

/// Identifies a process instance, so that a recycled process ID is not mistaken for the same process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProcessKey {
    pub process_id: u32,
    pub creation_time: SystemTime,
}

/// An authenticated client asking to be registered.
pub(super) struct Candidate {
    pub process: ProcessKey,
    pub user_sid: Sid,
    pub session_id: u32,
    pub display_name: Option<String>,
    /// Tells whether the client process still runs.
    pub is_live: Arc<dyn Fn() -> bool + Send + Sync>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Rejection {
    UserLimit,
    TotalLimit,
}

struct Entry {
    id: u64,
    process: ProcessKey,
    endpoint: RegisteredEndpoint,
    is_live: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Reserved entries count against the limits but are not yet visible to snapshots.
    welcomed: bool,
    close: CancellationToken,
}

#[derive(Default)]
struct State {
    available: bool,
    next_id: u64,
    entries: Vec<Entry>,
}

#[derive(Default)]
pub(super) struct Registry {
    state: Mutex<State>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry").finish_non_exhaustive()
    }
}

impl Registry {
    pub(super) fn set_available(&self, available: bool) {
        self.state.lock().available = available;
    }

    /// Reserves a connection slot for `candidate`, closing an older connection of the same process.
    ///
    /// The replaced connection frees exactly the user and total slot the new one takes, so a replacement never exceeds a limit.
    pub(super) fn reserve(self: &Arc<Self>, candidate: Candidate) -> Result<Reservation, Rejection> {
        let mut state = self.state.lock();

        if let Some(position) = state
            .entries
            .iter()
            .position(|entry| entry.process == candidate.process)
        {
            state.entries.remove(position).close.cancel();
        }

        let user_connections = state
            .entries
            .iter()
            .filter(|entry| entry.endpoint.user_sid == candidate.user_sid)
            .count();
        if user_connections >= MAX_CONNECTIONS_PER_USER {
            return Err(Rejection::UserLimit);
        }
        if state.entries.len() >= MAX_CONNECTIONS {
            return Err(Rejection::TotalLimit);
        }

        let id = state.next_id;
        state.next_id += 1;
        let close = CancellationToken::new();
        let (connection, commands) = ConnectionHandle::new();
        state.entries.push(Entry {
            id,
            process: candidate.process,
            endpoint: RegisteredEndpoint {
                user_sid: candidate.user_sid,
                session_id: candidate.session_id,
                display_name: candidate.display_name,
                connection,
            },
            is_live: candidate.is_live,
            welcomed: false,
            close: close.clone(),
        });

        Ok(Reservation {
            registry: Arc::clone(self),
            id,
            close,
            commands: Mutex::new(Some(commands)),
        })
    }

    pub(super) fn snapshot(&self) -> Result<Vec<RegisteredEndpoint>, RegistrationUnavailable> {
        let candidates: Vec<_> = {
            let state = self.state.lock();
            if !state.available {
                return Err(RegistrationUnavailable);
            }
            state
                .entries
                .iter()
                .filter(|entry| entry.welcomed && !entry.endpoint.connection.is_closed())
                .map(|entry| (entry.endpoint.clone(), Arc::clone(&entry.is_live)))
                .collect()
        };

        let mut endpoints = BTreeMap::new();
        for (endpoint, is_live) in candidates {
            if is_live() {
                endpoints
                    .entry((endpoint.user_sid.clone(), endpoint.session_id))
                    .or_insert(endpoint);
            }
        }

        Ok(endpoints.into_values().collect())
    }

    fn remove(&self, id: u64) {
        self.state.lock().entries.retain(|entry| entry.id != id);
    }

    fn mark_welcomed(&self, id: u64) {
        if let Some(entry) = self.state.lock().entries.iter_mut().find(|entry| entry.id == id) {
            entry.welcomed = true;
        }
    }
}

/// A connection's slot, released when dropped.
pub(super) struct Reservation {
    registry: Arc<Registry>,
    id: u64,
    close: CancellationToken,
    commands: Mutex<Option<mpsc::Receiver<Command>>>,
}

impl Reservation {
    /// Takes the queue of requests for this connection.
    ///
    /// INVARIANT: Called once, by the connection loop that serves this reservation.
    pub(super) fn take_commands(&self) -> mpsc::Receiver<Command> {
        self.commands.lock().take().expect("commands are taken once")
    }

    /// Makes the endpoint visible to snapshots, once `Welcome` was sent.
    pub(super) fn activate(&self) {
        self.registry.mark_welcomed(self.id);
    }

    /// Resolves when a newer connection from the same process replaced this one.
    pub(super) async fn replaced(&self) {
        self.close.cancelled().await;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.registry.remove(self.id);
    }
}

#[cfg(test)]
mod tests {
    use win_api_wrappers::identity::sid::StringSid;

    use super::*;

    fn sid(value: &str) -> Sid {
        StringSid::from_str(value)
            .expect("no NUL")
            .to_sid()
            .expect("valid SID string")
    }

    fn candidate(process_id: u32, user: &str, session_id: u32) -> Candidate {
        Candidate {
            process: ProcessKey {
                process_id,
                creation_time: SystemTime::UNIX_EPOCH,
            },
            user_sid: sid(user),
            session_id,
            display_name: None,
            is_live: Arc::new(|| true),
        }
    }

    fn available_registry() -> Arc<Registry> {
        let registry = Arc::new(Registry::default());
        registry.set_available(true);
        registry
    }

    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const BOB: &str = "S-1-5-21-1-2-3-1002";

    #[test]
    fn per_user_limit_is_four_connections() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = available_registry();
        let _held: Vec<_> = (0..4)
            .map(|pid| registry.reserve(candidate(pid, ALICE, 1)).expect("within the limit"))
            .collect();

        assert_eq!(
            registry.reserve(candidate(4, ALICE, 2)).err(),
            Some(Rejection::UserLimit)
        );
        registry
            .reserve(candidate(5, BOB, 1))
            .expect("another user is unaffected");
    }

    #[test]
    fn total_limit_is_sixty_four_connections() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = available_registry();
        let _held: Vec<_> = (0..64)
            .map(|pid| {
                let user = format!("S-1-5-21-1-2-3-{}", 2000 + pid / 4);
                registry.reserve(candidate(pid, &user, 1)).expect("within the limit")
            })
            .collect();

        assert_eq!(
            registry.reserve(candidate(64, BOB, 1)).err(),
            Some(Rejection::TotalLimit)
        );
    }

    #[tokio::test]
    async fn new_connection_from_a_process_replaces_its_older_one_even_at_the_limit() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = available_registry();
        let _others: Vec<_> = (1..4)
            .map(|pid| registry.reserve(candidate(pid, ALICE, 1)).expect("within the limit"))
            .collect();
        let older = registry.reserve(candidate(0, ALICE, 1)).expect("fourth connection");

        let newer = registry.reserve(candidate(0, ALICE, 1)).expect("replacement fits");

        tokio::time::timeout(std::time::Duration::from_secs(5), older.replaced())
            .await
            .expect("older connection is told to close");
        drop(older);
        newer.activate();
        assert_eq!(registry.snapshot().expect("available").len(), 1);
    }

    #[test]
    fn reserved_connection_is_not_visible_until_welcomed_and_leaves_on_drop() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = available_registry();

        let reservation = registry.reserve(candidate(1, ALICE, 1)).expect("reserve");
        assert!(registry.snapshot().expect("available").is_empty());
        reservation.activate();
        assert_eq!(registry.snapshot().expect("available").len(), 1);
        drop(reservation);

        assert!(registry.snapshot().expect("available").is_empty());
    }

    #[test]
    fn snapshot_lists_one_endpoint_per_user_and_session() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = available_registry();
        let held: Vec<_> = [(1, ALICE, 1), (2, ALICE, 1), (3, ALICE, 2), (4, BOB, 1)]
            .into_iter()
            .map(|(pid, user, session)| {
                let reservation = registry.reserve(candidate(pid, user, session)).expect("reserve");
                reservation.activate();
                reservation
            })
            .collect();

        let endpoints = registry.snapshot().expect("available");

        let mut listed: Vec<_> = endpoints
            .iter()
            .map(|endpoint| (endpoint.user_sid().to_string(), endpoint.session_id()))
            .collect();
        listed.sort();
        assert_eq!(
            listed,
            [(ALICE.to_owned(), 1), (ALICE.to_owned(), 2), (BOB.to_owned(), 1)]
        );
        drop(held);
    }

    #[test]
    fn snapshot_omits_endpoints_whose_process_exited() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = available_registry();
        let mut dead = candidate(1, ALICE, 1);
        dead.is_live = Arc::new(|| false);
        let dead = registry.reserve(dead).expect("reserve");
        dead.activate();

        assert!(registry.snapshot().expect("available").is_empty());
    }

    #[test]
    fn snapshot_fails_while_registration_is_not_served() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let registry = Arc::new(Registry::default());
        assert_eq!(registry.snapshot().err(), Some(RegistrationUnavailable));

        registry.set_available(true);
        assert!(registry.snapshot().is_ok());

        registry.set_available(false);
        assert_eq!(registry.snapshot().err(), Some(RegistrationUnavailable));
    }
}
