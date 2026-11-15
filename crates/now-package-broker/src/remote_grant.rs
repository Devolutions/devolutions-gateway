//! Single-use authorization grants for package requests.
//!
//! The Agent issues a grant for one target Windows SID and one complete typed request.
//! The broker consumes it against the SID captured from the named-pipe caller and the decoded request.
//! The store is in-memory only: grants do not survive a restart.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use now_policy_api::PackageRequest;
use parking_lot::Mutex;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use win_api_wrappers::identity::sid::Sid;

const GRANT_LIFETIME: Duration = Duration::from_secs(60);
const MAX_PENDING_GRANTS: usize = 256;

/// Opaque bearer secret authorizing one request; never logged or included in errors.
pub struct RemoteGrant(String);

impl RemoteGrant {
    /// Returns the secret to hand to the authorized client.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RemoteGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemoteGrant(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    /// Too many unexpired grants are pending.
    Full,
    /// The request has no canonical representation.
    Unserializable,
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("too many pending grants"),
            Self::Unserializable => f.write_str("request cannot be serialized"),
        }
    }
}

impl std::error::Error for IssueError {}

/// The grant is unknown, expired, already consumed, or bound to another SID or request.
///
/// The causes are deliberately indistinguishable to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantDenied;

impl fmt::Display for GrantDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("grant denied")
    }
}

impl std::error::Error for GrantDenied {}

struct Entry {
    sid: Sid,
    request: Value,
    expires_at: Instant,
}

/// Shared handle to the in-memory grant store; clones refer to the same store.
#[derive(Clone, Default)]
pub struct RemoteGrantStore {
    entries: Arc<Mutex<HashMap<[u8; 32], Entry>>>,
}

impl fmt::Debug for RemoteGrantStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteGrantStore").finish_non_exhaustive()
    }
}

impl RemoteGrantStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues a 60-second single-use grant for `request` executed by `sid`.
    pub fn issue(&self, sid: Sid, request: &PackageRequest) -> Result<RemoteGrant, IssueError> {
        self.issue_at(Instant::now(), sid, request)
    }

    /// Atomically verifies and consumes the grant for `sid` and `request`.
    ///
    /// A grant presented with a different SID or request stays valid for its rightful holder.
    pub fn consume(&self, grant: &str, sid: &Sid, request: &PackageRequest) -> Result<(), GrantDenied> {
        self.consume_at(Instant::now(), grant, sid, request)
    }

    fn issue_at(&self, now: Instant, sid: Sid, request: &PackageRequest) -> Result<RemoteGrant, IssueError> {
        let request = serde_json::to_value(request).map_err(|_| IssueError::Unserializable)?;

        let mut secret = [0u8; 32];
        secret[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        secret[16..].copy_from_slice(Uuid::new_v4().as_bytes());

        let mut entries = self.entries.lock();
        entries.retain(|_, entry| entry.expires_at > now);

        if entries.len() >= MAX_PENDING_GRANTS {
            return Err(IssueError::Full);
        }

        entries.insert(
            digest(&secret),
            Entry {
                sid,
                request,
                expires_at: now + GRANT_LIFETIME,
            },
        );

        Ok(RemoteGrant(hex::encode(secret)))
    }

    fn consume_at(&self, now: Instant, grant: &str, sid: &Sid, request: &PackageRequest) -> Result<(), GrantDenied> {
        let secret = hex::decode(grant).map_err(|_| GrantDenied)?;
        let request = serde_json::to_value(request).map_err(|_| GrantDenied)?;
        let key = digest(&secret);

        let mut entries = self.entries.lock();
        entries.retain(|_, entry| entry.expires_at > now);

        match entries.get(&key) {
            Some(entry) if entry.sid == *sid && entry.request == request => {
                entries.remove(&key);
                Ok(())
            }
            _ => Err(GrantDenied),
        }
    }
}

fn digest(secret: &[u8]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use now_policy_api as api;
    use windows::Win32::Security::{WinLocalSystemSid, WinWorldSid};

    use super::*;

    fn sid(kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE) -> Sid {
        Sid::from_well_known(kind, None).expect("well-known SID")
    }

    fn request() -> PackageRequest {
        PackageRequest {
            request_kind: api::PackageRequestKind,
            request_version: api::API_VERSION_STR.into(),
            request_id: api::ResourceId::from("req-1"),
            created_at: Utc::now(),
            operation: api::Operation::Install,
            manager: api::ManagerName::Winget,
            source: api::RequestSource {
                name: "winget".to_owned(),
                url: None,
            },
            package: api::RequestPackage {
                id: api::PackageIdentifier("Mozilla.Firefox".to_owned()),
                version: None,
                architecture: None,
                channel: None,
            },
            options: api::RequestOptions {
                scope: None,
                interactive: false,
                skip_hash_check: false,
                pre_release: false,
                custom_install_location: None,
                custom_parameters: Vec::new(),
                pre_operation_command: None,
                post_operation_command: None,
                kill_before_operation: Vec::new(),
                uninstall_previous: false,
                no_upgrade: false,
            },
            client: api::ClientContext {
                transport: api::Transport::HttpNamedPipe,
                requested_elevation: api::Elevation::Elevated,
                effective_user: "DOMAIN\\user".to_owned(),
                client_executable_path: "C:\\PackageBrokerClient.exe".to_owned(),
                client_version: "1.0.0".to_owned(),
            },
            include_command_preview: false,
            capture_output: false,
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn matching_grant_is_consumed_once() {
        let store = RemoteGrantStore::new();
        let (user, request) = (sid(WinWorldSid), request());
        let grant = store.issue(user.clone(), &request).expect("issue");

        assert_eq!(store.consume(grant.expose_secret(), &user, &request), Ok(()));
        assert_eq!(store.consume(grant.expose_secret(), &user, &request), Err(GrantDenied));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn grant_survives_json_round_trip_of_the_request() {
        let store = RemoteGrantStore::new();
        let (user, request) = (sid(WinWorldSid), request());
        let grant = store.issue(user.clone(), &request).expect("issue");

        let decoded: PackageRequest =
            serde_json::from_str(&serde_json::to_string_pretty(&request).expect("encode")).expect("decode");

        assert_eq!(store.consume(grant.expose_secret(), &user, &decoded), Ok(()));
    }

    fn assert_changed_request_is_denied(mutate: impl FnOnce(&mut PackageRequest)) {
        let store = RemoteGrantStore::new();
        let user = sid(WinWorldSid);
        let original = request();
        let grant = store.issue(user.clone(), &original).expect("issue");

        let mut changed = original;
        mutate(&mut changed);

        assert_eq!(store.consume(grant.expose_secret(), &user, &changed), Err(GrantDenied));
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §remote operations
    #[test]
    fn changed_capture_output_is_denied() {
        assert_changed_request_is_denied(|r| r.capture_output = true);
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §remote operations
    #[test]
    fn changed_command_preview_is_denied() {
        assert_changed_request_is_denied(|r| r.include_command_preview = true);
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §remote operations
    #[test]
    fn changed_skip_hash_check_is_denied() {
        assert_changed_request_is_denied(|r| r.options.skip_hash_check = true);
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §remote operations
    #[test]
    fn changed_install_location_is_denied() {
        assert_changed_request_is_denied(|r| r.options.custom_install_location = Some("C:\\x".to_owned()));
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §remote operations
    #[test]
    fn changed_custom_parameters_are_denied() {
        assert_changed_request_is_denied(|r| {
            r.options.custom_parameters = vec![api::CustomParameterString("--extra".to_owned())];
        });
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §remote operations
    #[test]
    fn changed_command_hook_is_denied() {
        assert_changed_request_is_denied(|r| r.options.post_operation_command = Some("calc.exe".to_owned()));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn changed_request_id_is_denied() {
        assert_changed_request_is_denied(|r| r.request_id = api::ResourceId::from("req-2"));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn changed_created_at_is_denied() {
        assert_changed_request_is_denied(|r| r.created_at += chrono::Duration::seconds(1));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn changed_client_is_denied() {
        assert_changed_request_is_denied(|r| r.client.effective_user = "DOMAIN\\other".to_owned());
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn changed_package_is_denied() {
        assert_changed_request_is_denied(|r| r.package.id = api::PackageIdentifier("Other.App".to_owned()));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn changed_operation_is_denied() {
        assert_changed_request_is_denied(|r| r.operation = api::Operation::Uninstall);
    }

    // oracle: scaffold a rejected attempt by another party should not burn the user's grant
    #[test]
    fn mismatched_attempt_does_not_consume_grant() {
        let store = RemoteGrantStore::new();
        let (user, original) = (sid(WinWorldSid), request());
        let grant = store.issue(user.clone(), &original).expect("issue");
        let mut changed = original.clone();
        changed.capture_output = true;

        assert_eq!(store.consume(grant.expose_secret(), &user, &changed), Err(GrantDenied));
        assert_eq!(store.consume(grant.expose_secret(), &user, &original), Ok(()));
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §remote operations
    #[test]
    fn other_sid_is_denied() {
        let store = RemoteGrantStore::new();
        let request = request();
        let grant = store.issue(sid(WinWorldSid), &request).expect("issue");

        assert_eq!(
            store.consume(grant.expose_secret(), &sid(WinLocalSystemSid), &request),
            Err(GrantDenied)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn unknown_and_malformed_grants_are_denied() {
        let store = RemoteGrantStore::new();
        let (user, request) = (sid(WinWorldSid), request());

        assert_eq!(store.consume(&"00".repeat(32), &user, &request), Err(GrantDenied));
        assert_eq!(store.consume("not hex", &user, &request), Err(GrantDenied));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn expired_grant_is_denied_and_removed() {
        let store = RemoteGrantStore::new();
        let (user, request) = (sid(WinWorldSid), request());
        let start = Instant::now();
        let grant = store.issue_at(start, user.clone(), &request).expect("issue");

        assert_eq!(
            store.consume_at(start + GRANT_LIFETIME, grant.expose_secret(), &user, &request),
            Err(GrantDenied)
        );
        assert!(store.entries.lock().is_empty());
    }

    // oracle: scaffold lifetime boundary of the internal 60-second default
    #[test]
    fn grant_valid_just_before_expiry() {
        let store = RemoteGrantStore::new();
        let (user, request) = (sid(WinWorldSid), request());
        let start = Instant::now();
        let grant = store.issue_at(start, user.clone(), &request).expect("issue");

        let just_before = start + GRANT_LIFETIME - Duration::from_millis(1);
        assert_eq!(
            store.consume_at(just_before, grant.expose_secret(), &user, &request),
            Ok(())
        );
    }

    // oracle: scaffold bounded memory is an implementation limit no document sets
    #[test]
    fn issuing_purges_expired_and_bounds_pending_grants() {
        let store = RemoteGrantStore::new();
        let (user, request) = (sid(WinWorldSid), request());
        let start = Instant::now();

        for _ in 0..MAX_PENDING_GRANTS {
            store.issue_at(start, user.clone(), &request).expect("issue");
        }
        assert_eq!(
            store
                .issue_at(start, user.clone(), &request)
                .expect_err("store is full"),
            IssueError::Full
        );

        store
            .issue_at(start + GRANT_LIFETIME, user, &request)
            .expect("expired grants make room");
        assert_eq!(store.entries.lock().len(), 1);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn concurrent_consumption_succeeds_exactly_once() {
        let store = RemoteGrantStore::new();
        let (user, request) = (sid(WinWorldSid), request());
        let grant = store.issue(user.clone(), &request).expect("issue");
        let secret = grant.expose_secret().to_owned();

        let successes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| store.consume(&secret, &user, &request).is_ok()))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("join"))
                .filter(|ok| *ok)
                .count()
        });

        assert_eq!(successes, 1);
    }

    // oracle: scaffold secrets must stay out of logs
    #[test]
    fn debug_does_not_reveal_secret() {
        let store = RemoteGrantStore::new();
        let grant = store.issue(sid(WinWorldSid), &request()).expect("issue");

        assert!(!format!("{grant:?}").contains(grant.expose_secret()));
    }
}
