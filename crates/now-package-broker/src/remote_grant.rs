//! Single-use authorization grants for remote package operations.
//!
//! The Agent issues a grant from the authority's operation fields and a target Windows SID.
//! The broker consumes it against the pipe caller and the decoded request.
//! The grant binds the authority operation fields, generated request ID and safe values for other effectful fields.
//! Caller identity is verified separately, and non-effectful metadata is excluded.
//! The store is in-memory only: grants do not survive a restart.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use now_policy_api::{
    self as api, Elevation, ManagerName, Operation, PackageIdentifier, PackageRequest, RequestSource, Scope,
    VersionString,
};
use parking_lot::Mutex;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use win_api_wrappers::identity::sid::Sid;

const GRANT_LIFETIME: Duration = Duration::from_secs(60);
const MAX_PENDING_GRANTS: usize = 256;
const MAX_RECORDS: usize = 1024;

/// Opaque bearer secret authorizing one request; never logged or included in errors.
///
/// It is 64 lowercase hexadecimal characters, so it is safe to send in an HTTP header.
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

/// The authority fields a grant is bound to.
#[derive(Debug, Clone)]
pub struct GrantSpec {
    pub operation: Operation,
    pub manager: ManagerName,
    /// Broker `Source.Name`, compared exactly without Unicode normalization; empty selects the default or no feed.
    pub source_name: String,
    /// Authority-authorized `Source.Url`, compared exactly; `None` authorizes no URL.
    /// Whether a manager honors or safely handles it is for the integration to decide.
    pub source_url: Option<String>,
    pub package_id: PackageIdentifier,
    /// Exact requested version, or `None` when no version is requested.
    pub version: Option<VersionString>,
    pub scope: Option<Scope>,
    pub requested_elevation: Elevation,
    /// SID of the user the operation runs as, taken from the authority's selection.
    pub target_sid: Sid,
    /// Fixed `Options.NoUpgrade` value the request must carry.
    ///
    /// The Agent sets it for WinGet installs so an install cannot upgrade an existing package.
    pub no_upgrade: bool,
}

/// A newly issued grant and the broker request ID it is bound to.
#[derive(Debug)]
pub struct IssuedGrant {
    pub grant: RemoteGrant,
    /// Lowercase hyphenated UUID the broker request must carry as `RequestId`.
    pub request_id: Uuid,
}

/// The pipe caller, after the handler has authenticated it.
///
/// Constructing one asserts that the pipe handler resolved the request's `Client.EffectiveUser` to `sid`
/// and verified `Client.ClientExecutablePath` against the retained image of the connected process.
/// Those two strings are excluded from the grant comparison, so only this assertion covers them.
#[derive(Debug, Clone)]
pub struct VerifiedCaller {
    sid: Sid,
}

impl VerifiedCaller {
    pub fn new(sid: Sid) -> Self {
        Self { sid }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    /// Too many unexpired grants are pending.
    Full,
    /// The request has no canonical representation.
    Unserializable,
    /// The source does not fit the operation: an install needs a source name, an uninstall has no source,
    /// and an update with an empty name has no URL.
    InvalidSource,
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("too many pending grants"),
            Self::Unserializable => f.write_str("request cannot be serialized"),
            Self::InvalidSource => f.write_str("source does not fit the operation"),
        }
    }
}

impl std::error::Error for IssueError {}

/// The grant is unknown, expired, already consumed, or bound to another caller or request.
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
    request_id: Uuid,
    expires_at: Instant,
}

/// What the Broker has positively observed about the one operation a grant authorized.
///
/// The states are ordered: a record only moves forward.
/// There is deliberately no "not started" or "failed" state, because the Broker cannot prove either.
/// An exit code alone does not establish the package's installed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OutcomeSummary {
    /// No matching record exists: never consumed, evicted, lost in a restart or bound to another request.
    Unknown,
    /// The grant was consumed; work may or may not have started.
    Consumed,
    /// The Broker started the operation's process.
    Started,
    /// The Broker observed the started process exit with this code.
    Exited { exit_code: i32 },
    /// The execution ended without an observable exit, preserving whether the process was started.
    ///
    /// This does not prove that the process stopped.
    Unobservable { started: bool },
}

struct Record {
    request_id: Uuid,
    state: OutcomeSummary,
    /// INVARIANT: strictly increasing across records, so the smallest value is the oldest.
    sequence: u64,
}

#[derive(Default)]
struct State {
    grants: HashMap<[u8; 32], Entry>,
    records: HashMap<[u8; 32], Record>,
    next_sequence: u64,
}

impl State {
    /// Inserts a record, evicting one when the table is full.
    ///
    /// Eviction prefers finished records, then the oldest.
    /// Evicting a record never restores its grant, which was removed when the record was created.
    fn insert_record(&mut self, key: [u8; 32], request_id: Uuid) {
        if MAX_RECORDS <= self.records.len() {
            let victim = self
                .records
                .iter()
                .min_by_key(|(_, record)| {
                    (
                        !matches!(
                            record.state,
                            OutcomeSummary::Exited { .. } | OutcomeSummary::Unobservable { .. }
                        ),
                        record.sequence,
                    )
                })
                .map(|(key, _)| *key);

            if let Some(victim) = victim {
                self.records.remove(&victim);
            }
        }

        let sequence = self.next_sequence;
        self.next_sequence += 1;

        self.records.insert(
            key,
            Record {
                request_id,
                state: OutcomeSummary::Consumed,
                sequence,
            },
        );
    }
}

/// The Broker execution path's handle for recording what it observes for one consumed grant.
///
/// Only [`RemoteGrantStore::consume`] creates one, and it is not `Clone`.
/// Updates are monotonic and are dropped silently when the record was evicted.
pub struct ExecutionRecord {
    store: RemoteGrantStore,
    key: [u8; 32],
}

impl ExecutionRecord {
    /// Records that the operation's process started; returns whether the record advanced.
    ///
    /// Call this only after the process was actually created.
    pub fn mark_started(&self) -> bool {
        self.advance(OutcomeSummary::Consumed, OutcomeSummary::Started)
    }

    /// Records that the started process exited with `exit_code`; returns whether the record advanced.
    pub fn mark_exited(&self, exit_code: i32) -> bool {
        self.advance(OutcomeSummary::Started, OutcomeSummary::Exited { exit_code })
    }

    /// Records that no exit can be observed, without discarding any start evidence.
    pub fn mark_unobservable(&self) -> bool {
        let mut state = self.store.state.lock();
        let Some(record) = state.records.get_mut(&self.key) else {
            return false;
        };
        let started = match record.state {
            OutcomeSummary::Consumed => false,
            OutcomeSummary::Started => true,
            _ => return false,
        };
        record.state = OutcomeSummary::Unobservable { started };
        true
    }

    fn advance(&self, from: OutcomeSummary, to: OutcomeSummary) -> bool {
        let mut state = self.store.state.lock();

        match state.records.get_mut(&self.key) {
            Some(record) if record.state == from => {
                record.state = to;
                true
            }
            _ => false,
        }
    }
}

impl fmt::Debug for ExecutionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionRecord").finish_non_exhaustive()
    }
}

/// Shared handle to the in-memory grant store; clones refer to the same store.
#[derive(Clone, Default)]
pub struct RemoteGrantStore {
    state: Arc<Mutex<State>>,
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

    /// Issues a 60-second single-use grant for the canonical request described by `spec`.
    pub fn issue(&self, spec: GrantSpec) -> Result<IssuedGrant, IssueError> {
        self.issue_at(Instant::now(), spec)
    }

    /// Atomically verifies and consumes the grant for `caller` and `request`, creating its outcome record.
    ///
    /// Call this before starting any process; the returned handle is the only way to update the record.
    /// A grant presented with a different caller or request stays valid for its rightful holder.
    pub fn consume(
        &self,
        grant: &str,
        caller: &VerifiedCaller,
        request: &PackageRequest,
    ) -> Result<ExecutionRecord, GrantDenied> {
        self.consume_at(Instant::now(), grant, caller, request)
    }

    /// Reads the non-secret outcome summary for an issued grant without changing it.
    ///
    /// Anything other than a record for this exact grant and Broker request ID is [`OutcomeSummary::Unknown`].
    pub fn outcome(&self, grant: &RemoteGrant, request_id: &Uuid) -> OutcomeSummary {
        let Ok(secret) = hex::decode(grant.expose_secret()) else {
            return OutcomeSummary::Unknown;
        };

        match self.state.lock().records.get(&digest(&secret)) {
            Some(record) if record.request_id == *request_id => record.state,
            _ => OutcomeSummary::Unknown,
        }
    }

    fn issue_at(&self, now: Instant, spec: GrantSpec) -> Result<IssuedGrant, IssueError> {
        // An empty name authorizes the manager's default feed (update) or no feed at all (uninstall); never an install.
        let source_fits = match spec.operation {
            Operation::Install => !spec.source_name.is_empty(),
            Operation::Update => !spec.source_name.is_empty() || spec.source_url.is_none(),
            Operation::Uninstall => spec.source_name.is_empty() && spec.source_url.is_none(),
        };
        if !source_fits {
            return Err(IssueError::InvalidSource);
        }

        let request_id = Uuid::new_v4();
        let request = comparable(&canonical_request(&spec, &request_id)).ok_or(IssueError::Unserializable)?;

        let mut secret = [0u8; 32];
        secret[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        secret[16..].copy_from_slice(Uuid::new_v4().as_bytes());

        let mut state = self.state.lock();
        state.grants.retain(|_, entry| entry.expires_at > now);

        if state.grants.len() >= MAX_PENDING_GRANTS {
            return Err(IssueError::Full);
        }

        state.grants.insert(
            digest(&secret),
            Entry {
                sid: spec.target_sid,
                request,
                request_id,
                expires_at: now + GRANT_LIFETIME,
            },
        );

        Ok(IssuedGrant {
            grant: RemoteGrant(hex::encode(secret)),
            request_id,
        })
    }

    fn consume_at(
        &self,
        now: Instant,
        grant: &str,
        caller: &VerifiedCaller,
        request: &PackageRequest,
    ) -> Result<ExecutionRecord, GrantDenied> {
        let secret = hex::decode(grant).map_err(|_| GrantDenied)?;
        let request = comparable(request).ok_or(GrantDenied)?;
        let key = digest(&secret);

        // The grant is removed and its record created under one lock, so concurrent duplicates cannot both win.
        let mut state = self.state.lock();
        state.grants.retain(|_, entry| entry.expires_at > now);

        match state.grants.get(&key) {
            Some(entry) if entry.sid == caller.sid && entry.request == request => {
                let request_id = entry.request_id;
                state.grants.remove(&key);
                state.insert_record(key, request_id);

                Ok(ExecutionRecord {
                    store: self.clone(),
                    key,
                })
            }
            _ => Err(GrantDenied),
        }
    }
}

/// Builds the one request the grant authorizes.
///
/// The struct literals are exhaustive on purpose: a field added to the request type stops this from compiling,
/// so a new field gets an explicit decision rather than silently authorizing any value.
/// UNTESTED: this exhaustiveness is checked only by the compiler, so on a `now-policy-api` upgrade
/// give each new field a fixed safe value here or bind it in the grant.
fn canonical_request(spec: &GrantSpec, request_id: &Uuid) -> PackageRequest {
    PackageRequest {
        request_kind: api::PackageRequestKind,
        request_version: api::API_VERSION_STR.into(),
        request_id: api::ResourceId::from(request_id.hyphenated().to_string().as_str()),
        created_at: Utc::now(),
        operation: spec.operation,
        manager: spec.manager,
        source: RequestSource {
            name: spec.source_name.clone(),
            url: spec.source_url.clone(),
        },
        package: api::RequestPackage {
            id: spec.package_id.clone(),
            version: spec.version.clone(),
            architecture: None,
            channel: None,
        },
        options: api::RequestOptions {
            scope: spec.scope,
            interactive: false,
            skip_hash_check: false,
            pre_release: false,
            custom_install_location: None,
            custom_parameters: Vec::new(),
            pre_operation_command: None,
            post_operation_command: None,
            kill_before_operation: Vec::new(),
            uninstall_previous: false,
            no_upgrade: spec.no_upgrade,
        },
        client: api::ClientContext {
            transport: api::Transport::HttpNamedPipe,
            requested_elevation: spec.requested_elevation,
            effective_user: String::new(),
            client_executable_path: String::new(),
            client_version: String::new(),
        },
        include_command_preview: false,
        capture_output: true,
    }
}

/// Serializes `request` without the fields the grant does not bind.
///
/// Comparing the whole remaining value, rather than selected fields, means any serialized field
/// that is not part of the canonical request denies authorization.
fn comparable(request: &PackageRequest) -> Option<Value> {
    let mut value = serde_json::to_value(request).ok()?;
    let top = value.as_object_mut()?;
    top.remove("CreatedAt");

    let client = top.get_mut("Client")?.as_object_mut()?;
    for field in ["ClientVersion", "EffectiveUser", "ClientExecutablePath"] {
        client.remove(field);
    }

    Some(value)
}

fn digest(secret: &[u8]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

#[cfg(test)]
mod tests {
    use now_policy_api::Transport;
    use windows::Win32::Security::{WinLocalSystemSid, WinWorldSid};

    use super::*;

    fn sid(kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE) -> Sid {
        Sid::from_well_known(kind, None).expect("well-known SID")
    }

    fn try_consume(
        store: &RemoteGrantStore,
        grant: &str,
        caller: &VerifiedCaller,
        request: &PackageRequest,
    ) -> Result<(), GrantDenied> {
        store.consume(grant, caller, request).map(drop)
    }

    fn caller() -> VerifiedCaller {
        VerifiedCaller::new(sid(WinWorldSid))
    }

    fn spec() -> GrantSpec {
        GrantSpec {
            operation: Operation::Install,
            manager: ManagerName::Winget,
            source_name: "winget".to_owned(),
            source_url: Some("https://cdn.winget.microsoft.com/cache".to_owned()),
            package_id: PackageIdentifier("Mozilla.Firefox".to_owned()),
            version: Some(VersionString("1.2.3".to_owned())),
            scope: Some(Scope::User),
            requested_elevation: Elevation::Standard,
            target_sid: sid(WinWorldSid),
            no_upgrade: false,
        }
    }

    // Written independently of `canonical_request` so that a shared mistake is not hidden.
    fn matching_request(spec: &GrantSpec, request_id: &Uuid) -> PackageRequest {
        PackageRequest {
            request_kind: api::PackageRequestKind,
            request_version: "1.0".into(),
            request_id: api::ResourceId::from(request_id.to_string().as_str()),
            created_at: Utc::now(),
            operation: spec.operation,
            manager: spec.manager,
            source: RequestSource {
                name: spec.source_name.clone(),
                url: spec.source_url.clone(),
            },
            package: api::RequestPackage {
                id: spec.package_id.clone(),
                version: spec.version.clone(),
                architecture: None,
                channel: None,
            },
            options: api::RequestOptions {
                scope: spec.scope,
                interactive: false,
                skip_hash_check: false,
                pre_release: false,
                custom_install_location: None,
                custom_parameters: Vec::new(),
                pre_operation_command: None,
                post_operation_command: None,
                kill_before_operation: Vec::new(),
                uninstall_previous: false,
                no_upgrade: spec.no_upgrade,
            },
            client: api::ClientContext {
                transport: Transport::HttpNamedPipe,
                requested_elevation: spec.requested_elevation,
                effective_user: "DOMAIN\\user".to_owned(),
                client_executable_path: "C:\\UniGetUI\\UniGetUI.exe".to_owned(),
                client_version: "1.0.0".to_owned(),
            },
            include_command_preview: false,
            capture_output: true,
        }
    }

    fn issued() -> (RemoteGrantStore, IssuedGrant, PackageRequest) {
        let store = RemoteGrantStore::new();
        let spec = spec();
        let issued = store.issue(spec.clone()).expect("issue");
        let request = matching_request(&spec, &issued.request_id);
        (store, issued, request)
    }

    fn assert_changed_request_is_denied(mutate: impl FnOnce(&mut PackageRequest)) {
        let (store, issued, mut request) = issued();
        mutate(&mut request);

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
    }

    fn assert_changed_spec_is_denied(mutate: impl FnOnce(&mut GrantSpec)) {
        let store = RemoteGrantStore::new();
        let mut spec = spec();
        let issued = store.issue(spec.clone()).expect("issue");
        mutate(&mut spec);
        let request = matching_request(&spec, &issued.request_id);

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
    }

    macro_rules! request_is_denied {
        ($name:ident, |$r:ident| $change:expr) => {
            // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
            #[test]
            fn $name() {
                assert_changed_request_is_denied(|$r| {
                    $change;
                });
            }
        };
    }

    macro_rules! spec_is_denied {
        ($name:ident, |$s:ident| $change:expr) => {
            // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
            #[test]
            fn $name() {
                assert_changed_spec_is_denied(|$s| {
                    $change;
                });
            }
        };
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn matching_request_is_consumed_once() {
        let (store, issued, request) = issued();

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Ok(())
        );
        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn created_at_and_client_strings_are_not_bound() {
        let (store, issued, mut request) = issued();
        request.created_at += chrono::Duration::days(30);
        request.client.client_version = "9.9.9".to_owned();
        request.client.effective_user = "OTHER\\name".to_owned();
        request.client.client_executable_path = "D:\\elsewhere.exe".to_owned();

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Ok(())
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn request_without_optional_authority_fields_is_consumed() {
        let store = RemoteGrantStore::new();
        let mut spec = spec();
        spec.version = None;
        spec.scope = None;
        spec.source_url = None;
        let issued = store.issue(spec.clone()).expect("issue");
        let request = matching_request(&spec, &issued.request_id);

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Ok(())
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn unauthorized_source_url_is_denied() {
        let store = RemoteGrantStore::new();
        let mut spec = spec();
        spec.source_url = None;
        let issued = store.issue(spec.clone()).expect("issue");
        let mut request = matching_request(&spec, &issued.request_id);
        request.source.url = Some("https://example.test/feed".to_owned());

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn empty_source_url_does_not_match_absent_url() {
        let store = RemoteGrantStore::new();
        let mut spec = spec();
        spec.source_url = None;
        let issued = store.issue(spec.clone()).expect("issue");
        let mut request = matching_request(&spec, &issued.request_id);
        request.source.url = Some(String::new());

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn canonically_equivalent_source_name_is_denied() {
        let store = RemoteGrantStore::new();
        let mut spec = spec();
        spec.source_name = "caf\u{e9}".to_owned();
        let issued = store.issue(spec.clone()).expect("issue");
        spec.source_name = "cafe\u{301}".to_owned();
        let request = matching_request(&spec, &issued.request_id);

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn install_needs_a_source_and_uninstall_has_none() {
        let store = RemoteGrantStore::new();

        let mut install = spec();
        install.source_name = String::new();
        install.source_url = None;
        assert_eq!(
            store.issue(install).expect_err("empty install"),
            IssueError::InvalidSource
        );

        let mut uninstall = spec();
        uninstall.operation = Operation::Uninstall;
        assert_eq!(
            store.issue(uninstall.clone()).expect_err("uninstall source"),
            IssueError::InvalidSource
        );

        uninstall.source_name = String::new();
        uninstall.source_url = None;
        store.issue(uninstall).expect("sourceless uninstall");
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn update_may_choose_the_default_feed_but_not_a_url_without_a_name() {
        let store = RemoteGrantStore::new();

        let mut update = spec();
        update.operation = Operation::Update;
        update.source_name = String::new();
        update.source_url = None;
        store.issue(update.clone()).expect("default-feed update");

        update.source_url = Some("https://example.invalid/feed".to_owned());
        assert_eq!(store.issue(update).expect_err("url only"), IssueError::InvalidSource);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn issued_request_id_is_a_lowercase_hyphenated_uuid() {
        let (_, issued, _) = issued();
        let text = issued.request_id.hyphenated().to_string();

        assert_eq!(text, text.to_lowercase());
        assert_eq!(text.len(), 36);
        assert_eq!(text.matches('-').count(), 4);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn grant_is_visible_ascii_without_header_separators() {
        let (_, issued, _) = issued();

        assert!(issued.grant.expose_secret().bytes().all(|b| b.is_ascii_alphanumeric()));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn other_caller_sid_is_denied() {
        let (store, issued, request) = issued();

        assert_eq!(
            try_consume(
                &store,
                issued.grant.expose_secret(),
                &VerifiedCaller::new(sid(WinLocalSystemSid)),
                &request
            ),
            Err(GrantDenied)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn unknown_and_malformed_grants_are_denied() {
        let (store, _, request) = issued();

        assert_eq!(
            try_consume(&store, &"00".repeat(32), &caller(), &request),
            Err(GrantDenied)
        );
        assert_eq!(try_consume(&store, "not hex", &caller(), &request), Err(GrantDenied));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn expired_grant_is_denied_and_removed() {
        let store = RemoteGrantStore::new();
        let spec = spec();
        let start = Instant::now();
        let issued = store.issue_at(start, spec.clone()).expect("issue");
        let request = matching_request(&spec, &issued.request_id);

        assert_eq!(
            store
                .consume_at(
                    start + GRANT_LIFETIME,
                    issued.grant.expose_secret(),
                    &caller(),
                    &request
                )
                .map(drop),
            Err(GrantDenied)
        );
        assert!(store.state.lock().grants.is_empty());
    }

    // oracle: mutant removing the pending cap or expiry purge lets the store grow without bound
    #[test]
    fn issuing_purges_expired_and_bounds_pending_grants() {
        let store = RemoteGrantStore::new();
        let start = Instant::now();

        for _ in 0..MAX_PENDING_GRANTS {
            store.issue_at(start, spec()).expect("issue");
        }
        assert_eq!(
            store.issue_at(start, spec()).expect_err("store is full"),
            IssueError::Full
        );

        store
            .issue_at(start + GRANT_LIFETIME, spec())
            .expect("expired grants make room");
        assert_eq!(store.state.lock().grants.len(), 1);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn concurrent_consumption_succeeds_exactly_once() {
        let (store, issued, request) = issued();
        let secret = issued.grant.expose_secret().to_owned();
        let caller = caller();

        let successes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| try_consume(&store, &secret, &caller, &request).is_ok()))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("join"))
                .filter(|ok| *ok)
                .count()
        });

        assert_eq!(successes, 1);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn mismatched_attempt_does_not_consume_grant() {
        let (store, issued, mut request) = issued();
        let genuine = request.clone();
        request.capture_output = false;

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &genuine),
            Ok(())
        );
    }

    // oracle: mutant Debug reveals the grant secret
    #[test]
    fn debug_does_not_reveal_secret() {
        let (_, issued, _) = issued();

        assert!(!format!("{issued:?}").contains(issued.grant.expose_secret()));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(changed_operation_is_denied, |s| s.operation = Operation::Uninstall);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(changed_manager_is_denied, |s| s.manager = ManagerName::Scoop);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(changed_source_name_is_denied, |s| s.source_name = "msstore".to_owned());
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(changed_source_url_is_denied, |s| s.source_url = None);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(changed_package_is_denied, |s| s.package_id =
        PackageIdentifier("Other.App".to_owned()));
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(changed_version_is_denied, |s| s.version =
        Some(VersionString("1.2.4".to_owned())));
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(dropped_version_is_denied, |s| s.version = None);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(changed_scope_is_denied, |s| s.scope = Some(Scope::Machine));
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(changed_elevation_is_denied, |s| s.requested_elevation =
        Elevation::Elevated);

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(changed_request_id_is_denied, |r| r.request_id =
        api::ResourceId::from(Uuid::new_v4().to_string().as_str()));
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(uppercase_request_id_is_denied, |r| r.request_id =
        api::ResourceId::from(r.request_id.to_string().to_uppercase().as_str()));
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(capture_output_off_is_denied, |r| r.capture_output = false);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(command_preview_is_denied, |r| r.include_command_preview = true);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(other_transport_is_denied, |r| r.client.transport =
        Transport::HttpLoopbackSimulator);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(other_request_version_is_denied, |r| r.request_version = "2.0".into());
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(interactive_is_denied, |r| r.options.interactive = true);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(skip_hash_check_is_denied, |r| r.options.skip_hash_check = true);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(pre_release_is_denied, |r| r.options.pre_release = true);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(install_location_is_denied, |r| r.options.custom_install_location =
        Some("C:\\x".to_owned()));
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(custom_parameters_are_denied, |r| r.options.custom_parameters =
        vec![api::CustomParameterString("--extra".to_owned())]);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(pre_command_hook_is_denied, |r| r.options.pre_operation_command =
        Some("calc.exe".to_owned()));
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(post_command_hook_is_denied, |r| r.options.post_operation_command =
        Some("calc.exe".to_owned()));
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(kill_before_operation_is_denied, |r| r.options.kill_before_operation =
        vec![api::ProcessName("app.exe".to_owned())]);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(uninstall_previous_is_denied, |r| r.options.uninstall_previous = true);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(no_upgrade_is_denied, |r| r.options.no_upgrade = true);
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(architecture_is_denied, |r| r.package.architecture =
        Some(api::Architecture::X64));
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    request_is_denied!(channel_is_denied, |r| r.package.channel = Some("beta".to_owned()));

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    spec_is_denied!(changed_no_upgrade_is_denied, |s| s.no_upgrade = true);

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn install_bound_to_no_upgrade_requires_it() {
        let store = RemoteGrantStore::new();
        let mut spec = spec();
        spec.no_upgrade = true;
        let issued = store.issue(spec.clone()).expect("issue");
        let mut request = matching_request(&spec, &issued.request_id);
        request.options.no_upgrade = false;

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );

        request.options.no_upgrade = true;

        assert_eq!(
            try_consume(&store, issued.grant.expose_secret(), &caller(), &request),
            Ok(())
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn concurrent_duplicates_create_one_record() {
        let (store, issued, request) = issued();
        let secret = issued.grant.expose_secret().to_owned();
        let caller = caller();

        let winners: Vec<ExecutionRecord> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| store.consume(&secret, &caller, &request).ok()))
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| handle.join().expect("join"))
                .collect()
        });

        assert_eq!(winners.len(), 1);
        assert_eq!(
            store.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Consumed
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn outcome_is_unknown_until_consumed_and_denial_creates_no_record() {
        let (store, issued, mut request) = issued();

        assert_eq!(
            store.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unknown
        );

        request.capture_output = false;
        assert!(
            store
                .consume(issued.grant.expose_secret(), &caller(), &request)
                .is_err()
        );

        assert_eq!(
            store.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unknown
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn outcome_lookup_requires_the_issued_grant_and_request_id() {
        let (store, issued, request) = issued();
        let other = store.issue(spec()).expect("issue");
        let _record = store
            .consume(issued.grant.expose_secret(), &caller(), &request)
            .expect("consume");

        assert_eq!(
            store.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Consumed
        );
        assert_eq!(store.outcome(&issued.grant, &Uuid::new_v4()), OutcomeSummary::Unknown);
        assert_eq!(store.outcome(&other.grant, &issued.request_id), OutcomeSummary::Unknown);
        assert_eq!(store.outcome(&other.grant, &other.request_id), OutcomeSummary::Unknown);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn outcome_only_moves_forward_with_positive_evidence() {
        let (store, issued, request) = issued();
        let record = store
            .consume(issued.grant.expose_secret(), &caller(), &request)
            .expect("consume");
        let read = || store.outcome(&issued.grant, &issued.request_id);

        assert!(!record.mark_exited(0), "exit without a started process is not evidence");
        assert_eq!(read(), OutcomeSummary::Consumed);

        assert!(record.mark_started());
        assert!(!record.mark_started());
        assert_eq!(read(), OutcomeSummary::Started);
        assert_eq!(read(), OutcomeSummary::Started, "reading does not mutate");

        assert!(record.mark_exited(3));
        assert!(!record.mark_exited(0));
        assert!(!record.mark_started());
        assert_eq!(read(), OutcomeSummary::Exited { exit_code: 3 });
        assert!(!record.mark_unobservable());
        assert_eq!(read(), OutcomeSummary::Exited { exit_code: 3 });
    }

    // oracle: mutant a terminal unobservable record gains a later, unreliable exit
    #[test]
    fn unobservable_outcome_keeps_start_evidence_and_is_terminal() {
        let (store, issued, request) = issued();
        let record = store
            .consume(issued.grant.expose_secret(), &caller(), &request)
            .expect("consume");
        assert!(record.mark_started());
        assert!(record.mark_unobservable());
        assert!(!record.mark_started());
        assert!(!record.mark_exited(0));
        assert!(!record.mark_unobservable());
        assert_eq!(
            store.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unobservable { started: true }
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn outcome_is_unknown_after_restart() {
        let (store, issued, request) = issued();
        let record = store
            .consume(issued.grant.expose_secret(), &caller(), &request)
            .expect("consume");
        record.mark_started();

        let restarted = RemoteGrantStore::new();

        assert_eq!(
            restarted.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unknown
        );
        assert_eq!(
            try_consume(&restarted, issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn evicted_active_record_is_unknown_and_its_grant_stays_spent() {
        let (store, first, request) = issued();
        let first_record = store
            .consume(first.grant.expose_secret(), &caller(), &request)
            .expect("consume");
        first_record.mark_started();

        let mut newest = None;
        for _ in 0..10_000 {
            let spec = spec();
            let issued = store.issue(spec.clone()).expect("issue");
            let request = matching_request(&spec, &issued.request_id);
            let record = store
                .consume(issued.grant.expose_secret(), &caller(), &request)
                .expect("consume");
            newest = Some((issued, record));
        }
        let (newest, _newest_record) = newest.expect("at least one grant");

        assert_eq!(store.outcome(&first.grant, &first.request_id), OutcomeSummary::Unknown);
        assert_eq!(
            store.outcome(&newest.grant, &newest.request_id),
            OutcomeSummary::Consumed
        );
        assert_eq!(
            try_consume(&store, first.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
        assert!(
            !first_record.mark_exited(0),
            "a late update must not resurrect an evicted record"
        );
        assert_eq!(store.outcome(&first.grant, &first.request_id), OutcomeSummary::Unknown);
    }
}
