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
    /// Canonical, nonempty broker `Source.Name`; compared exactly, without Unicode normalization.
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
    /// The source name is empty.
    EmptySourceName,
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("too many pending grants"),
            Self::Unserializable => f.write_str("request cannot be serialized"),
            Self::EmptySourceName => f.write_str("source name is empty"),
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

    /// Issues a 60-second single-use grant for the canonical request described by `spec`.
    pub fn issue(&self, spec: GrantSpec) -> Result<IssuedGrant, IssueError> {
        self.issue_at(Instant::now(), spec)
    }

    /// Atomically verifies and consumes the grant for `caller` and `request`.
    ///
    /// A grant presented with a different caller or request stays valid for its rightful holder.
    pub fn consume(&self, grant: &str, caller: &VerifiedCaller, request: &PackageRequest) -> Result<(), GrantDenied> {
        self.consume_at(Instant::now(), grant, caller, request)
    }

    fn issue_at(&self, now: Instant, spec: GrantSpec) -> Result<IssuedGrant, IssueError> {
        if spec.source_name.is_empty() {
            return Err(IssueError::EmptySourceName);
        }

        let request_id = Uuid::new_v4();
        let request = comparable(&canonical_request(&spec, &request_id)).ok_or(IssueError::Unserializable)?;

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
                sid: spec.target_sid,
                request,
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
    ) -> Result<(), GrantDenied> {
        let secret = hex::decode(grant).map_err(|_| GrantDenied)?;
        let request = comparable(request).ok_or(GrantDenied)?;
        let key = digest(&secret);

        let mut entries = self.entries.lock();
        entries.retain(|_, entry| entry.expires_at > now);

        match entries.get(&key) {
            Some(entry) if entry.sid == caller.sid && entry.request == request => {
                entries.remove(&key);
                Ok(())
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
            no_upgrade: false,
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
                no_upgrade: false,
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
            store.consume(issued.grant.expose_secret(), &caller(), &request),
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
            store.consume(issued.grant.expose_secret(), &caller(), &request),
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

        assert_eq!(store.consume(issued.grant.expose_secret(), &caller(), &request), Ok(()));
        assert_eq!(
            store.consume(issued.grant.expose_secret(), &caller(), &request),
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

        assert_eq!(store.consume(issued.grant.expose_secret(), &caller(), &request), Ok(()));
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

        assert_eq!(store.consume(issued.grant.expose_secret(), &caller(), &request), Ok(()));
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
            store.consume(issued.grant.expose_secret(), &caller(), &request),
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
            store.consume(issued.grant.expose_secret(), &caller(), &request),
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
            store.consume(issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn empty_source_name_cannot_be_issued() {
        let mut spec = spec();
        spec.source_name = String::new();

        assert_eq!(
            RemoteGrantStore::new().issue(spec).expect_err("empty name"),
            IssueError::EmptySourceName
        );
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
            store.consume(
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

        assert_eq!(store.consume(&"00".repeat(32), &caller(), &request), Err(GrantDenied));
        assert_eq!(store.consume("not hex", &caller(), &request), Err(GrantDenied));
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
            store.consume_at(
                start + GRANT_LIFETIME,
                issued.grant.expose_secret(),
                &caller(),
                &request
            ),
            Err(GrantDenied)
        );
        assert!(store.entries.lock().is_empty());
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
        assert_eq!(store.entries.lock().len(), 1);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn concurrent_consumption_succeeds_exactly_once() {
        let (store, issued, request) = issued();
        let secret = issued.grant.expose_secret().to_owned();
        let caller = caller();

        let successes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| store.consume(&secret, &caller, &request).is_ok()))
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
            store.consume(issued.grant.expose_secret(), &caller(), &request),
            Err(GrantDenied)
        );
        assert_eq!(store.consume(issued.grant.expose_secret(), &caller(), &genuine), Ok(()));
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
}
