//! This module holds in-memory state for the [agent contract][contract], [DVLS management API][dvls] and [mock control][mock].
//! One mutex around `State` serializes enrollment and rotation.
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.md
//! [dvls]: ../../../docs/agent-identity/INTENT.DVLS.md#management-api
//! [mock]: ../INTENT.md#mock-only-control

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use p256::ecdsa::VerifyingKey;
use rand::RngExt as _;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::ca::{self, DEFAULT_LEAF_LIFETIME_SECS, RootCa};
use crate::name_eval;
use crate::oracle::{AuthenticatedIdentity, CertStatus, NonceStore, RegisteredCert, check_csr};

/// The only config schema version the contract defines ([CONTRACT.md][contract], "5.2 `POST enroll`").
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.md#52-post-enroll
const CONFIG_VERSION: u64 = 1;

/// Error with an HTTP status and a machine-readable code, mapped to the right body
/// shape by the handlers.
#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) status: u16,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl ApiError {
    pub(crate) fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub(crate) fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(400, "invalid_request", message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, "not_found", message)
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, "conflict", message)
    }

    pub(crate) fn token_invalid() -> Self {
        Self::new(401, "token_invalid", "unknown or deleted token")
    }

    pub(crate) fn token_exhausted() -> Self {
        Self::new(403, "token_exhausted", "token has no remaining uses")
    }

    pub(crate) fn token_expired() -> Self {
        Self::new(401, "token_expired", "token is expired")
    }

    pub(crate) fn identity_revoked() -> Self {
        Self::new(403, "identity_revoked", "identity is revoked")
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "internal_error", message)
    }
}

/// Identifies which mock endpoint drops its next response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropTarget {
    Enroll,
    Renew,
    Confirm,
    CheckIn,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FailNextResponse {
    pub(crate) endpoint: DropTarget,
    pub(crate) status: u16,
    pub(crate) error: Option<&'static str>,
    pub(crate) retry_after_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum MalformedChannelUrl {
    Http,
    Query,
    Fragment,
}

/// Holds mock fault knobs merged field-by-field by `POST __mock__/faults`.
#[derive(Debug, Clone)]
pub(crate) struct Faults {
    pub(crate) drop_next_response: Option<DropTarget>,
    pub(crate) fail_next_response: Option<FailNextResponse>,
    pub(crate) clock_skew_secs: Option<i64>,
    pub(crate) leaf_lifetime_secs: Option<i64>,
    pub(crate) channel_available: bool,
    pub(crate) channel_broken: bool,
    pub(crate) malformed_channel_url: Option<MalformedChannelUrl>,
    pub(crate) rotation_rate_limit_per_sec: Option<u32>,
    /// Replaces `config.version` in every delivered config, so tests can deliver an unsupported version.
    pub(crate) config_version: Option<u64>,
}

impl Default for Faults {
    fn default() -> Self {
        Self {
            drop_next_response: None,
            fail_next_response: None,
            clock_skew_secs: None,
            leaf_lifetime_secs: None,
            channel_available: true,
            channel_broken: false,
            malformed_channel_url: None,
            rotation_rate_limit_per_sec: None,
            config_version: None,
        }
    }
}

/// Why a renewal was requested (§7.3 `RenewRequested.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenewReason {
    Admin,
    Rotation,
}

impl RenewReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RenewReason::Admin => "admin",
            RenewReason::Rotation => "rotation",
        }
    }
}

/// Stores a DVLS enrollment token.
/// Only the SHA-256 of the secret is stored (§2).
pub(crate) struct Token {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) max_uses: u64,
    pub(crate) used_count: u64,
    /// Unix seconds.
    pub(crate) expires_at: i64,
    pub(crate) friendly_name_format: Option<String>,
    pub(crate) config: Option<Value>,
    /// Unix seconds.
    pub(crate) created_at: i64,
    pub(crate) created_by: String,
    /// Deletion keeps the secret hash for same-token idempotent recovery.
    pub(crate) deleted_at: Option<i64>,
}

impl Token {
    /// Returns the DVLS token state, where `expired` wins over `exhausted`.
    pub(crate) fn state(&self, now: i64) -> &'static str {
        if now >= self.expires_at {
            "expired"
        } else if self.used_count >= self.max_uses {
            "exhausted"
        } else {
            "active"
        }
    }
}

/// An identity certificate with its lifecycle status (§8).
pub(crate) struct Cert {
    pub(crate) thumbprint: String,
    pub(crate) der: Vec<u8>,
    pub(crate) public_key: VerifyingKey,
    pub(crate) serial: String,
    /// Unix seconds.
    pub(crate) not_before: i64,
    /// Unix seconds.
    pub(crate) not_after: i64,
    /// Thumbprint of the issuing root.
    pub(crate) issuer: String,
    pub(crate) status: CertStatus,
    /// Monotonic issuance order, including certificates issued in the same second.
    pub(crate) issued_seq: u64,
}

impl Cert {
    fn active_on_root(&self, root: &str, now: i64) -> bool {
        matches!(self.status, CertStatus::Current | CertStatus::Pending) && self.issuer == root && now < self.not_after
    }
}

fn issued_key_hash(public_key: &VerifyingKey) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(ca::public_key_der(public_key)).into()
}

/// Stores a registered DVLS identity.
pub(crate) struct Identity {
    pub(crate) id: Uuid,
    pub(crate) friendly_name: String,
    pub(crate) metadata: Map<String, Value>,
    /// Strictly increasing creation order, even for enrollments in the same second.
    pub(crate) created_seq: u64,
    /// Unix seconds.
    pub(crate) created_at: i64,
    /// Unix seconds.
    pub(crate) last_seen_at: Option<i64>,
    /// Unix seconds.
    pub(crate) revoked_at: Option<i64>,
    pub(crate) renewal_requested: Option<RenewalFlag>,
    pub(crate) config: Value,
    pub(crate) token_id: Uuid,
    pub(crate) token_name: String,
    pub(crate) certs: Vec<Cert>,
}

pub(crate) struct RenewalFlag {
    pub(crate) reason: RenewReason,
    /// First issuance order eligible to clear this flag.
    pub(crate) min_issued_seq: u64,
}

impl Identity {
    pub(crate) fn config_revision(&self) -> u64 {
        self.config["revision"]
            .as_u64()
            .expect("identity config has a revision")
    }

    /// Returns the serialized config and its revision when a Hello reports an older applied revision.
    /// The channel sends it as the `ConfigUpdate` that follows `Welcome` ([CONTRACT.md][contract], "7.3 Sequence", step 7).
    ///
    /// [contract]: ../../../docs/agent-identity/CONTRACT.md#73-sequence
    pub(crate) fn config_update_after(&self, applied_revision: u64) -> Option<(String, u64)> {
        let revision = self.config_revision();
        (applied_revision < revision).then(|| {
            (
                serde_json::to_string(&self.config).expect("identity config is serializable"),
                revision,
            )
        })
    }

    pub(crate) fn current_cert(&self) -> Option<&Cert> {
        self.certs.iter().find(|c| c.status == CertStatus::Current)
    }

    pub(crate) fn revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub(crate) fn status(&self, now: i64) -> IdentityStatus {
        identity_status(
            self.revoked(),
            self.certs.iter().map(|c| (c.status, c.not_before, c.not_after)),
            now,
        )
    }
}

/// Identity status as the [DVLS intent][dvls] defines it ("Terminology"), distinct from the certificate statuses.
///
/// [dvls]: ../../../docs/agent-identity/INTENT.DVLS.md#terminology
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityStatus {
    Active,
    Grace,
    Expired,
    Revoked,
}

impl IdentityStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            IdentityStatus::Active => "active",
            IdentityStatus::Grace => "grace",
            IdentityStatus::Expired => "expired",
            IdentityStatus::Revoked => "revoked",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(IdentityStatus::Active),
            "grace" => Some(IdentityStatus::Grace),
            "expired" => Some(IdentityStatus::Expired),
            "revoked" => Some(IdentityStatus::Revoked),
            _ => None,
        }
    }
}

/// Derives an identity's status from its revocation and its certificates' `(status, notBefore, notAfter)`.
fn identity_status(revoked: bool, certs: impl IntoIterator<Item = (CertStatus, i64, i64)>, now: i64) -> IdentityStatus {
    if revoked {
        return IdentityStatus::Revoked;
    }
    let mut status = IdentityStatus::Expired;
    for (cert_status, not_before, not_after) in certs {
        if cert_status == CertStatus::Retired {
            continue;
        }
        if now < not_after {
            return IdentityStatus::Active;
        }
        // CONTRACT.md §6 and §8.2: renewal grace lasts the certificate's own lifetime.
        if now < not_after + (not_after - not_before) {
            status = IdentityStatus::Grace;
        }
    }
    status
}

/// Pushed into a live channel stream's task.
pub(crate) enum StreamPush {
    RenewRequested(&'static str),
    Reconnect(&'static str),
    ConfigUpdate(String),
    /// Retired certificate's 60-second reconnect period elapsed (§7.4).
    CloseOk,
    /// Identity revoked: close PERMISSION_DENIED + `identity_revoked`.
    CloseRevoked,
    /// Identity or certificate vanished (delete, reset): close with `identity_unknown`.
    CloseUnknown,
    /// The mock clock reached the certificate's `notAfter`.
    CloseExpired,
}

pub(crate) struct StreamHandle {
    pub(crate) identity_id: Uuid,
    pub(crate) cert_thumbprint: String,
    pub(crate) tx: mpsc::UnboundedSender<StreamPush>,
    /// Mock-clock second at which an old stream must close after confirmation.
    pub(crate) retire_at: Option<i64>,
}

fn has_live_old_root_stream(identity: &Identity, streams: &HashMap<Uuid, StreamHandle>, root: &str, now: i64) -> bool {
    identity.certs.iter().any(|cert| {
        cert.active_on_root(root, now)
            && cert.not_before <= now
            && streams
                .values()
                .any(|stream| stream.identity_id == identity.id && stream.cert_thumbprint == cert.thumbprint)
    })
}

/// Tracks an in-progress DVLS CA rotation.
pub(crate) struct Rotation {
    /// Thumbprints of the old and new roots.
    pub(crate) old_root: String,
    pub(crate) new_root: String,
    /// Unix seconds.
    pub(crate) deadline: i64,
}

#[derive(Default)]
pub(crate) struct RequestCounts {
    pub(crate) enroll_by_token: HashMap<Uuid, u64>,
    pub(crate) enroll_revoked_by_token: HashMap<Uuid, u64>,
    pub(crate) enroll_total: u64,
    pub(crate) enroll_retry_503: u64,
    pub(crate) renew: u64,
    pub(crate) renew_attempt_keyids: Vec<Option<String>>,
    pub(crate) renew_retry_503: u64,
    pub(crate) confirm: u64,
    pub(crate) confirm_retry_503: u64,
    pub(crate) check_in: u64,
    pub(crate) connect: u64,
    pub(crate) channel_attempts: u64,
    pub(crate) redirect_hits: u64,
    pub(crate) request_sequence: Vec<&'static str>,
    pub(crate) authenticated_connects: u64,
    pub(crate) correlated_acks: u64,
    pub(crate) overlap_open: u64,
}

pub(crate) struct Event {
    pub(crate) identity_id: Uuid,
    pub(crate) body: Value,
}

struct IssuedKey {
    identity_id: Uuid,
    token_id: Uuid,
    thumbprint: String,
    /// Records the original issuance time in Unix seconds, even after identity deletion.
    issued_at: i64,
}

pub struct State {
    pub(crate) tokens: HashMap<Uuid, Token>,
    /// SHA-256(secret) → token ID (§2).
    pub(crate) token_hashes: HashMap<[u8; 32], Uuid>,
    pub(crate) identities: HashMap<Uuid, Identity>,
    /// Certificate thumbprint → identity.
    pub(crate) cert_index: HashMap<String, Uuid>,
    /// INVARIANT: each issued SPKI key retains its token and issuance time after identity deletion.
    issued_keys: HashMap<[u8; 32], IssuedKey>,
    /// All known roots; the issuing root is the last one, `published` gates
    /// `trust-anchor` listing.
    pub(crate) roots: Vec<RootCa>,
    pub(crate) rotation: Option<Rotation>,
    pub(crate) nonces: NonceStore,
    pub(crate) faults: Faults,
    pub(crate) requests: RequestCounts,
    /// Mock-only barrier: retries receive 503 after a dropped response or injected confirm failure.
    pub(crate) retry_barrier: Option<DropTarget>,
    pub(crate) barrier_triggered: Option<DropTarget>,
    /// Authenticated live channel streams, by stream ID.
    pub(crate) streams: HashMap<Uuid, StreamHandle>,
    /// Signed openings that have received a Challenge but not passed Hello proof.
    pub(crate) challenged_streams: HashMap<Uuid, StreamHandle>,
    /// Valid Hello proofs held before authentication by the mock-only handshake barrier.
    pub(crate) paused_hellos: HashSet<Uuid>,
    closed_streams: HashSet<Uuid>,
    pub(crate) events: Vec<Event>,
    pub(crate) next_event_seq: u64,
    /// Pending pushes survive the deadline that ends the public rotation phase.
    pub(crate) rotation_push_queue: VecDeque<(Uuid, String)>,
    /// Sliding one-second rate window, shared across requests and rotation phases.
    pub(crate) rotation_push_times: VecDeque<Instant>,
    pub(crate) root_seq: u32,
    pub(crate) serial_seq: u64,
    pub(crate) next_identity_seq: u64,
    pub(crate) last_created_at: i64,
}

impl State {
    pub fn new(now: i64) -> anyhow::Result<Self> {
        let root = RootCa::generate(1, now)?;
        Ok(Self {
            tokens: HashMap::new(),
            token_hashes: HashMap::new(),
            identities: HashMap::new(),
            cert_index: HashMap::new(),
            issued_keys: HashMap::new(),
            roots: vec![root],
            rotation: None,
            nonces: NonceStore::default(),
            faults: Faults::default(),
            requests: RequestCounts::default(),
            retry_barrier: None,
            barrier_triggered: None,
            streams: HashMap::new(),
            challenged_streams: HashMap::new(),
            paused_hellos: HashSet::new(),
            closed_streams: HashSet::new(),
            events: Vec::new(),
            next_event_seq: 1,
            rotation_push_queue: VecDeque::new(),
            rotation_push_times: VecDeque::new(),
            root_seq: 1,
            serial_seq: 100,
            next_identity_seq: 1,
            last_created_at: now,
        })
    }

    pub(crate) fn record_event(&mut self, identity_id: Uuid, event_type: &str, fields: Value) {
        let mut body = fields.as_object().cloned().expect("event fields are an object");
        body.insert("seq".to_owned(), json!(self.next_event_seq));
        body.insert("type".to_owned(), json!(event_type));
        body.insert("identity_id".to_owned(), json!(identity_id));
        self.events.push(Event {
            identity_id,
            body: Value::Object(body),
        });
        self.next_event_seq += 1;
    }

    pub(crate) fn update_channel_available(&mut self, available: bool, base_url: &str) {
        if self.faults.channel_available == available {
            return;
        }
        self.faults.channel_available = available;
        self.change_every_config(|config| {
            if available {
                config.insert("agent_channel_url".to_owned(), json!(base_url));
            } else {
                config.remove("agent_channel_url");
            }
        });
    }

    /// Sets or clears the `config.version` override.
    /// A change bumps every identity's revision so agents treat the delivered config as newer than their stored one.
    pub(crate) fn update_config_version(&mut self, version: Option<u64>) {
        let previous = self.faults.config_version.unwrap_or(CONFIG_VERSION);
        self.faults.config_version = version;
        let version = version.unwrap_or(CONFIG_VERSION);
        if version == previous {
            return;
        }
        self.change_every_config(|config| {
            config.insert("version".to_owned(), json!(version));
        });
    }

    /// Applies `change` to every identity's config, bumps its revision and pushes it to live streams.
    fn change_every_config(&mut self, change: impl Fn(&mut Map<String, Value>)) {
        let mut changed = Vec::new();
        for identity in self.identities.values_mut() {
            let revision = identity
                .config_revision()
                .checked_add(1)
                .expect("config revision fits u64");
            let config = identity.config.as_object_mut().expect("identity config is an object");
            change(config);
            config.insert("revision".to_owned(), json!(revision));
            changed.push(identity.id);
        }
        for identity_id in changed {
            self.push_config_update(identity_id);
        }
    }

    pub(crate) fn merge_config_fields(&mut self, fields: &Map<String, Value>) -> usize {
        let mut changed = Vec::new();
        for identity in self.identities.values_mut() {
            let effective_change = fields
                .iter()
                .any(|(name, value)| identity.config.get(name) != Some(value));
            if effective_change {
                let revision = identity
                    .config_revision()
                    .checked_add(1)
                    .expect("config revision fits u64");
                identity
                    .config
                    .as_object_mut()
                    .expect("identity config is an object")
                    .extend(fields.clone());
                identity.config["revision"] = json!(revision);
                changed.push(identity.id);
            }
        }
        for identity_id in &changed {
            self.push_config_update(*identity_id);
        }
        changed.len()
    }

    fn push_config_update(&mut self, identity_id: Uuid) {
        let identity = self.identities.get(&identity_id).expect("identity exists");
        let revision = identity.config_revision();
        let config_json = serde_json::to_string(&identity.config).expect("identity config is serializable");
        self.record_event(identity_id, "config_changed", json!({ "revision": revision }));
        self.send_config_update(identity_id, &config_json, revision, "config_update_sent");
    }

    /// Sends a deliberately stale config without changing the server's effective revision.
    pub(crate) fn replay_stale_config(&mut self, identity_id: Uuid, revision: u64) -> Result<usize, ApiError> {
        let identity = self
            .identities
            .get(&identity_id)
            .ok_or_else(|| ApiError::not_found("unknown identity"))?;
        if revision >= identity.config_revision() {
            return Err(ApiError::invalid_request(
                "stale revision must be below the current revision",
            ));
        }
        let mut config = identity.config.clone();
        config["revision"] = json!(revision);
        config["mock_stale_marker"] = json!("ignore-me");
        let config_json = serde_json::to_string(&config).expect("mock config is serializable");
        Ok(self.send_config_update(identity_id, &config_json, revision, "stale_config_update_sent"))
    }

    fn send_config_update(
        &mut self,
        identity_id: Uuid,
        config_json: &str,
        revision: u64,
        event_type: &'static str,
    ) -> usize {
        let stream_ids = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.identity_id == identity_id)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let mut sent_count = 0;
        for stream_id in stream_ids {
            let sent = self
                .streams
                .get(&stream_id)
                .is_some_and(|stream| stream.tx.send(StreamPush::ConfigUpdate(config_json.to_owned())).is_ok());
            if sent {
                self.record_event(
                    identity_id,
                    event_type,
                    json!({ "stream_id": stream_id, "revision": revision }),
                );
                sent_count += 1;
            } else if let Some(stream) = self.streams.get(&stream_id) {
                let thumbprint = stream.cert_thumbprint.clone();
                self.close_stream(stream_id, identity_id, &thumbprint, "OK", None);
            }
        }
        sent_count
    }

    fn cert_status_changed(&mut self, identity_id: Uuid, thumbprint: &str, from: Option<CertStatus>, to: CertStatus) {
        let mut fields = json!({
            "cert_thumbprint": thumbprint,
            "to": to.as_str(),
        });
        if let Some(from) = from {
            fields["from"] = json!(from.as_str());
        }
        self.record_event(identity_id, "cert_status_changed", fields);
    }

    pub(crate) fn close_stream(
        &mut self,
        stream_id: Uuid,
        identity_id: Uuid,
        cert_thumbprint: &str,
        status: &str,
        error_code: Option<&str>,
    ) {
        self.streams.remove(&stream_id);
        self.challenged_streams.remove(&stream_id);
        self.paused_hellos.remove(&stream_id);
        if !self.identities.contains_key(&identity_id) || !self.closed_streams.insert(stream_id) {
            return;
        }
        let mut fields = json!({
            "stream_id": stream_id,
            "cert_thumbprint": cert_thumbprint,
            "status": status,
        });
        if let Some(error_code) = error_code {
            fields["error_code"] = json!(error_code);
        }
        self.record_event(identity_id, "stream_closed", fields);
    }

    /// Returns the newest root, which issues new leaves during DVLS rotation.
    pub(crate) fn issuing_root(&self) -> &RootCa {
        self.roots.last().expect("at least one root")
    }

    pub(crate) fn observe_enroll(&mut self, secret: &[u8; 32]) {
        use sha2::Digest as _;
        let hash: [u8; 32] = sha2::Sha256::digest(secret).into();
        if let Some(id) = self.token_hashes.get(&hash) {
            *self.requests.enroll_by_token.entry(*id).or_default() += 1;
        }
    }

    pub(crate) fn token_id(&self, secret: &[u8; 32]) -> Option<Uuid> {
        use sha2::Digest as _;
        let hash: [u8; 32] = sha2::Sha256::digest(secret).into();
        self.token_hashes.get(&hash).copied()
    }

    pub(crate) fn fail_next_response(&mut self, endpoint: DropTarget) -> Option<FailNextResponse> {
        if self
            .faults
            .fail_next_response
            .is_some_and(|fault| fault.endpoint == endpoint)
        {
            self.faults.fail_next_response.take()
        } else {
            None
        }
    }

    /// Resolves a certificate thumbprint for the §6 verifier.
    pub(crate) fn lookup_cert(&self, thumbprint: &str) -> Option<RegisteredCert> {
        lookup_cert(&self.identities, &self.cert_index, thumbprint)
    }

    /// Whether the identity has at least one authenticated live stream (§7).
    pub(crate) fn is_connected(&self, identity_id: Uuid) -> bool {
        self.streams.values().any(|s| s.identity_id == identity_id)
    }

    /// Pushes an event to every live stream of an identity; broken channels are dropped.
    pub(crate) fn push_to_identity(&mut self, identity_id: Uuid, push: &PushKind) {
        let dead: Vec<Uuid> = self
            .streams
            .iter()
            .filter(|(_, s)| s.identity_id == identity_id)
            .filter_map(|(id, s)| match push.send(&s.tx) {
                Err(_) => Some(*id),
                Ok(()) => None,
            })
            .collect();
        for id in dead {
            self.streams.remove(&id);
        }
    }

    /// §5.5: only confirm promotes pending, retires the old current certificate and schedules its streams to close.
    pub(crate) fn confirm(&mut self, auth: &AuthenticatedIdentity, now: i64) {
        let identity_id = auth.identity_id();
        let thumbprint = auth.cert_thumbprint();
        let identity = self
            .identities
            .get_mut(&identity_id)
            .expect("authenticated identity exists");
        let idx = identity
            .certs
            .iter()
            .position(|cert| cert.thumbprint == thumbprint)
            .expect("authenticated certificate exists");
        // UNTESTED: both promotion and an already-current retry refresh `last_seen_at`.
        // Confirm proves current key possession, and the management API's last-seen filters depend on this timestamp.
        // When changing this branch, check the management API's `lastSeenAt` after both confirm paths.
        identity.last_seen_at = Some(now);
        if identity.certs[idx].status == CertStatus::Current {
            return;
        }
        debug_assert_eq!(identity.certs[idx].status, CertStatus::Pending);
        identity.certs[idx].status = CertStatus::Current;
        if identity
            .renewal_requested
            .as_ref()
            .is_some_and(|flag| identity.certs[idx].issued_seq >= flag.min_issued_seq)
        {
            identity.renewal_requested = None;
        }
        let retired = identity
            .certs
            .iter_mut()
            .filter(|cert| cert.status == CertStatus::Current && cert.thumbprint != thumbprint)
            .map(|cert| {
                cert.status = CertStatus::Retired;
                cert.thumbprint.clone()
            })
            .collect::<Vec<_>>();
        self.cert_status_changed(identity_id, thumbprint, Some(CertStatus::Pending), CertStatus::Current);
        for old_thumbprint in retired {
            self.cert_status_changed(
                identity_id,
                &old_thumbprint,
                Some(CertStatus::Current),
                CertStatus::Retired,
            );
            let mut notified = Vec::new();
            for (stream_id, stream) in &mut self.streams {
                if stream.cert_thumbprint == old_thumbprint {
                    stream.retire_at = Some(now.saturating_add(60));
                    if PushKind::Reconnect("certificate_rotated").send(&stream.tx).is_ok() {
                        notified.push(*stream_id);
                    }
                }
            }
            for stream_id in notified {
                self.record_event(
                    identity_id,
                    "reconnect_sent",
                    json!({
                        "stream_id": stream_id,
                        "cert_thumbprint": old_thumbprint,
                        "reason": "certificate_rotated",
                    }),
                );
            }
        }
        self.complete_rotation_if_ready(now);
    }

    /// §5.2 enroll. `secret` is the 32-byte token secret; only its SHA-256 is matched.
    pub(crate) fn enroll(
        &mut self,
        secret: &[u8; 32],
        csr_der: &[u8],
        metadata: Map<String, Value>,
        now: i64,
        base_url: &str,
    ) -> Result<EnrollOutcome, ApiError> {
        let token_id = self.token_id(secret).ok_or_else(ApiError::token_invalid)?;

        let csr_key = check_csr(csr_der)
            .ok_or_else(|| ApiError::invalid_request("invalid CSR: P-256 key and valid self-signature required"))?;
        name_eval::validate_metadata(&metadata).map_err(ApiError::invalid_request)?;

        let csr_key_hash = issued_key_hash(&csr_key);
        let token = self.tokens.get(&token_id).expect("hash index consistent");
        if let Some(issued) = self.issued_keys.get(&csr_key_hash) {
            let identity = self.identities.get(&issued.identity_id);
            if issued.token_id == token_id
                && identity.is_some_and(|identity| {
                    !identity.revoked()
                        && identity
                            .current_cert()
                            .is_some_and(|cert| cert.thumbprint == issued.thumbprint)
                })
            {
                let chain = self.chain_for_current(issued.identity_id)?;
                return Ok(EnrollOutcome {
                    identity_id: issued.identity_id,
                    certificate_chain: chain,
                });
            }
            if token.deleted_at.is_some() {
                return Err(ApiError::token_invalid());
            }
            if issued.token_id != token_id {
                return Err(ApiError::invalid_request("CSR key belongs to another enrollment token"));
            }
            if identity.is_none_or(Identity::revoked) {
                return Err(ApiError::identity_revoked());
            }
            return Err(ApiError::invalid_request(
                "CSR key belongs to a pending or retired certificate",
            ));
        }

        if token.deleted_at.is_some() {
            return Err(ApiError::token_invalid());
        }
        if now >= token.expires_at {
            return Err(ApiError::token_expired());
        }
        if token.used_count >= token.max_uses {
            return Err(ApiError::token_exhausted());
        }

        // Both issuance and token consumption happen under the identity-creating state lock.
        let identity_id = Uuid::new_v4();
        let (format, token_name) = {
            let token = self.tokens.get(&token_id).expect("hash index consistent");
            (
                token
                    .friendly_name_format
                    .clone()
                    .unwrap_or_else(|| name_eval::DEFAULT_FRIENDLY_NAME_FORMAT.to_owned()),
                token.name.clone(),
            )
        };
        let friendly_name = name_eval::render_friendly_name(&format, &metadata, &token_name, identity_id);
        let issued_seq = self.serial_seq;
        let leaf = self.issue_leaf(identity_id, &csr_key, now)?;
        self.tokens
            .get_mut(&token_id)
            .expect("hash index consistent")
            .used_count += 1;
        let root_der = self.issuing_root().cert_der.clone();
        let cert = Cert {
            thumbprint: leaf.thumbprint.clone(),
            der: leaf.der.clone(),
            public_key: csr_key,
            serial: leaf.serial,
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            issuer: self.issuing_root().thumbprint.clone(),
            status: CertStatus::Current,
            issued_seq,
        };
        let cert_thumbprint = cert.thumbprint.clone();
        let created_at = now.max(self.last_created_at);
        self.last_created_at = created_at;
        let created_seq = self.next_identity_seq;
        self.next_identity_seq += 1;
        let mut config = self.tokens[&token_id]
            .config
            .as_ref()
            .map(|config| config.as_object().expect("token config is an object").clone())
            .unwrap_or_default();
        config.insert(
            "version".to_owned(),
            json!(self.faults.config_version.unwrap_or(CONFIG_VERSION)),
        );
        config.insert("revision".to_owned(), json!(1));
        config.remove("agent_channel_url");
        if self.faults.channel_available {
            let url = match self.faults.malformed_channel_url {
                Some(MalformedChannelUrl::Http) => base_url.replacen("https://", "http://", 1),
                Some(MalformedChannelUrl::Query) => format!("{base_url}?identity_probe=1"),
                Some(MalformedChannelUrl::Fragment) => format!("{base_url}#identity_probe"),
                None => base_url.to_owned(),
            };
            config.insert("agent_channel_url".to_owned(), json!(url));
        }
        let identity = Identity {
            id: identity_id,
            friendly_name,
            metadata,
            created_seq,
            created_at,
            last_seen_at: Some(now),
            revoked_at: None,
            renewal_requested: None,
            config: Value::Object(config),
            token_id,
            token_name,
            certs: vec![cert],
        };
        assert!(
            self.issued_keys
                .insert(
                    csr_key_hash,
                    IssuedKey {
                        identity_id,
                        token_id,
                        thumbprint: cert_thumbprint.clone(),
                        issued_at: leaf.not_before,
                    },
                )
                .is_none(),
            "public key uniqueness was checked under the state lock"
        );
        self.cert_index.insert(leaf.thumbprint, identity_id);
        self.identities.insert(identity_id, identity);
        self.cert_status_changed(identity_id, &cert_thumbprint, None, CertStatus::Current);
        Ok(EnrollOutcome {
            identity_id,
            certificate_chain: vec![leaf.der, root_der],
        })
    }

    fn chain_for_current(&self, identity_id: Uuid) -> Result<Vec<Vec<u8>>, ApiError> {
        let identity = self.identities.get(&identity_id).expect("identity exists");
        let current = identity.current_cert().expect("enrolled identity has a current cert");
        let root = self
            .roots
            .iter()
            .find(|r| r.thumbprint == current.issuer)
            .expect("issuing root is known");
        Ok(vec![current.der.clone(), root.cert_der.clone()])
    }

    fn issue_leaf(&mut self, identity_id: Uuid, public_key: &VerifyingKey, now: i64) -> Result<ca::Leaf, ApiError> {
        let lifetime = self.faults.leaf_lifetime_secs.unwrap_or(DEFAULT_LEAF_LIFETIME_SECS);
        let serial = self.serial_seq;
        self.serial_seq += 1;
        let root = self.issuing_root();
        ca::issue_leaf(root, identity_id, public_key, serial, now, lifetime)
            .map_err(|e| ApiError::internal(format!("failed to issue certificate: {e:#}")))
    }

    /// §5.3 renew validates the CSR and metadata, then enforces key idempotence and the one-pending rule.
    pub(crate) fn renew(
        &mut self,
        auth: &AuthenticatedIdentity,
        csr_der: &[u8],
        metadata: Map<String, Value>,
        now: i64,
    ) -> Result<Vec<Vec<u8>>, ApiError> {
        let identity_id = auth.identity_id();

        let csr_key = check_csr(csr_der)
            .ok_or_else(|| ApiError::invalid_request("invalid CSR: P-256 key and valid self-signature required"))?;
        name_eval::validate_metadata(&metadata).map_err(ApiError::invalid_request)?;

        let csr_key_hash = issued_key_hash(&csr_key);
        if let Some(issued) = self.issued_keys.get(&csr_key_hash) {
            let Some(identity) = self.identities.get(&issued.identity_id) else {
                return Err(ApiError::invalid_request("CSR key belongs to an issued certificate"));
            };
            let certificate = identity
                .certs
                .iter()
                .find(|cert| cert.thumbprint == issued.thumbprint)
                .expect("issued key index is consistent");
            if issued.identity_id != identity_id || certificate.status != CertStatus::Pending {
                return Err(ApiError::invalid_request("CSR key belongs to an issued certificate"));
            }
            let root = self
                .roots
                .iter()
                .find(|root| root.thumbprint == certificate.issuer)
                .expect("issuing root is known");
            let chain = vec![certificate.der.clone(), root.cert_der.clone()];
            let identity = self.identities.get_mut(&identity_id).expect("identity exists");
            identity.metadata = metadata;
            identity.last_seen_at = Some(now);
            return Ok(chain);
        }

        let issued_seq = self.serial_seq;
        let leaf = self.issue_leaf(identity_id, &csr_key, now)?;
        let root_der = self.issuing_root().cert_der.clone();
        let issuer = self.issuing_root().thumbprint.clone();
        let retired = {
            let identity = self.identities.get_mut(&identity_id).expect("identity exists");
            identity
                .certs
                .iter_mut()
                .filter(|cert| cert.status == CertStatus::Pending)
                .map(|cert| {
                    cert.status = CertStatus::Retired;
                    cert.thumbprint.clone()
                })
                .collect::<Vec<_>>()
        };
        for thumbprint in retired {
            self.cert_status_changed(identity_id, &thumbprint, Some(CertStatus::Pending), CertStatus::Retired);
        }
        let token_id = self.identities[&identity_id].token_id;
        // UNTESTED: a renewed key keeps its original issuance time after identity deletion.
        // Deleted identities must never make issued keys reusable or erase their issuance history.
        // When changing renewal, issue a pending key, delete its identity, and inspect `issued_keys`.
        assert!(
            self.issued_keys
                .insert(
                    csr_key_hash,
                    IssuedKey {
                        identity_id,
                        token_id,
                        thumbprint: leaf.thumbprint.clone(),
                        issued_at: leaf.not_before,
                    },
                )
                .is_none(),
            "public key uniqueness was checked under the state lock"
        );
        self.cert_index.insert(leaf.thumbprint.clone(), identity_id);
        let identity = self.identities.get_mut(&identity_id).expect("identity exists");
        identity.certs.push(Cert {
            thumbprint: leaf.thumbprint.clone(),
            der: leaf.der.clone(),
            public_key: csr_key,
            serial: leaf.serial,
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            issuer,
            status: CertStatus::Pending,
            issued_seq,
        });
        identity.metadata = metadata;
        identity.last_seen_at = Some(now);
        self.cert_status_changed(identity_id, &leaf.thumbprint, None, CertStatus::Pending);
        self.complete_rotation_if_ready(now);
        Ok(vec![leaf.der, root_der])
    }

    /// DVLS revocation is idempotent and closes live streams with `PERMISSION_DENIED` + `identity_revoked`.
    pub(crate) fn revoke(&mut self, identity_id: Uuid, now: i64) -> Result<(), ApiError> {
        let identity = self
            .identities
            .get_mut(&identity_id)
            .ok_or_else(|| ApiError::not_found("unknown identity"))?;
        if identity.revoked_at.is_none() {
            identity.revoked_at = Some(now);
        }
        self.push_to_identity(identity_id, &PushKind::CloseRevoked);
        self.complete_rotation_if_ready(now);
        Ok(())
    }

    /// DVLS identity deletion requires prior revocation.
    pub(crate) fn delete_identity(&mut self, identity_id: Uuid, now: i64) -> Result<(), ApiError> {
        let identity = self
            .identities
            .get(&identity_id)
            .ok_or_else(|| ApiError::not_found("unknown identity"))?;
        if !identity.revoked() {
            return Err(ApiError::conflict("identity must be revoked before deletion"));
        }
        self.push_to_identity(identity_id, &PushKind::CloseUnknown);
        let live = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.identity_id == identity_id)
            .map(|(id, stream)| (*id, stream.cert_thumbprint.clone()))
            .collect::<Vec<_>>();
        for (stream_id, thumbprint) in live {
            self.close_stream(
                stream_id,
                identity_id,
                &thumbprint,
                "UNAUTHENTICATED",
                Some("identity_unknown"),
            );
        }
        let removed = self.identities.remove(&identity_id).expect("identity exists");
        debug_assert!(
            removed.certs.iter().all(|cert| {
                self.issued_keys
                    .get(&issued_key_hash(&cert.public_key))
                    .is_some_and(|issued| issued.issued_at == cert.not_before)
            }),
            "issued keys retain their original issuance times after deletion"
        );
        self.complete_rotation_if_ready(now);
        Ok(())
    }

    /// DVLS request-renewal sets the flag (reason `admin`) and pushes to live streams.
    pub(crate) fn request_renewal(&mut self, identity_id: Uuid) -> Result<(), ApiError> {
        let min_issued_seq = self.serial_seq;
        let identity = self
            .identities
            .get_mut(&identity_id)
            .ok_or_else(|| ApiError::not_found("unknown identity"))?;
        identity.renewal_requested = Some(RenewalFlag {
            reason: RenewReason::Admin,
            min_issued_seq,
        });
        self.push_to_identity(identity_id, &PushKind::RenewRequested("admin"));
        Ok(())
    }

    /// Starts a DVLS rotation with the supplied deadline or the active old-root certificate maximum.
    /// The maximum is the latest `notAfter` of an unexpired current or pending old-root certificate of a non-revoked
    /// identity, or `now` if none exist.
    pub(crate) fn start_rotation(&mut self, deadline: Option<i64>, now: i64) -> Result<(), ApiError> {
        if self.rotation.is_some() {
            return Err(ApiError::conflict("a rotation is already in progress"));
        }
        let old_root = self.issuing_root().thumbprint.clone();
        let maximum = self
            .identities
            .values()
            .filter(|identity| !identity.revoked())
            .flat_map(|identity| &identity.certs)
            .filter(|cert| cert.active_on_root(&old_root, now))
            .map(|cert| cert.not_after)
            .max()
            .unwrap_or(now);
        let deadline = deadline.unwrap_or(maximum);
        if deadline > maximum {
            return Err(ApiError::invalid_request(
                "rotation deadline exceeds the latest active old-root certificate",
            ));
        }
        let new_root = RootCa::generate(self.root_seq + 1, now)
            .map_err(|e| ApiError::internal(format!("failed to generate root: {e:#}")))?;
        self.issuing_root_mut().key = None;
        self.root_seq += 1;
        let new_root_thumbprint = new_root.thumbprint.clone();
        self.roots.push(new_root);

        // The flag covers offline identities; a live, unexpired old-root connection also
        // enters the rate-limited push queue, which survives the rotation deadline.
        let min_issued_seq = self.serial_seq;
        for identity in self.identities.values_mut() {
            let on_old_root = !identity.revoked()
                && identity.certs.iter().any(|cert| {
                    matches!(cert.status, CertStatus::Current | CertStatus::Pending) && cert.issuer == old_root
                });
            if on_old_root {
                let can_push = has_live_old_root_stream(identity, &self.streams, &old_root, now);
                identity.renewal_requested = Some(RenewalFlag {
                    reason: RenewReason::Rotation,
                    min_issued_seq,
                });
                if can_push {
                    self.rotation_push_queue.push_back((identity.id, old_root.clone()));
                }
            }
        }
        self.rotation = Some(Rotation {
            old_root,
            new_root: new_root_thumbprint,
            deadline,
        });
        self.drain_rotation_pushes(now);
        self.complete_rotation_if_ready(now);
        Ok(())
    }

    fn issuing_root_mut(&mut self) -> &mut RootCa {
        self.roots.last_mut().expect("at least one root")
    }

    /// Sends at most the configured number of pushes within any rolling second.
    fn drain_rotation_pushes(&mut self, mock_now: i64) {
        let now = Instant::now();
        while self
            .rotation_push_times
            .front()
            .is_some_and(|sent| now.duration_since(*sent) >= Duration::from_secs(1))
        {
            self.rotation_push_times.pop_front();
        }
        let limit = self.faults.rotation_rate_limit_per_sec.unwrap_or(10) as usize;
        while self.rotation_push_times.len() < limit {
            let Some((identity_id, old_root)) = self.rotation_push_queue.pop_front() else {
                break;
            };
            let eligible = self.identities.get(&identity_id).is_some_and(|identity| {
                !identity.revoked() && has_live_old_root_stream(identity, &self.streams, &old_root, mock_now)
            });
            if eligible {
                self.push_to_identity(identity_id, &PushKind::RenewRequested("rotation"));
                self.rotation_push_times.push_back(now);
            }
        }
    }

    /// Counts non-revoked identities with unexpired current or pending certificates from the old root.
    pub(crate) fn active_identities_on_old_root(&self, now: i64) -> u64 {
        let Some(rotation) = &self.rotation else {
            return 0;
        };
        self.identities
            .values()
            .filter(|d| !d.revoked() && d.certs.iter().any(|cert| cert.active_on_root(&rotation.old_root, now)))
            .count() as u64
    }

    /// Removes the old root at the deadline or as soon as no old-root identity is active.
    fn complete_rotation_if_ready(&mut self, now: i64) {
        let Some(rotation) = &self.rotation else {
            return;
        };
        if now < rotation.deadline && self.active_identities_on_old_root(now) != 0 {
            return;
        }
        let old_root = rotation.old_root.clone();
        if let Some(root) = self.roots.iter_mut().find(|root| root.thumbprint == old_root) {
            root.published = false;
        }
        self.rotation = None;
    }

    /// Re-evaluates stream expiry and rotation completion on each request and clock change.
    pub(crate) fn tick(&mut self, now: i64) {
        let expired_challenges = self
            .challenged_streams
            .iter()
            .filter(|(_, stream)| {
                self.lookup_cert(&stream.cert_thumbprint)
                    .is_some_and(|cert| now >= cert.not_after)
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for stream_id in expired_challenges {
            if let Some(stream) = self.challenged_streams.remove(&stream_id) {
                let _ = PushKind::CloseExpired.send(&stream.tx);
                self.close_stream(
                    stream_id,
                    stream.identity_id,
                    &stream.cert_thumbprint,
                    "UNAUTHENTICATED",
                    Some("certificate_expired"),
                );
            }
        }
        let expired = self
            .streams
            .iter()
            .filter_map(|(id, stream)| {
                let reason = match self.lookup_cert(&stream.cert_thumbprint) {
                    None => Some(("UNAUTHENTICATED", "identity_unknown", PushKind::CloseUnknown)),
                    Some(cert) if cert.revoked => {
                        Some(("PERMISSION_DENIED", "identity_revoked", PushKind::CloseRevoked))
                    }
                    Some(cert) if now >= cert.not_after => {
                        Some(("UNAUTHENTICATED", "certificate_expired", PushKind::CloseExpired))
                    }
                    Some(_) => None,
                }?;
                Some((*id, reason))
            })
            .collect::<Vec<_>>();
        for (stream_id, (status, code, push)) in expired {
            if let Some(stream) = self.streams.remove(&stream_id) {
                let _ = push.send(&stream.tx);
                self.close_stream(
                    stream_id,
                    stream.identity_id,
                    &stream.cert_thumbprint,
                    status,
                    Some(code),
                );
            }
        }
        let retired = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.retire_at.is_some_and(|at| now >= at))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for stream_id in retired {
            if let Some(stream) = self.streams.remove(&stream_id) {
                let _ = PushKind::CloseOk.send(&stream.tx);
                self.close_stream(stream_id, stream.identity_id, &stream.cert_thumbprint, "OK", None);
            }
        }
        self.complete_rotation_if_ready(now);
        self.drain_rotation_pushes(now);
    }

    /// Mock reset clears tokens, identities, nonces, faults, rotation and the clock offset.
    /// It creates a fresh root and closes live streams with `identity_unknown`.
    pub(crate) fn reset(&mut self, now: i64) -> anyhow::Result<()> {
        let stream_ids: Vec<Uuid> = self.streams.keys().copied().collect();
        for id in &stream_ids {
            if let Some(handle) = self.streams.get(id) {
                let _ = PushKind::CloseUnknown.send(&handle.tx);
            }
        }
        for handle in self.challenged_streams.values() {
            let _ = PushKind::CloseUnknown.send(&handle.tx);
        }
        self.streams.clear();
        self.challenged_streams.clear();
        self.paused_hellos.clear();
        self.closed_streams.clear();
        self.tokens.clear();
        self.token_hashes.clear();
        self.identities.clear();
        self.cert_index.clear();
        self.issued_keys.clear();
        self.nonces = NonceStore::default();
        self.faults = Faults::default();
        self.requests = RequestCounts::default();
        self.retry_barrier = None;
        self.barrier_triggered = None;
        self.rotation = None;
        self.rotation_push_queue.clear();
        self.rotation_push_times.clear();
        self.events.clear();
        self.next_event_seq = 1;
        self.next_identity_seq = 1;
        self.last_created_at = now;
        self.root_seq += 1;
        self.roots = vec![RootCa::generate(self.root_seq, now)?];
        Ok(())
    }

    /// Creates a token record (validation done by the caller); returns the ID and the
    /// 32-byte secret (only its SHA-256 is stored, §2).
    pub(crate) fn create_token(
        &mut self,
        name: String,
        max_uses: u64,
        expires_at: i64,
        friendly_name_format: Option<String>,
        config: Option<Value>,
        now: i64,
    ) -> (Uuid, [u8; 32]) {
        let mut secret = [0u8; 32];
        rand::rng().fill(&mut secret[..]);
        let token = Token {
            id: Uuid::new_v4(),
            name,
            max_uses,
            used_count: 0,
            expires_at,
            friendly_name_format,
            config,
            created_at: now,
            created_by: "mock-admin".to_owned(),
            deleted_at: None,
        };
        use sha2::Digest as _;
        let hash: [u8; 32] = sha2::Sha256::digest(secret).into();
        let id = token.id;
        self.tokens.insert(id, token);
        self.token_hashes.insert(hash, id);
        (id, secret)
    }
}

/// Enroll outcome data.
pub(crate) struct EnrollOutcome {
    pub(crate) identity_id: Uuid,
    /// Leaf-first (§4).
    pub(crate) certificate_chain: Vec<Vec<u8>>,
}

/// Free-function form of [`State::lookup_cert`] so callers can split borrows (the
/// §6 verifier needs `&identities`/`&cert_index` and `&mut nonces` at once).
pub(crate) fn lookup_cert(
    identities: &HashMap<Uuid, Identity>,
    cert_index: &HashMap<String, Uuid>,
    thumbprint: &str,
) -> Option<RegisteredCert> {
    let identity_id = *cert_index.get(thumbprint)?;
    let identity = identities.get(&identity_id)?;
    let cert = identity.certs.iter().find(|c| c.thumbprint == thumbprint)?;
    Some(RegisteredCert {
        identity_id,
        revoked: identity.revoked(),
        status: cert.status,
        not_before: cert.not_before,
        not_after: cert.not_after,
        public_key: cert.public_key,
    })
}

/// Cloneable push description (sending borrows the channel).
pub(crate) enum PushKind {
    RenewRequested(&'static str),
    Reconnect(&'static str),
    CloseOk,
    CloseRevoked,
    CloseUnknown,
    CloseExpired,
}

impl PushKind {
    fn send(&self, tx: &mpsc::UnboundedSender<StreamPush>) -> Result<(), ()> {
        let push = match self {
            PushKind::RenewRequested(reason) => StreamPush::RenewRequested(reason),
            PushKind::Reconnect(reason) => StreamPush::Reconnect(reason),
            PushKind::CloseOk => StreamPush::CloseOk,
            PushKind::CloseRevoked => StreamPush::CloseRevoked,
            PushKind::CloseUnknown => StreamPush::CloseUnknown,
            PushKind::CloseExpired => StreamPush::CloseExpired,
        };
        tx.send(push).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use rstest::rstest;

    use super::*;

    // Certificates live 100 s, so CONTRACT.md §6 grants each one 100 s of renewal grace after `notAfter`.
    const CURRENT: (CertStatus, i64, i64) = (CertStatus::Current, 900, 1000);
    const PENDING: (CertStatus, i64, i64) = (CertStatus::Pending, 1000, 1100);

    #[rstest]
    #[case::current_unexpired(&[CURRENT], 999, IdentityStatus::Active)]
    #[case::current_at_not_after(&[CURRENT], 1000, IdentityStatus::Grace)]
    #[case::current_last_grace_second(&[CURRENT], 1099, IdentityStatus::Grace)]
    #[case::current_beyond_grace(&[CURRENT], 1100, IdentityStatus::Expired)]
    #[case::pending_unexpired_current_in_grace(&[CURRENT, PENDING], 1050, IdentityStatus::Active)]
    #[case::pending_unexpired_current_beyond_grace(&[CURRENT, (CertStatus::Pending, 1050, 1150)], 1100, IdentityStatus::Active)]
    #[case::pending_in_grace_current_beyond_grace(&[CURRENT, PENDING], 1100, IdentityStatus::Grace)]
    #[case::pending_beyond_grace(&[CURRENT, PENDING], 1200, IdentityStatus::Expired)]
    #[case::retired_unexpired(&[(CertStatus::Retired, 1000, 2000), CURRENT], 1100, IdentityStatus::Expired)]
    fn identity_status_follows_certificate_validity_and_grace(
        #[case] certs: &[(CertStatus, i64, i64)],
        #[case] now: i64,
        #[case] expected: IdentityStatus,
    ) {
        assert_eq!(identity_status(false, certs.iter().copied(), now), expected);
    }

    #[rstest]
    #[case::unexpired(999)]
    #[case::in_grace(1050)]
    #[case::beyond_grace(1100)]
    fn revocation_wins_over_certificate_validity(#[case] now: i64) {
        assert_eq!(identity_status(true, [CURRENT], now), IdentityStatus::Revoked);
    }

    #[test]
    fn rotation_destroys_the_old_signing_key() -> anyhow::Result<()> {
        let now = 1_790_000_000;
        let mut state = State::new(now)?;
        let old_root = state.issuing_root().thumbprint.clone();
        state
            .start_rotation(None, now)
            .expect("rotation without identities succeeds");
        assert!(state.rotation.is_none());
        assert!(
            state
                .roots
                .iter()
                .find(|root| root.thumbprint == old_root)
                .expect("old root remains for pinned certificates")
                .key
                .is_none()
        );
        assert!(!state.roots[0].published);
        assert!(state.issuing_root().key.is_some());
        Ok(())
    }

    #[test]
    fn rotation_completes_during_last_identity_revocation() -> anyhow::Result<()> {
        let now = 1_790_000_000;
        let mut state = State::new(now)?;
        let (_, secret) = state.create_token("test".to_owned(), 1, now + 3600, None, None, now);
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let csr = base64::engine::general_purpose::STANDARD
            .decode(vectors["csr"]["valid"]["csr"].as_str().expect("valid CSR vector"))?;
        let identity_id = state
            .enroll(&secret, &csr, Map::new(), now, "https://localhost/mock")
            .expect("enrollment succeeds")
            .identity_id;
        state
            .start_rotation(Some(now + 3600), now)
            .expect("rotation starts with one active old-root identity");
        assert!(state.rotation.is_some());
        state.revoke(identity_id, now).expect("revocation succeeds");
        assert!(state.rotation.is_none());
        assert_eq!(state.roots.iter().filter(|root| root.published).count(), 1);
        assert!(state.issuing_root().published);
        Ok(())
    }

    #[test]
    fn config_burst_preserves_stream_and_control_pushes() -> anyhow::Result<()> {
        let now = 1_790_000_000;
        let mut state = State::new(now)?;
        let (_, secret) = state.create_token("test".to_owned(), 1, now + 3600, None, None, now);
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let csr = base64::engine::general_purpose::STANDARD
            .decode(vectors["csr"]["valid"]["csr"].as_str().expect("valid CSR vector"))?;
        let identity_id = state
            .enroll(&secret, &csr, Map::new(), now, "https://localhost/mock")
            .expect("enrollment succeeds")
            .identity_id;
        let thumbprint = state.identities[&identity_id]
            .current_cert()
            .expect("current certificate")
            .thumbprint
            .clone();
        let stream_id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::unbounded_channel();
        state.streams.insert(
            stream_id,
            StreamHandle {
                identity_id,
                cert_thumbprint: thumbprint,
                tx,
                retire_at: None,
            },
        );
        for marker in 0..128 {
            let fields = json!({ "marker": marker }).as_object().cloned().expect("fields");
            assert_eq!(state.merge_config_fields(&fields), 1);
        }
        assert!(state.is_connected(identity_id));
        state.push_to_identity(identity_id, &PushKind::CloseRevoked);
        for marker in 0..128 {
            let StreamPush::ConfigUpdate(config_json) = rx.try_recv()? else {
                panic!("config update was dropped during a push burst");
            };
            let config: Value = serde_json::from_str(&config_json)?;
            assert_eq!(config["revision"], marker + 2);
            assert_eq!(config["marker"], marker);
        }
        assert!(matches!(rx.try_recv()?, StreamPush::CloseRevoked));
        assert!(state.is_connected(identity_id));
        assert_eq!(
            state
                .events
                .iter()
                .filter(|event| event.body["type"] == "config_update_sent")
                .count(),
            128
        );
        Ok(())
    }

    #[test]
    fn failed_issuance_does_not_consume_an_enrollment_use() -> anyhow::Result<()> {
        let now = 1_790_000_000;
        let mut state = State::new(now)?;
        let expired_root = state.issuing_root().not_after;
        let (token_id, secret) = state.create_token("test".to_owned(), 1, expired_root + 60, None, None, now);
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let csr = base64::engine::general_purpose::STANDARD
            .decode(vectors["csr"]["valid"]["csr"].as_str().expect("valid CSR vector"))?;
        assert!(
            state
                .enroll(&secret, &csr, Map::new(), expired_root, "https://localhost/mock")
                .is_err()
        );
        assert_eq!(state.tokens[&token_id].used_count, 0);
        assert!(state.identities.is_empty());
        Ok(())
    }

    #[test]
    fn issued_key_origin_and_time_survive_identity_deletion() -> anyhow::Result<()> {
        let now = 1_790_000_000;
        let mut state = State::new(now)?;
        let (owner_token_id, owner_secret) = state.create_token("owner".to_owned(), 1, now + 3600, None, None, now);
        let (other_token_id, other_secret) = state.create_token("other".to_owned(), 1, now + 3600, None, None, now);
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let csr = base64::engine::general_purpose::STANDARD
            .decode(vectors["csr"]["valid"]["csr"].as_str().expect("valid CSR vector"))?;
        let key_hash = issued_key_hash(&check_csr(&csr).expect("valid CSR"));
        let identity_id = state
            .enroll(&owner_secret, &csr, Map::new(), now, "https://localhost/mock")
            .expect("enrollment succeeds")
            .identity_id;
        let reject = |state: &mut State, secret: &[u8; 32]| {
            state
                .enroll(secret, &csr, Map::new(), now, "https://localhost/mock")
                .err()
                .expect("enrollment is rejected")
                .code
        };

        state.tokens.get_mut(&owner_token_id).expect("owner token").deleted_at = Some(now);
        assert_eq!(
            state
                .enroll(&owner_secret, &csr, Map::new(), now, "https://localhost/mock")
                .expect("deleted token replays its current key")
                .identity_id,
            identity_id
        );
        state.tokens.get_mut(&other_token_id).expect("other token").deleted_at = Some(now);
        assert_eq!(reject(&mut state, &other_secret), "token_invalid");
        state.tokens.get_mut(&other_token_id).expect("other token").deleted_at = None;
        assert_eq!(reject(&mut state, &other_secret), "invalid_request");

        state.revoke(identity_id, now).expect("revocation succeeds");
        assert_eq!(reject(&mut state, &owner_secret), "token_invalid");
        state.tokens.get_mut(&owner_token_id).expect("owner token").deleted_at = None;
        assert_eq!(reject(&mut state, &owner_secret), "identity_revoked");
        assert_eq!(reject(&mut state, &other_secret), "invalid_request");

        state.delete_identity(identity_id, now).expect("deletion succeeds");
        assert_eq!(reject(&mut state, &owner_secret), "identity_revoked");
        assert_eq!(reject(&mut state, &other_secret), "invalid_request");
        let issued = &state.issued_keys[&key_hash];
        assert_eq!(issued.identity_id, identity_id);
        assert_eq!(issued.token_id, owner_token_id);
        assert_eq!(issued.issued_at, now);
        Ok(())
    }

    #[test]
    fn enrollment_includes_token_config_at_initial_revision() -> anyhow::Result<()> {
        let now = 1_790_000_000;
        let mut state = State::new(now)?;
        let token_config = json!({ "psu_channel_url": "https://psu.example", "product_enabled": true });
        let (token_id, secret) =
            state.create_token("test".to_owned(), 1, now + 3600, None, Some(token_config.clone()), now);
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let csr = base64::engine::general_purpose::STANDARD
            .decode(vectors["csr"]["valid"]["csr"].as_str().expect("valid CSR vector"))?;
        let identity_id = state
            .enroll(&secret, &csr, Map::new(), now, "https://localhost/mock")
            .expect("enrollment succeeds")
            .identity_id;
        let config = &state.identities[&identity_id].config;
        assert_eq!(config["version"], 1);
        assert_eq!(config["revision"], 1);
        assert_eq!(config["agent_channel_url"], "https://localhost/mock");
        assert_eq!(config["psu_channel_url"], "https://psu.example");
        assert_eq!(config["product_enabled"], true);
        assert_eq!(state.tokens[&token_id].config, Some(token_config));

        let fields = json!({ "psu_channel_url": "https://psu.example" })
            .as_object()
            .cloned()
            .expect("config fields");
        assert_eq!(state.merge_config_fields(&fields), 0);
        assert_eq!(state.identities[&identity_id].config_revision(), 1);
        state.update_channel_available(false, "https://localhost/mock");
        assert_eq!(state.identities[&identity_id].config_revision(), 2);
        assert!(state.identities[&identity_id].config.get("agent_channel_url").is_none());
        Ok(())
    }

    /// An override that skipped the revision bump would leave the agent's stored config at the same revision,
    /// so neither a live push nor the reconciliation after Welcome would deliver the unsupported version.
    #[test]
    fn config_version_override_reaches_live_and_reconnecting_streams() -> anyhow::Result<()> {
        let now = 1_790_000_000;
        let mut state = State::new(now)?;
        let (_, secret) = state.create_token("test".to_owned(), 1, now + 3600, None, None, now);
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let csr = base64::engine::general_purpose::STANDARD
            .decode(vectors["csr"]["valid"]["csr"].as_str().expect("valid CSR vector"))?;
        let identity_id = state
            .enroll(&secret, &csr, Map::new(), now, "https://localhost/mock")
            .expect("enrollment succeeds")
            .identity_id;
        let thumbprint = state.identities[&identity_id]
            .current_cert()
            .expect("current certificate")
            .thumbprint
            .clone();
        let (tx, mut rx) = mpsc::unbounded_channel();
        state.streams.insert(
            Uuid::new_v4(),
            StreamHandle {
                identity_id,
                cert_thumbprint: thumbprint,
                tx,
                retire_at: None,
            },
        );
        let mut stored_revision = state.identities[&identity_id].config_revision();

        for (control, expected_version) in [(Some(2), 2), (Some(0), 0), (None, 1)] {
            state.update_config_version(control);

            let StreamPush::ConfigUpdate(pushed) = rx.try_recv()? else {
                panic!("expected a config update for {control:?}");
            };
            let pushed: Value = serde_json::from_str(&pushed)?;
            assert_eq!(pushed["version"], expected_version, "pushed for {control:?}");
            let pushed_revision = pushed["revision"].as_u64().expect("revision is an unsigned integer");
            assert!(
                stored_revision < pushed_revision,
                "pushed revision increases for {control:?}"
            );

            // A Hello still carrying the agent's stored revision is answered with the new config after Welcome.
            let (reconciled, reconciled_revision) = state.identities[&identity_id]
                .config_update_after(stored_revision)
                .expect("a stale Hello receives a config update");
            let reconciled: Value = serde_json::from_str(&reconciled)?;
            assert_eq!(reconciled["version"], expected_version, "reconciled for {control:?}");
            assert!(
                stored_revision < reconciled_revision,
                "reconciled revision increases for {control:?}"
            );

            stored_revision = pushed_revision;
        }
        Ok(())
    }
}
