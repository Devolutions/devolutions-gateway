//! In-memory state and business logic (CONTRACT.md §2–§9, §11). One mutex around
//! `State` makes enrollment and rotation critical sections trivially correct.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use p256::ecdsa::VerifyingKey;
use rand::RngExt as _;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::ca::{self, DEFAULT_LEAF_LIFETIME_SECS, RootCa};
use crate::name_eval;
use crate::oracle::{AuthenticatedDevice, CertStatus, NonceStore, RegisteredCert, check_csr};

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

    pub(crate) fn device_revoked() -> Self {
        Self::new(403, "device_revoked", "device is revoked")
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "internal_error", message)
    }
}

/// §11 `faults.drop_next_response` target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropTarget {
    Enroll,
    Renew,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FailNextResponse {
    pub(crate) endpoint: DropTarget,
    pub(crate) status: u16,
    pub(crate) error: Option<&'static str>,
}

/// §11 fault knobs. Merged field-by-field by `POST __mock__/faults`.
#[derive(Debug, Clone)]
pub(crate) struct Faults {
    pub(crate) drop_next_response: Option<DropTarget>,
    pub(crate) fail_next_response: Option<FailNextResponse>,
    pub(crate) clock_skew_secs: Option<i64>,
    pub(crate) leaf_lifetime_secs: Option<i64>,
    pub(crate) channel_available: bool,
    pub(crate) rotation_rate_limit_per_sec: Option<u32>,
}

impl Default for Faults {
    fn default() -> Self {
        Self {
            drop_next_response: None,
            fail_next_response: None,
            clock_skew_secs: None,
            leaf_lifetime_secs: None,
            channel_available: true,
            rotation_rate_limit_per_sec: None,
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

/// Enrollment token record (§9.1). Only the SHA-256 of the secret is stored (§2).
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
}

impl Token {
    /// §9.1 `state` field. `expired` wins over `exhausted` when both hold.
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

/// A device certificate with its lifecycle status (§8).
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

/// A registered device (§9.2).
pub(crate) struct Device {
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
    pub(crate) token_id: Uuid,
    pub(crate) token_name: String,
    pub(crate) certs: Vec<Cert>,
}

pub(crate) struct RenewalFlag {
    pub(crate) reason: RenewReason,
    /// First issuance order eligible to clear this flag.
    pub(crate) min_issued_seq: u64,
}

impl Device {
    pub(crate) fn current_cert(&self) -> Option<&Cert> {
        self.certs.iter().find(|c| c.status == CertStatus::Current)
    }

    pub(crate) fn revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// §9.2 `status` filter value.
    pub(crate) fn status(&self, now: i64) -> &'static str {
        if self.revoked() {
            "revoked"
        } else if self.current_cert().is_some_and(|c| now < c.not_after) {
            "active"
        } else {
            "expired"
        }
    }
}

/// Pushed into a live channel stream's task.
pub(crate) enum StreamPush {
    RenewRequested(&'static str),
    Reconnect(&'static str),
    /// Pending cert authenticated elsewhere: close with OK (§7.4).
    CloseOk,
    /// Device revoked: close PERMISSION_DENIED + `device_revoked`.
    CloseRevoked,
    /// Device or certificate vanished (delete, reset): close with `device_unknown`.
    CloseUnknown,
    /// The mock clock reached the certificate's `notAfter`.
    CloseExpired,
}

pub(crate) struct StreamHandle {
    pub(crate) device_id: Uuid,
    pub(crate) cert_thumbprint: String,
    pub(crate) tx: mpsc::Sender<StreamPush>,
}

/// An in-progress CA rotation (§9.3).
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
    pub(crate) renew_retry_503: u64,
    pub(crate) connect: u64,
    pub(crate) authenticated_connects: u64,
    pub(crate) correlated_acks: u64,
    pub(crate) overlap_open: u64,
}

pub(crate) struct Event {
    pub(crate) device_id: Uuid,
    pub(crate) body: Value,
}

pub struct State {
    pub(crate) tokens: HashMap<Uuid, Token>,
    /// SHA-256(secret) → token ID (§2).
    pub(crate) token_hashes: HashMap<[u8; 32], Uuid>,
    pub(crate) devices: HashMap<Uuid, Device>,
    /// Certificate thumbprint → device.
    pub(crate) cert_index: HashMap<String, Uuid>,
    /// Issued keys remain reserved after a revoked device is deleted.
    deleted_revoked_keys: HashSet<Vec<u8>>,
    /// All known roots; the issuing root is the last one, `published` gates
    /// `trust-anchor` listing.
    pub(crate) roots: Vec<RootCa>,
    pub(crate) rotation: Option<Rotation>,
    pub(crate) nonces: NonceStore,
    pub(crate) faults: Faults,
    pub(crate) requests: RequestCounts,
    /// Mock-only barrier: retry requests receive 503 after the first response is dropped.
    pub(crate) retry_barrier: Option<DropTarget>,
    pub(crate) dropped_response: Option<DropTarget>,
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
    pub(crate) next_device_seq: u64,
    pub(crate) last_created_at: i64,
}

impl State {
    pub fn new(now: i64) -> anyhow::Result<Self> {
        let root = RootCa::generate(1, now)?;
        Ok(Self {
            tokens: HashMap::new(),
            token_hashes: HashMap::new(),
            devices: HashMap::new(),
            cert_index: HashMap::new(),
            deleted_revoked_keys: HashSet::new(),
            roots: vec![root],
            rotation: None,
            nonces: NonceStore::default(),
            faults: Faults::default(),
            requests: RequestCounts::default(),
            retry_barrier: None,
            dropped_response: None,
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
            next_device_seq: 1,
            last_created_at: now,
        })
    }

    pub(crate) fn record_event(&mut self, device_id: Uuid, event_type: &str, fields: Value) {
        let mut body = fields.as_object().cloned().expect("event fields are an object");
        body.insert("seq".to_owned(), json!(self.next_event_seq));
        body.insert("type".to_owned(), json!(event_type));
        body.insert("device_id".to_owned(), json!(device_id));
        self.events.push(Event {
            device_id,
            body: Value::Object(body),
        });
        self.next_event_seq += 1;
    }

    fn cert_status_changed(&mut self, device_id: Uuid, thumbprint: &str, from: Option<CertStatus>, to: CertStatus) {
        let mut fields = json!({
            "cert_thumbprint": thumbprint,
            "to": to.as_str(),
        });
        if let Some(from) = from {
            fields["from"] = json!(from.as_str());
        }
        self.record_event(device_id, "cert_status_changed", fields);
    }

    pub(crate) fn close_stream(
        &mut self,
        stream_id: Uuid,
        device_id: Uuid,
        cert_thumbprint: &str,
        status: &str,
        error_code: Option<&str>,
    ) {
        self.streams.remove(&stream_id);
        self.challenged_streams.remove(&stream_id);
        self.paused_hellos.remove(&stream_id);
        if !self.devices.contains_key(&device_id) || !self.closed_streams.insert(stream_id) {
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
        self.record_event(device_id, "stream_closed", fields);
    }

    /// The root new leaves are issued from (the newest one, §9.3).
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
        lookup_cert(&self.devices, &self.cert_index, thumbprint)
    }

    /// Whether the device has at least one authenticated live stream (§7).
    pub(crate) fn is_connected(&self, device_id: Uuid) -> bool {
        self.streams.values().any(|s| s.device_id == device_id)
    }

    /// Pushes an event to every live stream of a device; broken channels are dropped.
    pub(crate) fn push_to_device(&mut self, device_id: Uuid, push: &PushKind) {
        let dead: Vec<Uuid> = self
            .streams
            .iter()
            .filter(|(_, s)| s.device_id == device_id)
            .filter_map(|(id, s)| match push.send(&s.tx) {
                Err(_) => Some(*id),
                Ok(()) => None,
            })
            .collect();
        for id in dead {
            self.streams.remove(&id);
        }
    }

    /// Pushes an event to every live stream authenticated with a certificate.
    pub(crate) fn push_to_cert_streams(&mut self, cert_thumbprint: &str, push: &PushKind) {
        let dead: Vec<Uuid> = self
            .streams
            .iter()
            .filter(|(_, s)| s.cert_thumbprint == cert_thumbprint)
            .filter_map(|(id, s)| match push.send(&s.tx) {
                Err(_) => Some(*id),
                Ok(()) => None,
            })
            .collect();
        for id in dead {
            self.streams.remove(&id);
        }
    }

    /// §8: when a `pending` certificate first authenticates (renew or channel), the
    /// previous `current` is retired and its streams close with OK, the pending becomes
    /// `current`. Also clears the renewal-requested flag when the authenticating
    /// certificate was issued after the flag was set.
    pub(crate) fn note_cert_authenticated(&mut self, device_id: Uuid, cert_thumbprint: &str) {
        let Some(device) = self.devices.get_mut(&device_id) else {
            return;
        };
        let Some(idx) = device.certs.iter().position(|c| c.thumbprint == cert_thumbprint) else {
            return;
        };
        let promoted = device.certs[idx].status == CertStatus::Pending;
        let retired = if promoted {
            device.certs[idx].status = CertStatus::Current;
            device
                .certs
                .iter_mut()
                .filter(|c| c.status == CertStatus::Current && c.thumbprint != cert_thumbprint)
                .map(|c| {
                    c.status = CertStatus::Retired;
                    c.thumbprint.clone()
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if let Some(flag) = &device.renewal_requested
            && device.certs[idx].issued_seq >= flag.min_issued_seq
        {
            device.renewal_requested = None;
        }
        if promoted {
            self.cert_status_changed(
                device_id,
                cert_thumbprint,
                Some(CertStatus::Pending),
                CertStatus::Current,
            );
        }
        for thumbprint in retired {
            self.cert_status_changed(device_id, &thumbprint, Some(CertStatus::Current), CertStatus::Retired);
            self.push_to_cert_streams(&thumbprint, &PushKind::CloseOk);
        }
    }

    /// §5.2 enroll. `secret` is the 32-byte token secret; only its SHA-256 is matched.
    pub(crate) fn enroll(
        &mut self,
        secret: &[u8; 32],
        csr_der: &[u8],
        metadata: Map<String, Value>,
        now: i64,
    ) -> Result<EnrollOutcome, ApiError> {
        let token_id = self.token_id(secret).ok_or_else(ApiError::token_invalid)?;

        let csr_key = check_csr(csr_der)
            .ok_or_else(|| ApiError::invalid_request("invalid CSR: P-256 key and valid self-signature required"))?;
        name_eval::validate_metadata(&metadata).map_err(ApiError::invalid_request)?;

        // Idempotence on the CSR public key (§2): an existing device with the same key
        // is returned without consuming a use; revoked devices reject.
        let csr_key_der = ca::public_key_der(&csr_key);
        let existing = self.devices.values().find_map(|device| {
            device
                .certs
                .iter()
                .find(|cert| ca::public_key_der(&cert.public_key) == csr_key_der)
                .map(|cert| (device.id, device.revoked(), cert.status))
        });
        if let Some((device_id, revoked, status)) = existing {
            if revoked {
                return Err(ApiError::device_revoked());
            }
            if status != CertStatus::Current {
                return Err(ApiError::invalid_request(
                    "CSR key belongs to a pending or retired certificate",
                ));
            }
            let device = self.devices.get_mut(&device_id).expect("matching device exists");
            device.metadata = metadata;
            device.last_seen_at = Some(now);
            let device_id = device.id;
            let friendly_name = device.friendly_name.clone();
            let chain = self.chain_for_current(device_id)?;
            return Ok(EnrollOutcome {
                device_id,
                friendly_name,
                certificate_chain: chain,
            });
        }
        if self.deleted_revoked_keys.contains(&csr_key_der) {
            return Err(ApiError::device_revoked());
        }

        let token = self.tokens.get(&token_id).expect("hash index consistent");
        if now >= token.expires_at {
            return Err(ApiError::token_expired());
        }
        if token.used_count >= token.max_uses {
            return Err(ApiError::token_exhausted());
        }

        // Both issuance and token consumption happen under the device-creating state lock.
        let device_id = Uuid::new_v4();
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
        let friendly_name = name_eval::render_friendly_name(&format, &metadata, &token_name, device_id);
        let issued_seq = self.serial_seq;
        let leaf = self.issue_leaf(device_id, &csr_key, now)?;
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
        let created_seq = self.next_device_seq;
        self.next_device_seq += 1;
        let device = Device {
            id: device_id,
            friendly_name: friendly_name.clone(),
            metadata,
            created_seq,
            created_at,
            last_seen_at: Some(now),
            revoked_at: None,
            renewal_requested: None,
            token_id,
            token_name,
            certs: vec![cert],
        };
        self.cert_index.insert(leaf.thumbprint, device_id);
        self.devices.insert(device_id, device);
        self.cert_status_changed(device_id, &cert_thumbprint, None, CertStatus::Current);
        Ok(EnrollOutcome {
            device_id,
            friendly_name,
            certificate_chain: vec![leaf.der, root_der],
        })
    }

    fn chain_for_current(&self, device_id: Uuid) -> Result<Vec<Vec<u8>>, ApiError> {
        let device = self.devices.get(&device_id).expect("device exists");
        let current = device.current_cert().expect("enrolled device has a current cert");
        let root = self
            .roots
            .iter()
            .find(|r| r.thumbprint == current.issuer)
            .expect("issuing root is known");
        Ok(vec![current.der.clone(), root.cert_der.clone()])
    }

    fn issue_leaf(&mut self, device_id: Uuid, public_key: &VerifyingKey, now: i64) -> Result<ca::Leaf, ApiError> {
        let lifetime = self.faults.leaf_lifetime_secs.unwrap_or(DEFAULT_LEAF_LIFETIME_SECS);
        let serial = self.serial_seq;
        self.serial_seq += 1;
        let root = self.issuing_root();
        ca::issue_leaf(root, device_id, public_key, serial, now, lifetime)
            .map_err(|e| ApiError::internal(format!("failed to issue certificate: {e:#}")))
    }

    /// §5.3 renew, after the signature has been verified by the caller. Handles the
    /// pending promotion (§8), CSR and metadata checks, idempotence on the new public
    /// key and the one-pending rule.
    pub(crate) fn renew(
        &mut self,
        auth: &AuthenticatedDevice,
        csr_der: &[u8],
        metadata: Map<String, Value>,
        now: i64,
    ) -> Result<Vec<Vec<u8>>, ApiError> {
        let device_id = auth.device_id();
        self.note_cert_authenticated(device_id, auth.cert_thumbprint());

        let csr_key = check_csr(csr_der)
            .ok_or_else(|| ApiError::invalid_request("invalid CSR: P-256 key and valid self-signature required"))?;
        name_eval::validate_metadata(&metadata).map_err(ApiError::invalid_request)?;

        let csr_key_der = ca::public_key_der(&csr_key);

        // Only a still-pending certificate of this device is a lost-response replay.
        let existing = self.devices.values().find_map(|device| {
            device
                .certs
                .iter()
                .find(|cert| ca::public_key_der(&cert.public_key) == csr_key_der)
                .map(|cert| (device.id, cert.status, cert.der.clone(), cert.issuer.clone()))
        });
        if let Some((owner, status, cert_der, issuer)) = existing {
            if owner != device_id || status != CertStatus::Pending {
                return Err(ApiError::invalid_request("CSR key belongs to an issued certificate"));
            }
            let root = self
                .roots
                .iter()
                .find(|root| root.thumbprint == issuer)
                .expect("issuing root is known");
            let chain = vec![cert_der, root.cert_der.clone()];
            let device = self.devices.get_mut(&device_id).expect("device exists");
            device.metadata = metadata;
            device.last_seen_at = Some(now);
            return Ok(chain);
        }
        if self.deleted_revoked_keys.contains(&csr_key_der) {
            return Err(ApiError::invalid_request("CSR key belongs to an issued certificate"));
        }

        let issued_seq = self.serial_seq;
        let leaf = self.issue_leaf(device_id, &csr_key, now)?;
        let root_der = self.issuing_root().cert_der.clone();
        let issuer = self.issuing_root().thumbprint.clone();
        let retired = {
            let device = self.devices.get_mut(&device_id).expect("device exists");
            device
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
            self.cert_status_changed(device_id, &thumbprint, Some(CertStatus::Pending), CertStatus::Retired);
        }
        self.cert_index.insert(leaf.thumbprint.clone(), device_id);
        let device = self.devices.get_mut(&device_id).expect("device exists");
        device.certs.push(Cert {
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
        device.metadata = metadata;
        device.last_seen_at = Some(now);
        self.cert_status_changed(device_id, &leaf.thumbprint, None, CertStatus::Pending);
        Ok(vec![leaf.der, root_der])
    }

    /// §9.2 revoke: idempotent, closes live streams PERMISSION_DENIED + device_revoked.
    pub(crate) fn revoke(&mut self, device_id: Uuid, now: i64) -> Result<(), ApiError> {
        let device = self
            .devices
            .get_mut(&device_id)
            .ok_or_else(|| ApiError::not_found("unknown device"))?;
        if device.revoked_at.is_none() {
            device.revoked_at = Some(now);
        }
        self.push_to_device(device_id, &PushKind::CloseRevoked);
        Ok(())
    }

    /// §9.2 delete: only when revoked.
    pub(crate) fn delete_device(&mut self, device_id: Uuid) -> Result<(), ApiError> {
        let device = self
            .devices
            .get(&device_id)
            .ok_or_else(|| ApiError::not_found("unknown device"))?;
        if !device.revoked() {
            return Err(ApiError::conflict("device must be revoked before deletion"));
        }
        let issued_keys = device
            .certs
            .iter()
            .map(|cert| ca::public_key_der(&cert.public_key))
            .collect::<Vec<_>>();
        self.push_to_device(device_id, &PushKind::CloseUnknown);
        let live = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.device_id == device_id)
            .map(|(id, stream)| (*id, stream.cert_thumbprint.clone()))
            .collect::<Vec<_>>();
        for (stream_id, thumbprint) in live {
            self.close_stream(
                stream_id,
                device_id,
                &thumbprint,
                "UNAUTHENTICATED",
                Some("device_unknown"),
            );
        }
        self.devices.remove(&device_id);
        self.deleted_revoked_keys.extend(issued_keys);
        Ok(())
    }

    /// §9.2 request-renewal: sets the flag (reason `admin`) and pushes to live streams.
    pub(crate) fn request_renewal(&mut self, device_id: Uuid) -> Result<(), ApiError> {
        let min_issued_seq = self.serial_seq;
        let device = self
            .devices
            .get_mut(&device_id)
            .ok_or_else(|| ApiError::not_found("unknown device"))?;
        device.renewal_requested = Some(RenewalFlag {
            reason: RenewReason::Admin,
            min_issued_seq,
        });
        self.push_to_device(device_id, &PushKind::RenewRequested("admin"));
        Ok(())
    }

    /// §9.3 rotation start. `deadline` is RFC 3339 or the literal `"now"`; absent means
    /// the latest `notAfter` among active devices on the old root (`now` when there are
    /// none).
    pub(crate) fn start_rotation(&mut self, deadline: Option<i64>, now: i64) -> Result<(), ApiError> {
        if self.rotation.is_some() {
            return Err(ApiError::conflict("a rotation is already in progress"));
        }
        let old_root = self.issuing_root().thumbprint.clone();
        let maximum = self
            .devices
            .values()
            .filter(|device| !device.revoked())
            .filter_map(Device::current_cert)
            .filter(|cert| cert.issuer == old_root && now < cert.not_after)
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

        // The flag covers offline devices; a live, unexpired old-root connection also
        // enters the rate-limited push queue, which survives the rotation deadline.
        let min_issued_seq = self.serial_seq;
        for device in self.devices.values_mut() {
            let on_old_root = !device.revoked() && device.current_cert().is_some_and(|c| c.issuer == old_root);
            if on_old_root {
                let can_push = device.current_cert().is_some_and(|cert| now < cert.not_after)
                    && self.streams.values().any(|stream| stream.device_id == device.id);
                device.renewal_requested = Some(RenewalFlag {
                    reason: RenewReason::Rotation,
                    min_issued_seq,
                });
                if can_push {
                    self.rotation_push_queue.push_back((device.id, old_root.clone()));
                }
            }
        }
        self.rotation = Some(Rotation {
            old_root,
            new_root: new_root_thumbprint,
            deadline,
        });
        self.drain_rotation_pushes(now);
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
            let Some((device_id, old_root)) = self.rotation_push_queue.pop_front() else {
                break;
            };
            let eligible = self.devices.get(&device_id).is_some_and(|device| {
                !device.revoked()
                    && device.current_cert().is_some_and(|cert| {
                        cert.issuer == old_root && cert.not_before <= mock_now && mock_now < cert.not_after
                    })
            });
            if eligible && self.is_connected(device_id) {
                self.push_to_device(device_id, &PushKind::RenewRequested("rotation"));
                self.rotation_push_times.push_back(now);
            }
        }
    }

    /// Non-revoked devices whose current certificate was issued by the old root (§9.3
    /// `activeDevicesOnOldRoot`).
    pub(crate) fn active_devices_on_old_root(&self, now: i64) -> u64 {
        let Some(rotation) = &self.rotation else {
            return 0;
        };
        self.devices
            .values()
            .filter(|d| {
                !d.revoked()
                    && d.current_cert()
                        .is_some_and(|c| c.issuer == rotation.old_root && now < c.not_after)
            })
            .count() as u64
    }

    /// Lazy rotation deadline handling: called on every request and by a 1 s ticker.
    /// When the mock clock reaches the deadline the old root leaves `trust-anchor`.
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
                    stream.device_id,
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
                    None => Some(("UNAUTHENTICATED", "device_unknown", PushKind::CloseUnknown)),
                    Some(cert) if cert.revoked => Some(("PERMISSION_DENIED", "device_revoked", PushKind::CloseRevoked)),
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
                self.close_stream(stream_id, stream.device_id, &stream.cert_thumbprint, status, Some(code));
            }
        }
        if let Some(rotation) = &self.rotation
            && now >= rotation.deadline
        {
            let old = rotation.old_root.clone();
            if let Some(root) = self.roots.iter_mut().find(|r| r.thumbprint == old) {
                root.published = false;
            }
            self.rotation = None;
        }
        self.drain_rotation_pushes(now);
    }

    /// §11 reset: clears tokens, devices, nonces, faults, rotation and the clock
    /// offset; creates a fresh root. Live streams are closed with `device_unknown`.
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
        self.devices.clear();
        self.cert_index.clear();
        self.deleted_revoked_keys.clear();
        self.nonces = NonceStore::default();
        self.faults = Faults::default();
        self.requests = RequestCounts::default();
        self.retry_barrier = None;
        self.dropped_response = None;
        self.rotation = None;
        self.rotation_push_queue.clear();
        self.rotation_push_times.clear();
        self.events.clear();
        self.next_event_seq = 1;
        self.next_device_seq = 1;
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
    pub(crate) device_id: Uuid,
    pub(crate) friendly_name: String,
    /// Leaf-first (§4).
    pub(crate) certificate_chain: Vec<Vec<u8>>,
}

/// Free-function form of [`State::lookup_cert`] so callers can split borrows (the
/// §6 verifier needs `&devices`/`&cert_index` and `&mut nonces` at once).
pub(crate) fn lookup_cert(
    devices: &HashMap<Uuid, Device>,
    cert_index: &HashMap<String, Uuid>,
    thumbprint: &str,
) -> Option<RegisteredCert> {
    let device_id = *cert_index.get(thumbprint)?;
    let device = devices.get(&device_id)?;
    let cert = device.certs.iter().find(|c| c.thumbprint == thumbprint)?;
    Some(RegisteredCert {
        device_id,
        revoked: device.revoked(),
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
    fn send(&self, tx: &mpsc::Sender<StreamPush>) -> Result<(), ()> {
        let push = match self {
            PushKind::RenewRequested(reason) => StreamPush::RenewRequested(reason),
            PushKind::Reconnect(reason) => StreamPush::Reconnect(reason),
            PushKind::CloseOk => StreamPush::CloseOk,
            PushKind::CloseRevoked => StreamPush::CloseRevoked,
            PushKind::CloseUnknown => StreamPush::CloseUnknown,
            PushKind::CloseExpired => StreamPush::CloseExpired,
        };
        tx.try_send(push).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn rotation_destroys_the_old_signing_key() -> anyhow::Result<()> {
        let now = 1_790_000_000;
        let mut state = State::new(now)?;
        let old_root = state.issuing_root().thumbprint.clone();
        state
            .start_rotation(None, now)
            .expect("rotation without devices succeeds");
        assert!(
            state
                .roots
                .iter()
                .find(|root| root.thumbprint == old_root)
                .expect("old root remains for pinned certificates")
                .key
                .is_none()
        );
        assert!(state.issuing_root().key.is_some());
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
        assert!(state.enroll(&secret, &csr, Map::new(), expired_root).is_err());
        assert_eq!(state.tokens[&token_id].used_count, 0);
        assert!(state.devices.is_empty());
        Ok(())
    }
}
