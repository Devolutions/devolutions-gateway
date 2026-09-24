//! In-memory state and business logic (CONTRACT.md §2–§9, §11). One mutex around
//! `State` makes enrollment and rotation critical sections trivially correct.

use std::collections::{HashMap, VecDeque};

use p256::ecdsa::VerifyingKey;
use rand::RngExt as _;
use serde_json::{Map, Value};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::ca::{self, DEFAULT_LEAF_LIFETIME_SECS, RootCa};
use crate::httpsig::{CertStatus, NonceStore, RegisteredCert};
use crate::name_eval;

/// Error with an HTTP status and a machine-readable code, mapped to the right body
/// shape by the handlers.
#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(400, "invalid_request", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, "not_found", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, "conflict", message)
    }

    pub fn token_invalid() -> Self {
        Self::new(401, "token_invalid", "unknown or deleted token")
    }

    pub fn token_exhausted() -> Self {
        Self::new(403, "token_exhausted", "token has no remaining uses")
    }

    pub fn token_expired() -> Self {
        Self::new(401, "token_expired", "token is expired")
    }

    pub fn device_revoked() -> Self {
        Self::new(403, "device_revoked", "device is revoked")
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "internal_error", message)
    }
}

/// §11 `faults.drop_next_response` target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropTarget {
    Enroll,
    Renew,
}

/// §11 fault knobs. Merged field-by-field by `POST __mock__/faults`.
#[derive(Debug, Clone)]
pub struct Faults {
    pub drop_next_response: Option<DropTarget>,
    pub clock_skew_secs: Option<i64>,
    pub leaf_lifetime_secs: Option<i64>,
    pub channel_available: bool,
    pub rotation_rate_limit_per_sec: Option<u32>,
}

impl Default for Faults {
    fn default() -> Self {
        Self {
            drop_next_response: None,
            clock_skew_secs: None,
            leaf_lifetime_secs: None,
            channel_available: true,
            rotation_rate_limit_per_sec: None,
        }
    }
}

/// Why a renewal was requested (§7.3 `RenewRequested.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewReason {
    Admin,
    Rotation,
}

impl RenewReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RenewReason::Admin => "admin",
            RenewReason::Rotation => "rotation",
        }
    }
}

/// Enrollment token record (§9.1). Only the SHA-256 of the secret is stored (§2).
pub struct Token {
    pub id: Uuid,
    pub name: String,
    pub max_uses: u64,
    pub used_count: u64,
    /// Unix seconds.
    pub expires_at: i64,
    pub friendly_name_format: Option<String>,
    pub config: Option<Value>,
    /// Unix seconds.
    pub created_at: i64,
    pub created_by: String,
}

impl Token {
    /// §9.1 `state` field. `expired` wins over `exhausted` when both hold.
    pub fn state(&self, now: i64) -> &'static str {
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
pub struct Cert {
    pub thumbprint: String,
    pub der: Vec<u8>,
    pub public_key: VerifyingKey,
    pub serial: String,
    /// Unix seconds.
    pub not_before: i64,
    /// Unix seconds.
    pub not_after: i64,
    /// Thumbprint of the issuing root.
    pub issuer: String,
    pub status: CertStatus,
    /// Monotonic issuance order, including certificates issued in the same second.
    pub issued_seq: u64,
}

/// A registered device (§9.2).
pub struct Device {
    pub id: Uuid,
    pub friendly_name: String,
    pub metadata: Map<String, Value>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub last_seen_at: Option<i64>,
    /// Unix seconds.
    pub revoked_at: Option<i64>,
    pub renewal_requested: Option<RenewalFlag>,
    pub token_id: Uuid,
    pub token_name: String,
    pub certs: Vec<Cert>,
}

pub struct RenewalFlag {
    pub reason: RenewReason,
    /// First issuance order eligible to clear this flag.
    pub min_issued_seq: u64,
}

impl Device {
    pub fn current_cert(&self) -> Option<&Cert> {
        self.certs.iter().find(|c| c.status == CertStatus::Current)
    }

    pub fn revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// §9.2 `status` filter value.
    pub fn status(&self, now: i64) -> &'static str {
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
pub enum StreamPush {
    RenewRequested(&'static str),
    Reconnect(&'static str),
    /// Pending cert authenticated elsewhere: close with OK (§7.4).
    CloseOk,
    /// Device revoked: close PERMISSION_DENIED + `device_revoked`.
    CloseRevoked,
    /// Device or certificate vanished (delete, reset): close with `device_unknown`.
    CloseUnknown,
}

pub struct StreamHandle {
    pub device_id: Uuid,
    pub cert_thumbprint: String,
    pub tx: mpsc::Sender<StreamPush>,
}

/// An in-progress CA rotation (§9.3).
pub struct Rotation {
    /// Thumbprints of the old and new roots.
    pub old_root: String,
    pub new_root: String,
    /// Unix seconds.
    pub deadline: i64,
    /// Connected devices still waiting for their rate-limited rotation push.
    pub push_queue: VecDeque<Uuid>,
}

#[derive(Default)]
pub struct RequestCounts {
    pub enroll_by_token: HashMap<Uuid, u64>,
    pub enroll_total: u64,
    pub renew: u64,
    pub connect: u64,
    pub authenticated_connects: u64,
    pub correlated_acks: u64,
    pub overlap_open: u64,
}

pub struct State {
    pub tokens: HashMap<Uuid, Token>,
    /// SHA-256(secret) → token ID (§2).
    pub token_hashes: HashMap<[u8; 32], Uuid>,
    pub devices: HashMap<Uuid, Device>,
    /// Certificate thumbprint → device.
    pub cert_index: HashMap<String, Uuid>,
    /// All known roots; the issuing root is the last one, `published` gates
    /// `trust-anchor` listing.
    pub roots: Vec<RootCa>,
    pub rotation: Option<Rotation>,
    pub nonces: NonceStore,
    pub faults: Faults,
    pub requests: RequestCounts,
    /// Authenticated live channel streams, by stream ID.
    pub streams: HashMap<Uuid, StreamHandle>,
    pub root_seq: u32,
    pub serial_seq: u64,
}

impl State {
    pub fn new(now: i64) -> anyhow::Result<Self> {
        let root = RootCa::generate(1, now)?;
        Ok(Self {
            tokens: HashMap::new(),
            token_hashes: HashMap::new(),
            devices: HashMap::new(),
            cert_index: HashMap::new(),
            roots: vec![root],
            rotation: None,
            nonces: NonceStore::default(),
            faults: Faults::default(),
            requests: RequestCounts::default(),
            streams: HashMap::new(),
            root_seq: 1,
            serial_seq: 100,
        })
    }

    /// The root new leaves are issued from (the newest one, §9.3).
    pub fn issuing_root(&self) -> &RootCa {
        self.roots.last().expect("at least one root")
    }

    pub fn observe_enroll(&mut self, secret: &[u8; 32]) {
        use sha2::Digest as _;
        let hash: [u8; 32] = sha2::Sha256::digest(secret).into();
        if let Some(id) = self.token_hashes.get(&hash) {
            *self.requests.enroll_by_token.entry(*id).or_default() += 1;
        }
    }

    /// Resolves a certificate thumbprint for the §6 verifier.
    pub fn lookup_cert(&self, thumbprint: &str) -> Option<RegisteredCert> {
        lookup_cert(&self.devices, &self.cert_index, thumbprint)
    }

    /// Whether the device has at least one authenticated live stream (§7).
    pub fn is_connected(&self, device_id: Uuid) -> bool {
        self.streams.values().any(|s| s.device_id == device_id)
    }

    /// Pushes an event to every live stream of a device; broken channels are dropped.
    pub fn push_to_device(&mut self, device_id: Uuid, push: &PushKind) {
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
    pub fn push_to_cert_streams(&mut self, cert_thumbprint: &str, push: &PushKind) {
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
    pub fn note_cert_authenticated(&mut self, device_id: Uuid, cert_thumbprint: &str) {
        let Some(device) = self.devices.get_mut(&device_id) else {
            return;
        };
        let Some(idx) = device.certs.iter().position(|c| c.thumbprint == cert_thumbprint) else {
            return;
        };
        if device.certs[idx].status == CertStatus::Pending {
            device.certs[idx].status = CertStatus::Current;
            let retired: Vec<String> = device
                .certs
                .iter_mut()
                .filter(|c| c.status == CertStatus::Current && c.thumbprint != cert_thumbprint)
                .map(|c| {
                    c.status = CertStatus::Retired;
                    c.thumbprint.clone()
                })
                .collect();
            for thumbprint in retired {
                self.push_to_cert_streams(&thumbprint, &PushKind::CloseOk);
            }
        }
        let device = self.devices.get_mut(&device_id).expect("device exists");
        if let Some(flag) = &device.renewal_requested
            && device.certs[idx].issued_seq >= flag.min_issued_seq
        {
            device.renewal_requested = None;
        }
    }

    /// §5.2 enroll. `secret` is the 32-byte token secret; only its SHA-256 is matched.
    pub fn enroll(
        &mut self,
        secret: &[u8; 32],
        csr_der: &[u8],
        metadata: Map<String, Value>,
        now: i64,
    ) -> Result<EnrollOutcome, ApiError> {
        use sha2::Digest as _;
        let hash: [u8; 32] = sha2::Sha256::digest(secret).into();
        let token_id = *self.token_hashes.get(&hash).ok_or_else(ApiError::token_invalid)?;

        let csr_key = crate::csr::check_csr(csr_der)
            .map_err(|_| ApiError::invalid_request("invalid CSR: P-256 key and valid self-signature required"))?;
        name_eval::validate_metadata(&metadata).map_err(ApiError::invalid_request)?;

        // Idempotence on the CSR public key (§2): an existing device with the same key
        // is returned without consuming a use; revoked devices reject.
        let csr_key_der = ca::public_key_der(&csr_key);
        let existing = self
            .devices
            .values()
            .find(|d| d.certs.iter().any(|c| ca::public_key_der(&c.public_key) == csr_key_der));
        if let Some(device) = existing {
            if device.revoked() {
                return Err(ApiError::device_revoked());
            }
            let device_id = device.id;
            let friendly_name = device.friendly_name.clone();
            let chain = self.chain_for_current(device_id)?;
            return Ok(EnrollOutcome {
                device_id,
                friendly_name,
                certificate_chain: chain,
            });
        }

        let token = self.tokens.get(&token_id).expect("hash index consistent");
        if now >= token.expires_at {
            return Err(ApiError::token_expired());
        }
        if token.used_count >= token.max_uses {
            return Err(ApiError::token_exhausted());
        }

        // Device-creating critical section: consume the use and create the device.
        let device_id = Uuid::new_v4();
        let (format, token_name) = {
            let token = self.tokens.get_mut(&token_id).expect("hash index consistent");
            token.used_count += 1;
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
        let token_record = self.tokens.get(&token_id).expect("token exists");
        let device = Device {
            id: device_id,
            friendly_name: friendly_name.clone(),
            metadata,
            created_at: now,
            last_seen_at: Some(now),
            revoked_at: None,
            renewal_requested: None,
            token_id,
            token_name: token_record.name.clone(),
            certs: vec![cert],
        };
        self.cert_index.insert(leaf.thumbprint, device_id);
        self.devices.insert(device_id, device);
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
    pub fn renew(
        &mut self,
        device_id: Uuid,
        authenticated_thumbprint: &str,
        csr_der: &[u8],
        metadata: Map<String, Value>,
        now: i64,
    ) -> Result<Vec<Vec<u8>>, ApiError> {
        self.note_cert_authenticated(device_id, authenticated_thumbprint);

        let csr_key = crate::csr::check_csr(csr_der)
            .map_err(|_| ApiError::invalid_request("invalid CSR: P-256 key and valid self-signature required"))?;
        name_eval::validate_metadata(&metadata).map_err(ApiError::invalid_request)?;

        let csr_key_der = ca::public_key_der(&csr_key);

        // Idempotence on the new public key: replay the matching pending certificate.
        // A renew to the current key is treated as a no-op replay of the current chain.
        {
            let device = self.devices.get(&device_id).expect("authenticated device exists");
            for cert in &device.certs {
                if ca::public_key_der(&cert.public_key) == csr_key_der {
                    let root = self
                        .roots
                        .iter()
                        .find(|r| r.thumbprint == cert.issuer)
                        .expect("issuing root is known");
                    let chain = vec![cert.der.clone(), root.cert_der.clone()];
                    let device = self.devices.get_mut(&device_id).expect("device exists");
                    device.metadata = metadata;
                    device.last_seen_at = Some(now);
                    return Ok(chain);
                }
            }
        }

        let issued_seq = self.serial_seq;
        let leaf = self.issue_leaf(device_id, &csr_key, now)?;
        let root_der = self.issuing_root().cert_der.clone();
        let issuer = self.issuing_root().thumbprint.clone();
        let device = self.devices.get_mut(&device_id).expect("device exists");

        // At most one pending certificate: a different new key retires the old pending.
        for cert in &mut device.certs {
            if cert.status == CertStatus::Pending {
                cert.status = CertStatus::Retired;
            }
        }
        self.cert_index.insert(leaf.thumbprint.clone(), device_id);
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
        Ok(vec![leaf.der, root_der])
    }

    /// §9.2 revoke: idempotent, closes live streams PERMISSION_DENIED + device_revoked.
    pub fn revoke(&mut self, device_id: Uuid, now: i64) -> Result<(), ApiError> {
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
    pub fn delete_device(&mut self, device_id: Uuid) -> Result<(), ApiError> {
        let device = self
            .devices
            .get(&device_id)
            .ok_or_else(|| ApiError::not_found("unknown device"))?;
        if !device.revoked() {
            return Err(ApiError::conflict("device must be revoked before deletion"));
        }
        self.push_to_device(device_id, &PushKind::CloseUnknown);
        self.devices.remove(&device_id);
        Ok(())
    }

    /// §9.2 request-renewal: sets the flag (reason `admin`) and pushes to live streams.
    pub fn request_renewal(&mut self, device_id: Uuid) -> Result<(), ApiError> {
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
    pub fn start_rotation(&mut self, deadline: Option<i64>, now: i64) -> Result<(), ApiError> {
        if self.rotation.is_some() {
            return Err(ApiError::conflict("a rotation is already in progress"));
        }
        let old_root = self.issuing_root().thumbprint.clone();
        let deadline = match deadline {
            Some(d) => d,
            None => self
                .devices
                .values()
                .filter(|d| !d.revoked())
                .filter_map(|d| d.current_cert())
                .filter(|c| c.issuer == old_root)
                .map(|c| c.not_after)
                .max()
                .unwrap_or(now),
        };
        self.root_seq += 1;
        let new_root = RootCa::generate(self.root_seq, now)
            .map_err(|e| ApiError::internal(format!("failed to generate root: {e:#}")))?;
        let new_root_thumbprint = new_root.thumbprint.clone();
        self.roots.push(new_root);

        // Flag every active device on the old root; connected ones get a rate-limited
        // RenewRequested push.
        let mut push_queue = VecDeque::new();
        let min_issued_seq = self.serial_seq;
        for device in self.devices.values_mut() {
            let on_old_root = !device.revoked() && device.current_cert().is_some_and(|c| c.issuer == old_root);
            if on_old_root {
                device.renewal_requested = Some(RenewalFlag {
                    reason: RenewReason::Rotation,
                    min_issued_seq,
                });
                if self.streams.values().any(|s| s.device_id == device.id) {
                    push_queue.push_back(device.id);
                }
            }
        }
        self.rotation = Some(Rotation {
            old_root,
            new_root: new_root_thumbprint,
            deadline,
            push_queue,
        });
        self.drain_rotation_pushes();
        Ok(())
    }

    /// Sends queued rotation pushes up to the per-call budget of the configured rate
    /// (each call represents one second of budget).
    fn drain_rotation_pushes(&mut self) {
        let budget = self
            .faults
            .rotation_rate_limit_per_sec
            .map_or(usize::MAX, |r| r as usize);
        let mut batch = Vec::new();
        if let Some(rotation) = &mut self.rotation {
            while batch.len() < budget {
                let Some(device_id) = rotation.push_queue.pop_front() else {
                    break;
                };
                batch.push(device_id);
            }
        }
        for device_id in batch {
            // Re-check: the device may have been deleted meanwhile.
            if self.devices.contains_key(&device_id) {
                self.push_to_device(device_id, &PushKind::RenewRequested("rotation"));
            }
        }
    }

    /// Non-revoked devices whose current certificate was issued by the old root (§9.3
    /// `activeDevicesOnOldRoot`).
    pub fn active_devices_on_old_root(&self) -> u64 {
        let Some(rotation) = &self.rotation else {
            return 0;
        };
        self.devices
            .values()
            .filter(|d| !d.revoked() && d.current_cert().is_some_and(|c| c.issuer == rotation.old_root))
            .count() as u64
    }

    /// Lazy rotation deadline handling: called on every request and by a 1 s ticker.
    /// When the mock clock reaches the deadline the old root leaves `trust-anchor`.
    pub fn tick(&mut self, now: i64) {
        if let Some(rotation) = &self.rotation
            && now >= rotation.deadline
        {
            let old = rotation.old_root.clone();
            if let Some(root) = self.roots.iter_mut().find(|r| r.thumbprint == old) {
                root.published = false;
            }
            self.rotation = None;
            return;
        }
        self.drain_rotation_pushes();
    }

    /// §11 reset: clears tokens, devices, nonces, faults, rotation and the clock
    /// offset; creates a fresh root. Live streams are closed with `device_unknown`.
    pub fn reset(&mut self, now: i64) -> anyhow::Result<()> {
        let stream_ids: Vec<Uuid> = self.streams.keys().copied().collect();
        for id in &stream_ids {
            if let Some(handle) = self.streams.get(id) {
                let _ = PushKind::CloseUnknown.send(&handle.tx);
            }
        }
        self.streams.clear();
        self.tokens.clear();
        self.token_hashes.clear();
        self.devices.clear();
        self.cert_index.clear();
        self.nonces = NonceStore::default();
        self.faults = Faults::default();
        self.requests = RequestCounts::default();
        self.rotation = None;
        self.root_seq += 1;
        self.roots = vec![RootCa::generate(self.root_seq, now)?];
        Ok(())
    }

    /// Creates a token record (validation done by the caller); returns the ID and the
    /// 32-byte secret (only its SHA-256 is stored, §2).
    pub fn create_token(
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
pub struct EnrollOutcome {
    pub device_id: Uuid,
    pub friendly_name: String,
    /// Leaf-first (§4).
    pub certificate_chain: Vec<Vec<u8>>,
}

/// Free-function form of [`State::lookup_cert`] so callers can split borrows (the
/// §6 verifier needs `&devices`/`&cert_index` and `&mut nonces` at once).
pub fn lookup_cert(
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
pub enum PushKind {
    RenewRequested(&'static str),
    Reconnect(&'static str),
    CloseOk,
    CloseRevoked,
    CloseUnknown,
}

impl PushKind {
    fn send(&self, tx: &mpsc::Sender<StreamPush>) -> Result<(), ()> {
        let push = match self {
            PushKind::RenewRequested(reason) => StreamPush::RenewRequested(reason),
            PushKind::Reconnect(reason) => StreamPush::Reconnect(reason),
            PushKind::CloseOk => StreamPush::CloseOk,
            PushKind::CloseRevoked => StreamPush::CloseRevoked,
            PushKind::CloseUnknown => StreamPush::CloseUnknown,
        };
        tx.try_send(push).map_err(|_| ())
    }
}
