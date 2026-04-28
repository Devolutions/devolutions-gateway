# DGW-378 — Explicit credential-injection identity design

**Bug**: [DGW-378](https://devolutions.atlassian.net/browse/DGW-378) · **Customer**: SFC-62 / 00114471 (ALPLA) · **Parent**: [PI-573](https://devolutions.atlassian.net/browse/PI-573) · **Coupled**: [DVLS-13821](https://devolutions.atlassian.net/browse/DVLS-13821)

This document supersedes both `docs/plans/DGW-378-implementation-plan.md` (on the experimental branch `dgw-378-session-redesign`) and the in-tree `docs/plans/DGW-378-kerberos-credssp-plan.md` snapshot. It is the design that the new branch `dgw-378-explicit-identity` will implement, and is the document Codex should review.

The experimental branch is preserved as historical context and runtime evidence; nothing in this design depends on it remaining alive.

---

## 1. Executive summary

Devolutions Gateway supports proxy-based credential injection for RDP. NTLM injection works on `master` today. Kerberos injection does not — production deployments hit a five-layer cascade beginning with `Read NTLM signature is invalid: [96, 116, 6, 6, 43, 6, 1, 5]` (an SPNEGO `NegTokenInit` reaching an NTLM-only acceptor).

The earlier remediation (`PI-573` / `dgw-378-session-redesign`) introduced a fake-KDC and a heuristic session router that disambiguates KDC traffic by inspecting AS-REQ principals and remembered TGT ciphertexts. That router is fundamentally a workaround for a missing piece: no field links `/jet/preflight provision-credentials` to the later `/jet/KdcProxy/<kdc_token>` HTTP requests it conceptually owns.

This design adds that field. A new identifier `cred_injection_id` (UUID) is minted at preflight time, propagated through DVLS-issued tokens as the JWT claim `jet_cred_id`, and used as the **only** routing key for KDC-side lookups. All AS-REQ principal inspection, principal-string normalisation, and TGT ciphertext fingerprinting from the experimental branch is dropped.

For backward compatibility, the field is optional on the consuming side (Gateway parses tokens that lack it). Old DVLS deployments continue to run NTLM credential injection unchanged. They do not get Kerberos injection — which matches pre-`PI-573` behaviour and therefore introduces no regression.

The fake-KDC machinery from `PI-573` (`crates/kdc`, `SessionKerberos`-like per-session keys, the CredSSP MITM pair, the HTTP scheme branch in `send_network_request`) is retained but simplified and graduates from `conf.debug.enable_unstable` to a first-class production feature. Loopback for U2U Kerberos (Windows mstsc) is handled via an in-process `inproc://cred/{cred_injection_id}` URL scheme rather than a self-issued kdc_token, eliminating the need for Gateway to hold any signing key.

---

## 2. Background

### 2.1 The customer issue

ALPLA (SFC-62 / 00114471) operates Devolutions Gateway in a Web Access flow: user → DVLS web → iron-remote-desktop (WASM) → Gateway → AD-joined RDP server. The target servers are domain-joined and accept Kerberos. The browser/WASM client, configured with the proxy credentials DVLS pre-shares at preflight time, sends SPNEGO/Kerberos in the CredSSP exchange. Gateway's CredSSP acceptor on `master` only understands NTLM, so the very first byte (`0x60` — ASN.1 SEQUENCE start of `NegTokenInit`) trips its NTLM signature parser, the connection dies with the `Read NTLM signature is invalid` error, and the user gets a generic failure.

The ALPLA bug surface is "layer 1" of a longer cascade documented in `DGW-378-FINDINGS.md`. Layers 2–5 only become visible once each prior layer is patched, and they exist on `master` regardless of whether anyone hits them in production:

| # | Layer | Master location | Failure when this layer is the next blocker |
|---|---|---|---|
| 1 | NTLM-lock fallback | `IronRDP/crates/ironrdp-acceptor/src/credssp.rs:110-114` ⨯ `rd_clean_path.rs:391-433` `else { None }` | `Read NTLM signature is invalid: [96, 116, 6, 6, 43, 6, 1, 5]` |
| 2 | Credential injection not engaged for Kerberos | `rd_clean_path.rs:556` credential-store fork | `UnknownCredentials: server not found in Kerberos database` |
| 3 | No `service_user` for U2U self-TGT | `sspi-rs/src/kerberos/server/mod.rs:148-152` | `WrongCredentialHandle: failed to request TGT ticket: no credentials provided` |
| 4 | Server-side `kdc_url` hardcoded `None` | `rd_clean_path.rs:419` | `NoAuthenticatingAuthority: No KDC server found` |
| 5 | `send_network_request` ignores HTTP scheme | `rdp_proxy.rs:637-643` | `InternalError: bad port value: <port>/KdcProxy/<long-token>` |

### 2.2 NTLM injection works because NTLM is two-party

For NTLM the entire authentication exchange is challenge-response between the client and the service:

```
NTLMSSP_NEGOTIATE  →
                  ←  NTLMSSP_CHALLENGE          (server picks a random nonce)
NTLMSSP_AUTHENTICATE  →                         (client sends HMAC(password_hash, nonce))
```

Gateway-as-CredSSP-server validates the `AUTHENTICATE` message by recomputing the same HMAC using the proxy password it stored at preflight time. Pure local arithmetic, no third party, no key material outside Gateway's process memory. Once Gateway accepts on the inbound leg, it performs an independent NTLM exchange on the outbound leg using the target credentials. The two exchanges are oblivious to each other.

This is what `master` already does in `rd_clean_path.rs::handle_with_credential_injection` and `rdp_proxy.rs::perform_credssp_with_client` / `perform_credssp_with_server`. None of it changes in this design.

### 2.3 Kerberos breaks the symmetry

Kerberos is a three-party protocol (client, service, KDC). The protocol fundamentally requires the validator of an `AP-REQ` to possess the long-term key (or, in U2U mode, the TGT session key) that the KDC used to encrypt the service ticket. Local recomputation from a stored password does not exist in Kerberos — the password is never the immediate decryption key for what is on the wire.

When iron-remote-desktop (or mstsc) sends an `AP-REQ` to Gateway as part of CredSSP, the ticket inside it has been issued by *some* KDC. If Gateway is to terminate that CredSSP (which it must, in order to substitute target credentials onto the outbound leg), Gateway needs the matching key. Real Active Directory KDCs do not export their database to a random gateway machine. The only way for Gateway to possess a usable decryption key is for Gateway itself to be the KDC that issued the ticket.

That is the whole reason `PI-573` introduced the fake-KDC: not because Kerberos is intrinsically harder than NTLM, but because the protocol shape forces a third actor and we have to embody it.

### 2.4 The earlier attempt and why we are redoing it

`PI-573` (Pavlo's work) shipped most of the right pieces:

- `crates/kdc` — a fake-KDC implementation built on `picky-krb`
- A CredSSP MITM pair (`perform_credssp_with_client`, `perform_credssp_with_server`)
- `SessionKerberos`-shaped per-session material (krbtgt key, ticket decryption key, service user)
- The `/jet/KdcProxy/<kdc_token>` HTTP route, gated behind `conf.debug.enable_unstable` and a static `conf.debug.kerberos` block

The piece that was missing was a **routing key**: when `/jet/KdcProxy` receives an HTTP POST, how does it know which credential-injection session this belongs to? The `kdc_token` is signed independently of the association token; it does not naturally carry a back-reference. The original solution used a single static `[debug.kerberos]` config block, which only works for a single-tenant test rig.

The experimental branch `dgw-378-session-redesign` tried to bridge that gap with a **classified, staged heuristic**:

1. Parse incoming KDC bytes to classify request as AS-REQ or TGS-REQ.
2. For AS-REQ: try `get_by_service_username(principal_username)`, then `get_sessions_by_proxy_username(f"{principal}@{realm}")`, then `get_sessions_by_proxy_local_name(principal_username)`. Reject ambiguous matches with `400`.
3. For TGS-REQ: look up by SHA-256 fingerprint of the TGT ciphertext that `remember_kdc_runtime_state` cached at the previous AS-REP.
4. Maintain four secondary indices (`proxy_username_index`, `proxy_local_name_index`, `service_username_index`, `tgt_ticket_index`) on `CredentialStore`.

It works. It also has uncomfortable properties:

- A growing surface of normalisation logic (`principal_local_name`, `normalize_proxy_username`, `domain\user` vs `user@realm`, case-insensitive lookups).
- A dependence on `service_user_name` being unique per session, requiring a synthetic `jet-{uuid}` value.
- A dependence on the AS-REP TGT ciphertext being stable between when the fake-KDC issues it and when the client returns it inside a TGS-REQ — true in practice but a coupling that exists nowhere on the protocol level.
- An implicit assumption that the proxy username `entry.mapping.proxy.username` is structured (a real-looking principal). In production we expect DVLS to ship UUID-like throwaway proxy usernames, in which case the "principal" matching arms become pointless.

The honest fix is to give the system the field it always wanted. Provision the identity at preflight, propagate it as a JWT claim, look up by it. No heuristics, no fallback, no normalisation of human-shaped strings.

---

## 3. Kerberos mechanics recap (the parts that matter for this design)

This section is a quick tour of the Kerberos messages and key relationships that Gateway-as-fake-KDC and Gateway-as-CredSSP-server must implement correctly. It is not a full RFC 4120 reference; it is a map of where each key lives at each moment, so the implementation reads as "a single state machine over a small key set" rather than "a magic library call".

### 3.1 Per-session keys

For each credential-injection session Gateway holds in `CredentialStore`:

| Symbol | Name | Source | Role |
|---|---|---|---|
| `Kg` | krbtgt key | random 32 bytes at preflight | encrypts every TGT the fake-KDC issues for this session |
| `Ks` | service long-term key | random 32 bytes at preflight | (standard mode only) encrypts service tickets for `TERMSRV/<gateway>`, also used by Gateway-as-Service to validate inbound AP-REQ |
| `Pp` | proxy password | from preflight payload | per-user key derivation: `kdf(Pp, salt(cname, realm))` validates AS-REQ PA_ENC_TIMESTAMP, decrypts AS-REP enc-part on the client side |
| `Ps` | service-user password | random 32 bytes at preflight | same as Pp but for Gateway's own AS-REQ when it self-fetches a TGT in U2U mode |

Transient session keys (`session_key_proxy`, `session_key_service`, `ticket_session_key`) are random scalars that fake-KDC generates at AS-REP / TGS-REP issuance time and embeds inside the encrypted ticket. They are never persisted by Gateway; on the next request they are recovered by re-decrypting the relevant ticket with the appropriate long-term key.

### 3.2 AS-REQ / AS-REP

```
AS-REQ {
  cname:   <UUID-string>,                              // proxy.username from the entry
  realm:   <whatever realm the client picks>,
  pa_data: PA_ENC_TIMESTAMP encrypted with kdf(Pp, salt(cname, realm))
}
```

fake-KDC handler:

1. Look up entry via the URL-encoded `cred_injection_id` (claim on `kdc_token`).
2. Build a `KerberosServer { realm: request.realm, krbtgt_key: Kg, users: [proxy_user, service_user], ticket_decryption_key: Some(Ks) }` configuration on the fly. **Realm is read from the request, not stored.**
3. Validate PA_ENC_TIMESTAMP using the password from the matching user entry.
4. Generate `session_key_proxy`, build TGT body `{ cname, session_key_proxy, validity }`, encrypt with `Kg`.
5. Build AS-REP enc-part `{ session_key_proxy, ... }`, encrypt with `kdf(Pp, salt)`.

Client decrypts the enc-part using its own `Pp`, retains `session_key_proxy`, treats the TGT itself as opaque.

### 3.3 TGS-REQ / TGS-REP, including U2U

```
TGS-REQ {
  padata: PA-TGS-REQ {
    AP-REQ {
      ticket:        <TGT, encrypted with Kg>,
      authenticator: encrypted with session_key_proxy
    }
  }
  body: {
    sname: "TERMSRV/<gateway hostname>",
    realm: <request realm>,
    options: { USE_SESSION_KEY: true|false, ... },
    additional_tickets: [TGT_service]   // present only when USE_SESSION_KEY=true
  }
}
```

fake-KDC handler:

1. Decrypt the TGT (AP-REQ.ticket) with `Kg` → recover `session_key_proxy` and `cname`.
2. Decrypt the authenticator with `session_key_proxy` → validate timestamp.
3. Decide which key encrypts the new service ticket:
   - `USE_SESSION_KEY=false` (standard mode): use `Ks`.
   - `USE_SESSION_KEY=true` (U2U): decrypt `additional_tickets[0]` (which is `TGT_service`) with `Kg` → extract `session_key_service` → use it.
4. Generate `ticket_session_key`, build service ticket body `{ cname, session_key=ticket_session_key, validity }`, encrypt with the chosen key.
5. Build TGS-REP enc-part `{ ticket_session_key, ... }`, encrypt with `session_key_proxy`.

### 3.4 AP-REQ at the CredSSP server (no KDC involvement)

```
AP-REQ {
  ticket:        <service ticket>,
  authenticator: encrypted with ticket_session_key
}
```

Gateway-as-CredSSP-server (running inside `perform_credssp_with_client`):

- Standard mode: decrypt service ticket with `Ks` → recover `ticket_session_key` and `cname` → decrypt authenticator → validate.
- U2U mode: decrypt service ticket with `session_key_service` (the value Gateway's own sspi-rs cached when it ran its self-AS-REQ in step 3.5).

This step does not touch `/jet/KdcProxy`. It happens entirely inside the inbound CredSSP TLS stream.

### 3.5 Why U2U requires Gateway to have its own TGT (the only reason loopback exists)

In U2U the service ticket is encrypted with the service's TGT session key. So Gateway-as-CredSSP-server cannot validate an inbound AP-REQ without already holding `session_key_service`, which only exists if it has its own TGT. To get that TGT it must run an AS-REQ as the `service_user` principal. sspi-rs running inside Gateway's CredSSP server context will issue this AS-REQ automatically — it sends it to the KDC URL configured in `KerberosServerConfig.kerberos_config.kdc_url`.

Whatever URL goes there is where Gateway calls itself to get its own TGT. The simplest implementation is an in-process dispatch (see §6.4); the older implementations did this over HTTP, which then required minting a per-session kdc_token and routing it through the auth middleware.

mstsc forces U2U on by default (the `USE_SESSION_KEY` flag is hard-coded by Microsoft's CredSSP client). iron-remote-desktop currently does the same. Even if we later force iron-remote-desktop into standard mode, mstsc support is a hard product requirement, so the U2U path must exist.

---

## 4. Architecture

### 4.1 The two-leg CredSSP MITM (unchanged from `master`)

```
[iron-remote-desktop / mstsc]   ←TLS₁+CredSSP→   [Gateway]   ←TLS₂+CredSSP→   [target RDP server]
                                                     │
                                                     ├─ fake-KDC (per-session Kg, Ks, Ps)
                                                     │
                                                     └─ in-process loopback path for U2U self-TGT
```

The two CredSSP exchanges are independent. There is no point at which Gateway "intercepts the client's AP-REQ and re-injects a Gateway-flavoured one"; instead, Gateway terminates the inbound exchange using fake-KDC keys and originates a fresh outbound exchange as a normal Kerberos client using the entry's target credentials. After both exchanges complete, the post-auth RDP byte stream is forwarded application-blind, decrypting on TLS₁ and re-encrypting onto TLS₂.

### 4.2 Per-session `SessionKerberos`

A new struct attached to `CredentialEntry`:

```rust
pub struct SessionKerberos {
    pub krbtgt_key: Vec<u8>,                // 32 random bytes — Kg
    pub service_long_term_key: Vec<u8>,     // 32 random bytes — Ks
    pub service_user_name: String,          // fixed "jet"; routing comes from cred_injection_id, not from this name
    pub service_user_password: String,      // 32 random bytes (hex) — Ps
}
```

`CredentialStoreHandle::insert` materialises one of these when given a credential mapping. The invariant `entry.kerberos.is_some() == entry.mapping.is_some()` is maintained centrally so callers cannot accidentally split the two.

Comparison with the experimental branch's `SessionKerberos`:

- `service_user_name` collapses from `jet-{uuid}` back to fixed `"jet"`. Routing is now done by `cred_injection_id` so the per-session uniqueness on the principal name is unnecessary.
- A new `service_long_term_key` field is added so standard-mode Kerberos has a distinct long-term key for `TERMSRV/<gateway>`. The experimental branch reused `ticket_decryption_key` for both standard and U2U paths, which works but conflates two roles.

### 4.3 Explicit identity: `cred_injection_id`

A fresh `Uuid` minted at preflight time. It serves as:

- The primary key of `CredentialStore.entries`.
- The `proxy.username` value DVLS hands to clients (so the Kerberos AS-REQ `cname` literally is the routing key, although the design does not depend on this — see §6).
- The value of the JWT claim `jet_cred_id` on association tokens and KDC tokens.
- The path component in the in-process loopback URL (§6.4).

Generation rule: DVLS-issued tokens **must** carry it (mandatory in the NuGet builder API). The Gateway-side preflight DTO accepts it as `Option<Uuid>` for backward compatibility — old DVLS deployments that omit it get a Gateway-generated UUID returned in the preflight response. They cannot then propagate it onto subsequent tokens, so they continue to work for NTLM injection (where the association-token JTI suffices) but do not get Kerberos injection.

### 4.4 In-process loopback for U2U

When `build_credential_injection_server_kerberos_config` constructs the `sspi::KerberosServerConfig` it sets:

```rust
kerberos_config: sspi::KerberosConfig {
    kdc_url: Some(format!("inproc://cred/{}", entry.cred_injection_id)),
    client_computer_name: Some(client_addr.to_string()),
}
```

`send_network_request` matches on the URL scheme. The new `inproc` arm parses `cred_injection_id` from the path, looks up the entry, builds the same `KerberosServer` configuration the HTTP route would build, calls `kdc::handle_kdc_proxy_message` directly, and returns the encoded reply bytes. No HTTP, no token, no auth middleware traversal — the call never leaves the Tokio runtime, let alone the process.

Why this beats the alternatives:

- **Pre-minted DVLS kdc_token stored on the entry.** Requires DVLS to produce two tokens at preflight time, complicates the contract, and introduces a network round-trip on every U2U flow.
- **Gateway self-signs a kdc_token.** Adds a new trust root and signing key to Gateway, which had previously been pure validator. Larger blast radius if leaked.
- **In-process dispatch (chosen).** Twenty extra lines in `send_network_request`, no new tokens, no network or auth surface area for a call that conceptually belongs inside the same process anyway.

External KDC traffic (browser / mstsc → `/jet/KdcProxy/{kdc_token}`) continues to traverse HTTP, the auth middleware, and the existing handler — that path is unaffected.

### 4.5 Realm transparency

`KerberosServer.realm` is filled from `kdc_proxy_message.target_domain` on every request. The fake-KDC never has a configured realm; whatever realm string the client puts in its AS-REQ becomes the realm of that exchange. The check that `kdc_token.krb_realm` matches the request realm remains in place.

DVLS, Hub, and the Gateway operator do not coordinate realm strings. The Kerberos protocol treats realm as load-bearing only at the KDC layer (cname lookups, salt construction); at the service layer (AP-REQ verification) realm is metadata. Because Gateway plays both roles inside one process, it can set `kdc_config.realm = request.realm` and the constraint becomes a tautology.

---

## 5. Wire contracts

### 5.1 Preflight `OP_PROVISION_CREDENTIALS`

The existing `ProvisionCredentialsParams` in `devolutions-gateway/src/api/preflight.rs` gains one optional field:

```rust
#[derive(Debug, Deserialize)]
struct ProvisionCredentialsParams {
    token: String,
    #[serde(flatten)]
    mapping: crate::credential::CleartextAppCredentialMapping,
    #[serde(default)]
    cred_injection_id: Option<Uuid>,           // NEW
    time_to_live: Option<u32>,
}
```

A new variant of `PreflightOutputKind` returns the resulting id (whether supplied by the caller or generated by Gateway):

```rust
#[serde(rename = "provisioned-credentials")]
ProvisionedCredentials {
    #[serde(rename = "cred_injection_id")]
    cred_injection_id: Uuid,
}
```

The handler at the `OP_PROVISION_CREDENTIALS` arm passes `params.cred_injection_id` into `CredentialStoreHandle::insert`, which generates a UUID when `None` and returns the final value. The preflight handler emits `PreflightOutputKind::ProvisionedCredentials { cred_injection_id }` instead of `Ack`.

(`OP_PROVISION_TOKEN` continues to emit `Ack` — only the credentials operation gains a structured response.)

### 5.2 JWT claims

Both `AssociationTokenClaims` and `KdcTokenClaims` in `devolutions-gateway/src/token.rs` gain:

```rust
/// Reference to a credential-injection record provisioned via /jet/preflight.
/// Required for Kerberos credential injection routing; absent on tokens that
/// do not participate in injection or come from pre-DGW-378 issuers.
#[serde(default)]
pub jet_cred_id: Option<Uuid>,
```

`KdcTokenClaims` continues to carry `krb_realm` and `krb_kdc`, which are still load-bearing for non-injection forwarding. The realm-match check against the incoming request realm stays.

### 5.3 NuGet `Devolutions.Gateway.Utils`

Three changes to the package source under `utils/dotnet/Devolutions.Gateway.Utils/src`:

**`AssociationClaims.cs`** — add a nullable property because not every association token participates in injection:

```csharp
[JsonPropertyName("jet_cred_id")]
[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
public Guid? JetCredId { get; set; }
```

**`KdcClaims.cs`** — same shape:

```csharp
[JsonPropertyName("jet_cred_id")]
[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
public Guid? JetCredId { get; set; }
```

The constructor remains positional with `jet_cred_id` set via property assignment (matches the existing `AssociationClaims` style for `TimeToLive`, `RecordingPolicy`, `ReusePolicy`).

**New file `ProvisionCredentialsRequest.cs`** — the request payload DTO that DVLS uses to POST to `/jet/preflight`. `CredInjectionId` is non-nullable here because every caller that wants Kerberos injection must supply one. (Old DVLS does not use this class; it constructs the JSON manually or uses pre-NuGet helpers.)

```csharp
public class ProvisionCredentialsRequest
{
    [JsonPropertyName("id")]
    public Guid Id { get; set; }                   // PreflightOperation.id

    [JsonPropertyName("kind")]
    public string Kind => "provision-credentials";

    [JsonPropertyName("token")]
    public string Token { get; set; }

    [JsonPropertyName("cred_injection_id")]
    public Guid CredInjectionId { get; set; }      // mandatory in the producer API

    [JsonPropertyName("proxy_credential")]
    public CleartextCredential ProxyCredential { get; set; }

    [JsonPropertyName("target_credential")]
    public CleartextCredential TargetCredential { get; set; }

    [JsonPropertyName("time_to_live")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? TimeToLive { get; set; }

    public ProvisionCredentialsRequest(
        Guid id,
        string token,
        Guid credInjectionId,
        CleartextCredential proxyCredential,
        CleartextCredential targetCredential,
        uint? timeToLive = null)
    {
        this.Id = id;
        this.Token = token;
        this.CredInjectionId = credInjectionId;
        this.ProxyCredential = proxyCredential;
        this.TargetCredential = targetCredential;
        this.TimeToLive = timeToLive;
    }
}

public class CleartextCredential
{
    [JsonPropertyName("kind")]
    public string Kind => "username-password";

    [JsonPropertyName("username")]
    public string Username { get; set; }

    [JsonPropertyName("password")]
    public string Password { get; set; }

    public CleartextCredential(string username, string password)
    {
        this.Username = username;
        this.Password = password;
    }
}
```

DVLS, Hub, and any other producer of credential-injection requests must adopt this class. NTLM-only producers can keep using string-built JSON if they wish — they will not get a `cred_injection_id` echoed back, which is fine because they do not need one.

---

## 6. Internal structures and lookup

### 6.1 `CredentialEntry`

```rust
#[derive(Debug)]
pub struct CredentialEntry {
    pub cred_injection_id: Uuid,                   // primary key; renamed from session_id
    pub association_token_jti: Uuid,
    pub token: String,
    pub mapping: Option<AppCredentialMapping>,
    pub expires_at: time::OffsetDateTime,
    pub kerberos: Option<Arc<SessionKerberos>>,
}
```

### 6.2 `CredentialStore`

The store keeps **two** indices and nothing else:

```rust
struct CredentialStore {
    entries: HashMap<Uuid /* cred_injection_id */, ArcCredentialEntry>,
    association_token_index: HashMap<Uuid /* token JTI */, Uuid /* cred_injection_id */>,
}
```

- `entries` is the authoritative table.
- `association_token_index` exists only so `/rdp` can recover entries from the association-token JTI when `jet_cred_id` is absent (old DVLS, NTLM injection).

Removed compared to the experimental branch:
- `proxy_username_index`
- `proxy_local_name_index`
- `service_username_index`
- `tgt_ticket_index`
- All AS-REQ principal-name normalisation helpers (`principal_local_name`, `normalize_proxy_username`)
- `remember_issued_tgt`, `ticket_fingerprint`, and the SHA-256 routing path

`CredentialStoreHandle::insert` accepts an optional `cred_injection_id`:

```rust
impl CredentialStoreHandle {
    pub fn insert(
        &self,
        token: String,
        mapping: Option<CleartextAppCredentialMapping>,
        cred_injection_id: Option<Uuid>,
        time_to_live: time::Duration,
    ) -> Result<(Uuid, Option<ArcCredentialEntry>), InsertError> {
        // Generates a UUID when cred_injection_id is None.
        // Returns the final id alongside any evicted previous entry.
    }

    pub fn get(&self, cred_injection_id: Uuid) -> Option<ArcCredentialEntry> { ... }

    pub fn get_by_token(&self, token: &str) -> Option<ArcCredentialEntry> { ... }
}
```

### 6.3 `/rdp` lookup

`devolutions-gateway/src/rd_clean_path.rs` and `devolutions-gateway/src/generic_client.rs`, at the point where they currently call `credential_store.get(token_id)`:

```rust
let entry = match claims.jet_cred_id {
    Some(id) => credential_store.get(id),
    None => credential_store.get_by_token(&token),
};
```

NTLM injection works on both arms. Kerberos injection only flows through the first arm.

### 6.4 `/jet/KdcProxy/<kdc_token>` lookup (external requests)

`devolutions-gateway/src/api/kdc_proxy.rs::kdc_proxy`, after the realm match check:

```rust
let entry = claims
    .jet_cred_id
    .and_then(|id| credential_store.get(id));

if let Some(entry) = entry {
    let kerberos_state = entry.kerberos.as_ref().context("session has no Kerberos state")?;
    let mapping = entry.mapping.as_ref().context("session has no credential mapping")?;
    let config = build_session_kdc_config(kerberos_state, mapping, &realm, &conf.hostname)?;
    let reply = kdc::handle_kdc_proxy_message(kdc_proxy_message, &config, &conf.hostname)?;
    return Ok(reply.to_vec()?);
}

// No matching session → fall through to the existing forward-to-real-KDC path.
```

There is no fallback discovery, no AS-REQ classification, no principal inspection. If `claims.jet_cred_id` is `None` or does not resolve, the request is simply forwarded as a non-injection KDC proxy operation. That matches pre-DGW-378 behaviour exactly.

### 6.5 In-process loopback (Gateway → fake-KDC)

`devolutions-gateway/src/rdp_proxy.rs::send_network_request`:

```rust
async fn send_network_request(
    request: &NetworkRequest,
    credential_store: &CredentialStoreHandle,
    gateway_hostname: &str,
) -> anyhow::Result<Vec<u8>> {
    match request.url.scheme() {
        "tcp" | "udp" => { /* existing TargetAddr path */ }
        "http" | "https" => { /* existing reqwest path */ }
        "inproc" => {
            // URL form: inproc://cred/{cred_injection_id}
            let cred_id: Uuid = request
                .url
                .path()
                .trim_start_matches('/')
                .parse()
                .context("malformed inproc URL")?;

            let entry = credential_store
                .get(cred_id)
                .context("credential entry no longer exists")?;
            let kerberos_state = entry.kerberos.as_ref().context("entry without Kerberos state")?;
            let mapping = entry.mapping.as_ref().context("entry without credential mapping")?;

            let kdc_message = KdcProxyMessage::from_raw_kerb_message(&request.data)
                .context("malformed inproc KDC payload")?;
            let request_realm = kdc_message
                .target_domain
                .0
                .as_ref()
                .context("inproc KDC payload missing realm")?
                .0
                .to_string();

            let config = build_session_kdc_config(
                kerberos_state,
                mapping,
                &request_realm,
                gateway_hostname,
            )?;
            let reply = kdc::handle_kdc_proxy_message(kdc_message, &config, gateway_hostname)?;
            Ok(reply.to_vec()?)
        }
        unsupported => anyhow::bail!("unsupported KDC request scheme: {unsupported}"),
    }
}
```

Implementation note: `send_network_request` must close over a `CredentialStoreHandle` (or receive it via `NetworkRequest` extension) for the `inproc` arm. The `tcp/udp/http/https` arms remain stateless. The signature change propagates into how `perform_credssp_with_client` dispatches network callbacks; concretely sspi-rs takes a closure, so the handle is captured into the closure at construction site.

---

## 7. Backward compatibility matrix

| Combination | Result | Notes |
|---|---|---|
| Old DVLS · iron-remote-desktop · NTLM | ✓ works | Goes through `get_by_token` JTI path, identical to `master` |
| Old DVLS · iron-remote-desktop · Kerberos | ✗ no injection (forward only) | Same as pre-DGW-378 master; no regression |
| Old DVLS · mstsc · NTLM | ✓ works | Same as NTLM/iron-remote-desktop |
| Old DVLS · mstsc · Kerberos | ✗ no injection | Same as pre-DGW-378 |
| New DVLS · iron-remote-desktop · NTLM | ✓ works | `jet_cred_id` path, but NTLM does not need fake-KDC |
| New DVLS · iron-remote-desktop · Kerberos (standard) | ✓ works | fake-KDC, no loopback |
| New DVLS · iron-remote-desktop · Kerberos (U2U) | ✓ works | fake-KDC + in-process loopback |
| New DVLS · mstsc · NTLM | ✓ works | |
| New DVLS · mstsc · Kerberos (forced U2U) | ✓ works | fake-KDC + in-process loopback |
| Plain forwarding (no preflight) | ✓ works | Untouched |

---

## 8. Removed configuration

The following fields under `[debug]` in Gateway's TOML configuration are removed in this design:

- `enable_unstable` — the umbrella flag that gated Kerberos credential injection. Removing it promotes the feature to first-class.
- `kerberos.kerberos_server` (the static `KerberosServer` block including `realm`, `users`, `ticket_decryption_key`, `service_user`).
- `kerberos.kdc_url` — replaced by per-session `inproc://cred/{cred_injection_id}` URLs constructed at runtime.

The associated DTOs (`KerberosConfig`, `KerberosServer`, `DomainUser`) under `crate::config::dto` are deleted alongside.

For migration we accept old config files containing these keys and silently ignore them. (Alternative: reject loudly. We will pick one of the two — leaning toward "accept and warn once" — once we see how operators react during internal testing.)

---

## 9. Implementation outline

In dependency order. Each numbered item corresponds to roughly one focused commit on the `dgw-378-explicit-identity` branch.

1. `token.rs` — add `jet_cred_id: Option<Uuid>` to `AssociationTokenClaims` and `KdcTokenClaims`.
2. `credential/mod.rs` — rename `session_id` → `cred_injection_id`, add `SessionKerberos`, add `kerberos: Option<Arc<SessionKerberos>>` to `CredentialEntry`, change `insert` signature, add `get_by_token`, drop unused indices/methods. Update internal call sites.
3. `api/preflight.rs` — extend `ProvisionCredentialsParams`, add `PreflightOutputKind::ProvisionedCredentials`, wire the response.
4. `crates/kdc` — promote out from behind `enable_unstable`. Confirm the existing standard + U2U handlers in this crate are correct with random `Kg`, `Ks`, `Ps`. (Pavlo's code; expected to be largely usable as is.)
5. `api/kdc_proxy.rs` — rewrite the handler around `claims.jet_cred_id` direct lookup. Remove all `KdcSessionLookup` / `AsReqSessionMatch` / classification machinery. Keep the realm-match check and the forward-to-real-KDC fallback.
6. `rdp_proxy.rs` — rewrite `build_credential_injection_server_kerberos_config` to build the `KerberosServerConfig` from `entry.kerberos` and use `inproc://cred/{id}` for `kdc_url`. Add the `inproc` arm to `send_network_request`. Adjust `perform_credssp_with_client`/`perform_credssp_with_server` plumbing so the network callback closes over the credential store.
7. `rd_clean_path.rs`, `generic_client.rs` — switch the credential-store lookup to `jet_cred_id`-first / `get_by_token`-fallback.
8. `config.rs` — drop `DebugConf::enable_unstable`, `DebugConf::kerberos`, and the supporting DTOs. Migrate the test suite that referenced them.
9. `openapi/gateway-api.yaml` — add the new preflight DTO field and response variant.
10. `utils/dotnet/Devolutions.Gateway.Utils` — add `JetCredId` to claim classes; add `ProvisionCredentialsRequest` and `CleartextCredential`.
11. Tests (see §10).
12. `CHANGELOG.md`, `docs/plans/2026-04-27-dgw-378-explicit-identity-design.md` (this document).

---

## 10. Test plan

### 10.1 Unit tests

- `credential/mod.rs`
  - `insert` returns a generated UUID when `cred_injection_id` is `None`; preserves the supplied UUID otherwise
  - `get_by_token` matches exact token, rejects tampered tokens
  - Eviction on association-token-JTI collision
  - Same proxy username can coexist across two entries (no spurious eviction)

- `api/kdc_proxy.rs`
  - With `jet_cred_id` pointing at a real entry: handler returns a fake-KDC reply
  - With `jet_cred_id` absent: handler forwards to the configured KDC (mock the forward target)
  - With `jet_cred_id` pointing at an expired/missing entry: handler forwards as if absent
  - Realm mismatch between `kdc_token.krb_realm` and request realm: 400 (existing behaviour, regression-locked)

- `rdp_proxy.rs`
  - `inproc` URL parsing: well-formed and malformed inputs
  - `inproc` arm dispatches to `kdc::handle_kdc_proxy_message` and returns its reply
  - `inproc` arm errors when entry is gone or missing Kerberos state

### 10.2 End-to-end tests (`testsuite/tests/cli/dgw/`)

Build on the experimental branch's `kdc_proxy.rs` test rig, but exercise the **explicit-id** path:

- `kdc_proxy_explicit_id.rs`
  - Provision credentials at preflight with a known `cred_injection_id`
  - Mint an association token and a kdc_token with that id baked into `jet_cred_id`
  - Hand-craft AS-REQ → expect AS-REP
  - Hand-craft TGS-REQ (standard mode) → expect TGS-REP
  - Hand-craft TGS-REQ (U2U mode, with the previously issued `TGT_service`) → expect TGS-REP encrypted with `session_key_service`

- `credential_injection_rdp.rs`
  - End-to-end RDP credential-injection flow against a fake target. Possibly out of reach for CI; mark as opt-in.

### 10.3 Manual verification

- iron-remote-desktop in standard mode → AD-joined target
- iron-remote-desktop in U2U mode (default) → AD-joined target
- mstsc native → AD-joined target via Gateway tunnel
- Confirm none of the layer 1–5 error strings (§2.1) appear in Gateway logs for any of the above

---

## 11. Open items

- Decide whether old config files containing `[debug.kerberos]` are accepted-with-warning or rejected outright.
- Decide whether to add a self-bootstrap mode where DVLS sends a `null` `cred_injection_id` and expects Gateway to mint and return one. (We have it as a backward-compat behaviour; the open question is whether to advertise it as a stable contract.)
- Confirm the iron-remote-desktop side of the wire is fine being told about `proxy_username = <UUID-string>`. There is nothing protocol-illegal about a UUID-shaped Kerberos principal name, but it is uncommon enough that a sanity test against AD-joined Windows clients is warranted.
- Confirm `crates/kdc` already exposes a standard-mode (`USE_SESSION_KEY=false`) code path that uses `ticket_decryption_key` correctly. We intend to keep it.

---

## 12. References

### In-tree (this branch)

- `docs/plans/2026-04-27-dgw-378-explicit-identity-design.md` — this document
- `devolutions-gateway/src/credential/mod.rs` — credential store
- `devolutions-gateway/src/api/preflight.rs` — preflight handler
- `devolutions-gateway/src/api/kdc_proxy.rs` — KDC proxy handler
- `devolutions-gateway/src/rd_clean_path.rs` — `/rdp` (RDCleanPath) entry
- `devolutions-gateway/src/rdp_proxy.rs` — CredSSP MITM and `send_network_request`
- `devolutions-gateway/src/token.rs` — token claim definitions
- `crates/kdc/` — fake-KDC implementation (pre-existing)
- `utils/dotnet/Devolutions.Gateway.Utils/src/` — NuGet package source

### On the experimental branch (`dgw-378-session-redesign`)

- `DGW-378-FINDINGS.md` — five-layer cascade investigation
- `RDP_NEGOTIATE_PROBE.md` — standalone Rust CLI probe
- `docs/plans/DGW-378-implementation-plan.md` — earlier (heuristic-based) implementation plan
- `docs/plans/DGW-378-architecture-walkthrough.html` — file:line tour of the experimental code
- `docs/plans/DGW-378-complete.html` — combined design + wire-protocol reference
- `docs/plans/rdp-credssp-wire-protocol.html` — CredSSP/Kerberos byte-level reference

### External

- RFC 4120 — Kerberos V5
- MS-RDPBCGR — RDP base protocol
- MS-CSSP — Credential Security Support Provider
- Microsoft U2U documentation (`USE_SESSION_KEY` flag in `KDC_OPTIONS`)
