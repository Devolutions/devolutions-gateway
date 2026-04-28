# DGW-378 Explicit Identity — Code Review (Round 3, post codex pass 3)

**Branch**: `dgw-378-explicit-identity` (working tree, uncommitted)
**Design**: `docs/plans/2026-04-27-dgw-378-explicit-identity-design.md`
**Reviewer**: senior reviewer, post-codex-pass-3
**Supersedes**: Round 2 review previously in this file.

---

## Summary verdict

**Ready to commit and open PR**, with two minor follow-ups deferrable to follow-up commits.

Round 3 closed all four critical / new-issue findings from Round 2. The cryptography is now sourced from `OsRng`, the proxy password is no longer cached in cleartext on `SessionKerberos`, the realm-transparency hole when `proxy.username` is a bare UUID is patched with a synthetic per-session realm, and the loopback URL uses an RFC 6761–reserved host. Tests are in place at the credential-store unit level. Logging now threads `cred_injection_id` through the key dispatch points.

What remains is two cleanup items the design called for but the implementation kept:

1. The outbound `krb_client_config` block tied to `conf.debug.kerberos.kdc_url` is still present in `rdp_proxy.rs` and `rd_clean_path.rs`. Production behaviour is correct (returns `None` when `enable_unstable=false`), but the dead branch prevents removing the legacy debug DTO that the design wanted gone.
2. End-to-end test coverage for the preflight → `/jet/KdcProxy` direct-lookup path was scoped in design §10 and has not been added.

Neither is a merge-blocker against the rest of the codebase as it stands. Both can be follow-up commits on the same branch.

---

## 1. Round 2 findings — final disposition

### 1.1 Weak entropy in `random_32_bytes()` — **✅ FIXED**

`devolutions-gateway/src/credential/mod.rs:336-340`:

```rust
fn random_32_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
```

`OsRng` from `chacha20poly1305::aead` (re-export of the `rand_core` `OsRng`) is the OS CSPRNG. All 256 bits are now drawn from a cryptographic source. `krbtgt_key`, `service_long_term_key`, and `service_user_password` (after hex encoding) all benefit.

### 1.2 `proxy_user_password` cleartext on `SessionKerberos` — **✅ FIXED**

`SessionKerberos` no longer carries any proxy-side material:

```rust
pub struct SessionKerberos {
    pub krbtgt_key: Vec<u8>,
    pub service_long_term_key: Vec<u8>,
    pub service_user_name: String,
    pub service_user_password: String,
    pub realm: String,
}
```

`build_session_kdc_config` now takes `&AppCredentialMapping` and decrypts on every call:

```rust
pub fn build_session_kdc_config(
    kerberos: &SessionKerberos,
    mapping: &AppCredentialMapping,
    realm: &str,
) -> anyhow::Result<kdc::config::KerberosServer> {
    let (proxy_user_name, proxy_password) = mapping.proxy.decrypt_password()?;
    ...
}
```

The proxy plaintext lives only for the duration of one fake-KDC handler invocation. `proxy_password` is a `SecretString` and zeroizes when the function returns. The `MASTER_KEY`-encrypted form on `entry.mapping.proxy.password` is the only persistent representation. This now matches the design's security model.

### 1.3 Realm transparency hole with bare-UUID `proxy.username` — **✅ FIXED**

`credential/mod.rs:194-204`:

```rust
fn realm_from_username(user_name: &str) -> Option<String> {
    user_name
        .split_once('@')
        .map(|(_, realm)| realm)
        .filter(|realm| !realm.is_empty())
        .map(str::to_owned)
}

fn synthetic_realm(cred_injection_id: Uuid) -> String {
    format!("CRED-{}.INVALID", cred_injection_id.simple()).to_ascii_uppercase()
}
```

`encrypt_with_kerberos` falls back to a synthetic per-session realm when `proxy_username` lacks `@realm`:

```rust
realm: realm_from_username(&proxy_username).unwrap_or_else(|| synthetic_realm(cred_injection_id)),
```

So `SessionKerberos.realm` is always populated. sspi-rs's `AuthIdentityBuffers::from_utf8(name, realm, password)` receives a non-empty realm, the U2U self-AS-REQ inside Gateway has somewhere to put `crealm`, and the in-process loopback handler has a fallback realm when `kdc_proxy_message.target_domain` is missing (`rdp_proxy.rs:715-720`).

The `.INVALID` TLD is RFC 2606–reserved and can never collide with a real DNS realm, so even if the synthetic realm string leaks into a log it is unambiguous.

There is one small residual concern: the synthetic realm is **only** used when DVLS hands a bare-UUID proxy username. Operators who manually configure injection with a real `user@realm` proxy username get that realm and not the synthetic one, which is the correct behaviour. Worth a one-line comment near `synthetic_realm` to record the intent.

### 1.4 `http://cred/{uuid}` sentinel — **✅ FIXED**

`rdp_proxy.rs:377` and `rdp_proxy.rs:666`:

```rust
let kdc_url = Url::parse(&format!("http://cred.invalid/{}", credential_entry.cred_injection_id))
    .context("build in-process KDC URL")?;
...
"http" | "https" => {
    if request.url.host_str() == Some("cred.invalid") {
        return send_in_process_kdc_request(request, credential_store, gateway_hostname).await;
    }
    ...
}
```

`cred.invalid` is RFC 6761–reserved, so it cannot resolve to a real host and cannot be inadvertently configured as an actual KDC proxy URL. The dispatcher distinguishes by exact host string match. Both the legacy `inproc` scheme path and the new `http://cred.invalid/` path now reach the same `send_in_process_kdc_request` helper, and the parsing inside the helper has been simplified to always use `KdcProxyMessage::from_raw` (the wire format sspi-rs actually emits for HTTP-shaped KDC proxy URLs). Cleaner than the Round 2 state.

### 1.5 Outbound `krb_client_config` still tied to debug config — **🟡 NOT addressed**

`rdp_proxy.rs:134-146` and `rd_clean_path.rs:404-416` both still contain:

```rust
let krb_client_config = if conf.debug.enable_unstable
    && let Some(crate::config::dto::KerberosConfig {
        kerberos_server: _,
        kdc_url,
    }) = conf.debug.kerberos.as_ref()
{
    Some(ironrdp_connector::credssp::KerberosConfig {
        kdc_proxy_url: kdc_url.clone(),
        hostname: Some(gateway_hostname.clone()),
    })
} else {
    None
};
```

Production behaviour: `enable_unstable=false` → returns `None` → sspi-rs does DNS / realm-based KDC discovery against the real AD KDC on the outbound leg. Correct.

But the design (§6.5 and §8) called for hard-removing this block, along with `conf.debug.enable_unstable`, `conf.debug.kerberos`, and the `KerberosConfig` / `KerberosServer` / `DomainUser` DTOs in `crate::config::dto`. Keeping the dead branch:

- Implies that `debug.kerberos.kdc_url` still has a meaningful production effect (it does not).
- Blocks deletion of the legacy DTOs, which now have no remaining live caller after `kdc_proxy.rs` was rewritten.
- Reads as a TODO that someone will eventually trip over.

**Recommended fix**:

```rust
let krb_client_config: Option<ironrdp_connector::credssp::KerberosConfig> = None;
```

Then a separate cleanup pass to delete `KerberosConfig` / `KerberosServer` / `DomainUser` DTOs and the `enable_unstable` and `kerberos` fields from `DebugConf`. Acceptable as a follow-up commit on this branch.

### 1.6 No tests — **✅ Partially addressed (unit), 🟡 e2e still missing**

`credential/mod.rs:387-590` adds a `#[cfg(test)]` module with five tests:

- `insert_generates_id_and_indexes_by_token` — confirms `Uuid::new_v4()` fallback path and JTI indexing.
- `insert_preserves_supplied_id` — confirms a caller-supplied `cred_injection_id` is honoured.
- `insert_evicts_previous_entry_on_jti_collision` — confirms the JTI re-binding semantics.
- `entries_with_same_proxy_username_can_coexist` — confirms two distinct injection sessions can share a proxy username.
- `uuid_proxy_username_gets_synthetic_realm` — confirms `synthetic_realm` fires for the design's intended bare-UUID case, and the synthetic realm starts with `CRED-` and ends with `.INVALID`.

These cover the credential-store invariants the design depends on. They use a hand-rolled base64-url + JWT-with-jti helper to avoid pulling test-only deps; not pretty, but self-contained.

What is **still missing** from design §10:

- `api/kdc_proxy.rs` unit coverage — there is none. Worth at least one test that an entry with `kerberos = Some(_)` and a request with `claims.jet_cred_id` reaches `build_session_kdc_config` and returns success, plus one test that the absence-of-jet_cred_id path falls through to forward-to-real-KDC without panic.
- `rdp_proxy.rs` unit coverage on the `inproc` / `http://cred.invalid/` URL parsing arm.
- `testsuite/tests/cli/dgw/kdc_proxy_explicit_id.rs` — the e2e the design called out by name. Not added.

Acceptable to defer all three to a follow-up commit on the branch, but the e2e is what proves the entire jet_cred_id path works in a running Gateway and should land before this branch is considered complete.

### 1.7 `cred_injection_id` not threaded through tracing — **✅ FIXED**

`api/kdc_proxy.rs:88-91`, `rd_clean_path.rs:524-526`, `generic_client.rs:147-149`, `rdp_proxy.rs:708-712` all now log the field on the relevant dispatch points:

```rust
debug!(
    cred_injection_id = %entry.cred_injection_id,
    "Switching to RdpProxy for credential injection (WebSocket)"
);
```

Per the project's tracing convention (CLAUDE.md global rules: `info!(?debug_var, var_name = %fmt_var, "message")`), structured fields are correctly emitted with `%` for the `Display`-shaped Uuid.

Two locations where the field is **not** logged but probably should be, for completeness:

- `credential/mod.rs::insert` — when generating a new ID (`unwrap_or_else(Uuid::new_v4)`) there is no `info!` recording the new id. Not strictly necessary because the caller logs it later, but useful for ops.
- `api/preflight.rs::handle_operation` (the `OP_PROVISION_CREDENTIALS` arm) — emits no log identifying the resulting `cred_injection_id` even though the response carries it. One `debug!(%cred_injection_id, ...)` would close the audit gap.

Both are nits, not blockers.

---

## 2. New issues found in Round 3

None.

The `kdc_proxy.rs` rewrite was an additional cleanup the previous review did not specifically request: codex deleted the old `conf.debug.kerberos.kerberos_server.realm(gateway_id)` realm-matching code-path that the original design called dead. Now the handler has exactly two arms — `Some(entry)` → `build_session_kdc_config` and fall-through forward to real KDC. This is a strict improvement on the previous state and matches the design's intent.

---

## 3. Confirmed-correct items (sanity record)

For traceability against the design:

- ✅ JWT claim `jet_cred_id: Option<Uuid>` on both `AssociationTokenClaims` and `KdcTokenClaims` (`token.rs:430`, `token.rs:585`), with `#[serde(default)]` deserialization helpers in `serde_impl::AssociationClaimsHelper` (line 1340) and `serde_impl::KdcClaimsHelper` (line 1380).
- ✅ Preflight DTO `cred_injection_id: Option<Uuid>` with `#[serde(default)]` (`api/preflight.rs:50`) and `PreflightOutputKind::ProvisionedCredentials` response variant carrying the final id (`api/preflight.rs:119-124`).
- ✅ `CredentialStore` reduced to `entries` + `association_token_index`; all heuristic indices removed.
- ✅ `CredentialEntry { cred_injection_id, association_token_jti, token, mapping, expires_at, kerberos }` matches the design.
- ✅ `/rdp` lookup precedence — `rd_clean_path.rs:516-520` and `generic_client.rs:140-143` use `claims.jet_cred_id` first, fall back to `get_by_token(token)`.
- ✅ `/jet/KdcProxy` lookup — `api/kdc_proxy.rs:87` direct lookup, no fallback heuristic.
- ✅ Realm transparency — `KerberosServer.realm` is filled from the request's `target_domain` on every call (`build_session_kdc_config(_, _, realm)`).
- ✅ NuGet `AssociationClaims.JetCredId: Guid?` and `KdcClaims.JetCredId: Guid?` — both nullable with `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]`.
- ✅ NuGet `ProvisionCredentialsRequest.CredInjectionId: Guid` — non-nullable, mandatory in the constructor signature.
- ✅ OpenAPI schema updates (`devolutions-gateway/openapi/gateway-api.yaml`) match the wire shape.
- ✅ tokengen tooling supports `--jet-cred-id` for both RdpTls and Kdc subcommands.
- ✅ Backward compatibility:
  - Old DVLS without `cred_injection_id` in preflight → Gateway generates one and continues; NTLM injection works through the JTI fallback (`get_by_token`).
  - `claims.jet_cred_id == None` on a KDC token → `kdc_proxy.rs` falls through to forward-to-real-KDC; no panic, no regression.

---

## 4. Coding-standard observations

Minor, in priority order:

1. **`build_session_kdc_config` allocates duplicate `DomainUser`** — the service identity is built three times in the same function (lines 158-168, then 173-177 for `service_user`). Could extract a closure or `let service_user = ...; vec![..., service_user.clone()]; service_user: Some(service_user)`. Stylistic.

2. **`kerberos_salt` takes `realm: &str, principal: &str`** — argument order inverted from the convention elsewhere where principal comes first. Not breaking; consistency.

3. **`base64_url_no_pad` in test code** — hand-rolled base64 implementation. The repo already pulls `base64` as a dep elsewhere; could use `base64::engine::general_purpose::URL_SAFE_NO_PAD::encode`. Test-only, low priority.

4. **`encrypt_with_kerberos` clones `proxy.username`** — the username is cloned before `proxy.encrypt()` consumes the credential. Could refactor to encrypt first, then take the username out via pattern match. Stylistic.

5. **`cleanup_task` uses `Vec::contains` for index pruning** — O(N²). Fine for the small-N case Gateway sees, but a `HashSet` would be O(N). Pre-existing pattern, not introduced by this change.

None of these are blocking.

---

## 5. Recommended path forward

In commit-ready order:

1. **Commit the current state as-is**, modulo the optional cleanups below. Suggested commit split:
   - `feat(dgw): jet_cred_id JWT claim and preflight contract` — `token.rs`, `api/preflight.rs`, `openapi.rs`, `gateway-api.yaml`, `webapp.rs`.
   - `refactor(dgw): credential store keyed by cred_injection_id` — `credential/mod.rs` (struct + indices + tests).
   - `feat(dgw): per-session SessionKerberos and explicit-id KDC routing` — `api/kdc_proxy.rs`, `rdp_proxy.rs`, `rd_clean_path.rs`, `generic_client.rs`.
   - `feat(tools): tokengen jet_cred_id support` — `tools/tokengen/**`.
   - `feat(utils): NuGet ProvisionCredentialsRequest and JetCredId claim` — `utils/dotnet/Devolutions.Gateway.Utils/**`.

2. **Follow-up commit (same branch, before PR merge)**: drop the dead `krb_client_config` branches in `rdp_proxy.rs:134` and `rd_clean_path.rs:404`, then remove `DebugConf::enable_unstable`, `DebugConf::kerberos`, and the `KerberosConfig` / `KerberosServer` / `DomainUser` DTOs from `crate::config::dto`. Adjust any downstream call sites.

3. **Follow-up commit (same branch, before PR merge)**: add the e2e test `testsuite/tests/cli/dgw/kdc_proxy_explicit_id.rs`. Reuse the test rig pattern from the experimental branch's `kdc_proxy.rs` testsuite file but exercise the `jet_cred_id` direct-lookup path.

4. **Optional** (could land on master in a separate PR): add `info!` statements on `cred_injection_id` generation in `CredentialStore::insert` and the preflight `OP_PROVISION_CREDENTIALS` handler.

The two follow-ups in 2 and 3 should land **on this branch before the PR is merged** so master ends up clean. Items 1 and 4 are independent.

---

## 6. Sign-off

The implementation faithfully realises the design and the previous review's critical findings have all been addressed. No security regressions remain on the cryptography surface; no plaintext-secret-at-rest issues remain on `SessionKerberos`; no fragile sentinel-host issue remains on the loopback URL; the realm transparency promise holds for the design's intended bare-UUID proxy username shape.

The two unfinished items — outbound config dead branch removal, and the e2e test — are scoped, named, and have a clean place to land. They should not gate sign-off on the rest of the branch.

**Verdict**: ready to commit; complete the two named follow-ups on the same branch before opening the PR.
