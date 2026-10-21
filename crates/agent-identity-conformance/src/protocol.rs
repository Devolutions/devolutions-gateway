use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use der::asn1::ObjectIdentifier;
use der::oid::AssociatedOid as _;
use der::{Decode as _, Encode as _};
use http::Method;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::{DecodePublicKey as _, EncodePublicKey as _};
use p384::ecdsa::{Signature as Signature384, VerifyingKey as VerifyingKey384};
use rand::RngExt as _;
use serde_json::{Value, json};
use sha2::Digest as _;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Barrier;
use tonic::Code;
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName, SubjectKeyIdentifier,
};

use crate::client::{Identity, Reply, Target, Token, count, decoded_certificate, expect_error, expect_status, field};
use crate::dvls::{
    self, CertificateStatus, Credential, IdentityQuery, IdentityRecord, IdentityStatus, Permission, Refusal,
    RotationDeadline, RotationStatus, Settings, SettingsChange, TokenSpec, TokenState, refusal,
};
use crate::signer::{KeyPair, SignatureParameter, SignedHeaders, thumbprint};
use crate::{Context, channel};

const TOKEN_LIFETIME: Duration = Duration::from_secs(3600);

async fn token(ctx: &Context, max_uses: u64) -> anyhow::Result<Token> {
    ctx.target
        .management()
        .create_token(max_uses, TOKEN_LIFETIME, None)
        .await
}

async fn identity(target: &Target, token: &Token, hostname: &str) -> anyhow::Result<Identity> {
    let key = KeyPair::generate()?;
    let reply = target
        .enroll(&token.text, &key, &json!({ "hostname": hostname }))
        .await?;
    let identity = Identity::from_enrollment(key, &reply)?;
    ensure!(
        reply.body["config"]["version"] == 1,
        "enrollment config.version is not 1"
    );
    if let Some(known) = target.authority_id {
        ensure!(
            identity.authority_id == known.to_string(),
            "enrollment returned an unexpected authority ID"
        );
    }
    Ok(identity)
}

async fn issued(ctx: &Context, hostname: &str) -> anyhow::Result<(Token, Identity)> {
    let token = token(ctx, 5).await?;
    let identity = identity(&ctx.target, &token, hostname).await?;
    Ok((token, identity))
}

fn fresh_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes[..]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn attach_content_digest(headers: &mut SignedHeaders, body: &[u8]) {
    headers.digest = Some(format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(body))
    ));
}

pub(crate) async fn wait_rotation_idle(target: &Target, window_secs: u64) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        if !target.management().rotation().await?.rotating() {
            return Ok(());
        }
        ensure!(
            started.elapsed() < Duration::from_secs(window_secs.saturating_add(5)),
            "rotation is already in progress; use a disposable DVLS target"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn begin_rotation(ctx: &Context) -> anyhow::Result<RotationStatus> {
    if ctx.mock() {
        return ctx.target.management().rotate(RotationDeadline::Default).await;
    }
    ensure!(
        ctx.disposable_dvls_target,
        "DVLS rotation requires --disposable-dvls-target"
    );
    wait_rotation_idle(&ctx.target, ctx.dvls_rotation_window_secs).await?;
    let deadline =
        time::OffsetDateTime::now_utc() + time::Duration::seconds(i64::try_from(ctx.dvls_rotation_window_secs)?);
    ctx.target.management().rotate(RotationDeadline::At(deadline)).await
}

async fn finish_rotation(ctx: &Context) -> anyhow::Result<()> {
    if !ctx.mock() {
        wait_rotation_idle(&ctx.target, ctx.dvls_rotation_window_secs).await?;
    }
    Ok(())
}

async fn next_config_update(
    stream: &mut channel::ChannelStream,
) -> anyhow::Result<(agent_channel_proto::ServerMessage, Value)> {
    let message = stream.next().await?;
    let Some(agent_channel_proto::server_message::Payload::ConfigUpdate(update)) = message.payload.as_ref() else {
        anyhow::bail!("expected ConfigUpdate after config revision changed");
    };
    let config: Value = serde_json::from_str(&update.config_json).context("decode ConfigUpdate config_json")?;
    ensure!(config.is_object(), "ConfigUpdate config_json is not an object");
    Ok((message, config))
}

async fn check_in_config(target: &Target, identity: &Identity) -> anyhow::Result<Value> {
    let reply = target.check_in(identity, &json!({})).await?;
    expect_status(&reply, 200)?;
    let config = reply.body["config"].clone();
    ensure!(config.is_object(), "check-in response omitted its config object");
    Ok(config)
}

async fn identity_record(target: &Target, id: &str) -> anyhow::Result<IdentityRecord> {
    target.management().identity(id).await
}

async fn assert_identity_metadata_and_certificates_unchanged(
    target: &Target,
    id: &str,
    before: &IdentityRecord,
) -> anyhow::Result<()> {
    let after = identity_record(target, id).await?;
    ensure!(
        after.metadata == before.metadata && after.certificates == before.certificates,
        "rejected key reuse changed identity metadata or certificate identities/statuses"
    );
    Ok(())
}

/// The non-revoked identities that hold an unexpired current or pending certificate from `issuer`.
async fn active_old_root_ids(ctx: &Context, issuer: &str) -> anyhow::Result<HashSet<String>> {
    let now = chain_evaluation_time(ctx).await?;
    let identities = ctx
        .target
        .management()
        .all_identities(&IdentityQuery::default().full())
        .await?;
    Ok(identities
        .into_iter()
        .filter(|identity| {
            identity.status != IdentityStatus::Revoked
                && identity.certificates().iter().any(|cert| {
                    matches!(cert.status, CertificateStatus::Current | CertificateStatus::Pending)
                        && cert.issuer == issuer
                        && cert.not_after.unix_timestamp() >= now
                })
        })
        .map(|identity| identity.id)
        .collect())
}

fn require_isolated_old_root_fixture(active: &HashSet<String>, expected: &[&str], mock: bool) -> anyhow::Result<()> {
    ensure!(
        expected.iter().all(|id| active.contains(*id)),
        "newly enrolled identity is missing from the active old-root listing"
    );
    if active.len() > expected.len() {
        if !mock {
            return Err(crate::Incomplete("disposable DVLS target has other active old-root identities").into());
        }
        anyhow::bail!("mock reset left unrelated active old-root identities");
    }
    Ok(())
}

async fn isolated_old_root_fixture(ctx: &Context, issuer: &str, expected: &[&str]) -> anyhow::Result<()> {
    let active = active_old_root_ids(ctx, issuer).await?;
    require_isolated_old_root_fixture(&active, expected, ctx.mock())
}

async fn signed_renew(target: &Target, current: &Identity, key: &KeyPair, metadata: &Value) -> anyhow::Result<Reply> {
    target.renew(current, key, metadata).await
}

fn assert_root(root: &Value) -> anyhow::Result<()> {
    let certificate = field(root, "certificate")?;
    ensure!(
        thumbprint(certificate)? == field(root, "thumbprint")?,
        "trust-anchor thumbprint mismatch"
    );
    let der = decoded_certificate(certificate)?;
    let cert = Certificate::from_der(&der)?;
    ensure!(
        cert.tbs_certificate().issuer() == cert.tbs_certificate().subject(),
        "root is not self-issued"
    );
    let before = field(root, "not_before")?;
    let after = field(root, "not_after")?;
    ensure!(
        before.ends_with('Z') && after.ends_with('Z'),
        "trust-anchor dates are not UTC Z strings"
    );
    let before = time::OffsetDateTime::parse(before, &Rfc3339)?.unix_timestamp();
    let after = time::OffsetDateTime::parse(after, &Rfc3339)?.unix_timestamp();
    let cert_before = i64::try_from(
        cert.tbs_certificate()
            .validity()
            .not_before
            .to_unix_duration()
            .as_secs(),
    )?;
    let cert_after = i64::try_from(cert.tbs_certificate().validity().not_after.to_unix_duration().as_secs())?;
    ensure!(
        before == cert_before && after == cert_after,
        "trust-anchor dates disagree with DER validity"
    );
    Ok(())
}

fn assert_leaf_profile(
    leaf: &str,
    root: &str,
    identity_id: &str,
    key: &KeyPair,
    lifetime_secs: u64,
) -> anyhow::Result<()> {
    let cert = Certificate::from_der(&decoded_certificate(leaf)?)?;
    let root = Certificate::from_der(&decoded_certificate(root)?)?;
    let expected = format!("CN={identity_id}").parse::<x509_cert::name::Name>()?;
    ensure!(
        cert.tbs_certificate().subject() == &expected,
        "leaf subject does not match identity ID"
    );
    let expected_spki = key.key.verifying_key().to_public_key_der()?;
    ensure!(
        cert.tbs_certificate().subject_public_key_info().to_der()? == expected_spki.as_bytes(),
        "issued certificate does not contain the CSR public key"
    );
    let (_, san) = cert
        .tbs_certificate()
        .get_extension::<SubjectAltName>()?
        .context("leaf lacks subject alternative name")?;
    let uri = format!("urn:uuid:{identity_id}");
    ensure!(
        san.0
            .iter()
            .any(|name| matches!(name, GeneralName::UniformResourceIdentifier(value) if value.as_str() == uri)),
        "leaf SAN lacks the identity URI"
    );
    let (_, eku) = cert
        .tbs_certificate()
        .get_extension::<ExtendedKeyUsage>()?
        .context("leaf lacks extended key usage")?;
    ensure!(
        eku.0.contains(&"1.3.6.1.5.5.7.3.2".parse()?),
        "leaf lacks clientAuth EKU"
    );
    let (_, key_usage) = cert
        .tbs_certificate()
        .get_extension::<KeyUsage>()?
        .context("leaf lacks key usage")?;
    ensure!(key_usage.digital_signature(), "leaf lacks digitalSignature key usage");
    assert_leaf_extensions(&cert)?;
    let validity = cert.tbs_certificate().validity();
    ensure!(
        validity.not_before.to_unix_duration() < validity.not_after.to_unix_duration(),
        "leaf validity has empty lifetime"
    );
    ensure!(
        validity.not_after.to_unix_duration() <= root.tbs_certificate().validity().not_after.to_unix_duration(),
        "leaf outlives issuing root"
    );
    let expected_end = (validity.not_before.to_unix_duration() + Duration::from_secs(lifetime_secs))
        .min(root.tbs_certificate().validity().not_after.to_unix_duration());
    ensure!(
        validity.not_after.to_unix_duration() == expected_end,
        "leaf lifetime is not {lifetime_secs} seconds capped at the issuing root"
    );
    Ok(())
}

/// CONTRACT.agent-identity.md §4: "The leaf carries no other extension except an authority key identifier and a subject key identifier; in particular it carries no basicConstraints".
///
/// The failure names each other extension's OID.
fn assert_leaf_extensions(leaf: &Certificate) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
    let allowed = [
        SubjectAltName::OID,
        ExtendedKeyUsage::OID,
        KeyUsage::OID,
        AuthorityKeyIdentifier::OID,
        SubjectKeyIdentifier::OID,
    ];
    let others = leaf
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|extension| !allowed.contains(&extension.extn_id))
        .map(|extension| extension.extn_id.to_string())
        .collect::<Vec<_>>();
    ensure!(
        others.is_empty(),
        "leaf carries extensions other than SAN, EKU, KeyUsage, AKI and SKI: {}",
        others.join(", ")
    );
    Ok(())
}

async fn chain_evaluation_time(ctx: &Context) -> anyhow::Result<i64> {
    if ctx.mock() {
        let reply = ctx.target.control("time/advance", &json!({ "secs": 0 })).await?;
        expect_status(&reply, 200)?;
        return reply.body["now"].as_i64().context("mock omitted evaluation time");
    }
    Ok(time::OffsetDateTime::now_utc().unix_timestamp())
}

/// Validates an issued chain against the published roots.
///
/// The root profile and the number of CA tiers are each authority's choice ([CONTRACT.agent-identity.md] §4 "Certificates"), so only RFC 5280 path rules apply: intermediates must be CAs allowed to sign certificates, while the trust anchor needs no extensions.
/// An issuer signature algorithm this tester cannot verify makes the test incomplete rather than failed.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
fn verify_chain(chain: &[String], roots: &Value, now: i64) -> anyhow::Result<()> {
    ensure!(chain.len() >= 2, "certificate chain has no issuer");
    let certs = chain
        .iter()
        .map(|encoded| Certificate::from_der(&decoded_certificate(encoded)?).map_err(anyhow::Error::from))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for intermediate in &certs[1..certs.len() - 1] {
        let basic = intermediate.tbs_certificate().get_extension::<BasicConstraints>()?;
        ensure!(
            basic.is_some_and(|(_, basic)| basic.ca),
            "chain intermediate is not a CA"
        );
        if let Some((_, usage)) = intermediate.tbs_certificate().get_extension::<KeyUsage>()? {
            ensure!(usage.key_cert_sign(), "chain intermediate lacks keyCertSign");
        }
    }
    let anchors = roots["roots"].as_array().context("missing trust anchors")?;
    let root_der = decoded_certificate(chain.last().context("missing chain root")?)?;
    let published = anchors
        .iter()
        .map(|root| decoded_certificate(field(root, "certificate")?))
        .collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(
        published.iter().any(|root| root == &root_der),
        "chain does not end at a published root"
    );
    for cert in &certs {
        let validity = cert.tbs_certificate().validity();
        let before = i64::try_from(validity.not_before.to_unix_duration().as_secs())?;
        let after = i64::try_from(validity.not_after.to_unix_duration().as_secs())?;
        ensure!(
            before <= now && now <= after,
            "certificate chain element is not valid at evaluation time"
        );
    }
    for pair in certs.windows(2) {
        ensure!(
            pair[0].tbs_certificate().issuer() == pair[1].tbs_certificate().subject(),
            "certificate issuer mismatch"
        );
        let issuer_key = pair[1].tbs_certificate().subject_public_key_info();
        let curve = (issuer_key.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"))
            .then_some(issuer_key.algorithm.parameters.as_ref())
            .flatten()
            .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
        let algorithm = pair[0].signature_algorithm().oid;
        let signed_bytes = pair[0].tbs_certificate().to_der()?;
        let signature = pair[0].signature().as_bytes().context("certificate signature")?;
        if curve == Some(ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"))
            && algorithm == ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2")
        {
            let key = VerifyingKey::from_public_key_der(&issuer_key.to_der()?)?;
            key.verify(&signed_bytes, &Signature::from_der(signature)?)?;
        } else if curve == Some(ObjectIdentifier::new_unwrap("1.3.132.0.34"))
            && algorithm == ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3")
        {
            let key = VerifyingKey384::from_public_key_der(&issuer_key.to_der()?)?;
            key.verify(&signed_bytes, &Signature384::from_der(signature)?)?;
        } else {
            return Err(crate::Incomplete(
                "the tester cannot verify the issuer's certificate signature algorithm; only P-256 with SHA-256 and P-384 with SHA-384 are supported",
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) async fn p_trust_anchor_lists_roots(ctx: Context) -> anyhow::Result<()> {
    let roots = ctx.target.trust_anchor().await?;
    let entries = roots["roots"].as_array().context("missing roots")?;
    ensure!(
        (1..=2).contains(&entries.len()),
        "trust-anchor must publish exactly one root, or two during rotation"
    );
    for root in entries {
        assert_root(root)?;
    }
    let (_, identity) = issued(&ctx, "anchor").await?;
    verify_chain(&identity.certificate_chain, &roots, chain_evaluation_time(&ctx).await?)?;
    ensure!(
        uuid::Uuid::parse_str(&identity.authority_id).is_ok(),
        "invalid authority ID"
    );
    ensure!(
        uuid::Uuid::parse_str(&identity.identity_id).is_ok(),
        "invalid identity ID"
    );
    assert_leaf_profile(
        &identity.certificate_chain[0],
        identity.certificate_chain.last().context("missing issuer")?,
        &identity.identity_id,
        &identity.key,
        ctx.leaf_lifetime_secs,
    )?;
    Ok(())
}

pub(crate) async fn p_channel_url_expectation(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "channel-availability").await?;
    if ctx.expect_channel {
        ensure!(
            identity.agent_channel_url.is_some(),
            "enrollment omitted config.agent_channel_url while --expect-channel=true"
        );
    } else {
        ensure!(
            identity.agent_channel_url.is_some() == ctx.channel_available,
            "enrollment config.agent_channel_url availability changed during this run"
        );
    }
    if let Some(channel_url) = &identity.agent_channel_url {
        let parsed = reqwest::Url::parse(channel_url).context("parse config.agent_channel_url")?;
        ensure!(
            parsed.scheme() == "https" && parsed.query().is_none() && parsed.fragment().is_none(),
            "config.agent_channel_url must be an HTTPS URL without a query or fragment"
        );
        if ctx.mock() {
            ensure!(
                channel_url == &ctx.target.base_url,
                "mock config.agent_channel_url does not include its path prefix"
            );
        }
    }
    Ok(())
}

pub(crate) async fn p_reset_rebases_root_validity(ctx: Context) -> anyhow::Result<()> {
    let old = ctx.target.trust_anchor().await?;
    ctx.target.advance(90 * 24 * 3600).await?;
    ctx.target.reset().await?;
    let roots = ctx.target.trust_anchor().await?;
    ensure!(
        roots["roots"][0]["thumbprint"] != old["roots"][0]["thumbprint"],
        "mock reset retained the old root"
    );
    let (_, identity) = issued(&ctx, "after-reset").await?;
    verify_chain(&identity.certificate_chain, &roots, chain_evaluation_time(&ctx).await?)?;
    Ok(())
}

pub(crate) async fn p_token_n_uses_consumed_then_exhausted(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 3).await?;
    let mut authority_id = None;
    for n in 1..=3 {
        let enrolled = identity(&ctx.target, &token, &format!("host-{n}")).await?;
        if let Some(id) = &authority_id {
            ensure!(&enrolled.authority_id == id, "authority ID changed across enrollments");
        }
        authority_id = Some(enrolled.authority_id);
        let record = ctx.target.management().token(&token.id).await?;
        ensure!(record.used_count == n, "enrollment did not consume exactly one use");
    }
    let reply = ctx
        .target
        .enroll(&token.text, &KeyPair::generate()?, &json!({}))
        .await?;
    expect_error(&reply, 403, "token_exhausted")?;
    Ok(())
}

pub(crate) async fn p_token_concurrent_enrollment_respects_max_uses(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 5).await?;
    let mut tasks = tokio::task::JoinSet::new();
    let barrier = Arc::new(Barrier::new(21));
    for index in 0..20 {
        let target = ctx.target.clone();
        let secret = token.text.clone();
        let key = KeyPair::generate()?;
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            target
                .enroll(&secret, &key, &json!({ "hostname": format!("c-{index}") }))
                .await
        });
    }
    barrier.wait().await;
    let mut success = 0;
    let mut exhausted = 0;
    let mut ids = HashSet::new();
    while let Some(outcome) = tasks.join_next().await {
        let reply = outcome??;
        match reply.status {
            200 => {
                let id = field(&reply.body, "identity_id")?;
                ensure!(
                    ids.insert(id.to_owned()),
                    "concurrent enrollments returned duplicate identity IDs"
                );
                success += 1;
            }
            403 => {
                expect_error(&reply, 403, "token_exhausted")?;
                exhausted += 1;
            }
            _ => anyhow::bail!("unexpected concurrent enrollment status {}", reply.status),
        }
    }
    ensure!(
        success == 5 && exhausted == 15,
        "concurrent uses were not atomic: {success} successes"
    );
    let record = ctx.target.management().token(&token.id).await?;
    ensure!(record.used_count == 5, "concurrent use count is incorrect");
    ensure!(
        ctx.target.management().identity_count(&token).await? == 5,
        "concurrent enrollment created unexpected identities"
    );
    Ok(())
}

pub(crate) async fn p_concurrent_same_key_enroll_replays_winner(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 1).await?;
    let csr = KeyPair::generate()?.csr;
    let body = json!({ "csr": csr, "metadata": { "hostname": "shared-key" } });
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let target = ctx.target.clone();
        let secret = token.text.clone();
        let body = body.clone();
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            target.agent(Method::POST, "/enroll", Some(&body), Some(&secret)).await
        });
    }
    barrier.wait().await;
    let mut replies = Vec::new();
    while let Some(outcome) = tasks.join_next().await {
        let reply = outcome??;
        expect_status(&reply, 200)?;
        replies.push(reply);
    }
    ensure!(
        replies.len() == 2
            && replies[0].body["identity_id"] == replies[1].body["identity_id"]
            && replies[0].body["certificate_chain"] == replies[1].body["certificate_chain"]
            && ctx.target.management().token(&token.id).await?.used_count == 1
            && ctx.target.management().identity_count(&token).await? == 1,
        "concurrent same-key enrolls did not replay one winning identity and consume one use"
    );
    Ok(())
}

pub(crate) async fn p_concurrent_same_key_renew_replays_winner(ctx: Context) -> anyhow::Result<()> {
    let (token, identity) = issued(&ctx, "shared-renew").await?;
    let key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": key.csr, "metadata": { "hostname": "shared-renewal" } }))?;
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let target = ctx.target.clone();
        let body = body.clone();
        let headers = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            target.signed_renew(&body, &headers, None).await
        });
    }
    barrier.wait().await;
    let mut replies = Vec::new();
    while let Some(outcome) = tasks.join_next().await {
        let reply = outcome??;
        expect_status(&reply, 200)?;
        replies.push(reply);
    }
    let record = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        replies.len() == 2
            && replies[0].body["certificate_chain"] == replies[1].body["certificate_chain"]
            && record.certificates.as_ref().is_some_and(|certs| certs
                .iter()
                .filter(|cert| cert.status == CertificateStatus::Pending)
                .count()
                == 1)
            && ctx.target.management().token(&token.id).await?.used_count == 1,
        "concurrent same-CSR renews issued more than one pending certificate"
    );
    Ok(())
}

pub(crate) async fn p_failed_enrollment_consumes_nothing(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 2).await?;
    let (prefix, _) = token.text.rsplit_once('.').context("token structure")?;
    let invalid_secret = format!(
        "{prefix}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x61; 32])
    );
    expect_error(
        &ctx.target
            .send(
                Method::POST,
                "/api/agent-identity/v1/enroll",
                Some(b"{"),
                Some(&invalid_secret),
                None,
            )
            .await?,
        401,
        "token_invalid",
    )?;
    let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
    let bad_csr = field(&vectors["csr"]["bad_self_signature"], "csr")?;
    let wrong_algorithm = field(&vectors["csr"]["ecdsa_with_sha384"], "csr")?;
    for csr in [bad_csr, wrong_algorithm] {
        let bad = ctx
            .target
            .agent(
                Method::POST,
                "/enroll",
                Some(&json!({ "csr": csr, "metadata": {} })),
                Some(&token.text),
            )
            .await?;
        expect_error(&bad, 400, "invalid_request")?;
    }
    let invalid = ctx
        .target
        .enroll(&token.text, &KeyPair::generate()?, &json!({ "hostname": 3 }))
        .await?;
    expect_error(&invalid, 400, "invalid_request")?;
    let record = ctx.target.management().token(&token.id).await?;
    ensure!(record.used_count == 0, "invalid enrollment consumed a use");
    Ok(())
}

pub(crate) async fn p_token_errors_distinct(ctx: Context) -> anyhow::Result<()> {
    let first_token = token(&ctx, 1).await?;
    let (prefix, _) = first_token.text.rsplit_once('.').context("invalid issued token")?;
    let wrong_secret = format!(
        "{prefix}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x57; 32])
    );
    let invalid = ctx
        .target
        .enroll(&wrong_secret, &KeyPair::generate()?, &json!({}))
        .await?;
    expect_error(&invalid, 401, "token_invalid")?;
    let _ = identity(&ctx.target, &first_token, "exhaust").await?;
    let exhausted = ctx
        .target
        .enroll(&first_token.text, &KeyPair::generate()?, &json!({}))
        .await?;
    expect_error(&exhausted, 403, "token_exhausted")?;
    let other = token(&ctx, 1).await?;
    ctx.target.management().delete_token(&other.id).await?;
    let deleted = ctx
        .target
        .enroll(&other.text, &KeyPair::generate()?, &json!({}))
        .await?;
    expect_error(&deleted, 401, "token_invalid")?;
    Ok(())
}

pub(crate) async fn p_token_expired(ctx: Context) -> anyhow::Result<()> {
    let token = ctx
        .target
        .management()
        .create_token(1, Duration::from_secs(3), None)
        .await?;
    ctx.target.advance(5).await?;
    let expired = ctx
        .target
        .enroll(&token.text, &KeyPair::generate()?, &json!({}))
        .await?;
    expect_error(&expired, 401, "token_expired")?;
    let record = ctx.target.management().token(&token.id).await?;
    ensure!(record.state == TokenState::Expired, "token not marked expired");
    ensure!(record.used_count == 0, "expired token consumed a use");
    Ok(())
}

pub(crate) async fn p_enroll_idempotent_same_key(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 1).await?;
    let key = KeyPair::generate()?;
    let first = ctx
        .target
        .enroll(&token.text, &key, &json!({ "hostname": "original" }))
        .await?;
    expect_status(&first, 200)?;
    let before = identity_record(&ctx.target, field(&first.body, "identity_id")?).await?;
    if ctx.mock() {
        ctx.target.advance(2).await?;
    } else {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let replay = ctx
        .target
        .enroll(&token.text, &key, &json!({ "hostname": "changed" }))
        .await?;
    expect_status(&replay, 200)?;
    ensure!(
        first.body["identity_id"] == replay.body["identity_id"]
            && first.body["certificate_chain"] == replay.body["certificate_chain"],
        "same-key replay was not idempotent"
    );
    let record = ctx.target.management().token(&token.id).await?;
    ensure!(record.used_count == 1, "idempotent replay consumed a use");
    if ctx.mock() {
        ensure!(
            count(&ctx.target.requests(Some(&token)).await?, "enroll")? == 2,
            "mock did not observe both enrollment requests"
        );
    }
    let replayed_record = identity_record(&ctx.target, field(&first.body, "identity_id")?).await?;
    ensure!(
        replayed_record.metadata == before.metadata && replayed_record.last_seen_at == before.last_seen_at,
        "idempotent enrollment changed metadata or last_seen_at"
    );
    if ctx.mock() {
        ctx.target.advance(3601).await?;
        let expired_replay = ctx
            .target
            .enroll(&token.text, &key, &json!({ "hostname": "after-expiry" }))
            .await?;
        expect_status(&expired_replay, 200)?;
        ensure!(
            expired_replay.body["identity_id"] == first.body["identity_id"]
                && expired_replay.body["certificate_chain"] == first.body["certificate_chain"]
                && ctx.target.management().token(&token.id).await?.used_count == 1
                && identity_record(&ctx.target, field(&first.body, "identity_id")?)
                    .await?
                    .metadata
                    == before.metadata,
            "expired-token current-key replay created, consumed or changed an identity"
        );
    }
    Ok(())
}

pub(crate) async fn p_token_config_contributes_to_effective_config(ctx: Context) -> anyhow::Result<()> {
    let mut spec = TokenSpec::new(1, TOKEN_LIFETIME)?;
    spec.config = Some([("psu_channel_url".to_owned(), "https://psu.example".to_owned())].into());
    let token = ctx.target.management().create_token_from(&spec).await?;
    let identity = identity(&ctx.target, &token, "token-config").await?;
    ensure!(
        identity.config["psu_channel_url"] == "https://psu.example",
        "enrollment omitted the token's product-specific config"
    );
    ensure!(
        check_in_config(&ctx.target, &identity).await?["psu_channel_url"] == "https://psu.example",
        "check-in omitted the token's product-specific config"
    );
    Ok(())
}

pub(crate) async fn p_deleted_token_replays_own_key_only(ctx: Context) -> anyhow::Result<()> {
    let foreign_token = token(&ctx, 1).await?;
    let token = token(&ctx, 2).await?;
    let key = KeyPair::generate()?;
    let first = ctx
        .target
        .enroll(&token.text, &key, &json!({ "hostname": "original" }))
        .await?;
    expect_status(&first, 200)?;
    let identity_id = field(&first.body, "identity_id")?;
    let before = identity_record(&ctx.target, identity_id).await?;
    let foreign = identity(&ctx.target, &foreign_token, "foreign").await?;
    ctx.target.management().delete_token(&token.id).await?;
    ensure!(
        refusal(ctx.target.management().token(&token.id).await)? == Refusal::NotFound,
        "deleted token is still listed"
    );
    let replay = ctx
        .target
        .enroll(&token.text, &key, &json!({ "hostname": "must-not-replace" }))
        .await?;
    expect_status(&replay, 200)?;
    ensure!(
        replay.body["identity_id"] == first.body["identity_id"]
            && replay.body["certificate_chain"] == first.body["certificate_chain"],
        "deleted token could not recover its own committed enrollment"
    );
    let after = identity_record(&ctx.target, identity_id).await?;
    ensure!(
        after.metadata == before.metadata && after.last_seen_at == before.last_seen_at,
        "deleted-token replay changed identity state"
    );
    expect_error(
        &ctx.target
            .enroll(&token.text, &KeyPair::generate()?, &json!({}))
            .await?,
        401,
        "token_invalid",
    )?;
    expect_error(
        &ctx.target.enroll(&token.text, &foreign.key, &json!({})).await?,
        401,
        "token_invalid",
    )?;
    ctx.target.management().revoke(&foreign.identity_id).await?;
    expect_error(
        &ctx.target.enroll(&token.text, &foreign.key, &json!({})).await?,
        401,
        "token_invalid",
    )?;
    ctx.target.management().delete_identity(&foreign.identity_id).await?;
    expect_error(
        &ctx.target.enroll(&token.text, &foreign.key, &json!({})).await?,
        401,
        "token_invalid",
    )?;
    expect_status(&ctx.target.enroll(&token.text, &key, &json!({})).await?, 200)?;
    ensure!(
        ctx.target.management().identity_count(&token).await? == 1
            && identity_record(&ctx.target, identity_id).await? == before,
        "deleted token issued another identity or changed its own replayed identity"
    );
    Ok(())
}

pub(crate) async fn p_enroll_revoked_same_key_rejected(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 2).await?;
    let key = KeyPair::generate()?;
    let enrolled = ctx.target.enroll(&token.text, &key, &json!({})).await?;
    let identity = Identity::from_enrollment(key, &enrolled)?;
    ctx.target.management().revoke(&identity.identity_id).await?;
    let refused = ctx.target.enroll(&token.text, &identity.key, &json!({})).await?;
    expect_error(&refused, 403, "identity_revoked")?;
    let record = ctx.target.management().token(&token.id).await?;
    ensure!(record.used_count == 1, "revoked replay consumed a use");
    Ok(())
}

pub(crate) async fn p_enroll_certificate_key_reuse_rules(ctx: Context) -> anyhow::Result<()> {
    let original_token = token(&ctx, 1).await?;
    let original_key = KeyPair::generate()?;
    let first = ctx
        .target
        .enroll(&original_token.text, &original_key, &json!({ "hostname": "original" }))
        .await?;
    let identity = Identity::from_enrollment(original_key, &first)?;
    let original_record = identity_record(&ctx.target, &identity.identity_id).await?;
    let original_name = original_record.friendly_name.as_str().to_owned();
    let other_token = token(&ctx, 1).await?;
    expect_error(
        &ctx.target
            .enroll(&other_token.text, &identity.key, &json!({ "hostname": "foreign" }))
            .await?,
        400,
        "invalid_request",
    )?;
    let replay = ctx
        .target
        .enroll(&original_token.text, &identity.key, &json!({ "hostname": "refreshed" }))
        .await?;
    expect_status(&replay, 200)?;
    ensure!(
        replay.body["identity_id"] == identity.identity_id
            && replay.body["certificate_chain"] == first.body["certificate_chain"],
        "current-key enrollment did not replay the existing identity and current chain"
    );
    let replayed_record = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        replayed_record.metadata == original_record.metadata
            && replayed_record.last_seen_at == original_record.last_seen_at
            && replayed_record.friendly_name == original_name,
        "current-key replay changed identity metadata, last_seen_at or friendly name"
    );
    let first_pending = KeyPair::generate()?;
    expect_status(&ctx.target.renew(&identity, &first_pending, &json!({})).await?, 200)?;
    let pending_before = identity_record(&ctx.target, &identity.identity_id).await?;
    for bearer in [&other_token.text, &original_token.text] {
        expect_error(
            &ctx.target.enroll(bearer, &first_pending, &json!({})).await?,
            400,
            "invalid_request",
        )?;
    }
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &pending_before).await?;
    let second_pending = KeyPair::generate()?;
    expect_status(&ctx.target.renew(&identity, &second_pending, &json!({})).await?, 200)?;
    let retired_before = identity_record(&ctx.target, &identity.identity_id).await?;
    for bearer in [&other_token.text, &original_token.text] {
        for key in [&first_pending, &second_pending] {
            expect_error(
                &ctx.target.enroll(bearer, key, &json!({})).await?,
                400,
                "invalid_request",
            )?;
        }
    }
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &retired_before).await?;
    ctx.target.management().revoke(&identity.identity_id).await?;
    for key in [&identity.key, &first_pending, &second_pending] {
        expect_error(
            &ctx.target.enroll(&other_token.text, key, &json!({})).await?,
            400,
            "invalid_request",
        )?;
    }
    ctx.target.management().delete_identity(&identity.identity_id).await?;
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    // Only a non-deleted identity's key is matched against its token, so a deleted identity's key gets `identity_revoked` whichever token presents it.
    for key in [&identity.key, &first_pending, &second_pending] {
        for bearer in [&other_token.text, &original_token.text] {
            expect_error(
                &ctx.target.enroll(bearer, key, &json!({})).await?,
                403,
                "identity_revoked",
            )?;
        }
    }
    ensure!(
        ctx.target.management().token(&other_token.id).await?.used_count == 0
            && ctx.target.management().token(&original_token.id).await?.used_count == 1
            && ctx.target.management().identity_count(&original_token).await? == 0,
        "key-reuse attempts consumed a token use or recreated a deleted identity"
    );
    Ok(())
}

pub(crate) async fn p_renew_certificate_key_reuse_rules(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "renew-a").await?;
    let (_, other) = issued(&ctx, "renew-b").await?;
    let initial = identity_record(&ctx.target, &identity.identity_id).await?;
    for key in [&identity.key, &other.key] {
        expect_error(
            &ctx.target.renew(&identity, key, &json!({})).await?,
            400,
            "invalid_request",
        )?;
        assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &initial).await?;
    }
    let pending = KeyPair::generate()?;
    let first = ctx.target.renew(&identity, &pending, &json!({})).await?;
    expect_status(&first, 200)?;
    let replay = ctx.target.renew(&identity, &pending, &json!({})).await?;
    expect_status(&replay, 200)?;
    ensure!(
        replay.body["certificate_chain"] == first.body["certificate_chain"],
        "pending-key retry did not replay the pending chain"
    );
    let replacement = KeyPair::generate()?;
    expect_status(&ctx.target.renew(&identity, &replacement, &json!({})).await?, 200)?;
    let renewed = identity_record(&ctx.target, &identity.identity_id).await?;
    expect_error(
        &ctx.target.renew(&identity, &pending, &json!({})).await?,
        400,
        "invalid_request",
    )?;
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &renewed).await?;
    let other_pending = KeyPair::generate()?;
    expect_status(&ctx.target.renew(&other, &other_pending, &json!({})).await?, 200)?;
    let other_replacement = KeyPair::generate()?;
    expect_status(&ctx.target.renew(&other, &other_replacement, &json!({})).await?, 200)?;
    for key in [&other.key, &other_pending, &other_replacement] {
        expect_error(
            &ctx.target.renew(&identity, key, &json!({})).await?,
            400,
            "invalid_request",
        )?;
        assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &renewed).await?;
    }
    ctx.target.management().revoke(&other.identity_id).await?;
    ctx.target.management().delete_identity(&other.identity_id).await?;
    for key in [&other.key, &other_pending, &other_replacement] {
        expect_error(
            &ctx.target.renew(&identity, key, &json!({})).await?,
            400,
            "invalid_request",
        )?;
        assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &renewed).await?;
    }
    ensure!(
        renewed.certificates.as_ref().is_some_and(|certs| certs.len() == 3
            && certs
                .iter()
                .filter(|cert| cert.status == CertificateStatus::Pending)
                .count()
                == 1),
        "renewal fixture did not have exactly one pending certificate"
    );
    Ok(())
}

pub(crate) async fn p_metadata_limits(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 12).await?;
    let many = (0..33)
        .map(|n| (format!("k{n}"), json!("v")))
        .collect::<serde_json::Map<_, _>>();
    let exactly_16_kib = (0..16)
        .map(|n| (format!("k{n:02}"), json!("a".repeat(1021))))
        .collect::<serde_json::Map<_, _>>();
    let mut oversized_object = exactly_16_kib.clone();
    oversized_object.insert("extra".to_owned(), json!("x"));
    let invalid = [
        json!({ "hostname": 42 }),
        json!({ "hostname": { "nested": "no" } }),
        json!({ "Bad-Key": "x" }),
        json!({ "hostname": "z".repeat(1025) }),
        json!({ "hostname": "x\u{7f}" }),
        json!({ "hostname": "x\u{0085}" }),
        Value::Object(many),
        Value::Object(oversized_object),
    ];
    for metadata in invalid {
        let reply = ctx.target.enroll(&token.text, &KeyPair::generate()?, &metadata).await?;
        expect_error(&reply, 400, "invalid_request")?;
    }
    let key = KeyPair::generate()?;
    for body in [
        json!({ "csr": key.csr }),
        json!({ "csr": key.csr, "metadata": null }),
        json!({ "csr": key.csr, "metadata": [] }),
    ] {
        expect_error(
            &ctx.target
                .agent(Method::POST, "/enroll", Some(&body), Some(&token.text))
                .await?,
            400,
            "invalid_request",
        )?;
    }
    let within_limit = (0..8)
        .map(|n| (format!("field{n}"), json!("\"".repeat(1000))))
        .collect::<serde_json::Map<_, _>>();
    let escaped = ctx
        .target
        .enroll(&token.text, &KeyPair::generate()?, &Value::Object(within_limit))
        .await?;
    expect_status(&escaped, 200)?;
    let record = ctx.target.management().token(&token.id).await?;
    ensure!(
        record.used_count == 1,
        "metadata validation used an incorrect size measure or consumed a failed request"
    );
    expect_status(
        &ctx.target
            .enroll(&token.text, &KeyPair::generate()?, &Value::Object(exactly_16_kib))
            .await?,
        200,
    )?;
    let key = KeyPair::generate()?;
    let enrolled = ctx
        .target
        .enroll(&token.text, &key, &json!({ "custom_key": "kept" }))
        .await?;
    let identity = Identity::from_enrollment(key, &enrolled)?;
    let record = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        record.metadata_value("custom_key") == Some("kept"),
        "unknown metadata key was not retained"
    );
    Ok(())
}

pub(crate) async fn p_friendly_name_format(ctx: Context) -> anyhow::Result<()> {
    let management = ctx.target.management();
    let token = management
        .create_token(2, TOKEN_LIFETIME, Some("  {hostname}-{{ok}}-{token_name}-{fqdn}  "))
        .await?;
    let name = management.token(&token.id).await?.name;
    let first_identity = identity(&ctx.target, &token, "hello").await?;
    let first_name = identity_record(&ctx.target, &first_identity.identity_id)
        .await?
        .friendly_name;
    ensure!(
        first_name == format!("hello-{{ok}}-{name}-"),
        "friendly name formatting incorrect: {first_name}"
    );
    let empty_token = management.create_token(1, TOKEN_LIFETIME, Some("{hostname}")).await?;
    let empty = identity(&ctx.target, &empty_token, "").await?;
    ensure!(
        identity_record(&ctx.target, &empty.identity_id).await?.friendly_name == empty.identity_id,
        "empty friendly name did not fall back to identity ID"
    );
    let long_token = management.create_token(1, TOKEN_LIFETIME, Some("{hostname}")).await?;
    let long = identity(&ctx.target, &long_token, &"é".repeat(260)).await?;
    ensure!(
        identity_record(&ctx.target, &long.identity_id)
            .await?
            .friendly_name
            .chars()
            .count()
            == 255,
        "friendly name not limited to 255 characters"
    );
    for format in ["{not_a_known_key}", "prefix}"] {
        let mut spec = TokenSpec::new(1, TOKEN_LIFETIME)?;
        spec.friendly_name_format = Some(format.to_owned());
        ensure!(
            refusal(management.create_token_from(&spec).await)? == Refusal::Invalid,
            "friendly-name format {format:?} was not rejected"
        );
    }
    Ok(())
}

pub(crate) async fn p_identity_cannot_impersonate_another(ctx: Context) -> anyhow::Result<()> {
    let (_, a) = issued(&ctx, "alpha").await?;
    let (b_token, b) = issued(&ctx, "bravo").await?;
    let b_before = identity_record(&ctx.target, &b.identity_id).await?;
    let new_key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({
        "csr": new_key.csr,
        "identity_id": b.identity_id,
        "metadata": { "hostname": "changed", "identity_id": b.identity_id }
    }))?;
    let forged = a.key.sign_now(&b.thumbprint, "renew", Some(&body));
    expect_error(
        &ctx.target.signed_renew(&body, &forged, None).await?,
        401,
        "signature_invalid",
    )?;
    let token_only = ctx
        .target
        .send(
            Method::POST,
            "/api/agent-identity/v1/renew",
            Some(&body),
            Some(&b_token.text),
            None,
        )
        .await?;
    expect_error(&token_only, 401, "signature_invalid")?;
    let valid = a.key.sign_now(&a.thumbprint, "renew", Some(&body));
    expect_status(&ctx.target.signed_renew(&body, &valid, Some(&b_token.text)).await?, 200)?;
    let a_record = identity_record(&ctx.target, &a.identity_id).await?;
    let b_record = identity_record(&ctx.target, &b.identity_id).await?;
    ensure!(
        a_record.metadata_value("hostname") == Some("changed"),
        "A's renewal did not update A"
    );
    ensure!(
        b_record.metadata_value("hostname") == Some("bravo"),
        "A modified B's metadata"
    );
    ensure!(
        b_record.certificates == b_before.certificates,
        "A changed B's certificates"
    );
    Ok(())
}

pub(crate) async fn p_channel_hello_cannot_impersonate_another(ctx: Context) -> anyhow::Result<()> {
    let (_, a) = issued(&ctx, "alpha").await?;
    let (_, b) = issued(&ctx, "bravo").await?;
    let b_before = identity_record(&ctx.target, &b.identity_id).await?;
    let mut stream = channel::open(&ctx.target, &a).await?;
    stream
        .hello(&a, &[("hostname", "channel-a"), ("identity_id", &b.identity_id)])
        .await?;
    let a_after_hello = identity_record(&ctx.target, &a.identity_id).await?;
    ensure!(
        a_after_hello.metadata_value("hostname") == Some("channel-a")
            && a_after_hello.metadata_value("identity_id") == Some(&*b.identity_id),
        "A's Hello did not update A's metadata"
    );
    let b_after_hello = identity_record(&ctx.target, &b.identity_id).await?;
    ensure!(
        b_after_hello.metadata == b_before.metadata
            && b_after_hello.certificates == b_before.certificates
            && b_after_hello.last_seen_at == b_before.last_seen_at
            && b_after_hello.connected == b_before.connected,
        "A's Hello modified B's identity"
    );
    Ok(())
}

pub(crate) async fn p_renew_digest_integrity(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "original").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let key = KeyPair::generate()?;
    let original = serde_json::to_vec(&json!({ "csr": key.csr, "metadata": { "hostname": "original" } }))?;
    let changed = serde_json::to_vec(&json!({ "csr": key.csr, "metadata": { "hostname": "tampered" } }))?;
    let mut last_nonce = String::new();
    for (variant, replace_digest) in [("body only", false), ("body and digest", true)] {
        let nonce = loop {
            let nonce = fresh_nonce();
            if nonce != last_nonce {
                break nonce;
            }
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut signed = identity
            .key
            .sign(&identity.thumbprint, "renew", Some(&original), now, now + 60, &nonce);
        last_nonce = nonce;
        if replace_digest {
            signed.digest = Some(format!(
                "sha-256=:{}:",
                base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&changed))
            ));
        }
        expect_error(
            &ctx.target.signed_renew(&changed, &signed, None).await?,
            401,
            "signature_invalid",
        )
        .with_context(|| format!("{variant} tampering"))?;
        let after = identity_record(&ctx.target, &identity.identity_id).await?;
        ensure!(
            after.metadata == before.metadata
                && after.certificates == before.certificates
                && after.last_seen_at == before.last_seen_at,
            "{variant} tampering changed identity state"
        );
        ensure!(
            after
                .certificates
                .as_ref()
                .is_some_and(|certs| certs.iter().all(|cert| cert.status != CertificateStatus::Pending)),
            "{variant} tampering created a pending certificate"
        );
    }
    Ok(())
}

async fn renew_in_alternate_parameter_order(ctx: &Context) -> anyhow::Result<(Identity, SignedHeaders)> {
    use SignatureParameter::{Algorithm, Created, Expires, KeyId, Nonce, Tag};

    let (_, mut identity) = issued(ctx, "parameter-order").await?;
    let new_key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({
        "csr": new_key.csr,
        "metadata": { "hostname": "renewed-in-alternate-order" },
    }))?;
    let renew_headers = identity.key.sign_now_with_order(
        &identity.thumbprint,
        "renew",
        Some(&body),
        &[Created, Expires, Nonce, Algorithm, KeyId, Tag],
    );
    let reply = ctx.target.signed_renew(&body, &renew_headers, None).await?;
    expect_status(&reply, 200)?;
    identity.adopt_certificate(&reply.body["certificate_chain"], new_key)?;
    let renewed = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        renewed.has_certificate(&identity.thumbprint, CertificateStatus::Pending)
            && renewed.metadata_value("hostname") == Some("renewed-in-alternate-order"),
        "alternate-order renew did not create a pending certificate and update metadata"
    );
    Ok((identity, renew_headers))
}

pub(crate) async fn p_signature_parameter_order_accepted_renew(ctx: Context) -> anyhow::Result<()> {
    renew_in_alternate_parameter_order(&ctx).await?;
    Ok(())
}

pub(crate) async fn p_signature_parameter_order_accepted_connect(ctx: Context) -> anyhow::Result<()> {
    use SignatureParameter::{Algorithm, Created, Expires, KeyId, Nonce, Tag};

    let (identity, renew_headers) = renew_in_alternate_parameter_order(&ctx).await?;
    let connect_headers = identity.key.sign_now_with_order(
        &identity.thumbprint,
        "connect",
        None,
        &[Tag, Created, Expires, Nonce, KeyId, Algorithm],
    );
    ensure!(
        renew_headers.nonce != connect_headers.nonce,
        "tester reused the renew nonce"
    );
    let mut stream = channel::open_with_headers(&ctx.target, &identity, connect_headers).await?;
    stream
        .hello(&identity, &[("hostname", "connected-in-alternate-order")])
        .await?;
    Ok(())
}

pub(crate) async fn p_renew_rejects_sha384_csr(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "original").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
    let csr = field(&vectors["csr"]["ecdsa_with_sha384"], "csr")?;
    let body = serde_json::to_vec(&json!({ "csr": csr, "metadata": { "hostname": "changed" } }))?;
    let signed = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
    expect_error(
        &ctx.target.signed_renew(&body, &signed, None).await?,
        400,
        "invalid_request",
    )?;
    let after = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        before.metadata == after.metadata
            && before.certificates == after.certificates
            && after
                .certificates
                .as_ref()
                .is_some_and(|certs| certs.iter().all(|cert| cert.status != CertificateStatus::Pending)),
        "SHA-384 CSR changed metadata or created a pending certificate"
    );
    Ok(())
}

pub(crate) async fn p_replay_nonce_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "replay").await?;
    let new_key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": new_key.csr, "metadata": {} }))?;
    let nonce = fresh_nonce();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let bad = KeyPair::generate()?.sign(&identity.thumbprint, "renew", Some(&body), now, now + 60, &nonce);
    expect_error(
        &ctx.target.signed_renew(&body, &bad, None).await?,
        401,
        "signature_invalid",
    )?;
    let headers = identity
        .key
        .sign(&identity.thumbprint, "renew", Some(&body), now, now + 60, &nonce);
    expect_status(&ctx.target.signed_renew(&body, &headers, None).await?, 200)?;
    expect_error(
        &ctx.target.signed_renew(&body, &headers, None).await?,
        401,
        "signature_invalid",
    )?;
    let shorter = identity
        .key
        .sign(&identity.thumbprint, "renew", Some(&body), now, now + 1, &nonce);
    expect_error(
        &ctx.target.signed_renew(&body, &shorter, None).await?,
        401,
        "signature_invalid",
    )?;
    if ctx.mock() {
        ctx.target.advance(62).await?;
        expect_error(
            &ctx.target.signed_renew(&body, &headers, None).await?,
            401,
            "signature_invalid",
        )?;
        ensure!(
            count(&ctx.target.requests(None).await?, "renew")? == 5,
            "mock did not observe all renewal attempts"
        );
    }
    Ok(())
}

pub(crate) async fn p_replay_window_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "window").await?;
    let new_key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": new_key.csr, "metadata": {} }))?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    for (created, expires) in [
        (now + 62, now + 122),
        (now - 123, now - 63),
        (now, now + 301),
        (now, now),
        (now, now - 1),
    ] {
        let headers = identity.key.sign(
            &identity.thumbprint,
            "renew",
            Some(&body),
            created,
            expires,
            &fresh_nonce(),
        );
        let rejected = ctx.target.signed_renew(&body, &headers, None).await?;
        expect_error(&rejected, 401, "clock_skew")?;
    }
    let old_created = now - 1_000;
    let mut wrong_tag = identity.key.sign(
        &identity.thumbprint,
        "renew",
        Some(&body),
        old_created,
        old_created + 60,
        &fresh_nonce(),
    );
    wrong_tag.input = wrong_tag.input.replace(";tag=\"renew\"", ";tag=\"connect\"");
    resign_input(&identity.key, &mut wrong_tag)?;
    expect_error(
        &ctx.target.signed_renew(&body, &wrong_tag, None).await?,
        401,
        "signature_invalid",
    )?;
    let unknown_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42; 32]);
    let wrong_keyid = identity.key.sign(
        &unknown_key,
        "renew",
        Some(&body),
        old_created,
        old_created + 60,
        &fresh_nonce(),
    );
    expect_error(
        &ctx.target.signed_renew(&body, &wrong_keyid, None).await?,
        401,
        "clock_skew",
    )?;
    Ok(())
}

pub(crate) async fn p_connect_signature_replayed_to_renew(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "cross-tag").await?;
    let new_key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": new_key.csr, "metadata": {} }))?;
    let mut connect_tag = identity.key.sign_now(&identity.thumbprint, "connect", None);
    attach_content_digest(&mut connect_tag, &body);
    let rejected = ctx.target.signed_renew(&body, &connect_tag, None).await?;
    expect_error(&rejected, 401, "signature_invalid")?;
    Ok(())
}

pub(crate) async fn p_renew_signature_rejected_on_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "reverse-cross-tag").await?;
    let csr = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": csr.csr, "metadata": {} }))?;
    let renew_tag = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
    let status = channel::open_with_headers(&ctx.target, &identity, renew_tag)
        .await
        .err()
        .context("renew-tagged signature opened a channel")?;
    channel::expect_refused_opening(
        status.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
        Code::Unauthenticated,
        "signature_invalid",
    )?;
    Ok(())
}

pub(crate) async fn p_channel_duplicate_signature_metadata_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "duplicate-channel-signature").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    for name in ["signature-input", "signature"] {
        let failure = channel::open_with_duplicate_header(&ctx.target, &identity, name)
            .await
            .err()
            .with_context(|| format!("duplicate {name} metadata opened a channel"))?;
        channel::expect_refused_opening(
            failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
            Code::Unauthenticated,
            "signature_invalid",
        )?;
    }
    let after = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        !after.connected && after.metadata == before.metadata && after.last_seen_at == before.last_seen_at,
        "duplicate signed channel metadata authenticated or changed identity state"
    );
    Ok(())
}

pub(crate) async fn p_confirm_cross_tag_signatures_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "confirm-cross-tag").await?;
    let old_thumb = identity.thumbprint.clone();
    let connect_tag = identity.key.sign_now(&old_thumb, "connect", None);
    expect_error(
        &ctx.target.signed_confirm(&connect_tag, None).await?,
        401,
        "signature_invalid",
    )?;
    let csr = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": csr.csr, "metadata": {} }))?;
    let renew_tag = identity.key.sign_now(&old_thumb, "renew", Some(&body));
    expect_error(
        &ctx.target.signed_confirm(&renew_tag, None).await?,
        401,
        "signature_invalid",
    )?;
    let new_key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &new_key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], new_key)?;
    let csr = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": csr.csr, "metadata": {} }))?;
    let mut confirm_tag = identity.key.sign_now(&identity.thumbprint, "confirm", None);
    attach_content_digest(&mut confirm_tag, &body);
    expect_error(
        &ctx.target.signed_renew(&body, &confirm_tag, None).await?,
        401,
        "signature_invalid",
    )?;
    let unchanged = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        unchanged.has_certificate(&old_thumb, CertificateStatus::Current)
            && unchanged.has_certificate(&identity.thumbprint, CertificateStatus::Pending),
        "cross-tag probes changed certificate statuses"
    );
    Ok(())
}

pub(crate) async fn p_confirm_signature_rejected_on_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "confirm-to-connect").await?;
    let old_thumb = identity.thumbprint.clone();
    let confirm_tag = identity.key.sign_now(&identity.thumbprint, "confirm", None);
    let failure = channel::open_with_headers(&ctx.target, &identity, confirm_tag)
        .await
        .err()
        .context("confirm-tagged signature opened a channel")?;
    channel::expect_refused_opening(
        failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
        Code::Unauthenticated,
        "signature_invalid",
    )?;
    let pending_key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &pending_key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], pending_key)?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .has_certificate(&identity.thumbprint, CertificateStatus::Pending),
        "confirm-to-Connect fixture did not issue a pending certificate"
    );
    let confirm_tag = identity.key.sign_now(&identity.thumbprint, "confirm", None);
    let failure = channel::open_with_headers(&ctx.target, &identity, confirm_tag)
        .await
        .err()
        .context("pending confirm-tagged signature opened a channel")?;
    channel::expect_refused_opening(
        failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
        Code::Unauthenticated,
        "signature_invalid",
    )?;
    let unchanged = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        !unchanged.connected
            && unchanged.has_certificate(&old_thumb, CertificateStatus::Current)
            && unchanged.has_certificate(&identity.thumbprint, CertificateStatus::Pending),
        "confirm-tagged channel probe changed certificate status or connected the identity"
    );
    Ok(())
}

async fn next_last_seen_second(ctx: &Context) -> anyhow::Result<()> {
    if ctx.mock() {
        ctx.target.advance(2).await
    } else {
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(())
    }
}

pub(crate) async fn p_check_in_current_and_pending(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "check-in").await?;
    let enrolled = identity.config.clone();
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let initial_seen = before.last_seen_at.context("new identity has no last-seen time")?;
    let created_at = before.created_at.context("full identity omitted the creation time")?;
    ensure!(
        enrolled["revision"].as_u64().is_some() && created_at <= initial_seen,
        "enrollment omitted a config revision or the identity's initial last-seen time"
    );
    next_last_seen_second(&ctx).await?;
    let current = ctx
        .target
        .check_in(&identity, &json!({ "hostname": "current-check-in" }))
        .await?;
    expect_status(&current, 200)?;
    let after = identity_record(&ctx.target, &identity.identity_id).await?;
    let current_seen = after
        .last_seen_at
        .context("current check-in did not set the last-seen time")?;
    ensure!(
        current.body["config"] == enrolled
            && current.body["renewal_requested"] == false
            && after.metadata_value("hostname") == Some("current-check-in")
            && initial_seen < current_seen,
        "current-certificate check-in did not return config or refresh metadata and the last-seen time"
    );
    ctx.target.management().request_renewal(&identity.identity_id).await?;
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let before_pending = identity_record(&ctx.target, &identity.identity_id).await?;
    next_last_seen_second(&ctx).await?;
    let pending = ctx
        .target
        .check_in(&identity, &json!({ "hostname": "pending-check-in" }))
        .await?;
    expect_status(&pending, 200)?;
    let after_pending = identity_record(&ctx.target, &identity.identity_id).await?;
    let pending_seen = after_pending
        .last_seen_at
        .context("pending check-in did not set the last-seen time")?;
    ensure!(
        pending.body["config"] == enrolled
            && pending.body["renewal_requested"] == true
            && after_pending.has_certificate(&identity.thumbprint, CertificateStatus::Pending)
            && after_pending.metadata_value("hostname") == Some("pending-check-in")
            && before_pending
                .last_seen_at
                .is_none_or(|previous| pending_seen > previous),
        "pending-certificate check-in did not return config or refresh metadata and the last-seen time"
    );
    let before_invalid = after_pending;
    next_last_seen_second(&ctx).await?;
    let signed = identity.key.sign_now(&identity.thumbprint, "check-in", Some(b"{}"));
    expect_error(
        &ctx.target.signed_check_in(b"{}", &signed).await?,
        400,
        "invalid_request",
    )?;
    let undercovered_body = serde_json::to_vec(&json!({ "metadata": { "hostname": "undercovered" } }))?;
    let mut undercovered = identity
        .key
        .sign_now(&identity.thumbprint, "check-in", Some(&undercovered_body));
    undercovered.input = undercovered
        .input
        .replace("(\"@method\" \"content-digest\")", "(\"@method\")");
    resign_input(&identity.key, &mut undercovered)?;
    expect_error(
        &ctx.target.signed_check_in(&undercovered_body, &undercovered).await?,
        401,
        "signature_invalid",
    )?;
    let body = serde_json::to_vec(&json!({ "metadata": { "hostname": "untampered" } }))?;
    let signed = identity.key.sign_now(&identity.thumbprint, "check-in", Some(&body));
    let tampered = serde_json::to_vec(&json!({ "metadata": { "hostname": "tampered" } }))?;
    expect_error(
        &ctx.target.signed_check_in(&tampered, &signed).await?,
        401,
        "signature_invalid",
    )?;
    let after_invalid = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        after_invalid.metadata == before_invalid.metadata && after_invalid.last_seen_at == before_invalid.last_seen_at,
        "invalid check-in changed metadata or the last-seen time"
    );
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let confirmed = ctx.target.check_in(&identity, &json!({})).await?;
    expect_status(&confirmed, 200)?;
    ensure!(
        confirmed.body["renewal_requested"] == false && confirmed.body["config"] == enrolled,
        "confirm did not clear the check-in renewal flag"
    );
    Ok(())
}

pub(crate) async fn p_check_in_cross_tag_signatures_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "check-in-cross-tag").await?;
    let body = serde_json::to_vec(&json!({ "metadata": {} }))?;
    let check_in_tag = identity.key.sign_now(&identity.thumbprint, "check-in", Some(&body));
    expect_error(
        &ctx.target.signed_confirm(&check_in_tag, None).await?,
        401,
        "signature_invalid",
    )?;
    expect_error(
        &ctx.target.signed_renew(&body, &check_in_tag, None).await?,
        401,
        "signature_invalid",
    )?;

    for tag in ["connect", "confirm"] {
        let mut headers = identity.key.sign_now(&identity.thumbprint, tag, None);
        attach_content_digest(&mut headers, &body);
        expect_error(
            &ctx.target.signed_check_in(&body, &headers).await?,
            401,
            "signature_invalid",
        )?;
    }
    let csr = KeyPair::generate()?;
    let renew_body = serde_json::to_vec(&json!({ "csr": csr.csr, "metadata": {} }))?;
    let renew_tag = identity.key.sign_now(&identity.thumbprint, "renew", Some(&renew_body));
    expect_error(
        &ctx.target.signed_check_in(&renew_body, &renew_tag).await?,
        401,
        "signature_invalid",
    )?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .certificates
            .as_ref()
            .is_some_and(|certs| certs.len() == 1 && certs[0].status == CertificateStatus::Current),
        "cross-tag check-in probes changed certificate statuses"
    );
    Ok(())
}

pub(crate) async fn p_check_in_signature_rejected_on_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "check-in-to-connect").await?;
    let body = serde_json::to_vec(&json!({ "metadata": {} }))?;
    let headers = identity.key.sign_now(&identity.thumbprint, "check-in", Some(&body));
    let failure = channel::open_with_headers(&ctx.target, &identity, headers)
        .await
        .err()
        .context("check-in-tagged signature opened a channel")?;
    channel::expect_refused_opening(
        failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
        Code::Unauthenticated,
        "signature_invalid",
    )
}

fn resign_input(key: &KeyPair, headers: &mut SignedHeaders) -> anyhow::Result<()> {
    let input = headers
        .input
        .split_once('=')
        .map(|(_, value)| value)
        .context("missing signature-input member")?;
    let mut base = String::from("\"@method\": POST\n");
    if input
        .split(';')
        .next()
        .is_some_and(|components| components.contains("\"content-digest\""))
    {
        let digest = headers.digest.as_deref().context("missing content digest")?;
        base.push_str(&format!("\"content-digest\": {digest}\n"));
    }
    base.push_str(&format!("\"@signature-params\": {input}"));
    let signature: Signature = key.key.sign(base.as_bytes());
    headers.signature = format!(
        "sig=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    Ok(())
}

fn sign_with_components(
    identity: &Identity,
    tag: &str,
    body: Option<&[u8]>,
    path: &str,
    components: &[&str],
) -> anyhow::Result<SignedHeaders> {
    let mut signed = identity.key.sign_now(&identity.thumbprint, tag, body);
    let profile = if body.is_some() {
        "(\"@method\" \"content-digest\")"
    } else {
        "(\"@method\")"
    };
    let covered = format!(
        "({})",
        components
            .iter()
            .map(|component| format!("\"{component}\""))
            .collect::<Vec<_>>()
            .join(" ")
    );
    ensure!(signed.input.contains(profile), "unexpected signature profile");
    signed.input = signed.input.replacen(profile, &covered, 1);
    let mut base = String::new();
    for component in components {
        match *component {
            "@method" => base.push_str("\"@method\": POST\n"),
            "content-digest" => {
                base.push_str(&format!(
                    "\"content-digest\": {}\n",
                    signed.digest.as_deref().context("missing content-digest")?
                ));
            }
            "@path" => base.push_str(&format!("\"@path\": {path}\n")),
            _ => anyhow::bail!("unexpected covered component {component}"),
        }
    }
    base.push_str(&format!(
        "\"@signature-params\": {}",
        signed.input.strip_prefix("sig=").context("missing signature label")?
    ));
    let signature: Signature = identity.key.key.sign(base.as_bytes());
    identity.key.key.verifying_key().verify(base.as_bytes(), &signature)?;
    signed.signature = format!(
        "sig=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    Ok(signed)
}

pub(crate) async fn p_same_tag_covered_components_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "same-tag-components").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let http_prefix = reqwest::Url::parse(&ctx.target.base_url)?
        .path()
        .trim_end_matches('/')
        .to_owned();
    let next_key = KeyPair::generate()?;
    for tag in ["renew", "check-in", "confirm"] {
        let path = format!("{http_prefix}/api/agent-identity/v1/{tag}");
        for variant in ["over-covered", "reordered", "duplicated"] {
            let with_body = tag != "confirm";
            let components = match (variant, with_body) {
                ("over-covered", true) => vec!["@method", "content-digest", "@path"],
                ("over-covered", false) => vec!["@method", "@path"],
                ("reordered", true) => vec!["content-digest", "@method"],
                ("reordered", false) => continue,
                ("duplicated", true) => vec!["@method", "content-digest", "content-digest"],
                ("duplicated", false) => vec!["@method", "@method"],
                _ => unreachable!("all component variants are known"),
            };
            let body = match tag {
                "renew" => Some(serde_json::to_vec(
                    &json!({ "csr": next_key.csr, "metadata": { "hostname": "must-not-change" } }),
                )?),
                "check-in" => Some(serde_json::to_vec(
                    &json!({ "metadata": { "hostname": "must-not-change" } }),
                )?),
                _ => None,
            };
            let signed = sign_with_components(&identity, tag, body.as_deref(), &path, &components)?;
            let reply = match tag {
                "renew" => {
                    ctx.target
                        .signed_renew(body.as_deref().context("renew body")?, &signed, None)
                        .await?
                }
                "check-in" => {
                    ctx.target
                        .signed_check_in(body.as_deref().context("check-in body")?, &signed)
                        .await?
                }
                "confirm" => ctx.target.signed_confirm(&signed, None).await?,
                _ => unreachable!("all HTTP tags are known"),
            };
            expect_error(&reply, 401, "signature_invalid")
                .with_context(|| format!("{variant} {tag} components were accepted"))?;
            ensure!(
                identity_record(&ctx.target, &identity.identity_id).await? == before,
                "{variant} {tag} components changed identity state"
            );
        }
    }
    Ok(())
}

pub(crate) async fn p_same_tag_connect_components_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "same-tag-connect-components").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let channel_prefix = reqwest::Url::parse(
        identity
            .agent_channel_url
            .as_deref()
            .context("same-tag connect requires a channel URL")?,
    )?
    .path()
    .trim_end_matches('/')
    .to_owned();
    let path = format!("{channel_prefix}/devolutions.agent.channel.v1.AgentChannel/Connect");
    for (variant, components) in [
        ("over-covered", &["@method", "@path"][..]),
        ("duplicated", &["@method", "@method"][..]),
    ] {
        let signed = sign_with_components(&identity, "connect", None, &path, components)?;
        let failure = channel::open_with_headers(&ctx.target, &identity, signed)
            .await
            .err()
            .with_context(|| format!("{variant} connect components authenticated a channel"))?;
        channel::expect_refused_opening(
            failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
            Code::Unauthenticated,
            "signature_invalid",
        )?;
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await? == before,
            "{variant} connect components changed identity state"
        );
    }
    Ok(())
}

pub(crate) async fn p_extra_signature_parameters_rejected_renew(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "extra-renew-parameter").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": key.csr, "metadata": { "hostname": "unchanged" } }))?;
    for parameter in [";conformance=\"extra\"", ";conformance"] {
        let mut headers = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
        headers.input.push_str(parameter);
        resign_input(&identity.key, &mut headers)?;
        expect_error(
            &ctx.target.signed_renew(&body, &headers, None).await?,
            401,
            "signature_invalid",
        )?;
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await? == before,
            "extra {parameter} renew signature parameter changed identity state"
        );
    }
    Ok(())
}

pub(crate) async fn p_extra_signature_parameters_rejected_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "extra-connect-parameter").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    for parameter in [";conformance=\"extra\"", ";conformance"] {
        let mut headers = identity.key.sign_now(&identity.thumbprint, "connect", None);
        headers.input.push_str(parameter);
        resign_input(&identity.key, &mut headers)?;
        let failure = channel::open_with_headers(&ctx.target, &identity, headers)
            .await
            .err()
            .with_context(|| format!("extra {parameter} parameter authenticated a channel"))?;
        channel::expect_refused_opening(
            failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
            Code::Unauthenticated,
            "signature_invalid",
        )?;
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await? == before,
            "extra {parameter} connect signature parameter changed identity state"
        );
    }
    Ok(())
}

pub(crate) async fn p_signature_parser_wire_negatives(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "wire-negatives").await?;
    let original = identity_record(&ctx.target, &identity.identity_id).await?;
    let key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": key.csr, "metadata": { "hostname": "rejected" } }))?;
    for variant in [
        "missing_digest",
        "missing_created",
        "missing_expires",
        "missing_nonce",
        "missing_keyid",
        "missing_alg",
        "missing_tag",
        "wrong_alg",
        "wrong_label",
        "two_signatures",
        "digest_not_covered",
        "two_digest_members",
        "bad_nonce",
        "der_signature",
        "truncated_signature",
    ] {
        let mut headers = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
        match variant {
            "missing_digest" => headers.digest = None,
            "missing_created" | "missing_expires" | "missing_nonce" | "missing_keyid" | "missing_alg"
            | "missing_tag" => {
                let name = variant.strip_prefix("missing_").context("missing parameter")?;
                headers.input = headers
                    .input
                    .split(';')
                    .filter(|param| !param.starts_with(&format!("{name}=")))
                    .collect::<Vec<_>>()
                    .join(";");
                resign_input(&identity.key, &mut headers)?;
            }
            "wrong_alg" => {
                headers.input = headers.input.replace("ecdsa-p256-sha256", "ecdsa-p384-sha384");
                resign_input(&identity.key, &mut headers)?;
            }
            "wrong_label" => {
                headers.input = headers.input.replacen("sig=", "sig1=", 1);
                headers.signature = headers.signature.replacen("sig=", "sig1=", 1);
            }
            "two_signatures" => {
                let second_input = headers.input[4..].to_owned();
                let second_signature = headers.signature[4..].to_owned();
                headers.input.push_str(&format!(", sig2={second_input}"));
                headers.signature.push_str(&format!(", sig2={second_signature}"));
            }
            "digest_not_covered" => {
                headers.input = headers
                    .input
                    .replace("(\"@method\" \"content-digest\")", "(\"@method\")");
                resign_input(&identity.key, &mut headers)?;
            }
            "two_digest_members" => {
                let digest = headers.digest.take().context("signed content digest")?;
                let sha512 = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&body));
                headers.digest = Some(format!("{digest}, sha-512=:{sha512}:"));
                resign_input(&identity.key, &mut headers)?;
            }
            "bad_nonce" => {
                headers.input = headers.input.replace(&headers.nonce, "not-base64url!");
                resign_input(&identity.key, &mut headers)?;
            }
            "der_signature" | "truncated_signature" => {
                let encoded = headers
                    .signature
                    .strip_prefix("sig=:")
                    .and_then(|value| value.strip_suffix(':'))
                    .context("signature encoding")?;
                let raw = base64::engine::general_purpose::STANDARD.decode(encoded)?;
                let signature = if variant == "der_signature" {
                    Signature::from_slice(&raw)?.to_der().as_bytes().to_vec()
                } else {
                    raw[..raw.len() - 1].to_vec()
                };
                headers.signature = format!("sig=:{}:", base64::engine::general_purpose::STANDARD.encode(signature));
            }
            _ => anyhow::bail!("unknown wire-negative variant"),
        }
        expect_error(
            &ctx.target.signed_renew(&body, &headers, None).await?,
            401,
            "signature_invalid",
        )
        .with_context(|| format!("wire-negative variant {variant}"))?;
        let after = identity_record(&ctx.target, &identity.identity_id).await?;
        ensure!(
            after.metadata == original.metadata
                && after.certificates == original.certificates
                && after.last_seen_at == original.last_seen_at,
            "wire-negative variant {variant} changed identity state"
        );
    }
    let check_in_body = serde_json::to_vec(&json!({ "metadata": { "hostname": "rejected-check-in" } }))?;
    let mut check_in_headers = identity
        .key
        .sign_now(&identity.thumbprint, "check-in", Some(&check_in_body));
    let digest = check_in_headers
        .digest
        .take()
        .context("signed check-in digest missing")?;
    let sha512 = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&check_in_body));
    check_in_headers.digest = Some(format!("{digest}, sha-512=:{sha512}:"));
    resign_input(&identity.key, &mut check_in_headers)?;
    expect_error(
        &ctx.target.signed_check_in(&check_in_body, &check_in_headers).await?,
        401,
        "signature_invalid",
    )?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id).await? == original,
        "correctly signed check-in with two Content-Digest members changed identity state"
    );
    for (tag, request_body) in [("renew", &body), ("check-in", &check_in_body)] {
        let repeated_fields: &[&str] = if tag == "renew" {
            &["content-digest", "signature-input", "signature"]
        } else {
            &["content-digest"]
        };
        for &repeated in repeated_fields {
            let mut signed = identity.key.sign_now(&identity.thumbprint, tag, Some(request_body));
            let digest = signed.digest.as_deref().context("signed digest missing")?.to_owned();
            if repeated == "content-digest" {
                signed.digest = Some(format!("{digest}, {digest}"));
                resign_input(&identity.key, &mut signed)?;
            }
            let mut headers = http::HeaderMap::new();
            headers.insert("content-digest", digest.parse()?);
            headers.insert("signature-input", signed.input.parse()?);
            headers.insert("signature", signed.signature.parse()?);
            let repeated_value = match repeated {
                "content-digest" => &digest,
                "signature-input" => &signed.input,
                "signature" => &signed.signature,
                _ => unreachable!("all repeated names are known"),
            };
            headers.append(repeated, repeated_value.parse()?);
            let response = ctx
                .target
                .http
                .post(format!("{}/api/agent-identity/v1/{tag}", ctx.target.base_url))
                .headers(headers)
                .header("content-type", "application/json")
                .body(request_body.clone())
                .send()
                .await?;
            let reply = Reply {
                status: response.status().as_u16(),
                body: response.json().await?,
            };
            expect_error(&reply, 401, "signature_invalid")?;
            ensure!(
                identity_record(&ctx.target, &identity.identity_id).await? == original,
                "duplicate {repeated} headers on {tag} changed identity state"
            );
        }
    }
    Ok(())
}

pub(crate) async fn p_signature_noncanonical_base64_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "noncanonical-base64").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": key.csr, "metadata": { "hostname": "rejected" } }))?;
    let sign = || identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
    for (variant, headers) in [
        (
            "signature with non-zero pad bits",
            rewrite_signature(sign(), with_nonzero_pad_bits)?,
        ),
        ("unpadded signature", rewrite_signature(sign(), without_padding)?),
        (
            "digest with non-zero pad bits",
            rewrite_digest(&identity.key, sign(), with_nonzero_pad_bits)?,
        ),
        (
            "unpadded digest",
            rewrite_digest(&identity.key, sign(), without_padding)?,
        ),
    ] {
        expect_error(
            &ctx.target.signed_renew(&body, &headers, None).await?,
            401,
            "signature_invalid",
        )
        .with_context(|| format!("renew {variant}"))?;
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await? == before,
            "renew {variant} changed identity state"
        );
    }
    Ok(())
}

pub(crate) async fn p_signature_repeated_raw_items_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "repeated-raw-items").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": key.csr, "metadata": { "hostname": "rejected" } }))?;
    let sign = || identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
    for (variant, headers) in [
        (
            "tag parameter signed over the received member",
            resigned(&identity.key, with_repeated_tag(sign(), "renew"))?,
        ),
        (
            "tag parameter signed over the member a last-wins parser keeps",
            with_repeated_tag(sign(), "renew"),
        ),
        ("Signature-Input label in one field", with_repeated_input_label(sign())),
        ("Signature label in one field", with_repeated_signature_label(sign())),
        (
            "Content-Digest member signed over the received field",
            resigned(&identity.key, with_repeated_digest_member(sign())?)?,
        ),
    ] {
        expect_error(
            &ctx.target.signed_renew(&body, &headers, None).await?,
            401,
            "signature_invalid",
        )
        .with_context(|| format!("renew with a repeated {variant}"))?;
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await? == before,
            "renew with a repeated {variant} changed identity state"
        );
    }
    Ok(())
}

pub(crate) async fn p_connect_signature_noncanonical_or_repeated_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "connect-wire-negatives").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let sign = || identity.key.sign_now(&identity.thumbprint, "connect", None);
    for (variant, headers) in [
        (
            "signature with non-zero pad bits",
            rewrite_signature(sign(), with_nonzero_pad_bits)?,
        ),
        ("unpadded signature", rewrite_signature(sign(), without_padding)?),
        (
            "repeated tag signed over the received member",
            resigned(&identity.key, with_repeated_tag(sign(), "connect"))?,
        ),
        (
            "repeated tag signed over the member a last-wins parser keeps",
            with_repeated_tag(sign(), "connect"),
        ),
        (
            "Signature-Input label repeated in one value",
            with_repeated_input_label(sign()),
        ),
        (
            "Signature label repeated in one value",
            with_repeated_signature_label(sign()),
        ),
    ] {
        let failure = channel::open_with_headers(&ctx.target, &identity, headers)
            .await
            .err()
            .with_context(|| format!("connect {variant} opened a channel"))?;
        channel::expect_refused_opening(
            failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
            Code::Unauthenticated,
            "signature_invalid",
        )
        .with_context(|| format!("connect {variant}"))?;
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await? == before,
            "connect {variant} changed identity state"
        );
    }
    Ok(())
}

fn resigned(key: &KeyPair, mut headers: SignedHeaders) -> anyhow::Result<SignedHeaders> {
    resign_input(key, &mut headers)?;
    Ok(headers)
}

fn rewrite_signature(
    mut headers: SignedHeaders,
    rewrite: fn(&str) -> anyhow::Result<String>,
) -> anyhow::Result<SignedHeaders> {
    headers.signature = rewrite(&headers.signature)?;
    Ok(headers)
}

/// Rewrites `Content-Digest` and signs the rewritten value, so only its encoding is wrong.
fn rewrite_digest(
    key: &KeyPair,
    mut headers: SignedHeaders,
    rewrite: fn(&str) -> anyhow::Result<String>,
) -> anyhow::Result<SignedHeaders> {
    headers.digest = Some(rewrite(headers.digest.as_deref().context("signed content digest")?)?);
    resigned(key, headers)
}

/// Appends a second, identical `tag` parameter without re-signing.
///
/// The signature still covers the member that an RFC 8941 parser keeps, since it retains only the last occurrence.
fn with_repeated_tag(mut headers: SignedHeaders, tag: &str) -> SignedHeaders {
    headers.input.push_str(&format!(";tag=\"{tag}\""));
    headers
}

/// Repeats the whole `sig` member in one `Signature-Input` value; both copies match the signed member.
fn with_repeated_input_label(mut headers: SignedHeaders) -> SignedHeaders {
    headers.input = format!("{0}, {0}", headers.input);
    headers
}

/// Repeats the whole `sig` member in one `Signature` value; both copies carry the valid signature.
fn with_repeated_signature_label(mut headers: SignedHeaders) -> SignedHeaders {
    headers.signature = format!("{0}, {0}", headers.signature);
    headers
}

/// Repeats the `sha-256` member in one `Content-Digest` value without re-signing.
///
/// A covered header's signature-base value is its raw field value (RFC 9421 §2.1), so only a signature over the repeated value isolates the duplicate rule.
fn with_repeated_digest_member(mut headers: SignedHeaders) -> anyhow::Result<SignedHeaders> {
    let digest = headers.digest.as_deref().context("signed content digest")?;
    headers.digest = Some(format!("{digest}, {digest}"));
    Ok(headers)
}

/// Splits an RFC 8941 byte sequence field value such as `sig=:<base64>:` around its base64 text.
fn split_byte_sequence(value: &str) -> anyhow::Result<(&str, &str)> {
    let (prefix, rest) = value.split_once(':').context("field value has no byte sequence")?;
    let encoded = rest.strip_suffix(':').context("byte sequence is not terminated")?;
    Ok((prefix, encoded))
}

/// Sets a padding bit of the last base64 character, so lenient decoders still return the same bytes.
fn with_nonzero_pad_bits(value: &str) -> anyhow::Result<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (prefix, encoded) = split_byte_sequence(value)?;
    let data = encoded.trim_end_matches('=');
    let padding = encoded.len() - data.len();
    ensure!(matches!(padding, 1 | 2), "byte sequence has no padding bits");
    let (head, last) = data.split_at(data.len() - 1);
    let index = ALPHABET
        .iter()
        .position(|symbol| last.as_bytes() == [*symbol])
        .context("byte sequence is not base64")?;
    ensure!(index & 1 == 0, "byte sequence already has non-zero padding bits");
    Ok(format!(
        "{prefix}:{head}{}{}:",
        char::from(ALPHABET[index | 1]),
        "=".repeat(padding)
    ))
}

fn without_padding(value: &str) -> anyhow::Result<String> {
    let (prefix, encoded) = split_byte_sequence(value)?;
    let data = encoded.trim_end_matches('=');
    ensure!(data.len() < encoded.len(), "byte sequence has no padding");
    Ok(format!("{prefix}:{data}:"))
}

pub(crate) async fn p_renew_happy_path(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "unchanged").await?;
    let original_name = identity_record(&ctx.target, &identity.identity_id).await?.friendly_name;
    let new_key = KeyPair::generate()?;
    let reply = signed_renew(&ctx.target, &identity, &new_key, &json!({ "hostname": "updated" })).await?;
    expect_status(&reply, 200)?;
    let new_chain = reply.body["certificate_chain"]
        .as_array()
        .context("renew chain")?
        .iter()
        .map(|item| item.as_str().context("chain item").map(str::to_owned))
        .collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(!new_chain.is_empty(), "renewal returned no certificate");
    verify_chain(
        &new_chain,
        &ctx.target.trust_anchor().await?,
        chain_evaluation_time(&ctx).await?,
    )?;
    assert_leaf_profile(
        &new_chain[0],
        new_chain.last().context("missing renewal issuer")?,
        &identity.identity_id,
        &new_key,
        ctx.leaf_lifetime_secs,
    )?;
    identity.adopt_certificate(&reply.body["certificate_chain"], new_key)?;
    let pending = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        pending.has_certificate(&identity.thumbprint, CertificateStatus::Pending),
        "new certificate not pending"
    );
    ensure!(
        pending.friendly_name == original_name,
        "friendly name changed on renewal"
    );
    ensure!(
        pending.metadata_value("hostname") == Some("updated"),
        "renewal metadata not updated"
    );
    let replay_key = KeyPair {
        key: identity.key.key.clone(),
        csr: identity.key.csr.clone(),
    };
    if ctx.mock() {
        ctx.target.advance(2).await?;
    }
    expect_status(
        &ctx.target
            .renew(&identity, &replay_key, &json!({ "hostname": "pending-replay" }))
            .await?,
        200,
    )?;
    let replayed = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        replayed.has_certificate(&identity.thumbprint, CertificateStatus::Pending)
            && replayed.metadata_value("hostname") == Some("pending-replay"),
        "replayed renew did not update metadata or promoted the pending certificate"
    );
    if ctx.mock() {
        ensure!(
            replayed.last_seen_at > pending.last_seen_at,
            "replayed renew did not refresh the last-seen time"
        );
    }
    ensure!(
        replayed.friendly_name == original_name,
        "replayed renew changed friendly name"
    );
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .has_certificate(&identity.thumbprint, CertificateStatus::Current),
        "confirm did not promote the pending certificate"
    );
    Ok(())
}

pub(crate) async fn p_confirm_promotes_and_is_idempotent(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "confirm-idempotent").await?;
    let old_thumb = identity.thumbprint.clone();
    let original = identity_record(&ctx.target, &identity.identity_id).await?;
    let initial_seen = original.last_seen_at.context("new identity has no last-seen time")?;
    let original_events = if ctx.mock() {
        Some(ctx.target.events(&identity.identity_id).await?)
    } else {
        None
    };
    next_last_seen_second(&ctx).await?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let already_current = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        already_current.certificates == original.certificates
            && initial_seen
                < already_current
                    .last_seen_at
                    .context("current confirm omitted the last-seen time")?,
        "confirm with an already current certificate changed status or did not refresh the last-seen time"
    );
    if let Some(events) = &original_events {
        ensure!(
            ctx.target.events(&identity.identity_id).await? == *events,
            "confirm with an already current certificate emitted a lifecycle event"
        );
    }

    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let before_promotion = identity_record(&ctx.target, &identity.identity_id).await?;
    next_last_seen_second(&ctx).await?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let promoted = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        promoted.has_certificate(&old_thumb, CertificateStatus::Retired)
            && promoted.has_certificate(&identity.thumbprint, CertificateStatus::Current)
            && before_promotion
                .last_seen_at
                .context("renew omitted the last-seen time")?
                < promoted
                    .last_seen_at
                    .context("pending confirm omitted the last-seen time")?,
        "confirm did not promote pending, retire current or refresh the last-seen time"
    );
    let events = if ctx.mock() {
        Some(ctx.target.events(&identity.identity_id).await?)
    } else {
        None
    };
    next_last_seen_second(&ctx).await?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let replayed = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        replayed.certificates == promoted.certificates
            && promoted
                .last_seen_at
                .context("confirmed identity omitted the last-seen time")?
                < replayed
                    .last_seen_at
                    .context("confirm retry omitted the last-seen time")?,
        "idempotent confirm retry changed certificate statuses or failed to refresh the last-seen time"
    );
    if let Some(events) = events {
        ensure!(
            ctx.target.events(&identity.identity_id).await? == events,
            "idempotent confirm retry emitted another promotion"
        );
    }
    Ok(())
}

pub(crate) async fn p_confirm_retired_certificate_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "retired-confirm").await?;
    let first_key = KeyPair::generate()?;
    let first = ctx.target.renew(&identity, &first_key, &json!({})).await?;
    expect_status(&first, 200)?;
    let first_thumb = thumbprint(
        first.body["certificate_chain"][0]
            .as_str()
            .context("first pending leaf")?,
    )?;
    let second = ctx.target.renew(&identity, &KeyPair::generate()?, &json!({})).await?;
    expect_status(&second, 200)?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        before.has_certificate(&first_thumb, CertificateStatus::Retired),
        "replacement did not retire the first pending certificate"
    );
    let signed = first_key.sign_now(&first_thumb, "confirm", None);
    expect_error(
        &ctx.target.signed_confirm(&signed, None).await?,
        401,
        "identity_unknown",
    )?;
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &before).await?;
    Ok(())
}

pub(crate) async fn p_confirm_expired_pending_certificate_rejected(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 20 })).await?;
    let (_, mut identity) = issued(&ctx, "expired-confirm").await?;
    let old_thumb = identity.thumbprint.clone();
    let old_key = KeyPair {
        key: identity.key.key.clone(),
        csr: identity.key.csr.clone(),
    };
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    ctx.target.advance(21).await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    expect_error(&ctx.target.confirm(&identity).await?, 401, "certificate_expired")?;
    expect_error(
        &ctx.target
            .check_in(&identity, &json!({ "hostname": "expired-pending" }))
            .await?,
        401,
        "certificate_expired",
    )?;
    let old_confirm = old_key.sign_now(&old_thumb, "confirm", None);
    expect_error(
        &ctx.target.signed_confirm(&old_confirm, None).await?,
        401,
        "certificate_expired",
    )?;
    let old_body = serde_json::to_vec(&json!({ "metadata": { "hostname": "expired-current" } }))?;
    let old_check_in = old_key.sign_now(&old_thumb, "check-in", Some(&old_body));
    expect_error(
        &ctx.target.signed_check_in(&old_body, &old_check_in).await?,
        401,
        "certificate_expired",
    )?;
    let after = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        after.certificates == before.certificates
            && after.metadata == before.metadata
            && after.last_seen_at == before.last_seen_at
            && after.has_certificate(&old_thumb, CertificateStatus::Current)
            && after.has_certificate(&identity.thumbprint, CertificateStatus::Pending),
        "expired current or pending check-in/confirm changed identity state"
    );
    Ok(())
}

pub(crate) async fn p_confirm_nonempty_body_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "confirm-body").await?;
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let signed = identity.key.sign_now(&identity.thumbprint, "confirm", None);
    expect_error(
        &ctx.target.signed_confirm(&signed, Some(b"{}")).await?,
        400,
        "invalid_request",
    )?;
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &before).await?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    Ok(())
}

pub(crate) async fn p_confirm_faults_do_not_duplicate_promotion(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "confirm-faults").await?;
    let old_thumb = identity.thumbprint.clone();
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    expect_status(
        &ctx.target
            .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
            .await?,
        200,
    )?;
    ctx.target
        .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
        .await?;
    expect_status(&ctx.target.confirm(&identity).await?, 503)?;
    expect_status(&ctx.target.confirm(&identity).await?, 503)?;
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &before).await?;
    expect_status(
        &ctx.target
            .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
            .await?,
        200,
    )?;

    ctx.target.faults(&json!({ "drop_next_response": "confirm" })).await?;
    ensure!(
        ctx.target.confirm(&identity).await.is_err(),
        "dropped confirm returned a response"
    );
    let promoted = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        promoted.has_certificate(&old_thumb, CertificateStatus::Retired)
            && promoted.has_certificate(&identity.thumbprint, CertificateStatus::Current),
        "dropped confirm did not commit the promotion"
    );
    let events = ctx.target.events(&identity.identity_id).await?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let requests = ctx.target.requests(None).await?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id).await?.certificates == promoted.certificates
            && ctx.target.events(&identity.identity_id).await? == events
            && count(&requests, "confirm")? == 4
            && count(&requests, "confirm_retry_503")? == 1
            && requests["request_sequence"].as_array().is_some_and(|sequence| sequence
                .iter()
                .filter(|entry| *entry == "confirm_204")
                .count()
                == 2),
        "idempotent confirm retry duplicated the promotion"
    );
    Ok(())
}

pub(crate) async fn p_renew_idempotent_lost_response(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "lost-renew").await?;
    let new_key = KeyPair::generate()?;
    expect_status(
        &ctx.target
            .control("retry-barrier", &json!({ "endpoint": "renew", "pause": true }))
            .await?,
        200,
    )?;
    ctx.target.faults(&json!({ "drop_next_response": "renew" })).await?;
    let first = ctx.target.renew(&identity, &new_key, &json!({})).await;
    ensure!(first.is_err(), "fault did not drop the renew response");
    let pending = identity_record(&ctx.target, &identity.identity_id).await?;
    let pending_certs = pending
        .certificates
        .as_ref()
        .context("missing certificates")?
        .iter()
        .filter(|cert| cert.status == CertificateStatus::Pending)
        .collect::<Vec<_>>();
    ensure!(
        pending_certs.len() == 1,
        "lost response did not commit exactly one pending certificate"
    );
    expect_status(&ctx.target.renew(&identity, &new_key, &json!({})).await?, 503)?;
    ensure!(
        count(&ctx.target.requests(None).await?, "renew_retry_503")? == 1,
        "mock did not block the renewal retry"
    );
    expect_status(
        &ctx.target
            .control("retry-barrier", &json!({ "endpoint": "renew", "pause": false }))
            .await?,
        200,
    )?;
    let retry = ctx.target.renew(&identity, &new_key, &json!({})).await?;
    expect_status(&retry, 200)?;
    let retry_thumbprint = thumbprint(retry.body["certificate_chain"][0].as_str().context("retry leaf")?)?;
    ensure!(
        pending_certs[0].thumbprint == retry_thumbprint,
        "renew retry issued a second certificate"
    );
    Ok(())
}

pub(crate) async fn p_mock_enroll_retry_barrier(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 1).await?;
    let key = KeyPair::generate()?;
    expect_status(
        &ctx.target
            .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": true }))
            .await?,
        200,
    )?;
    ctx.target.faults(&json!({ "drop_next_response": "enroll" })).await?;
    ensure!(
        ctx.target.enroll(&token.text, &key, &json!({})).await.is_err(),
        "fault did not drop the enrollment response"
    );
    let listing = ctx
        .target
        .management()
        .identities(&IdentityQuery::enrolled_with(&token))
        .await?;
    ensure!(
        listing.total_count == 1 && ctx.target.management().token(&token.id).await?.used_count == 1,
        "dropped enrollment did not commit once"
    );
    expect_status(&ctx.target.enroll(&token.text, &key, &json!({})).await?, 503)?;
    ensure!(
        count(&ctx.target.requests(Some(&token)).await?, "enroll_retry_503")? == 1,
        "mock did not block the enrollment retry"
    );
    expect_status(
        &ctx.target
            .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": false }))
            .await?,
        200,
    )?;
    let replay = ctx.target.enroll(&token.text, &key, &json!({})).await?;
    expect_status(&replay, 200)?;
    ensure!(
        replay.body["identity_id"] == listing.items[0].id
            && ctx.target.management().token(&token.id).await?.used_count == 1,
        "replay created a second identity or consumed another use"
    );
    ctx.target
        .management()
        .revoke(field(&replay.body, "identity_id")?)
        .await?;
    expect_error(
        &ctx.target.enroll(&token.text, &key, &json!({})).await?,
        403,
        "identity_revoked",
    )?;
    ensure!(
        count(&ctx.target.requests(Some(&token)).await?, "enroll_identity_revoked")? == 1,
        "mock did not record the revoked-key enrollment rejection"
    );
    Ok(())
}

pub(crate) async fn p_renew_second_pending_retires_first(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "pending").await?;
    let first_key = KeyPair::generate()?;
    let first = ctx.target.renew(&identity, &first_key, &json!({})).await?;
    expect_status(&first, 200)?;
    let first_thumb = thumbprint(first.body["certificate_chain"][0].as_str().context("first leaf")?)?;
    let second_key = KeyPair::generate()?;
    let second = ctx.target.renew(&identity, &second_key, &json!({})).await?;
    expect_status(&second, 200)?;
    let second_thumb = thumbprint(second.body["certificate_chain"][0].as_str().context("second leaf")?)?;
    let current = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        current.has_certificate(&first_thumb, CertificateStatus::Retired),
        "first pending certificate was not retired"
    );
    ensure!(
        current.has_certificate(&second_thumb, CertificateStatus::Pending),
        "second pending certificate missing"
    );
    let old = Identity {
        thumbprint: first_thumb,
        certificate_chain: first.body["certificate_chain"]
            .as_array()
            .context("first chain")?
            .iter()
            .map(|c| c.as_str().context("chain item").map(str::to_owned))
            .collect::<anyhow::Result<_>>()?,
        key: first_key,
        ..identity
    };
    expect_error(
        &ctx.target.renew(&old, &KeyPair::generate()?, &json!({})).await?,
        401,
        "identity_unknown",
    )?;
    Ok(())
}

pub(crate) async fn p_retired_pending_certificate_cannot_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "retired-connect").await?;
    let first_key = KeyPair::generate()?;
    let first = ctx.target.renew(&identity, &first_key, &json!({})).await?;
    expect_status(&first, 200)?;
    expect_status(
        &ctx.target.renew(&identity, &KeyPair::generate()?, &json!({})).await?,
        200,
    )?;
    let old = Identity {
        thumbprint: thumbprint(first.body["certificate_chain"][0].as_str().context("retired leaf")?)?,
        certificate_chain: first.body["certificate_chain"]
            .as_array()
            .context("retired chain")?
            .iter()
            .map(|cert| cert.as_str().context("chain item").map(str::to_owned))
            .collect::<anyhow::Result<Vec<_>>>()?,
        key: first_key,
        ..identity
    };
    let error = match channel::open(&ctx.target, &old).await {
        Ok(_) => anyhow::bail!("retired pending certificate opened a channel"),
        Err(error) => error,
    };
    let status = error
        .downcast_ref::<tonic::Status>()
        .context("no gRPC status for retired certificate")?;
    channel::expect_refused_opening(status, Code::Unauthenticated, "identity_unknown")?;
    Ok(())
}

pub(crate) async fn p_renew_within_grace(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 4 })).await?;
    let (_, identity) = issued(&ctx, "grace").await?;
    ctx.target.advance(5).await?;
    let key = KeyPair::generate()?;
    let reply = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&reply, 200)?;
    let chain = reply.body["certificate_chain"]
        .as_array()
        .context("grace renewal chain missing")?
        .iter()
        .map(|value| value.as_str().context("grace chain item").map(str::to_owned))
        .collect::<anyhow::Result<Vec<_>>>()?;
    verify_chain(
        &chain,
        &ctx.target.trust_anchor().await?,
        chain_evaluation_time(&ctx).await?,
    )?;
    assert_leaf_profile(
        chain.first().context("grace leaf missing")?,
        chain.last().context("grace root missing")?,
        &identity.identity_id,
        &key,
        4,
    )?;
    Ok(())
}

pub(crate) async fn p_renew_beyond_grace(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 4 })).await?;
    let (_, identity) = issued(&ctx, "too-late").await?;
    ctx.target.advance(9).await?;
    let reply = ctx.target.renew(&identity, &KeyPair::generate()?, &json!({})).await?;
    expect_error(&reply, 401, "certificate_expired")?;
    Ok(())
}

pub(crate) async fn p_revocation_blocks_renew_and_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "revoke").await?;
    ctx.target.management().revoke(&identity.identity_id).await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let reply = ctx.target.renew(&identity, &KeyPair::generate()?, &json!({})).await?;
    expect_error(&reply, 403, "identity_revoked")?;
    expect_error(&ctx.target.confirm(&identity).await?, 403, "identity_revoked")?;
    expect_error(
        &ctx.target
            .check_in(&identity, &json!({ "hostname": "should-not-update" }))
            .await?,
        403,
        "identity_revoked",
    )?;
    let next = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": next.csr, "metadata": { "hostname": "correct" } }))?;
    let signed = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
    let altered = serde_json::to_vec(&json!({ "csr": next.csr, "metadata": { "hostname": "tampered" } }))?;
    expect_error(
        &ctx.target.signed_renew(&altered, &signed, None).await?,
        403,
        "identity_revoked",
    )?;
    let wrong_signer = KeyPair::generate()?.sign_now(&identity.thumbprint, "renew", Some(&body));
    expect_error(
        &ctx.target.signed_renew(&body, &wrong_signer, None).await?,
        403,
        "identity_revoked",
    )?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id).await? == before,
        "revoked renew, confirm or check-in changed identity state"
    );
    Ok(())
}

pub(crate) async fn p_revocation_blocks_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "revoked-connect").await?;
    ctx.target.management().revoke(&identity.identity_id).await?;
    let status = channel::open(&ctx.target, &identity)
        .await
        .err()
        .context("revoked cert connected")?;
    channel::expect_refused_opening(
        status
            .downcast_ref::<tonic::Status>()
            .context("revoked open did not yield gRPC status")?,
        Code::PermissionDenied,
        "identity_revoked",
    )?;
    Ok(())
}

pub(crate) async fn p_delete_only_when_revoked_then_unknown(ctx: Context) -> anyhow::Result<()> {
    let (token, identity) = issued(&ctx, "delete").await?;
    let management = ctx.target.management();
    ensure!(
        refusal(management.delete_identity(&identity.identity_id).await)? == Refusal::Conflict,
        "an identity that is not revoked was deleted"
    );
    management.revoke(&identity.identity_id).await?;
    management.delete_identity(&identity.identity_id).await?;
    let reply = ctx.target.renew(&identity, &KeyPair::generate()?, &json!({})).await?;
    expect_error(&reply, 401, "identity_unknown")?;
    expect_error(&ctx.target.confirm(&identity).await?, 401, "identity_unknown")?;
    expect_error(
        &ctx.target
            .check_in(&identity, &json!({ "hostname": "should-not-update" }))
            .await?,
        401,
        "identity_unknown",
    )?;
    let next = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": next.csr, "metadata": { "hostname": "correct" } }))?;
    let signed = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
    let altered = serde_json::to_vec(&json!({ "csr": next.csr, "metadata": { "hostname": "tampered" } }))?;
    expect_error(
        &ctx.target.signed_renew(&altered, &signed, None).await?,
        401,
        "identity_unknown",
    )?;
    let wrong_signer = KeyPair::generate()?.sign_now(&identity.thumbprint, "renew", Some(&body));
    expect_error(
        &ctx.target.signed_renew(&body, &wrong_signer, None).await?,
        401,
        "identity_unknown",
    )?;
    ensure!(
        ctx.target
            .management()
            .find_identity(&identity.identity_id)
            .await?
            .is_none()
            && ctx.target.management().identity_count(&token).await? == 0
            && ctx.target.management().token(&token.id).await?.used_count == 1,
        "deleted key was reintroduced by renew, confirm or check-in"
    );
    Ok(())
}

pub(crate) async fn p_deleted_certificate_cannot_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "deleted-connect").await?;
    ctx.target.management().revoke(&identity.identity_id).await?;
    ctx.target.management().delete_identity(&identity.identity_id).await?;
    let status = channel::open(&ctx.target, &identity)
        .await
        .err()
        .context("deleted cert connected")?;
    channel::expect_refused_opening(
        status
            .downcast_ref::<tonic::Status>()
            .context("deleted open did not yield gRPC status")?,
        Code::Unauthenticated,
        "identity_unknown",
    )?;
    Ok(())
}

pub(crate) async fn p_channel_hello_updates_metadata_and_connected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "initial").await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let challenge = stream.challenge().await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(!before.connected, "identity connected before Hello");
    ensure!(
        before.metadata_value("hostname") == Some("initial"),
        "metadata updated before Hello"
    );
    if ctx.mock() {
        ctx.target.advance(2).await?;
    } else {
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }
    let hello_id = stream
        .send_hello(
            &identity,
            &challenge,
            &[("hostname", "channel"), ("arch", "x86_64")],
            None,
        )
        .await?;
    let welcome = stream.next().await?;
    let Some(agent_channel_proto::server_message::Payload::Welcome(payload)) = welcome.payload else {
        anyhow::bail!("channel did not send Welcome");
    };
    ensure!(
        welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "Welcome correlation is wrong"
    );
    let server_time = payload.server_time.context("Welcome omitted server_time")?;
    let after = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(after.connected, "identity not connected after Hello");
    ensure!(
        after.metadata_value("hostname") == Some("channel") && after.metadata_value("arch") == Some("x86_64"),
        "Hello metadata not stored"
    );
    let after_time = after
        .last_seen_at
        .context("Hello did not set the last-seen time")?
        .unix_timestamp();
    if let Some(before_time) = before.last_seen_at {
        ensure!(
            after_time > before_time.unix_timestamp(),
            "Hello did not advance the last-seen time"
        );
    }
    ensure!(
        server_time.seconds.abs_diff(after_time) <= 2,
        "Welcome server_time disagrees with the last-seen time"
    );
    Ok(())
}

pub(crate) async fn p_channel_agent_message_refreshes_last_seen(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "agent-message").await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    stream.hello(&identity, &[]).await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let seen_before = before
        .last_seen_at
        .context("authenticated Hello omitted the last-seen time")?;
    next_last_seen_second(&ctx).await?;
    ctx.target.management().request_renewal(&identity.identity_id).await?;
    let request = stream.next().await?;
    ensure!(
        matches!(
            request.payload.as_ref(),
            Some(agent_channel_proto::server_message::Payload::RenewRequested(_))
        ),
        "authenticated stream did not receive RenewRequested"
    );
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .last_seen_at
            .context("management API request omitted the last-seen time")?
            == seen_before,
        "management API request or server push refreshed the last-seen time before AgentMessage"
    );
    stream.ack(&request).await?;
    let started = Instant::now();
    loop {
        let after = identity_record(&ctx.target, &identity.identity_id).await?;
        if seen_before < after.last_seen_at.context("AgentMessage omitted the last-seen time")? {
            break;
        }
        ensure!(
            started.elapsed() < Duration::from_secs(5),
            "authenticated AgentMessage did not refresh the last-seen time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

pub(crate) async fn p_handshake_barrier_holds_authentication(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "barrier").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    expect_status(&ctx.target.control("handshake", &json!({ "pause": true })).await?, 200)?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let challenge = stream.challenge().await?;
    let hello_id = stream
        .send_hello(&identity, &challenge, &[("hostname", "after-pause")], None)
        .await?;
    let started = Instant::now();
    loop {
        if count(&ctx.target.requests(None).await?, "paused_hellos")? == 1 {
            break;
        }
        ensure!(
            started.elapsed() < Duration::from_secs(2),
            "valid Hello never reached the handshake barrier"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let paused = ctx.target.paused_stream_ids().await?;
    ensure!(
        paused.len() == 1
            && ctx
                .target
                .events(&identity.identity_id)
                .await?
                .iter()
                .any(|event| { event["type"] == "stream_opened" && event["stream_id"] == paused[0] }),
        "mock handshake did not identify the held stream"
    );
    let waiting = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        !waiting.connected
            && waiting.metadata == before.metadata
            && waiting.last_seen_at == before.last_seen_at
            && ctx
                .target
                .events(&identity.identity_id)
                .await?
                .iter()
                .all(|event| event["type"] != "stream_authenticated"),
        "held Hello authenticated or changed identity state before release"
    );
    expect_status(&ctx.target.control("handshake", &json!({ "pause": false })).await?, 200)?;
    let welcome = stream.next().await?;
    ensure!(
        matches!(
            welcome.payload,
            Some(agent_channel_proto::server_message::Payload::Welcome(_))
        ) && welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "released Hello did not receive its Welcome"
    );
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .metadata_value("hostname")
            == Some("after-pause")
            && ctx.target.paused_stream_ids().await?.is_empty(),
        "handshake release did not authenticate and clear the barrier"
    );
    Ok(())
}

pub(crate) async fn p_channel_proof_replay_fails(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "untouched").await?;
    let (_, other) = issued(&ctx, "other-device").await?;
    let mut first = channel::open(&ctx.target, &identity).await?;
    let first_challenge = first.challenge().await?;
    let Some(agent_channel_proto::server_message::Payload::Challenge(first_challenge_bytes)) =
        first_challenge.payload.as_ref()
    else {
        anyhow::bail!("first stream missing challenge");
    };
    let original_challenge = first_challenge_bytes.challenge.clone();
    let original_nonce = first.headers.nonce.clone();
    let mut challenges = HashSet::from([original_challenge.clone()]);
    let mut nonces = HashSet::from([original_nonce.clone()]);
    let captured = identity.key.channel_proof(&original_challenge, &original_nonce);
    drop(first);

    if ctx.mock() {
        ctx.target.advance(2).await?;
    } else {
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }
    let initial = identity_record(&ctx.target, &identity.identity_id).await?;
    let mut replay_headers = None;
    for variant in [
        "wrong_challenge",
        "wrong_nonce",
        "wrong_key",
        "wrong_correlation",
        "captured_proof",
    ] {
        let mut stream = channel::open(&ctx.target, &identity).await?;
        let challenge = stream.challenge().await?;
        let Some(agent_channel_proto::server_message::Payload::Challenge(payload)) = challenge.payload.as_ref() else {
            anyhow::bail!("stream missing challenge");
        };
        ensure!(
            challenges.insert(payload.challenge.clone()),
            "channel reused a challenge from another stream"
        );
        ensure!(
            nonces.insert(stream.headers.nonce.clone()),
            "tester reused a connect nonce"
        );
        let proof = match variant {
            "wrong_challenge" => identity.key.channel_proof(&original_challenge, &stream.headers.nonce),
            "wrong_nonce" => identity.key.channel_proof(&payload.challenge, &original_nonce),
            "wrong_key" => other.key.channel_proof(&payload.challenge, &stream.headers.nonce),
            "wrong_correlation" => identity.key.channel_proof(&payload.challenge, &stream.headers.nonce),
            _ => captured.clone(),
        };
        if variant == "wrong_correlation" {
            stream
                .send(&agent_channel_proto::AgentMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    correlation_id: Some(uuid::Uuid::new_v4().to_string()),
                    payload: Some(agent_channel_proto::agent_message::Payload::Hello(
                        agent_channel_proto::Hello {
                            metadata: [("hostname".to_owned(), "untrusted".to_owned())].into(),
                            capabilities: Vec::new(),
                            applied_state_versions: Default::default(),
                            proof,
                        },
                    )),
                })
                .await
                .context("send miscorrelated Hello")?;
        } else {
            stream
                .send_hello(&identity, &challenge, &[("hostname", "untrusted")], Some(proof))
                .await?;
        }
        let rejection = stream.closing_status(Duration::from_secs(3)).await?;
        channel::expect_status(&rejection, Code::Unauthenticated, "signature_invalid")
            .with_context(|| format!("variant {variant}"))?;
        let record = identity_record(&ctx.target, &identity.identity_id).await?;
        ensure!(!record.connected, "{variant} connected the identity");
        ensure!(
            record.last_seen_at == initial.last_seen_at,
            "{variant} updated the last-seen time"
        );
        ensure!(record.metadata == initial.metadata, "{variant} changed metadata");
        replay_headers = Some(stream.headers);
    }
    let replayed = channel::open_with_headers(&ctx.target, &identity, replay_headers.context("no opening headers")?)
        .await
        .err()
        .context("reused opening headers were accepted")?;
    channel::expect_refused_opening(
        replayed
            .downcast_ref::<tonic::Status>()
            .context("missing replay gRPC status")?,
        Code::Unauthenticated,
        "signature_invalid",
    )?;
    Ok(())
}

/// What a test sends on a stream that awaits `Hello`, to check that a closure of [CONTRACT.agent-identity.md] §7.4 comes ahead of every §7.3 step 4 failure.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
#[derive(Clone, Copy, Debug)]
enum AwaitedHello {
    /// A `Hello` whose proof verifies.
    Valid,
    /// A `Hello` whose proof does not verify.
    BadProof,
    /// Nothing, so the 10-second `Hello` deadline passes.
    Missing,
}

/// Opens one stream per variant and reads its `Challenge`, so that every stream awaits `Hello`.
async fn streams_awaiting_hello(
    ctx: &Context,
    identity: &Identity,
    variants: &[AwaitedHello],
) -> anyhow::Result<Vec<(AwaitedHello, channel::ChannelStream, agent_channel_proto::ServerMessage)>> {
    let mut streams = Vec::new();
    for &variant in variants {
        let mut stream = channel::open(&ctx.target, identity).await?;
        let challenge = stream.challenge().await?;
        streams.push((variant, stream, challenge));
    }
    Ok(streams)
}

/// Sends the variant's `Hello`, if any, and returns the status that closes the stream.
async fn close_awaiting_hello(
    identity: &Identity,
    stream: &mut channel::ChannelStream,
    challenge: &agent_channel_proto::ServerMessage,
    variant: AwaitedHello,
) -> anyhow::Result<tonic::Status> {
    let proof = match variant {
        AwaitedHello::Valid => None,
        AwaitedHello::BadProof => Some(vec![0; 64]),
        AwaitedHello::Missing => return stream.closing_status(Duration::from_secs(11)).await,
    };
    // The closing status decides the outcome, and it also explains a stream that closed before this send.
    let _ = stream
        .send_hello(identity, challenge, &[("hostname", "awaiting-hello")], proof)
        .await;
    stream.closing_status(Duration::from_secs(3)).await
}

pub(crate) async fn p_channel_revoked_before_hello(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "before-revocation").await?;
    let streams = streams_awaiting_hello(
        &ctx,
        &identity,
        &[AwaitedHello::Valid, AwaitedHello::BadProof, AwaitedHello::Missing],
    )
    .await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(!before.connected, "identity connected before Hello");
    let authenticated = if ctx.mock() {
        Some(count(&ctx.target.requests(None).await?, "authenticated_connects")?)
    } else {
        None
    };
    ctx.target.management().revoke(&identity.identity_id).await?;
    let revoked = identity_record(&ctx.target, &identity.identity_id).await?;
    for (variant, mut stream, challenge) in streams {
        let rejected = close_awaiting_hello(&identity, &mut stream, &challenge, variant).await?;
        channel::expect_status(&rejected, Code::PermissionDenied, "identity_revoked")
            .and_then(|()| channel::expect_server_time(&rejected))
            .with_context(|| format!("revoked stream awaiting Hello, {variant:?} Hello"))?;
    }
    let after = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        !after.connected
            && after.metadata == revoked.metadata
            && after.certificates == revoked.certificates
            && after.last_seen_at == before.last_seen_at,
        "revoked stream changed identity state before Welcome"
    );
    if let Some(authenticated) = authenticated {
        ensure!(
            count(&ctx.target.requests(None).await?, "authenticated_connects")? == authenticated,
            "revoked stream was registered as authenticated"
        );
    }
    Ok(())
}

/// A stream awaiting `Hello` whose identity is revoked and then deleted closes as `identity_unknown` ([CONTRACT.agent-identity.md] §7.4).
///
/// The authority checks revocation and deletion when `Hello` arrives, so both changes precede the check when the test sends `Hello` after them.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) async fn p_channel_deleted_before_hello(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "before-deletion").await?;
    let streams = streams_awaiting_hello(&ctx, &identity, &[AwaitedHello::Valid, AwaitedHello::BadProof]).await?;
    let authenticated = if ctx.mock() {
        Some(count(&ctx.target.requests(None).await?, "authenticated_connects")?)
    } else {
        None
    };
    ctx.target.management().revoke(&identity.identity_id).await?;
    ctx.target.management().delete_identity(&identity.identity_id).await?;
    for (variant, mut stream, challenge) in streams {
        let rejected = close_awaiting_hello(&identity, &mut stream, &challenge, variant).await?;
        channel::expect_status(&rejected, Code::Unauthenticated, "identity_unknown")
            .and_then(|()| channel::expect_server_time(&rejected))
            .with_context(|| format!("deleted stream awaiting Hello, {variant:?} Hello"))?;
    }
    ensure!(
        ctx.target
            .management()
            .find_identity(&identity.identity_id)
            .await?
            .is_none(),
        "a Hello for a deleted identity restored it"
    );
    if let Some(authenticated) = authenticated {
        ensure!(
            count(&ctx.target.requests(None).await?, "authenticated_connects")? == authenticated,
            "deleted stream was registered as authenticated"
        );
    }
    Ok(())
}

pub(crate) async fn p_channel_no_hello_timeout(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "no-hello").await?;
    let initial = identity_record(&ctx.target, &identity.identity_id).await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let _ = stream.challenge().await?;
    let started = Instant::now();
    let rejected = stream.closing_status(Duration::from_secs(11)).await?;
    channel::expect_status(&rejected, Code::Unauthenticated, "signature_invalid")?;
    ensure!(
        started.elapsed() <= Duration::from_millis(10_800),
        "channel exceeded the ten-second Hello deadline"
    );
    let record = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(!record.connected, "identity connected without Hello");
    ensure!(
        record.last_seen_at == initial.last_seen_at,
        "last-seen time updated without Hello"
    );
    Ok(())
}

pub(crate) async fn p_channel_hello_invalid_metadata_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "invalid-hello-metadata").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let long_key = format!("k{}", "a".repeat(64));
    let long_value = "v".repeat(1025);
    let full_value = "v".repeat(1024);
    let numbered_keys = (0..33).map(|index| format!("k{index:02}")).collect::<Vec<_>>();
    for (variant, metadata) in [
        ("an uppercase key", vec![("Hostname", "host")]),
        ("a 65-character key", vec![(long_key.as_str(), "host")]),
        ("a control character", vec![("hostname", "bad\u{7}host")]),
        ("a 1025-byte value", vec![("hostname", long_value.as_str())]),
        ("33 keys", numbered_keys.iter().map(|key| (key.as_str(), "v")).collect()),
        (
            "more than 16 KiB in total",
            numbered_keys[..16]
                .iter()
                .map(|key| (key.as_str(), full_value.as_str()))
                .collect(),
        ),
    ] {
        let mut stream = channel::open(&ctx.target, &identity).await?;
        let challenge = stream.challenge().await?;
        stream.send_hello(&identity, &challenge, &metadata, None).await?;
        let status = stream
            .closing_status(Duration::from_secs(3))
            .await
            .with_context(|| format!("Hello metadata with {variant}"))?;
        channel::expect_status(&status, Code::InvalidArgument, "invalid_request")
            .with_context(|| format!("Hello metadata with {variant}"))?;
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await? == before,
            "Hello metadata with {variant} changed identity state"
        );
    }
    Ok(())
}

/// How a frame departs from a valid `AgentMessage` of exactly [`channel::MAX_ENVELOPE_LEN`] bytes, so that the authority cannot decode it.
#[derive(Clone, Copy, Debug)]
enum Undecodable {
    /// The envelope `id`, a protobuf `string`, starts with the byte 0xFF, which UTF-8 never uses.
    // oracle: spec RFC 3629 §1
    // oracle: spec Protocol Buffers "Feature Settings for Editions" §features.utf8_validation
    InvalidUtf8,
    /// The last byte is cut, so the last field holds fewer bytes than its length prefix declares.
    // oracle: spec Protocol Buffers "Encoding" §Length-Delimited Records
    Truncated,
    /// One more byte of padding makes the frame one byte longer than the envelope limit.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    Oversized,
}

impl Undecodable {
    const ALL: [Self; 3] = [Self::InvalidUtf8, Self::Truncated, Self::Oversized];

    /// Applies the defect to the frame that `valid` serializes from an envelope `id` and a frame length.
    fn frame(self, valid: impl Fn(&[u8], usize) -> anyhow::Result<Vec<u8>>) -> anyhow::Result<Vec<u8>> {
        let mut id = uuid::Uuid::new_v4().to_string().into_bytes();
        match self {
            Self::InvalidUtf8 => {
                id[0] = 0xFF;
                valid(&id, channel::MAX_ENVELOPE_LEN)
            }
            Self::Truncated => {
                let mut frame = valid(&id, channel::MAX_ENVELOPE_LEN)?;
                frame.pop();
                Ok(frame)
            }
            Self::Oversized => valid(&id, channel::MAX_ENVELOPE_LEN + 1),
        }
    }
}

/// A first agent message that the authority cannot decode, including one over the envelope limit, closes the stream as `signature_invalid` and changes nothing.
///
/// See [CONTRACT.agent-identity.md] §7.3 "Sequence", step 4, and §7.1 "Service".
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) async fn p_channel_undecodable_first_message_rejected(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    let (_, identity) = issued(&ctx, "enrolled").await?;
    let metadata = [("hostname", "undecodable")];
    next_last_seen_second(&ctx).await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    for undecodable in Undecodable::ALL {
        let mut stream = channel::open(&ctx.target, &identity).await?;
        let challenge = stream.challenge().await?;
        let frame = undecodable.frame(|id, len| stream.hello_frame(&identity, &challenge, &metadata, id, len))?;
        stream.send_frame(frame).await?;
        let status = stream
            .closing_status(Duration::from_secs(3))
            .await
            .with_context(|| format!("{undecodable:?} Hello"))?;
        channel::expect_status(&status, Code::Unauthenticated, "signature_invalid")
            .with_context(|| format!("{undecodable:?} Hello"))?;
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await? == before,
            "{undecodable:?} Hello changed identity state"
        );
    }
    // The valid frame that each defect departs from authenticates the stream, so each refusal comes from its defect alone.
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let challenge = stream.challenge().await?;
    let id = uuid::Uuid::new_v4().to_string();
    let frame = stream.hello_frame(
        &identity,
        &challenge,
        &metadata,
        id.as_bytes(),
        channel::MAX_ENVELOPE_LEN,
    )?;
    stream.send_frame(frame).await?;
    let welcome = stream.next().await?;
    ensure!(
        matches!(
            welcome.payload,
            Some(agent_channel_proto::server_message::Payload::Welcome(_))
        ) && welcome.correlation_id.as_deref() == Some(id.as_str()),
        "a valid Hello of {} bytes did not receive its Welcome",
        channel::MAX_ENVELOPE_LEN
    );
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .metadata_value("hostname")
            == Some("undecodable"),
        "a valid Hello of {} bytes did not replace the metadata",
        channel::MAX_ENVELOPE_LEN
    );
    Ok(())
}

/// An agent message that the authority cannot decode, including one over the envelope limit, closes an authenticated stream as `invalid_request`.
///
/// See [CONTRACT.agent-identity.md] §7.4 "Termination" and §7.1 "Service".
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) async fn p_channel_undecodable_message_after_welcome_rejected(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    let (_, identity) = issued(&ctx, "after-welcome").await?;
    // An envelope whose only other field is one the schema does not define, so it carries no known payload.
    let unknown_payload =
        |id: &[u8], len| channel::agent_message_frame(id, &agent_channel_proto::AgentMessage::default(), len);
    for undecodable in Undecodable::ALL {
        let mut stream = channel::open(&ctx.target, &identity).await?;
        stream.hello(&identity, &[]).await?;
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
        // The authority ignores the valid frame that the defect departs from, so the stream stays open until the defective one.
        let id = uuid::Uuid::new_v4().to_string();
        stream
            .send_frame(unknown_payload(id.as_bytes(), channel::MAX_ENVELOPE_LEN)?)
            .await?;
        ensure!(
            tokio::time::timeout(Duration::from_millis(500), stream.stream.message())
                .await
                .is_err(),
            "a valid message of {} bytes with an unknown payload got a reply or ended the stream",
            channel::MAX_ENVELOPE_LEN
        );
        stream.send_frame(undecodable.frame(unknown_payload)?).await?;
        let status = stream
            .closing_status(Duration::from_secs(3))
            .await
            .with_context(|| format!("{undecodable:?} message after Welcome"))?;
        channel::expect_status(&status, Code::InvalidArgument, "invalid_request")
            .with_context(|| format!("{undecodable:?} message after Welcome"))?;
    }
    Ok(())
}

pub(crate) async fn p_channel_clock_skew_refusal_carries_server_time(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "skewed-opening").await?;
    let created = time::OffsetDateTime::now_utc().unix_timestamp() - 600;
    let headers = identity.key.sign(
        &identity.thumbprint,
        "connect",
        None,
        created,
        created + 60,
        &fresh_nonce(),
    );
    let failure = channel::open_with_headers(&ctx.target, &identity, headers)
        .await
        .err()
        .context("stale connect signature opened a channel")?;
    channel::expect_refused_opening(
        failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
        Code::Unauthenticated,
        "clock_skew",
    )
}

pub(crate) async fn p_channel_server_time_corrects_skew(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "server-time-retry").await?;
    ctx.target.faults(&json!({ "clock_skew_secs": 900 })).await?;
    let failure = channel::open(&ctx.target, &identity)
        .await
        .err()
        .context("connect signature 900 seconds behind the authority opened a channel")?;
    let status = failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?;
    channel::expect_refused_opening(status, Code::Unauthenticated, "clock_skew")?;
    let server_time = status
        .metadata()
        .get("server-time")
        .context("refused opening has no server-time trailer")?
        .to_str()?;
    let created = time::OffsetDateTime::parse(server_time, &Rfc3339)?.unix_timestamp();
    let headers = identity.key.sign(
        &identity.thumbprint,
        "connect",
        None,
        created,
        created + 60,
        &fresh_nonce(),
    );
    let mut stream = channel::open_with_headers(&ctx.target, &identity, headers)
        .await
        .context("connect signature created at the server-time trailer was refused")?;
    stream.hello(&identity, &[]).await
}

pub(crate) async fn p_channel_unavailable_no_channel_url(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "channel_available": false })).await?;
    let token = token(&ctx, 1).await?;
    let key = KeyPair::generate()?;
    let reply = ctx
        .target
        .enroll(&token.text, &key, &json!({ "hostname": "unavailable" }))
        .await?;
    expect_status(&reply, 200)?;
    ensure!(
        reply.body["config"].get("agent_channel_url").is_none(),
        "enroll included config.agent_channel_url for unavailable channel"
    );
    let identity = Identity::from_enrollment(key, &reply)?;
    ensure!(
        identity.agent_channel_url.is_none(),
        "enroll returned config.agent_channel_url for unavailable channel"
    );
    let failure = channel::probe_unavailable(&ctx.target, &identity)
        .await
        .err()
        .context("unavailable channel accepted a stream")?;
    ensure!(
        failure
            .downcast_ref::<tonic::Status>()
            .is_some_and(|status| status.code() == Code::Unavailable),
        "unavailable channel did not return gRPC UNAVAILABLE"
    );
    Ok(())
}

pub(crate) async fn p_mock_malformed_https_channel_urls(ctx: Context) -> anyhow::Result<()> {
    for (variant, suffix) in [("query", "?identity_probe=1"), ("fragment", "#identity_probe")] {
        ctx.target.faults(&json!({ "malformed_channel_url": variant })).await?;
        let (_, identity) = issued(&ctx, variant).await?;
        ensure!(
            identity.agent_channel_url.as_deref() == Some(format!("{}{suffix}", ctx.target.base_url).as_str()),
            "mock did not return an HTTPS agent_channel_url with a {variant}"
        );
    }
    ctx.target.faults(&json!({ "malformed_channel_url": null })).await?;
    let (_, restored) = issued(&ctx, "restored-channel-url").await?;
    ensure!(
        restored.agent_channel_url.as_deref() == Some(ctx.target.base_url.as_str()),
        "clearing the malformed-URL fault did not restore the HTTPS channel URL"
    );
    let before = ctx.target.requests(None).await?;
    let response = ctx
        .target
        .http
        .post(format!("{}/not-the-channel", ctx.target.base_url))
        .header(reqwest::header::CONTENT_TYPE, "application/grpc")
        .send()
        .await?;
    ensure!(response.status() == 404, "mock accepted an unrelated gRPC path");
    let after = ctx.target.requests(None).await?;
    ensure!(
        count(&after, "channel_attempts")? == count(&before, "channel_attempts")? + 1
            && count(&after, "connect")? == count(&before, "connect")?,
        "mock did not count a gRPC channel attempt on an unrelated path"
    );
    Ok(())
}

pub(crate) async fn p_config_revision_monotonic_changes(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "config-revisions").await?;
    let (_, other) = issued(&ctx, "second-config-revisions").await?;
    let initial = check_in_config(&ctx.target, &identity).await?;
    ensure!(
        initial == identity.config,
        "check-in changed the effective config returned at enrollment"
    );
    let other_initial = count(&check_in_config(&ctx.target, &other).await?, "revision")?;
    ctx.target.faults(&json!({ "channel_broken": true })).await?;
    let failure = channel::open(&ctx.target, &identity)
        .await
        .err()
        .context("broken channel accepted a stream")?;
    ensure!(
        failure
            .downcast_ref::<tonic::Status>()
            .is_some_and(|status| status.code() == Code::Unavailable),
        "channel_broken did not return UNAVAILABLE"
    );
    ensure!(
        check_in_config(&ctx.target, &identity).await? == initial,
        "transport failure changed the effective config revision"
    );

    ctx.target.faults(&json!({ "channel_available": false })).await?;
    let disabled = check_in_config(&ctx.target, &identity).await?;
    let other_disabled = count(&check_in_config(&ctx.target, &other).await?, "revision")?;
    ensure!(
        count(&disabled, "revision")? > count(&initial, "revision")?
            && disabled.get("agent_channel_url").is_none()
            && other_disabled > other_initial,
        "disabling the channel did not raise every identity's config revision"
    );
    ctx.target.faults(&json!({ "channel_available": false })).await?;
    ensure!(
        check_in_config(&ctx.target, &identity).await? == disabled,
        "no-op channel toggle raised the config revision"
    );
    ctx.target.faults(&json!({ "channel_available": true })).await?;
    let enabled = check_in_config(&ctx.target, &identity).await?;
    ensure!(
        count(&enabled, "revision")? > count(&disabled, "revision")?
            && enabled["agent_channel_url"] == ctx.target.base_url,
        "re-enabling the channel did not restore its URL at a higher revision"
    );
    ctx.target.faults(&json!({ "channel_broken": false })).await?;
    ensure!(
        check_in_config(&ctx.target, &identity).await? == enabled,
        "fixing the transport raised an unchanged config revision"
    );

    let changed = ctx
        .target
        .control("config", &json!({ "fields": { "conformance_flag": true } }))
        .await?;
    expect_status(&changed, 200)?;
    ensure!(
        changed.body["updatedIdentities"] == 2,
        "config change did not update both identities"
    );
    let extended = check_in_config(&ctx.target, &identity).await?;
    ensure!(
        count(&extended, "revision")? > count(&enabled, "revision")? && extended["conformance_flag"] == true,
        "extra config field did not raise the revision"
    );
    let unchanged = ctx
        .target
        .control("config", &json!({ "fields": { "conformance_flag": true } }))
        .await?;
    expect_status(&unchanged, 200)?;
    ensure!(
        unchanged.body["updatedIdentities"] == 0 && check_in_config(&ctx.target, &identity).await? == extended,
        "identical config fields raised the revision"
    );
    expect_status(
        &ctx.target
            .control("config", &json!({ "fields": { "revision": 999 } }))
            .await?,
        400,
    )?;
    ensure!(
        check_in_config(&ctx.target, &identity).await? == extended,
        "reserved config field modified the identity"
    );
    expect_status(
        &ctx.target
            .control("config", &json!({ "fields": { "conformance_flag": false } }))
            .await?,
        200,
    )?;
    let final_config = check_in_config(&ctx.target, &identity).await?;
    ensure!(
        count(&final_config, "revision")? > count(&extended, "revision")?
            && final_config["conformance_flag"] == false
            && count(&check_in_config(&ctx.target, &other).await?, "revision")? > other_disabled,
        "replacing a field did not advance both identity revisions"
    );
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    expect_status(
        &ctx.target
            .control("reconnect", &json!({ "identity_id": identity.identity_id }))
            .await?,
        202,
    )?;
    ensure!(
        check_in_config(&ctx.target, &identity).await? == final_config,
        "renew, confirm or reconnect changed an unaffected config revision"
    );
    Ok(())
}

/// On DVLS, the identity's revision goes stale through the only config change DVLS's management API makes: switching the agent channel off and on.
/// DVLS's intent, "Certificates and channel", offers the channel as `config.agent_channel_url`, which the switch withdraws and restores.
pub(crate) async fn p_config_hello_reconciles_stale_revision(ctx: Context) -> anyhow::Result<()> {
    if ctx.mock() {
        return stale_hello_reconciled(&ctx).await;
    }
    require_settings_changes(&ctx)?;
    let original = ctx.target.management().settings().await?;
    restoring_settings(&ctx, &original, stale_hello_reconciled(&ctx)).await
}

async fn stale_hello_reconciled(ctx: &Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(ctx, "stale-config").await?;
    let announced_revision = if ctx.mock() {
        if count(&identity.config, "revision")? == 0 {
            expect_status(
                &ctx.target
                    .control("config", &json!({ "fields": { "conformance_stale_hello": true } }))
                    .await?,
                200,
            )?;
            let updated = check_in_config(&ctx.target, &identity).await?;
            ensure!(
                count(&updated, "revision")? > 0,
                "mock did not raise revision zero before the stale-Hello probe"
            );
            identity.config = updated;
        }
        count(&identity.config, "revision")? - 1
    } else {
        let enrolled_revision = count(&identity.config, "revision")?;
        let management = ctx.target.management();
        for enabled in [false, true] {
            management
                .change_settings(&SettingsChange {
                    channel_enabled: Some(enabled),
                    ..SettingsChange::default()
                })
                .await?;
        }
        let updated = check_in_config(&ctx.target, &identity).await?;
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enroll
        // oracle: intent docs/agent-identity/INTENT.DVLS.md §Certificates and channel
        ensure!(
            count(&updated, "revision")? > enrolled_revision && updated.get("agent_channel_url").is_some(),
            "switching the agent channel off and on did not raise the config revision"
        );
        identity.config = updated;
        enrolled_revision
    };
    let current_revision = count(&identity.config, "revision")?;
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-channel-sequence
    let mut stale = channel::open(&ctx.target, &identity).await?;
    let challenge = stale.challenge().await?;
    let hello_id = stale
        .send_hello_with_revision(&identity, &challenge, &[], None, announced_revision)
        .await?;
    let welcome = stale.next().await?;
    ensure!(
        matches!(
            welcome.payload,
            Some(agent_channel_proto::server_message::Payload::Welcome(_))
        ) && welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "stale Hello did not receive Welcome first"
    );
    let (update, config) = next_config_update(&mut stale).await?;
    ensure!(
        config == identity.config,
        "stale Hello did not receive the current config immediately after Welcome"
    );
    stale.ack(&update).await?;

    let mut current = channel::open(&ctx.target, &identity).await?;
    current.hello(&identity, &[]).await?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(200), current.stream.message())
            .await
            .is_err(),
        "up-to-date Hello received an unnecessary ConfigUpdate"
    );
    if ctx.mock() {
        let events = ctx.target.events(&identity.identity_id).await?;
        let applied = events
            .iter()
            .filter(|event| event["type"] == "stream_authenticated")
            .map(|event| event["applied_config_revision"].as_u64())
            .collect::<Vec<_>>();
        ensure!(
            applied == [Some(announced_revision), Some(current_revision)]
                && events
                    .iter()
                    .filter(|event| event["type"] == "config_update_sent")
                    .count()
                    == 1,
            "mock did not distinguish stale from current Hello revisions"
        );
    }
    Ok(())
}

pub(crate) async fn p_config_update_pushes_higher_revision(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "config-push").await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    stream.hello(&identity, &[]).await?;
    let first = ctx
        .target
        .control("config", &json!({ "fields": { "conformance_note": "updated" } }))
        .await?;
    expect_status(&first, 200)?;
    let (message, config) = next_config_update(&mut stream).await?;
    let enrolled_revision = count(&identity.config, "revision")?;
    let updated_revision = count(&config, "revision")?;
    ensure!(
        updated_revision > enrolled_revision
            && config["conformance_note"] == "updated"
            && config == check_in_config(&ctx.target, &identity).await?,
        "config edit did not push a higher effective revision"
    );
    stream.ack(&message).await?;
    let stale = ctx
        .target
        .control(
            "config/stale",
            &json!({ "identity_id": identity.identity_id, "revision": enrolled_revision }),
        )
        .await?;
    expect_status(&stale, 200)?;
    ensure!(stale.body["sent"] == 1, "stale ConfigUpdate was not delivered");
    let (stale_message, stale_config) = next_config_update(&mut stream).await?;
    ensure!(
        count(&stale_config, "revision")? == enrolled_revision
            && stale_config["mock_stale_marker"] == "ignore-me"
            && check_in_config(&ctx.target, &identity).await? == config,
        "stale ConfigUpdate modified the server's effective revision"
    );
    stream.ack(&stale_message).await?;
    ctx.target.faults(&json!({ "channel_available": false })).await?;
    let (disabled, config) = next_config_update(&mut stream).await?;
    let disabled_revision = count(&config, "revision")?;
    ensure!(
        disabled_revision > updated_revision && config.get("agent_channel_url").is_none(),
        "channel toggle did not push a higher revision without agent_channel_url"
    );
    stream.ack(&disabled).await?;
    let events = ctx.target.events(&identity.identity_id).await?;
    let changed = events
        .iter()
        .filter(|event| event["type"] == "config_changed")
        .map(|event| count(event, "revision"))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let pushed = events
        .iter()
        .filter(|event| event["type"] == "config_update_sent")
        .map(|event| count(event, "revision"))
        .collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(
        changed == [updated_revision, disabled_revision] && pushed == changed,
        "config change and push events did not advance in order"
    );
    Ok(())
}

pub(crate) async fn p_request_renewal_connected_and_on_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "push").await?;
    let mut connected = channel::open(&ctx.target, &identity).await?;
    connected.hello(&identity, &[("hostname", "push")]).await?;
    ctx.target.management().request_renewal(&identity.identity_id).await?;
    let pushed = connected.next().await?;
    ensure!(
        matches!(
            pushed.payload,
            Some(agent_channel_proto::server_message::Payload::RenewRequested(ref reason))
                if reason.reason == "admin"
        ),
        "connected stream did not get admin renewal request"
    );
    connected.ack(&pushed).await?;
    if ctx.mock() {
        let started = Instant::now();
        loop {
            if count(&ctx.target.requests(None).await?, "correlated_acks")? >= 1 {
                break;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(2),
                "mock did not observe correlated Ack"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let mut reconnect = channel::open(&ctx.target, &identity).await?;
    reconnect.hello(&identity, &[("hostname", "push")]).await?;
    let repeated = reconnect.next().await?;
    ensure!(
        matches!(
            repeated.payload,
            Some(agent_channel_proto::server_message::Payload::RenewRequested(ref reason))
                if reason.reason == "admin"
        ),
        "renewal request was not repeated on connect"
    );
    reconnect.ack(&repeated).await?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .renewal_requested,
        "request flag cleared too early"
    );
    Ok(())
}

pub(crate) async fn p_reconnect_push_and_handoff(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "reconnect").await?;
    let mut old = channel::open(&ctx.target, &identity).await?;
    old.hello(&identity, &[]).await?;
    let before = ctx.target.requests(None).await?;
    expect_status(
        &ctx.target
            .control("reconnect", &json!({ "identity_id": identity.identity_id }))
            .await?,
        202,
    )?;
    let pushed = old.next().await?;
    ensure!(
        matches!(
            pushed.payload,
            Some(agent_channel_proto::server_message::Payload::Reconnect(ref message))
                if message.reason == "mock"
        ),
        "mock did not push Reconnect"
    );
    let mut replacement = channel::open(&ctx.target, &identity).await?;
    let challenge = replacement.challenge().await?;
    ensure!(
        count(&ctx.target.requests(None).await?, "overlap_open")? == count(&before, "overlap_open")?,
        "opening headers counted as an authenticated overlap"
    );
    let hello_id = replacement.send_hello(&identity, &challenge, &[], None).await?;
    let welcome = replacement.next().await?;
    ensure!(
        matches!(
            welcome.payload,
            Some(agent_channel_proto::server_message::Payload::Welcome(_))
        ) && welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "replacement did not receive correlated Welcome"
    );
    ensure!(
        count(&ctx.target.requests(None).await?, "authenticated_connects")? > count(&before, "authenticated_connects")?,
        "replacement channel did not authenticate"
    );
    ensure!(
        count(&ctx.target.requests(None).await?, "overlap_open")? > count(&before, "overlap_open")?,
        "authenticated replacement did not overlap old stream"
    );
    drop(old);
    let started = Instant::now();
    loop {
        let observed = ctx.target.requests(None).await?;
        if count(&observed, "active_streams")? == 1 {
            break;
        }
        ensure!(
            started.elapsed() < Duration::from_secs(2),
            "old channel did not close after replacement"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ensure!(
        identity_record(&ctx.target, &identity.identity_id).await?.connected,
        "replacement did not preserve connection"
    );
    let events = ctx.target.events(&identity.identity_id).await?;
    let opened = events
        .iter()
        .filter(|event| event["type"] == "stream_authenticated")
        .collect::<Vec<_>>();
    ensure!(opened.len() == 2, "reconnect did not authenticate two streams");
    let old_stream_id = field(opened[0], "stream_id")?;
    let new_sequence = count(opened[1], "seq")?;
    ensure!(
        events.iter().any(|event| {
            event["type"] == "stream_closed"
                && event["stream_id"] == old_stream_id
                && event["status"] == "OK"
                && event["seq"].as_u64().is_some_and(|seq| seq > new_sequence)
        }),
        "old stream closed before its replacement authenticated"
    );
    Ok(())
}

pub(crate) async fn p_request_renewal_flag_cleared_only_on_confirm(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "offline-flag").await?;
    ctx.target.management().request_renewal(&identity.identity_id).await?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .renewal_requested,
        "offline renewal request flag was not set"
    );
    let next_key = KeyPair::generate()?;
    let pending = ctx.target.renew(&identity, &next_key, &json!({})).await?;
    expect_status(&pending, 200)?;
    identity.adopt_certificate(&pending.body["certificate_chain"], next_key)?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .renewal_requested,
        "flag cleared when pending certificate was merely issued"
    );
    let replay_key = KeyPair {
        key: identity.key.key.clone(),
        csr: identity.key.csr.clone(),
    };
    expect_status(&ctx.target.renew(&identity, &replay_key, &json!({})).await?, 200)?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .renewal_requested,
        "pending-signed renew cleared the request flag"
    );
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let current = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        !current.renewal_requested && current.has_certificate(&identity.thumbprint, CertificateStatus::Current),
        "confirm did not clear the request flag"
    );
    Ok(())
}

pub(crate) async fn p_request_renewal_flag_cleared_after_new_cert(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "clear-flag").await?;
    let mut old = channel::open(&ctx.target, &identity).await?;
    old.hello(&identity, &[]).await?;
    ctx.target.management().request_renewal(&identity.identity_id).await?;
    let request = old.next().await?;
    old.ack(&request).await?;
    let next_key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &next_key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], next_key)?;
    let pending = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        pending.renewal_requested && pending.has_certificate(&identity.thumbprint, CertificateStatus::Pending),
        "renewal request cleared before confirmation"
    );
    let mut new_stream = channel::open(&ctx.target, &identity).await?;
    let challenge = new_stream.challenge().await?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .renewal_requested,
        "opening headers cleared the renewal request"
    );
    let hello_id = new_stream.send_hello(&identity, &challenge, &[], None).await?;
    let welcome = new_stream.next().await?;
    ensure!(
        matches!(
            welcome.payload,
            Some(agent_channel_proto::server_message::Payload::Welcome(_))
        ) && welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "new certificate did not receive its correlated Welcome"
    );
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .renewal_requested,
        "pending certificate's Hello cleared the renewal request"
    );
    let still_requested = new_stream.next().await?;
    ensure!(
        matches!(
            still_requested.payload,
            Some(agent_channel_proto::server_message::Payload::RenewRequested(ref reason))
                if reason.reason == "admin"
        ),
        "pending-certificate channel did not receive the outstanding renewal request"
    );
    new_stream.ack(&still_requested).await?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    ensure!(
        !identity_record(&ctx.target, &identity.identity_id)
            .await?
            .renewal_requested,
        "confirm did not clear the renewal request"
    );
    let mut additional = channel::open(&ctx.target, &identity).await?;
    additional.hello(&identity, &[]).await?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(250), additional.stream.message())
            .await
            .is_err(),
        "renewal request was pushed after flag cleared"
    );
    Ok(())
}

pub(crate) async fn p_revocation_closes_stream(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "live-revoke").await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    stream.hello(&identity, &[]).await?;
    ctx.target.management().revoke(&identity.identity_id).await?;
    let status = stream.closing_status(Duration::from_secs(3)).await?;
    channel::expect_status(&status, Code::PermissionDenied, "identity_revoked")?;
    ensure!(
        !identity_record(&ctx.target, &identity.identity_id).await?.connected,
        "revoked stream still connected"
    );
    Ok(())
}

pub(crate) async fn p_stream_closes_at_not_after(ctx: Context) -> anyhow::Result<()> {
    if ctx.mock() {
        ctx.target.faults(&json!({ "leaf_lifetime_secs": 20 })).await?;
    }
    let (_, identity) = issued(&ctx, "expires").await?;
    let not_after = identity_record(&ctx.target, &identity.identity_id)
        .await?
        .not_after()
        .context("identity has no current certificate")?
        .unix_timestamp();
    let mut stream = if ctx.mock() {
        let mut authenticated = None;
        for _ in 0..3 {
            let milliseconds = u64::try_from(
                time::OffsetDateTime::now_utc()
                    .unix_timestamp_nanos()
                    .rem_euclid(1_000_000_000),
            )? / 1_000_000;
            if milliseconds > 150 {
                tokio::time::sleep(Duration::from_millis(1050 - milliseconds)).await;
            }
            let now = ctx.target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
                .as_i64()
                .context("mock clock is missing")?;
            ctx.target.advance(not_after - now - 1).await?;
            let mut opened = match channel::open(&ctx.target, &identity).await {
                Ok(stream) => stream,
                Err(error)
                    if error.downcast_ref::<tonic::Status>().is_some_and(|status| {
                        status
                            .metadata()
                            .get("error-code")
                            .is_some_and(|code| code == "certificate_expired")
                    }) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let Err(error) = opened.hello(&identity, &[]).await {
                if error.downcast_ref::<tonic::Status>().is_some_and(|status| {
                    status
                        .metadata()
                        .get("error-code")
                        .is_some_and(|code| code == "certificate_expired")
                }) {
                    continue;
                }
                return Err(error);
            }
            let now = ctx.target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
                .as_i64()
                .context("mock clock is missing")?;
            if now == not_after - 1 {
                authenticated = Some(opened);
                break;
            }
        }
        authenticated.context("could not authenticate at notAfter - 1 without a wall-clock second rollover")?
    } else {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        ensure!(
            not_after > now + 4,
            "real-target leaf is too short to open before expiry"
        );
        tokio::time::sleep(Duration::from_secs(u64::try_from(not_after - now - 4)?)).await;
        let mut opened = channel::open(&ctx.target, &identity).await?;
        opened.hello(&identity, &[]).await?;
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await?.connected,
            "stream was not authenticated just before expiry"
        );
        opened
    };
    let status = if ctx.mock() {
        ctx.target.advance(1).await?;
        stream.closing_status(Duration::from_millis(900)).await?
    } else {
        stream.closing_status(Duration::from_secs(6)).await?
    };
    channel::expect_status(&status, Code::Unauthenticated, "certificate_expired")?;
    if ctx.mock() {
        ensure!(
            ctx.target.events(&identity.identity_id).await?.iter().any(|event| {
                event["type"] == "stream_closed"
                    && event["status"] == "UNAUTHENTICATED"
                    && event["error_code"] == "certificate_expired"
            }),
            "time/advance did not record immediate stream expiry"
        );
    }
    if !ctx.mock() {
        ensure!(
            time::OffsetDateTime::now_utc().unix_timestamp() <= not_after + 2,
            "real-target stream closed more than two seconds after notAfter"
        );
    }
    ensure!(
        !identity_record(&ctx.target, &identity.identity_id).await?.connected,
        "expired stream still connected"
    );
    Ok(())
}

pub(crate) async fn p_expired_certificate_refused_at_stream_open(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 20 })).await?;
    let (_, identity) = issued(&ctx, "expired-open").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let not_after = before
        .not_after()
        .context("identity has no current certificate")?
        .unix_timestamp();
    // CONTRACT.agent-identity.md §6 accepts a connect while `now <= notAfter`, and §7.4 closes a stream no later than `notAfter`, so an opening at `notAfter` gets its Challenge and then closes.
    expect_status(
        &ctx.target.control("time/freeze", &json!({ "now": not_after })).await?,
        200,
    )?;
    let mut at_expiry = channel::open(&ctx.target, &identity).await?;
    let _ = at_expiry.challenge().await?;
    channel::expect_status(
        &at_expiry.closing_status(Duration::from_millis(900)).await?,
        Code::Unauthenticated,
        "certificate_expired",
    )?;
    expect_status(
        &ctx.target
            .control("time/freeze", &json!({ "now": not_after + 1 }))
            .await?,
        200,
    )?;
    let failure = channel::open(&ctx.target, &identity)
        .await
        .err()
        .context("expired certificate opened a stream")?;
    channel::expect_refused_opening(
        failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
        Code::Unauthenticated,
        "certificate_expired",
    )?;
    let after = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        !after.connected
            && after.metadata == before.metadata
            && after.last_seen_at == before.last_seen_at
            && ctx
                .target
                .events(&identity.identity_id)
                .await?
                .iter()
                .all(|event| event["type"] != "stream_authenticated"),
        "expired opening authenticated a stream or changed identity state"
    );
    Ok(())
}

pub(crate) async fn p_challenged_stream_expires_on_advance(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 20 })).await?;
    let (_, identity) = issued(&ctx, "challenge-expiry").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let not_after = before
        .not_after()
        .context("identity has no current certificate")?
        .unix_timestamp();
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let _ = stream.challenge().await?;
    ensure!(
        !identity_record(&ctx.target, &identity.identity_id).await?.connected,
        "Challenge alone authenticated an identity"
    );
    let now = ctx.target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
        .as_i64()
        .context("mock clock is missing")?;
    ctx.target.advance(not_after - now).await?;
    let status = stream.closing_status(Duration::from_millis(900)).await?;
    channel::expect_status(&status, Code::Unauthenticated, "certificate_expired")?;
    channel::expect_server_time(&status)?;
    let after = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        !after.connected && after.metadata == before.metadata && after.last_seen_at == before.last_seen_at,
        "expired unproven stream changed identity state"
    );
    let events = ctx.target.events(&identity.identity_id).await?;
    ensure!(
        events.iter().any(|event| {
            event["type"] == "stream_closed"
                && event["status"] == "UNAUTHENTICATED"
                && event["error_code"] == "certificate_expired"
        }) && events.iter().all(|event| event["type"] != "stream_authenticated"),
        "challenged stream was not closed at the mock clock boundary"
    );
    Ok(())
}

pub(crate) async fn p_pending_cert_auth_does_not_promote(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "make-before-break").await?;
    let old_thumb = identity.thumbprint.clone();
    let mut old = channel::open(&ctx.target, &identity).await?;
    old.hello(&identity, &[]).await?;
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let events_before_replay = if ctx.mock() {
        Some(ctx.target.events(&identity.identity_id).await?)
    } else {
        None
    };
    let replay_key = KeyPair {
        key: identity.key.key.clone(),
        csr: identity.key.csr.clone(),
    };
    expect_status(&ctx.target.renew(&identity, &replay_key, &json!({})).await?, 200)?;
    if let Some(events) = events_before_replay {
        let after = ctx.target.events(&identity.identity_id).await?;
        ensure!(
            after
                .iter()
                .filter(|event| event["type"] == "cert_status_changed")
                .collect::<Vec<_>>()
                == events
                    .iter()
                    .filter(|event| event["type"] == "cert_status_changed")
                    .collect::<Vec<_>>()
                && after.iter().any(|event| {
                    event["type"] == "renew_received" && event["cert_thumbprint"] == identity.thumbprint
                }),
            "pending-signed renewal changed certificate statuses before confirm"
        );
    }
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        before.has_certificate(&old_thumb, CertificateStatus::Current)
            && before.has_certificate(&identity.thumbprint, CertificateStatus::Pending)
            && before.connected,
        "renewal promoted the pending certificate before confirmation"
    );
    let mut unauthenticated = channel::open(&ctx.target, &identity).await?;
    let challenge = unauthenticated.challenge().await?;
    let opened = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        opened.has_certificate(&old_thumb, CertificateStatus::Current)
            && opened.has_certificate(&identity.thumbprint, CertificateStatus::Pending),
        "opening headers promoted the pending certificate"
    );
    ensure!(
        tokio::time::timeout(Duration::from_millis(200), old.stream.message())
            .await
            .is_err(),
        "opening headers closed the old authenticated stream"
    );
    unauthenticated
        .send_hello(
            &identity,
            &challenge,
            &[("hostname", "not-authenticated")],
            Some(vec![0; 64]),
        )
        .await?;
    let status = unauthenticated.closing_status(Duration::from_secs(3)).await?;
    channel::expect_status(&status, Code::Unauthenticated, "signature_invalid")?;
    let rejected = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        rejected.has_certificate(&old_thumb, CertificateStatus::Current)
            && rejected.has_certificate(&identity.thumbprint, CertificateStatus::Pending)
            && rejected.connected,
        "bad proof promoted the pending certificate"
    );
    ensure!(
        rejected.metadata == before.metadata,
        "bad proof changed identity metadata"
    );
    ensure!(
        tokio::time::timeout(Duration::from_millis(200), old.stream.message())
            .await
            .is_err(),
        "bad proof closed the old authenticated stream"
    );
    let mut pending_stream = channel::open(&ctx.target, &identity).await?;
    pending_stream.hello(&identity, &[]).await?;
    let after_hello = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        after_hello.has_certificate(&old_thumb, CertificateStatus::Current)
            && after_hello.has_certificate(&identity.thumbprint, CertificateStatus::Pending)
            && after_hello.connected,
        "authenticated pending certificate promoted before confirm"
    );
    ensure!(
        tokio::time::timeout(Duration::from_millis(200), old.stream.message())
            .await
            .is_err(),
        "pending-certificate Hello closed the old authenticated stream"
    );
    if ctx.mock() {
        let events = ctx.target.events(&identity.identity_id).await?;
        ensure!(
            events.iter().any(|event| {
                event["type"] == "stream_authenticated" && event["cert_thumbprint"] == identity.thumbprint
            }) && events.iter().all(|event| {
                event["type"] != "cert_status_changed"
                    || event["cert_thumbprint"] != identity.thumbprint
                    || event["to"] != "current"
            }),
            "pending-certificate Hello promoted the certificate in the event log"
        );
    }
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let confirmed = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        confirmed.has_certificate(&old_thumb, CertificateStatus::Retired)
            && confirmed.has_certificate(&identity.thumbprint, CertificateStatus::Current),
        "confirm did not promote pending and retire old current"
    );
    Ok(())
}

pub(crate) async fn p_confirm_reconnects_and_closes_retired_stream_at_grace(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "retired-stream-grace").await?;
    let old_thumb = identity.thumbprint.clone();
    let mut old = channel::open(&ctx.target, &identity).await?;
    old.hello(&identity, &[]).await?;
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let mut replacement = channel::open(&ctx.target, &identity).await?;
    replacement.hello(&identity, &[]).await?;
    let now = chain_evaluation_time(&ctx).await?;
    expect_status(&ctx.target.control("time/freeze", &json!({ "now": now })).await?, 200)?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;

    let pushed = old.next().await?;
    ensure!(
        matches!(
            pushed.payload,
            Some(agent_channel_proto::server_message::Payload::Reconnect(ref message))
                if message.reason == "certificate_rotated"
        ),
        "retired stream did not receive Reconnect(certificate_rotated)"
    );
    let record = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        record.has_certificate(&old_thumb, CertificateStatus::Retired)
            && record.has_certificate(&identity.thumbprint, CertificateStatus::Current)
            && record.connected,
        "confirm did not promote while keeping the replacement stream connected"
    );
    let events = ctx.target.events(&identity.identity_id).await?;
    let promoted = events
        .iter()
        .find(|event| {
            event["type"] == "cert_status_changed"
                && event["cert_thumbprint"] == identity.thumbprint
                && event["to"] == "current"
        })
        .context("confirm promotion event missing")?;
    let reconnect = events
        .iter()
        .find(|event| {
            event["type"] == "reconnect_sent"
                && event["cert_thumbprint"] == old_thumb
                && event["reason"] == "certificate_rotated"
        })
        .context("retired stream reconnect event missing")?;
    ensure!(
        count(promoted, "seq")? < count(reconnect, "seq")?,
        "reconnect push was sent before confirmation promoted the certificate"
    );

    expect_status(
        &ctx.target.control("time/freeze", &json!({ "now": now + 59 })).await?,
        200,
    )?;
    ensure!(
        ctx.target
            .events(&identity.identity_id)
            .await?
            .iter()
            .all(|event| { event["type"] != "stream_closed" || event["cert_thumbprint"] != old_thumb }),
        "retired stream closed before its 60-second reconnect grace elapsed"
    );
    ensure!(
        tokio::time::timeout(Duration::from_millis(150), old.stream.message())
            .await
            .is_err(),
        "retired stream closed before the 60-second boundary"
    );
    expect_status(
        &ctx.target.control("time/freeze", &json!({ "now": now + 60 })).await?,
        200,
    )?;
    ensure!(
        tokio::time::timeout(Duration::from_secs(3), old.stream.message())
            .await
            .context("retired stream did not close at 60 seconds")??
            .is_none(),
        "retired stream did not close cleanly at 60 seconds"
    );
    let events = ctx.target.events(&identity.identity_id).await?;
    let closed = events
        .iter()
        .find(|event| {
            event["type"] == "stream_closed" && event["cert_thumbprint"] == old_thumb && event["status"] == "OK"
        })
        .context("retired stream has no clean close event")?;
    let new_auth = events
        .iter()
        .find(|event| event["type"] == "stream_authenticated" && event["cert_thumbprint"] == identity.thumbprint)
        .context("replacement stream was not authenticated")?;
    ensure!(
        count(closed, "seq")? > count(reconnect, "seq")?
            && count(closed, "seq")? > count(new_auth, "seq")?
            && identity_record(&ctx.target, &identity.identity_id).await?.connected,
        "retired stream closed before reconnect or replacement authentication"
    );
    Ok(())
}

pub(crate) async fn p_channel_retired_before_hello_completes_then_reconnects(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "retired-before-hello").await?;
    let old_thumb = identity.thumbprint.clone();
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let challenge = stream.challenge().await?;
    let Some(agent_channel_proto::server_message::Payload::Challenge(payload)) = challenge.payload.as_ref() else {
        anyhow::bail!("stream missing challenge");
    };
    let old_proof = identity.key.channel_proof(&payload.challenge, &stream.headers.nonce);
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let now = chain_evaluation_time(&ctx).await?;
    expect_status(&ctx.target.control("time/freeze", &json!({ "now": now })).await?, 200)?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .has_certificate(&old_thumb, CertificateStatus::Retired),
        "confirm did not retire the certificate that opened the stream"
    );

    let hello_id = stream.send_hello(&identity, &challenge, &[], Some(old_proof)).await?;
    let welcome = stream.next().await?;
    ensure!(
        matches!(
            welcome.payload,
            Some(agent_channel_proto::server_message::Payload::Welcome(_))
        ) && welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "stream retired while awaiting Hello did not complete its handshake"
    );
    let pushed = stream.next().await?;
    ensure!(
        matches!(
            pushed.payload,
            Some(agent_channel_proto::server_message::Payload::Reconnect(ref message))
                if message.reason == "certificate_rotated"
        ),
        "stream retired while awaiting Hello did not receive Reconnect(certificate_rotated) after Welcome"
    );
    ensure!(
        identity_record(&ctx.target, &identity.identity_id).await?.connected,
        "stream retired while awaiting Hello did not authenticate"
    );

    expect_status(
        &ctx.target.control("time/freeze", &json!({ "now": now + 59 })).await?,
        200,
    )?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(150), stream.stream.message())
            .await
            .is_err(),
        "stream retired while awaiting Hello closed before the 60-second boundary"
    );
    expect_status(
        &ctx.target.control("time/freeze", &json!({ "now": now + 60 })).await?,
        200,
    )?;
    ensure!(
        tokio::time::timeout(Duration::from_secs(3), stream.stream.message())
            .await
            .context("stream retired while awaiting Hello did not close at 60 seconds")??
            .is_none(),
        "stream retired while awaiting Hello did not close with OK at 60 seconds"
    );
    Ok(())
}

pub(crate) async fn p_rotation_publishes_both_roots_and_issues_from_new(ctx: Context) -> anyhow::Result<()> {
    if !ctx.mock() {
        wait_rotation_idle(&ctx.target, ctx.dvls_rotation_window_secs).await?;
    }
    let before = ctx.target.trust_anchor().await?;
    let old = before["roots"].as_array().context("old roots")?;
    ensure!(old.len() == 1, "expected exactly one root before rotation");
    let old_thumb = field(&old[0], "thumbprint")?.to_owned();
    let _ = issued(&ctx, "old-root").await?;
    begin_rotation(&ctx).await?;
    let roots = ctx.target.trust_anchor().await?;
    let published = roots["roots"].as_array().context("rotation roots")?;
    ensure!(published.len() == 2, "rotation did not publish exactly two roots");
    ensure!(
        published.iter().any(|root| root["thumbprint"] == old_thumb),
        "old root disappeared before rotation deadline"
    );
    for root in published {
        assert_root(root)?;
    }
    let (_, identity) = issued(&ctx, "new-root").await?;
    verify_chain(&identity.certificate_chain, &roots, chain_evaluation_time(&ctx).await?)?;
    let new_root = thumbprint(identity.certificate_chain.last().context("missing issued root")?)?;
    ensure!(new_root != old_thumb, "rotation issued from the old root");
    let record = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        record.issuer() == Some(&*new_root),
        "identity issuer did not switch to new root"
    );
    finish_rotation(&ctx).await?;
    Ok(())
}

pub(crate) async fn p_rotation_status_counts(ctx: Context) -> anyhow::Result<()> {
    let (_, mut a) = issued(&ctx, "old-a").await?;
    let (_, b) = issued(&ctx, "old-b").await?;
    let old_root = identity_record(&ctx.target, &a.identity_id)
        .await?
        .issuer()
        .context("identity has no current certificate")?
        .to_owned();
    let expected = active_old_root_ids(&ctx, &old_root).await?;
    ensure!(
        expected.contains(&a.identity_id) && expected.contains(&b.identity_id),
        "new identities are missing from the full old-root listing"
    );
    let started = begin_rotation(&ctx).await?;
    ensure!(started.rotating(), "rotation not in progress");
    ensure!(
        started.active_identities_on_old_root == expected.len() as u64,
        "rotation did not count all active old-root identities"
    );
    ensure!(
        identity_record(&ctx.target, &a.identity_id).await?.renewal_requested
            && identity_record(&ctx.target, &b.identity_id).await?.renewal_requested,
        "rotation did not flag offline old-root identities"
    );
    let new_key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&a, &new_key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    a.adopt_certificate(&renewed.body["certificate_chain"], new_key)?;
    expect_status(&ctx.target.confirm(&a).await?, 204)?;
    ensure!(
        !identity_record(&ctx.target, &a.identity_id).await?.renewal_requested,
        "confirm did not clear the rotation flag"
    );
    let status = ctx.target.management().rotation().await?;
    ensure!(
        status.active_identities_on_old_root == active_old_root_ids(&ctx, &old_root).await?.len() as u64,
        "migration old-root count disagrees with all listing pages"
    );
    ctx.target.management().revoke(&b.identity_id).await?;
    let status = ctx.target.management().rotation().await?;
    ensure!(
        status.active_identities_on_old_root == active_old_root_ids(&ctx, &old_root).await?.len() as u64,
        "revoked identity remained in the old-root count"
    );
    finish_rotation(&ctx).await?;
    Ok(())
}

pub(crate) async fn p_rotation_conflict_409(ctx: Context) -> anyhow::Result<()> {
    let _ = issued(&ctx, "rotation").await?;
    begin_rotation(&ctx).await?;
    ensure!(
        refusal(ctx.target.management().rotate(RotationDeadline::Default).await)? == Refusal::Conflict,
        "a second rotation started while one was running"
    );
    finish_rotation(&ctx).await?;
    Ok(())
}

pub(crate) async fn p_rotation_completes_early_when_last_identity_migrates(ctx: Context) -> anyhow::Result<()> {
    let (_, mut first) = issued(&ctx, "first-old-root").await?;
    let (_, mut last) = issued(&ctx, "last-old-root").await?;
    let old_root = thumbprint(first.certificate_chain.last().context("missing old root")?)?;
    ensure!(
        thumbprint(last.certificate_chain.last().context("missing old root")?)? == old_root,
        "identities were not enrolled under the same old root"
    );

    let started = ctx.target.management().rotate(RotationDeadline::Default).await?;
    ensure!(
        started.rotating() && started.active_identities_on_old_root == 2,
        "rotation did not start with both old-root identities"
    );
    let deadline = started.deadline()?.unix_timestamp();
    ensure!(
        deadline - chain_evaluation_time(&ctx).await? > 60,
        "rotation deadline is not far enough away to test early completion"
    );
    let new_root = started.new_root()?.to_owned();
    ensure!(new_root != old_root, "rotation did not create a new root");

    for (remaining, identity) in [(1, &mut first), (0, &mut last)] {
        let new_key = KeyPair::generate()?;
        let renewed = ctx.target.renew(identity, &new_key, &json!({})).await?;
        expect_status(&renewed, 200)?;
        identity.adopt_certificate(&renewed.body["certificate_chain"], new_key)?;
        let pending = identity_record(&ctx.target, &identity.identity_id).await?;
        ensure!(
            pending.has_certificate(&identity.thumbprint, CertificateStatus::Pending)
                && pending.issuer() == Some(&*old_root),
            "renewal migrated the identity before confirmation"
        );
        let before_auth = ctx.target.management().rotation().await?;
        ensure!(
            before_auth.rotating() && before_auth.active_identities_on_old_root == remaining + 1,
            "rotation completed before the old-root certificate was replaced"
        );

        expect_status(&ctx.target.confirm(identity).await?, 204)?;
        let migrated = identity_record(&ctx.target, &identity.identity_id).await?;
        ensure!(
            migrated.has_certificate(&identity.thumbprint, CertificateStatus::Current)
                && migrated.issuer() == Some(&*new_root),
            "confirm did not migrate the identity to the new root"
        );
        let status = ctx.target.management().rotation().await?;
        let roots = ctx.target.trust_anchor().await?;
        let published = roots["roots"].as_array().context("published roots")?;
        ensure!(
            status.active_identities_on_old_root == remaining,
            "migration did not update the old-root identity count"
        );
        if remaining == 1 {
            ensure!(
                status.rotating()
                    && published.len() == 2
                    && published.iter().any(|root| root["thumbprint"] == old_root),
                "rotation stopped while an old-root identity was still active"
            );
        } else {
            ensure!(
                !status.rotating()
                    && published.len() == 1
                    && published[0]["thumbprint"] == new_root
                    && chain_evaluation_time(&ctx).await? < deadline - 30,
                "rotation did not finish early with only the new root published"
            );
        }
    }
    Ok(())
}

pub(crate) async fn p_rotation_completes_immediately_without_old_root_identities(ctx: Context) -> anyhow::Result<()> {
    let original = ctx.target.trust_anchor().await?;
    let original_roots = original["roots"].as_array().context("original roots")?;
    ensure!(original_roots.len() == 1, "expected one root before rotation");
    let old_root = field(&original_roots[0], "thumbprint")?;

    let started = ctx.target.management().rotate(RotationDeadline::Default).await?;
    ensure!(
        !started.rotating()
            && started.active_identities_on_old_root == 0
            && started.deadline.is_none()
            && started.old_root.is_none()
            && started.new_root.is_none(),
        "rotation without old-root identities did not complete in the POST response"
    );
    let status = ctx.target.management().rotation().await?;
    ensure!(status == started, "completed rotation did not remain idle");
    let roots = ctx.target.trust_anchor().await?;
    let published = roots["roots"].as_array().context("published roots")?;
    ensure!(
        published.len() == 1 && published[0]["thumbprint"] != old_root,
        "rotation without old-root identities did not replace the published root"
    );
    assert_root(&published[0])?;
    Ok(())
}

pub(crate) async fn p_rotation_deadline_bound(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 30 })).await?;
    let (_, expired) = issued(&ctx, "expired-old-root").await?;
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 120 })).await?;
    let (_, active) = issued(&ctx, "active-old-root").await?;
    let (_, revoked) = issued(&ctx, "revoked-old-root").await?;
    ctx.target.management().revoke(&revoked.identity_id).await?;
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 60 })).await?;
    let (_, pending_only) = issued(&ctx, "expired-current-pending-old-root").await?;
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 240 })).await?;
    expect_status(
        &ctx.target
            .renew(&pending_only, &KeyPair::generate()?, &json!({}))
            .await?,
        200,
    )?;
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 120 })).await?;
    let (_, both) = issued(&ctx, "current-and-pending-old-root").await?;
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 180 })).await?;
    expect_status(&ctx.target.renew(&both, &KeyPair::generate()?, &json!({})).await?, 200)?;
    ctx.target.advance(61).await?;

    let expired_record = identity_record(&ctx.target, &expired.identity_id).await?;
    ensure!(
        expired_record.status == IdentityStatus::Expired,
        "fixture certificate did not expire"
    );
    let pending_record = identity_record(&ctx.target, &pending_only.identity_id).await?;
    let current_expiry = pending_record
        .not_after()
        .context("identity has no current certificate")?;
    ensure!(
        current_expiry.unix_timestamp() < chain_evaluation_time(&ctx).await?
            && pending_record
                .certificates
                .as_ref()
                .is_some_and(|certs| certs.iter().any(|cert| cert.status == CertificateStatus::Pending)),
        "fixture lacks a live pending old-root certificate with an expired current certificate"
    );
    // DVLS's intent, "Terminology": `active` holds "an unexpired current or pending certificate".
    ensure!(
        pending_record.status == IdentityStatus::Active,
        "an identity with only an unexpired pending certificate is not active"
    );
    let both_record = identity_record(&ctx.target, &both.identity_id).await?;
    ensure!(
        both_record.status == IdentityStatus::Active
            && both_record
                .certificates
                .as_ref()
                .is_some_and(|certs| certs.iter().any(|cert| cert.status == CertificateStatus::Pending)),
        "fixture lacks both current and pending old-root certificates"
    );
    let pending_cert = pending_record
        .certificates
        .as_ref()
        .context("pending identity certificates")?
        .iter()
        .find(|cert| cert.status == CertificateStatus::Pending)
        .context("pending old-root certificate")?;
    let maximum = pending_cert.not_after;
    ensure!(
        identity_record(&ctx.target, &active.identity_id)
            .await?
            .not_after()
            .context("identity has no current certificate")?
            < maximum,
        "pending certificate does not determine the rotation maximum"
    );
    let too_late = RotationDeadline::At(maximum + time::Duration::seconds(1));
    ensure!(
        refusal(ctx.target.management().rotate(too_late).await)? == Refusal::Unprocessable,
        "a deadline after the rotation maximum was accepted"
    );
    ensure!(
        !ctx.target.management().rotation().await?.rotating()
            && ctx.target.trust_anchor().await?["roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 1),
        "rejected late deadline started a rotation"
    );
    let started = ctx.target.management().rotate(RotationDeadline::Default).await?;
    ensure!(
        started.deadline == Some(maximum)
            && started.active_identities_on_old_root == 3
            && active_old_root_ids(&ctx, started.old_root()?).await?.len() == 3,
        "rotation maximum or identity count excluded a pending certificate or counted one identity twice"
    );
    Ok(())
}

pub(crate) async fn p_rotation_disposable_deadline_above_own_max_rejected(ctx: Context) -> anyhow::Result<()> {
    ensure!(
        ctx.mock() || ctx.disposable_dvls_target,
        "requires a disposable DVLS target"
    );
    wait_rotation_idle(&ctx.target, ctx.dvls_rotation_window_secs).await?;
    let original_root = field(&ctx.target.trust_anchor().await?["roots"][0], "thumbprint")?.to_owned();
    isolated_old_root_fixture(&ctx, &original_root, &[]).await?;
    let (_, first) = issued(&ctx, "disposable-deadline-first").await?;
    let (_, second) = issued(&ctx, "disposable-deadline-second").await?;
    expect_status(
        &ctx.target.renew(&second, &KeyPair::generate()?, &json!({})).await?,
        200,
    )?;
    if let Err(error) =
        isolated_old_root_fixture(&ctx, &original_root, &[&first.identity_id, &second.identity_id]).await
    {
        for id in [&first.identity_id, &second.identity_id] {
            let _ = ctx.target.management().revoke(id).await;
        }
        return Err(error);
    }
    let now = chain_evaluation_time(&ctx).await?;
    let mut candidate_dates = Vec::new();
    for id in [&first.identity_id, &second.identity_id] {
        let record = identity_record(&ctx.target, id).await?;
        for cert in record.certificates.as_ref().context("own certificates are missing")? {
            let not_after = cert.not_after;
            if matches!(cert.status, CertificateStatus::Current | CertificateStatus::Pending)
                && cert.issuer == original_root
                && not_after.unix_timestamp() >= now
            {
                candidate_dates.push(not_after);
            }
        }
    }
    ensure!(
        candidate_dates.len() == 3,
        "fixture did not issue two current and one pending old-root certificate"
    );
    let maximum = candidate_dates
        .into_iter()
        .max()
        .context("own old-root maximum is missing")?;
    let too_late = RotationDeadline::At(maximum + time::Duration::days(1));
    ensure!(
        refusal(ctx.target.management().rotate(too_late).await)? == Refusal::Unprocessable,
        "a deadline after the rotation maximum was accepted"
    );
    let status = ctx.target.management().rotation().await?;
    ensure!(
        !status.rotating()
            && ctx.target.trust_anchor().await?["roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 1 && roots[0]["thumbprint"] == original_root),
        "deadline above the maximum of own enrolled certificates started a rotation"
    );
    for id in [&first.identity_id, &second.identity_id] {
        ctx.target.management().revoke(id).await?;
    }
    Ok(())
}

pub(crate) async fn p_rotation_disposable_completes_before_future_deadline(ctx: Context) -> anyhow::Result<()> {
    ensure!(
        ctx.mock() || ctx.disposable_dvls_target,
        "requires a disposable DVLS target"
    );
    wait_rotation_idle(&ctx.target, ctx.dvls_rotation_window_secs).await?;
    let old_root = field(&ctx.target.trust_anchor().await?["roots"][0], "thumbprint")?.to_owned();
    isolated_old_root_fixture(&ctx, &old_root, &[]).await?;
    let (_, mut identity) = issued(&ctx, "disposable-early-completion").await?;
    let original = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        original.issuer().context("identity has no current certificate")? == old_root,
        "disposable fixture enrolled under a different root"
    );
    if let Err(error) = isolated_old_root_fixture(&ctx, &old_root, &[&identity.identity_id]).await {
        let _ = ctx.target.management().revoke(&identity.identity_id).await;
        return Err(error);
    }
    let maximum = original.not_after().context("identity has no current certificate")?;
    let now = chain_evaluation_time(&ctx).await?;
    let deadline = maximum.min(time::OffsetDateTime::from_unix_timestamp(
        now + i64::try_from(ctx.dvls_rotation_window_secs)?,
    )?);
    ensure!(
        deadline.unix_timestamp() > now + 2,
        "own certificate expires before an early-completion probe"
    );
    let started = ctx.target.management().rotate(RotationDeadline::At(deadline)).await?;
    ensure!(
        started.rotating() && started.active_identities_on_old_root == 1,
        "disposable target does not have exactly one active old-root identity"
    );
    let new_root = started.new_root()?.to_owned();
    let new_key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &new_key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], new_key)?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let status = ctx.target.management().rotation().await?;
    let published = ctx.target.trust_anchor().await?;
    ensure!(
        old_root != new_root
            && !status.rotating()
            && status.active_identities_on_old_root == 0
            && chain_evaluation_time(&ctx).await? < deadline.unix_timestamp()
            && published["roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 1 && roots[0]["thumbprint"] == new_root)
            && identity_record(&ctx.target, &identity.identity_id).await?.issuer() == Some(&*new_root),
        "rotation did not complete when the last old-root identity migrated before its deadline"
    );
    ctx.target.management().revoke(&identity.identity_id).await?;
    Ok(())
}

pub(crate) async fn p_rotation_grace_renewal_after_early_completion(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 60 })).await?;
    let (_, expired) = issued(&ctx, "grace-old-root").await?;
    let old_root = thumbprint(expired.certificate_chain.last().context("missing old root")?)?;
    let expiry = identity_record(&ctx.target, &expired.identity_id)
        .await?
        .not_after()
        .context("identity has no current certificate")?
        .unix_timestamp();
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 600 })).await?;
    let (_, revoked) = issued(&ctx, "long-lived-old-root").await?;

    let started = ctx.target.management().rotate(RotationDeadline::Default).await?;
    ensure!(
        started.rotating() && started.active_identities_on_old_root == 2,
        "rotation did not count both old-root identities"
    );
    let deadline = started.deadline()?.unix_timestamp();
    let new_root = started.new_root()?;
    ctx.target.management().revoke(&revoked.identity_id).await?;
    let remaining = ctx.target.management().rotation().await?;
    ensure!(
        remaining.rotating()
            && remaining.active_identities_on_old_root == 1
            && ctx.target.trust_anchor().await?["roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 2),
        "rotation finished while the short-lived old-root certificate was unexpired"
    );

    let until_expiry = expiry - chain_evaluation_time(&ctx).await?;
    ensure!(
        until_expiry > 0,
        "old-root certificate expired before the boundary test"
    );
    // A certificate is unexpired while `now <= notAfter` (CONTRACT.agent-identity.md §6), so it expires one second
    // after `notAfter`.
    ctx.target.advance(until_expiry + 1).await?;
    let now = chain_evaluation_time(&ctx).await?;
    ensure!(
        now > expiry && now < expiry + 60 && now < deadline - 60,
        "certificate is not expired within grace and before the rotation deadline"
    );
    let completed = ctx.target.management().rotation().await?;
    let roots = ctx.target.trust_anchor().await?;
    ensure!(
        !completed.rotating()
            && completed.active_identities_on_old_root == 0
            && roots["roots"]
                .as_array()
                .is_some_and(|entries| entries.len() == 1 && entries[0]["thumbprint"] == new_root),
        "expiry of the last active old-root certificate did not finish the rotation early"
    );
    // DVLS's intent, "Terminology": `grace` holds "no unexpired certificate but one within renewal grace".
    ensure!(
        identity_record(&ctx.target, &expired.identity_id).await?.status == IdentityStatus::Grace,
        "an identity whose only certificate expired within renewal grace is not in grace"
    );

    let new_key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&expired, &new_key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    let chain = renewed.body["certificate_chain"]
        .as_array()
        .context("grace renewal chain")?
        .iter()
        .map(|cert| cert.as_str().context("chain element").map(str::to_owned))
        .collect::<anyhow::Result<Vec<_>>>()?;
    verify_chain(&chain, &roots, chain_evaluation_time(&ctx).await?)?;
    ensure!(
        thumbprint(chain.last().context("new root")?)? == new_root
            && new_root != old_root
            && !ctx.target.management().rotation().await?.rotating(),
        "expired old-root certificate did not renew onto the new root after early completion"
    );
    Ok(())
}

pub(crate) async fn p_rotation_completes_early_at_certificate_expiry_via_freeze(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 30 })).await?;
    let (_, short) = issued(&ctx, "freeze-short-old-root").await?;
    let expiry = identity_record(&ctx.target, &short.identity_id)
        .await?
        .not_after()
        .context("identity has no current certificate")?
        .unix_timestamp();
    let old_root = thumbprint(short.certificate_chain.last().context("missing old root")?)?;
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 180 })).await?;
    let (_, long) = issued(&ctx, "freeze-long-old-root").await?;
    let started = ctx.target.management().rotate(RotationDeadline::Default).await?;
    ensure!(
        started.rotating() && started.active_identities_on_old_root == 2,
        "rotation did not start with two active old-root certificates"
    );
    let deadline = started.deadline()?.unix_timestamp();
    ctx.target.management().revoke(&long.identity_id).await?;

    // A certificate is unexpired while `now <= notAfter` (CONTRACT.agent-identity.md §6), so the rotation completes one second after `notAfter`.
    let at_expiry = ctx.target.control("time/freeze", &json!({ "now": expiry })).await?;
    expect_status(&at_expiry, 200)?;
    ensure!(
        at_expiry.body["published_roots"]
            .as_array()
            .is_some_and(|roots| roots.len() == 2)
            && ctx.target.management().rotation().await?.active_identities_on_old_root == 1,
        "old root was removed while the last certificate was unexpired at its notAfter"
    );
    let expired = ctx.target.control("time/freeze", &json!({ "now": expiry + 1 })).await?;
    expect_status(&expired, 200)?;
    ensure!(
        expiry + 1 < deadline
            && expired.body["published_roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 1 && roots[0] != old_root)
            && !ctx.target.management().rotation().await?.rotating(),
        "freezing the clock just after certificate expiry did not complete the rotation immediately"
    );
    Ok(())
}

pub(crate) async fn p_rotation_push_rate_survives_deadline(ctx: Context) -> anyhow::Result<()> {
    ctx.target
        .faults(&json!({ "rotation_rate_limit_per_sec": 1, "leaf_lifetime_secs": 30 }))
        .await?;
    let mut pushes = tokio::task::JoinSet::new();
    for index in 0..3 {
        let (_, identity) = issued(&ctx, &format!("rate-{index}")).await?;
        let mut stream = channel::open(&ctx.target, &identity).await?;
        stream.hello(&identity, &[]).await?;
        pushes.spawn(async move {
            let push = stream.next().await?;
            ensure!(
                matches!(
                    push.payload,
                    Some(agent_channel_proto::server_message::Payload::RenewRequested(ref renewal))
                        if renewal.reason == "rotation"
                ),
                "queued rotation push has the wrong payload"
            );
            Ok::<_, anyhow::Error>(Instant::now())
        });
    }
    let start = Instant::now();
    ctx.target.management().rotate(RotationDeadline::Now).await?;
    let first = tokio::time::timeout(Duration::from_millis(500), pushes.join_next())
        .await?
        .context("first rotation push missing")???;
    ensure!(
        first.duration_since(start) < Duration::from_millis(500),
        "first rotation push was not immediate"
    );
    for _ in 0..10 {
        let roots = ctx.target.trust_anchor().await?;
        ensure!(
            roots["roots"].as_array().is_some_and(|items| items.len() == 1),
            "deadline did not apply"
        );
    }
    if start.elapsed() < Duration::from_millis(800) {
        ensure!(
            pushes.try_join_next().is_none(),
            "HTTP requests reset the rotation push rate budget"
        );
    }
    let second = tokio::time::timeout(Duration::from_secs(3), pushes.join_next())
        .await?
        .context("second rotation push did not drain after deadline")???;
    let third = tokio::time::timeout(Duration::from_secs(3), pushes.join_next())
        .await?
        .context("third rotation push did not drain after deadline")???;
    ensure!(
        second.duration_since(first) >= Duration::from_millis(800)
            && third.duration_since(second) >= Duration::from_millis(800),
        "rotation pushes exceeded one per elapsed second"
    );
    Ok(())
}

pub(crate) async fn p_rotation_deadline_removes_old_root(ctx: Context) -> anyhow::Result<()> {
    if !ctx.mock() {
        wait_rotation_idle(&ctx.target, ctx.dvls_rotation_window_secs).await?;
    }
    let original = ctx.target.trust_anchor().await?;
    let old_thumb = field(&original["roots"][0], "thumbprint")?.to_owned();
    let _ = issued(&ctx, "deadline-old-root").await?;
    let started = if ctx.mock() {
        let now = ctx.target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
            .as_i64()
            .context("mock clock is missing")?;
        let deadline = time::OffsetDateTime::from_unix_timestamp(now + 20)?;
        ctx.target.management().rotate(RotationDeadline::At(deadline)).await?
    } else {
        begin_rotation(&ctx).await?
    };
    let deadline = started.deadline()?.unix_timestamp();
    ensure!(
        ctx.target.trust_anchor().await?["roots"]
            .as_array()
            .context("roots")?
            .len()
            == 2,
        "old root not published"
    );
    if ctx.mock() {
        let before = ctx
            .target
            .control("time/freeze", &json!({ "now": deadline - 1 }))
            .await?;
        expect_status(&before, 200)?;
        ensure!(
            before.body["now"] == deadline - 1
                && before.body["published_roots"]
                    .as_array()
                    .is_some_and(|roots| roots.len() == 2 && roots.iter().any(|root| root == &old_thumb)),
            "old root was removed before the deadline"
        );
        ensure!(
            ctx.target.trust_anchor().await?["roots"]
                .as_array()
                .is_some_and(|roots| { roots.len() == 2 && roots.iter().any(|root| root["thumbprint"] == old_thumb) }),
            "trust-anchor omitted the old root before the deadline"
        );
        let at_deadline = ctx.target.control("time/freeze", &json!({ "now": deadline })).await?;
        expect_status(&at_deadline, 200)?;
        ensure!(
            at_deadline.body["now"] == deadline
                && at_deadline.body["published_roots"]
                    .as_array()
                    .is_some_and(|roots| roots.len() == 1 && roots.iter().all(|root| root != &old_thumb)),
            "old root remained published at the exact deadline"
        );
    } else {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        ensure!(deadline > now + 2, "DVLS deadline passed before boundary check");
        tokio::time::sleep(Duration::from_secs(u64::try_from(deadline - now - 2)?)).await;
        ensure!(
            ctx.target.trust_anchor().await?["roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 2),
            "DVLS removed the old root before the deadline"
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if now < deadline {
            tokio::time::sleep(Duration::from_secs(u64::try_from(deadline - now)?)).await;
        }
    }
    let mut after = ctx.target.trust_anchor().await?;
    if !ctx.mock() && after["roots"].as_array().is_none_or(|roots| roots.len() != 1) {
        let started = Instant::now();
        loop {
            after = ctx.target.trust_anchor().await?;
            if after["roots"].as_array().is_some_and(|roots| roots.len() == 1) {
                break;
            }
            ensure!(
                started.elapsed() <= Duration::from_secs(2),
                "DVLS removed the old root more than two seconds after the deadline"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let entries = after["roots"].as_array().context("roots after deadline")?;
    ensure!(entries.len() == 1, "old root remained after the exact mock deadline");
    ensure!(
        ctx.mock() || time::OffsetDateTime::now_utc().unix_timestamp() <= deadline + 2,
        "old root was removed more than two seconds after deadline"
    );
    ensure!(entries[0]["thumbprint"] != old_thumb, "old root still trusted");
    Ok(())
}

pub(crate) async fn p_rotation_old_root_cert_renewable_after_deadline(ctx: Context) -> anyhow::Result<()> {
    let (_, old) = issued(&ctx, "still-allowed").await?;
    let original_root = thumbprint(old.certificate_chain.last().context("missing old root")?)?;
    ctx.target.management().rotate(RotationDeadline::Now).await?;
    ctx.target.advance(1).await?;
    let roots = ctx.target.trust_anchor().await?;
    ensure!(
        roots["roots"]
            .as_array()
            .context("published roots")?
            .iter()
            .all(|root| root["thumbprint"] != original_root),
        "old root remained published after emergency deadline"
    );
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&old, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    let new_chain = renewed.body["certificate_chain"]
        .as_array()
        .context("renewal chain")?
        .iter()
        .map(|value| value.as_str().context("chain item").map(str::to_owned))
        .collect::<anyhow::Result<Vec<_>>>()?;
    verify_chain(&new_chain, &roots, chain_evaluation_time(&ctx).await?)?;
    ensure!(
        thumbprint(new_chain.last().context("root")?)? != original_root,
        "renewal issued under old root"
    );
    Ok(())
}

pub(crate) async fn p_rotation_emergency_deadline(ctx: Context) -> anyhow::Result<()> {
    if !ctx.mock() {
        ensure!(
            ctx.disposable_dvls_target,
            "DVLS rotation requires --disposable-dvls-target"
        );
        wait_rotation_idle(&ctx.target, ctx.dvls_rotation_window_secs).await?;
    }
    let (_, identity) = issued(&ctx, "emergency-old-root").await?;
    let before = ctx.target.trust_anchor().await?;
    let roots = before["roots"].as_array().context("roots before emergency rotation")?;
    ensure!(
        roots.len() == 1,
        "emergency rotation did not start with one published root"
    );
    let old_thumb = field(&roots[0], "thumbprint")?.to_owned();
    let old_record = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        old_record.status == IdentityStatus::Active
            && !old_record.connected
            && old_record.issuer() == Some(&*old_thumb)
            && old_record.has_certificate(&identity.thumbprint, CertificateStatus::Current),
        "emergency rotation fixture lacks an active, unconnected old-root identity"
    );
    ctx.target.management().rotate(RotationDeadline::Now).await?;
    let started = Instant::now();
    loop {
        let after = ctx.target.trust_anchor().await?;
        let published = after["roots"].as_array().context("emergency roots")?;
        if published.len() == 1 && published[0]["thumbprint"] != old_thumb {
            break;
        }
        ensure!(
            !ctx.mock() && started.elapsed() < Duration::from_secs(2),
            "emergency deadline retained the old root while its identity was active"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let remaining = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        remaining.status == IdentityStatus::Active
            && !remaining.connected
            && remaining.issuer() == Some(&*old_thumb)
            && remaining.has_certificate(&identity.thumbprint, CertificateStatus::Current),
        "emergency rotation changed the old-root identity rather than only publishing the new root"
    );
    Ok(())
}

pub(crate) async fn p_rotation_request_renewal_pushed(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "rotation-push").await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    stream.hello(&identity, &[]).await?;
    begin_rotation(&ctx).await?;
    let push = stream
        .next_with_timeout(if ctx.mock() {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(ctx.dvls_rotation_window_secs.saturating_add(5))
        })
        .await?;
    ensure!(
        matches!(
            push.payload,
            Some(agent_channel_proto::server_message::Payload::RenewRequested(ref reason))
                if reason.reason == "rotation"
        ),
        "rotation did not push RenewRequested(rotation)"
    );
    stream.ack(&push).await?;
    finish_rotation(&ctx).await?;
    Ok(())
}

pub(crate) async fn p_rotation_pending_only_old_root_receives_push(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 30 })).await?;
    let (_, mut identity) = issued(&ctx, "pending-only-old-root").await?;
    let old_root = thumbprint(identity.certificate_chain.last().context("missing old root")?)?;
    let current_expiry = identity_record(&ctx.target, &identity.identity_id)
        .await?
        .not_after()
        .context("identity has no current certificate")?
        .unix_timestamp();
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 120 })).await?;
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    ensure!(
        thumbprint(identity.certificate_chain.last().context("missing pending root")?)? == old_root,
        "pending certificate was not issued under the old root"
    );
    let mut stream = channel::open(&ctx.target, &identity).await?;
    stream.hello(&identity, &[]).await?;
    let until_expiry = current_expiry - chain_evaluation_time(&ctx).await?;
    ensure!(until_expiry > 0, "current certificate expired before the boundary test");
    // A certificate is unexpired while `now <= notAfter` (CONTRACT.agent-identity.md §6), so the current certificate expires one second after `notAfter`.
    ctx.target.advance(until_expiry + 1).await?;
    let record = identity_record(&ctx.target, &identity.identity_id).await?;
    ensure!(
        record.connected && record.has_certificate(&identity.thumbprint, CertificateStatus::Pending),
        "pending-only old-root stream was not connected after current expiry"
    );
    // DVLS's intent, "Terminology": `active` holds "an unexpired current or pending certificate".
    ensure!(
        record.status == IdentityStatus::Active,
        "an identity with only an unexpired pending certificate is not active"
    );
    let started = ctx.target.management().rotate(RotationDeadline::Default).await?;
    ensure!(
        started.rotating()
            && started.active_identities_on_old_root == 1
            && ctx.target.trust_anchor().await?["roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 2),
        "rotation omitted the pending-only old-root identity"
    );
    let push = stream.next().await?;
    ensure!(
        matches!(
            push.payload,
            Some(agent_channel_proto::server_message::Payload::RenewRequested(ref reason))
                if reason.reason == "rotation"
        ),
        "pending-only old-root stream did not receive RenewRequested(rotation)"
    );
    stream.ack(&push).await?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id)
            .await?
            .renewal_requested,
        "rotation did not persist the request-renewal flag for the pending-only identity"
    );
    Ok(())
}

pub(crate) async fn p_listing_pagination_stable_during_concurrent_enrollment(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 10).await?;
    let mut created = Vec::new();
    for n in 0..4 {
        created.push(
            identity(&ctx.target, &token, &format!("initial-{n}"))
                .await?
                .identity_id,
        );
    }
    let initial = created.clone();
    let mut overlapping = Vec::new();
    let mut page = 1;
    loop {
        ensure!(page <= 20, "overlapping page walk did not reach the last page");
        let listing = listing_page(&ctx.target, &token, page).await?;
        overlapping.extend(listing.rows.into_iter().map(|(id, _)| id));
        if page >= listing.total_pages {
            break;
        }
        if page <= 3 {
            for n in 0..2 {
                created.push(
                    identity(&ctx.target, &token, &format!("overlapping-{page}-{n}"))
                        .await?
                        .identity_id,
                );
            }
        }
        page += 1;
    }
    let mut distinct: Vec<String> = Vec::new();
    for id in overlapping {
        if !distinct.contains(&id) {
            distinct.push(id);
        }
    }
    ensure!(
        initial.iter().all(|id| distinct.contains(id)),
        "overlapping page walk missed an identity that existed when it started"
    );
    let mut in_creation_order = created.iter();
    ensure!(
        distinct.iter().all(|id| in_creation_order.any(|created| created == id)),
        "overlapping page walk listed identities out of creation order"
    );

    let mut walked = Vec::new();
    let mut timestamps = Vec::new();
    for page in 1..=5 {
        let listing = listing_page(&ctx.target, &token, page).await?;
        ensure!(
            listing.total_count == created.len() as u64 && listing.total_pages == 5,
            "page {page} reports {} identities on {} pages instead of {} on 5",
            listing.total_count,
            listing.total_pages,
            created.len()
        );
        for (id, created_at) in listing.rows {
            walked.push(id);
            timestamps.push(created_at);
        }
    }
    ensure!(
        walked == created,
        "page walk without concurrent enrollment did not list every identity exactly once in creation order"
    );
    ensure!(
        timestamps.windows(2).all(|pair| pair[0] <= pair[1]),
        "creation time decreased in creation order"
    );
    ensure!(
        refusal(listing_page(&ctx.target, &token, 6).await)? == Refusal::Invalid,
        "page past the last page was not refused"
    );
    Ok(())
}

/// One two-row page of the token's identities as `(id, creation time)` pairs, with the reported totals.
struct ListingPage {
    rows: Vec<(String, time::OffsetDateTime)>,
    total_count: u64,
    total_pages: u64,
}

async fn listing_page(target: &Target, token: &Token, page: u64) -> anyhow::Result<ListingPage> {
    let listing = target
        .management()
        .identities(&IdentityQuery::enrolled_with(token).full().page(page, 2))
        .await?;
    let rows = listing
        .items
        .into_iter()
        .map(|row| {
            Ok((
                row.id,
                row.created_at.context("full listing omitted the creation time")?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(ListingPage {
        rows,
        total_count: listing.total_count,
        total_pages: listing.total_pages,
    })
}

pub(crate) async fn p_listing_views_filters_and_bounds(ctx: Context) -> anyhow::Result<()> {
    let management = ctx.target.management();
    let decoy_token = token(&ctx, 1).await?;
    let token = token(&ctx, 5).await?;
    let active_key = KeyPair::generate()?;
    let active_reply = ctx
        .target
        .enroll(
            &token.text,
            &active_key,
            &json!({ "hostname": "filter-host", "os_name": "Linux" }),
        )
        .await?;
    let active = Identity::from_enrollment(active_key, &active_reply)?;
    let revoked = identity(&ctx.target, &token, "other-host").await?;
    let decoy = identity(&ctx.target, &decoy_token, "decoy-host").await?;
    ensure!(
        management.identity_count(&decoy_token).await? == 1,
        "decoy token identity not listed"
    );
    ensure!(
        identity_record(&ctx.target, &decoy.identity_id).await?.id == decoy.identity_id,
        "decoy identity missing"
    );
    management.revoke(&revoked.identity_id).await?;
    let renamed = management.rename(&active.identity_id, "Filter-Host-Renamed").await?;
    ensure!(
        renamed.friendly_name == "Filter-Host-Renamed",
        "identity rename was not persisted"
    );
    for invalid in ["".to_owned(), "x".repeat(256)] {
        ensure!(
            refusal(management.rename(&active.identity_id, &invalid).await)? == Refusal::Invalid,
            "friendly name of {} characters was accepted",
            invalid.chars().count()
        );
    }
    let of_token = || IdentityQuery::enrolled_with(&token);
    let summary = management
        .identities(
            &of_token()
                .summary()
                .metadata(&["hostname", "arch"])
                .status(IdentityStatus::Active),
        )
        .await?;
    let [row] = summary.items.as_slice() else {
        anyhow::bail!("active filter returned {} identities", summary.items.len());
    };
    ensure!(
        summary.total_count == 1 && row.id == active.identity_id,
        "active filter selected wrong identity"
    );
    ensure!(
        row.friendly_name == "Filter-Host-Renamed",
        "summary did not reflect renamed identity"
    );
    ensure!(
        row.metadata_value("hostname") == Some("filter-host"),
        "metadata subset missing hostname"
    );
    ensure!(
        row.metadata_value("arch").is_none() && row.metadata_value("os_name").is_none(),
        "metadata subset included a key outside the subset"
    );
    ensure!(row.certificates.is_none(), "summary included full certificates");
    let full = management
        .identities(&of_token().full().status(IdentityStatus::Revoked))
        .await?;
    ensure!(
        full.total_count == 1
            && full.items.len() == 1
            && full.items[0].id == revoked.identity_id
            && full.items[0].status == IdentityStatus::Revoked,
        "revoked filter selected wrong identity or status"
    );
    ensure!(full.items[0].certificates.is_some(), "full view has no certificates");
    let by_name = management.identities(&of_token().name_contains("FILTER-HOST")).await?;
    ensure!(
        by_name.total_count == 1 && by_name.items.first().is_some_and(|row| row.id == active.identity_id),
        "friendly-name substring filter failed"
    );
    let all_metadata = management
        .identities(&of_token().full().status(IdentityStatus::Active))
        .await?;
    ensure!(
        all_metadata
            .items
            .first()
            .is_some_and(|row| row.metadata_value("os_name") == Some("Linux")),
        "full view omitted metadata"
    );
    let issuer = row.issuer().context("summary omitted the current certificate")?;
    let by_issuer = management.identities(&of_token().issuer(issuer)).await?;
    ensure!(
        by_issuer.total_count == 2
            && by_issuer.items.iter().map(|row| row.id.as_str()).collect::<Vec<_>>()
                == [active.identity_id.as_str(), revoked.identity_id.as_str()],
        "issuer filter returned incorrect identity IDs"
    );
    let paged = management.identities(&of_token().page(2, 1)).await?;
    ensure!(
        paged.size == 1
            && paged.number == 2
            && paged.total_count == 2
            && paged.total_pages == 2
            && paged.items.len() == 1
            && paged.items[0].id == revoked.identity_id,
        "page fields incorrect"
    );
    // A page past the last, and a page number beyond the management API's integers, are invalid.
    for (number, size) in [
        (1, 0),
        (1, dvls::MAX_PAGE_SIZE + 1),
        (0, 1),
        (3, 1),
        (u64::MAX, dvls::MAX_PAGE_SIZE),
    ] {
        ensure!(
            refusal(management.identities(&of_token().page(number, size)).await)? == Refusal::Invalid,
            "page {number} of size {size} was accepted"
        );
    }
    expect_status(
        &ctx.target
            .renew(&active, &KeyPair::generate()?, &json!({ "hostname": "filter-host" }))
            .await?,
        200,
    )?;
    next_last_seen_second(&ctx).await?;
    expect_status(
        &ctx.target
            .check_in(&active, &json!({ "hostname": "filter-host" }))
            .await?,
        200,
    )?;
    let observed = identity_record(&ctx.target, &active.identity_id).await?;
    let instant = observed
        .last_seen_at
        .context("check-in did not set the last-seen time for filtering")?;
    let after = instant - time::Duration::seconds(1);
    let before = instant + time::Duration::seconds(1);
    for (query, expected) in [
        (of_token().status(IdentityStatus::Active).last_seen_from(after), true),
        (of_token().status(IdentityStatus::Active).last_seen_to(before), true),
        (of_token().status(IdentityStatus::Active).last_seen_from(before), false),
    ] {
        let result = management.identities(&query).await?;
        ensure!(
            result.total_count == u64::from(expected)
                && if expected {
                    result.items.len() == 1
                        && result.items[0].id == active.identity_id
                        && result.items[0].status == IdentityStatus::Active
                } else {
                    result.items.is_empty()
                },
            "last-seen filter returned the wrong identity IDs or statuses"
        );
    }
    if ctx.mock() {
        // The active identity's current and pending certificates both last 90 days, so its renewal grace lasts 90 more.
        for (days, status) in [(91, IdentityStatus::Grace), (90, IdentityStatus::Expired)] {
            ctx.target.advance(days * 24 * 3600).await?;
            let filtered = management.identities(&of_token().status(status)).await?;
            ensure!(
                filtered.total_count == 1
                    && filtered.items.len() == 1
                    && filtered.items[0].id == active.identity_id
                    && filtered.items[0].status == status,
                "{status:?} status filter selected wrong identity ID or status"
            );
        }
    }
    Ok(())
}

pub(crate) async fn p_management_tokens_crud_and_states(ctx: Context) -> anyhow::Result<()> {
    let management = ctx.target.management();
    let token = token(&ctx, 1).await?;
    let record = management.token(&token.id).await?;
    ensure!(
        record.state == TokenState::Active && record.used_count == 0,
        "new token not active"
    );
    ensure!(
        !management.token_discloses_secret(&token).await?,
        "token secret leaked in its management API record"
    );
    ensure!(
        management
            .all_tokens()
            .await?
            .iter()
            .any(|record| record.id == token.id),
        "created token not listed"
    );
    let _ = identity(&ctx.target, &token, "exhaust").await?;
    let record = management.token(&token.id).await?;
    ensure!(
        record.state == TokenState::Exhausted && record.used_count == 1,
        "exhausted state incorrect"
    );
    if ctx.mock() {
        let expiring = management.create_token(1, Duration::from_secs(2), None).await?;
        ctx.target.advance(4).await?;
        ensure!(
            management.token(&expiring.id).await?.state == TokenState::Expired,
            "expired token did not enter expired state"
        );
    }
    management.delete_token(&token.id).await?;
    ensure!(
        refusal(management.token(&token.id).await)? == Refusal::NotFound,
        "deleted token is still readable"
    );
    // DVLS's intent, "Enrollment tokens": a token allows from 1 to 1,000,000 uses and expires at most 365 days ahead.
    for uses in [0, 1_000_001] {
        let spec = TokenSpec::new(uses, TOKEN_LIFETIME)?;
        ensure!(
            refusal(management.create_token_from(&spec).await)? == Refusal::Invalid,
            "token with {uses} uses was accepted"
        );
    }
    let spec = TokenSpec::new(1, Duration::from_secs(366 * 24 * 3600))?;
    ensure!(
        refusal(management.create_token_from(&spec).await)? == Refusal::Invalid,
        "token expiring after 365 days was accepted"
    );
    // The document: a token page holds at most 500 tokens.
    management.tokens(1, dvls::MAX_TOKEN_PAGE_SIZE).await?;
    for (number, size) in [(1, 0), (1, dvls::MAX_TOKEN_PAGE_SIZE + 1), (0, 1)] {
        ensure!(
            refusal(management.tokens(number, size).await)? == Refusal::Invalid,
            "token page {number} of size {size} was accepted"
        );
    }
    Ok(())
}

pub(crate) async fn p_management_requires_auth(ctx: Context) -> anyhow::Result<()> {
    assert_management_routes_denied(&ctx, Credential::Absent, |_| true, Refusal::Unauthenticated).await?;
    // oracle: spec DVLS public API contract §6
    let unknown = unknown_token_id();
    assert_management_routes_denied(&ctx, Credential::TokenId(&unknown), |_| true, Refusal::Unauthenticated).await?;
    Ok(())
}

/// A `tokenId` that names no session.
///
/// It is a GUID, so that DVLS refuses it as an invalid token, with a `PublicApiError`, rather than as a malformed one, with an empty 401 (DVLS's public API contract, "6. Errors").
fn unknown_token_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn trust_anchor_snapshot(value: &Value) -> anyhow::Result<Vec<Value>> {
    let roots = value["roots"]
        .as_array()
        .context("trust-anchor response omitted roots")?;
    let mut known = roots
        .iter()
        .map(|root| {
            let mut known = serde_json::Map::new();
            for name in ["certificate", "thumbprint", "not_before", "not_after"] {
                known.insert(name.to_owned(), json!(field(root, name)?));
            }
            Ok(Value::Object(known))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    known.sort_by(|left, right| left["thumbprint"].as_str().cmp(&right["thumbprint"].as_str()));
    Ok(known)
}

/// Checks that `credential` gets `expected` from every management API route that `selected` keeps, without any state change.
async fn assert_management_routes_denied(
    ctx: &Context,
    credential: Credential<'_>,
    selected: impl Fn(Permission) -> bool,
    expected: Refusal,
) -> anyhow::Result<()> {
    let token = token(ctx, 1).await?;
    let identity = identity(&ctx.target, &token, "untouched").await?;
    let mut stream = if ctx.mock() && ctx.channel_available {
        let mut stream = channel::open(&ctx.target, &identity).await?;
        stream.hello(&identity, &[]).await?;
        Some(stream)
    } else {
        None
    };
    let management = ctx.target.management();
    let identity_before = identity_record(&ctx.target, &identity.identity_id).await?;
    let token_before = management.token(&token.id).await?;
    let roots_before = trust_anchor_snapshot(&ctx.target.trust_anchor().await?)?;
    let rotation_before = management.rotation().await?;
    let settings_before = management.settings().await?;
    let events_before = if ctx.mock() {
        Some(ctx.target.events(&identity.identity_id).await?)
    } else {
        None
    };
    let mut create = TokenSpec::new(1, TOKEN_LIFETIME)?;
    create.name = format!("unauthorized-{}", uuid::Uuid::new_v4());
    // On a non-disposable DVLS target, the rotation request is malformed and the settings change empty, so that neither can change the target even if authorization is broken.
    let routes = dvls::routes(&token.id, &identity.identity_id, &create, "unauthorized", !ctx.mock())?;
    let denied = ctx.target.management_as(credential);
    for route in routes.iter().filter(|route| selected(route.permission)) {
        ensure!(
            refusal(denied.call(route).await)? == expected,
            "unauthorized {route} was not refused as {expected:?}"
        );
        ensure!(
            management.token(&token.id).await? == token_before,
            "unauthorized {route} changed the enrollment token"
        );
        ensure!(
            management
                .all_tokens()
                .await?
                .iter()
                .all(|record| record.name != create.name),
            "unauthorized {route} created a token"
        );
        ensure!(
            identity_record(&ctx.target, &identity.identity_id).await? == identity_before,
            "unauthorized {route} changed the identity"
        );
        ensure!(
            management.rotation().await? == rotation_before
                && trust_anchor_snapshot(&ctx.target.trust_anchor().await?)? == roots_before,
            "unauthorized {route} changed CA rotation state"
        );
        ensure!(
            management.settings().await? == settings_before,
            "unauthorized {route} changed the settings"
        );
        if let Some(events) = &events_before {
            ensure!(
                ctx.target.events(&identity.identity_id).await? == *events,
                "unauthorized {route} changed the channel or certificate events"
            );
        }
    }
    if let Some(stream) = stream.as_mut() {
        ensure!(
            tokio::time::timeout(Duration::from_millis(100), stream.stream.message())
                .await
                .is_err(),
            "unauthorized management API request pushed a channel message"
        );
    }
    Ok(())
}

/// The OpenAPI document gives each operation a 403 response that names the permission it lacks, such as "Missing the AgentIdentityManage permission" for a settings change.
///
/// Each route group, the settings included, is called with a credential lacking that group's permission; on the mock it holds every other permission, so none stands in for the missing one.
pub(crate) async fn p_management_permission_denied(ctx: Context) -> anyhow::Result<()> {
    for permission in Permission::ALL {
        let session =
            dvls::session_lacking(&ctx, permission).ok_or(crate::Incomplete("requires --unprivileged-app-key"))?;
        assert_management_routes_denied(
            &ctx,
            Credential::Session(&session),
            |required| required == permission,
            Refusal::Forbidden,
        )
        .await
        .with_context(|| format!("credential lacking {permission:?}"))?;
    }
    Ok(())
}

pub(crate) async fn p_rotation_start_requires_auth(ctx: Context) -> anyhow::Result<()> {
    ensure!(
        ctx.mock() || ctx.disposable_dvls_target,
        "rotation authorization requires a disposable DVLS target"
    );
    let before = trust_anchor_snapshot(&ctx.target.trust_anchor().await?)?;
    let rotation = ctx.target.management().rotation().await?;
    // oracle: spec DVLS public API contract §6
    let unknown = unknown_token_id();
    let lacking = dvls::session_lacking(&ctx, Permission::RotateRoot);
    let mut credentials = vec![
        (Credential::Absent, Refusal::Unauthenticated),
        (Credential::TokenId(&unknown), Refusal::Unauthenticated),
    ];
    credentials.extend(
        lacking
            .as_deref()
            .map(|session| (Credential::Session(session), Refusal::Forbidden)),
    );
    for (credential, expected) in credentials {
        ensure!(
            refusal(ctx.target.management_as(credential).rotate(RotationDeadline::Now).await)? == expected,
            "unauthorized rotation was not refused as {expected:?}"
        );
        ensure!(
            trust_anchor_snapshot(&ctx.target.trust_anchor().await?)? == before,
            "unauthorized rotation changed published roots"
        );
        ensure!(
            ctx.target.management().rotation().await? == rotation,
            "unauthorized rotation changed state"
        );
    }
    Ok(())
}

/// The OpenAPI document, on a token's `expiresOn`: "in the future and at most 365 days ahead ... (Default: 90 days ahead)".
pub(crate) async fn p_token_expiry_default_and_maximum(ctx: Context) -> anyhow::Result<()> {
    let management = ctx.target.management();
    let mut spec = TokenSpec::new(1, TOKEN_LIFETIME)?;
    spec.expires_on = None;
    let default = management.create_token_from(&spec).await?;
    let record = management.token(&default.id).await?;
    let ahead = record.expires_on - record.created_on;
    ensure!(
        (ahead - time::Duration::days(90)).abs() <= time::Duration::MINUTE,
        "a token created without an expiry expires {ahead} after its creation instead of 90 days"
    );
    let longest = management
        .create_token_from(&TokenSpec::new(1, Duration::from_secs(365 * DAY_SECS - 3600))?)
        .await?;
    let mut past = TokenSpec::new(1, TOKEN_LIFETIME)?;
    past.expires_on = Some(time::OffsetDateTime::now_utc() - time::Duration::HOUR);
    ensure!(
        refusal(management.create_token_from(&past).await)? == Refusal::Invalid,
        "a token that has already expired was accepted"
    );
    for token in [default, longest] {
        management.delete_token(&token.id).await?;
    }
    Ok(())
}

/// The OpenAPI document: starting a rotation is 409 when "no root exists yet", and "The first token also creates the Agent Identity root".
pub(crate) async fn p_rotation_without_root_conflicts(ctx: Context) -> anyhow::Result<()> {
    expect_status(
        &ctx.target.control("reset", &json!({ "without_root": true })).await?,
        200,
    )?;
    let published = |roots: &Value| roots["roots"].as_array().map(Vec::len);
    ensure!(
        published(&ctx.target.trust_anchor().await?) == Some(0),
        "an authority without a root published one"
    );
    ensure!(
        refusal(ctx.target.management().rotate(RotationDeadline::Default).await)? == Refusal::Conflict,
        "a rotation started without a root"
    );
    ensure!(
        !ctx.target.management().rotation().await?.rotating()
            && published(&ctx.target.trust_anchor().await?) == Some(0),
        "a refused rotation without a root changed the rotation or published a root"
    );
    let _ = token(&ctx, 1).await?;
    ensure!(
        published(&ctx.target.trust_anchor().await?) == Some(1),
        "the first token did not create the root"
    );
    Ok(())
}

/// The OpenAPI document: starting a rotation is 409 when "the root key is unavailable", and creating the first token is 409 when "The first root cannot be created because the data encryption key is unavailable".
pub(crate) async fn p_root_key_unavailable_conflicts(ctx: Context) -> anyhow::Result<()> {
    let _ = issued(&ctx, "root-key").await?;
    let roots = trust_anchor_snapshot(&ctx.target.trust_anchor().await?)?;
    ctx.target.faults(&json!({ "root_key_unavailable": true })).await?;
    ensure!(
        refusal(ctx.target.management().rotate(RotationDeadline::Default).await)? == Refusal::Conflict,
        "a rotation started with an unavailable root key"
    );
    ensure!(
        !ctx.target.management().rotation().await?.rotating()
            && trust_anchor_snapshot(&ctx.target.trust_anchor().await?)? == roots,
        "a refused rotation changed the rotation or the published roots"
    );

    expect_status(
        &ctx.target.control("reset", &json!({ "without_root": true })).await?,
        200,
    )?;
    ctx.target.faults(&json!({ "root_key_unavailable": true })).await?;
    let spec = TokenSpec::new(1, TOKEN_LIFETIME)?;
    ensure!(
        refusal(ctx.target.management().create_token_from(&spec).await)? == Refusal::Conflict,
        "the first token was created although its root could not be"
    );
    ensure!(
        ctx.target
            .management()
            .all_tokens()
            .await?
            .iter()
            .all(|record| record.name != spec.name)
            && ctx.target.trust_anchor().await?["roots"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "a refused first token was kept or published a root"
    );
    Ok(())
}

/// The OpenAPI document, on the settings: `authorityId` is "The authority_id agents receive at enrollment", and `isAgentChannelAvailable` is "Whether DVLS offers the agent channel: it is enabled and the hosting supports it".
/// DVLS's intent, "Certificates and channel", offers the channel as `config.agent_channel_url`.
pub(crate) async fn p_settings_read(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "settings").await?;
    let settings = ctx.target.management().settings().await?;
    ensure!(
        uuid::Uuid::parse_str(&settings.authority_id)? == uuid::Uuid::parse_str(&identity.authority_id)?,
        "the settings report another authority ID than enrollment"
    );
    ensure!(
        settings.channel_available == identity.agent_channel_url.is_some(),
        "the settings and enrollment disagree on whether the agent channel is offered"
    );
    ensure!(
        settings.channel_enabled || !settings.channel_available,
        "the agent channel is offered while it is disabled"
    );
    Ok(())
}

/// The OpenAPI document, on a settings change: `certificateLifetimeDays` is "from 1 to 365 days" and `rotationNotificationsPerSecond` "from 1 to 1000".
pub(crate) async fn p_settings_change_bounds(ctx: Context) -> anyhow::Result<()> {
    require_settings_changes(&ctx)?;
    let management = ctx.target.management();
    let original = management.settings().await?;
    restoring_settings(&ctx, &original, async {
        let lifetime = |days| SettingsChange {
            certificate_lifetime_days: Some(days),
            ..SettingsChange::default()
        };
        let rate = |per_second| SettingsChange {
            rotation_notifications_per_second: Some(per_second),
            ..SettingsChange::default()
        };
        for (change, name) in [
            (lifetime(0), "a certificate lifetime of 0 days"),
            (lifetime(366), "a certificate lifetime of 366 days"),
            (rate(0), "0 rotation notifications per second"),
            (rate(1001), "1001 rotation notifications per second"),
        ] {
            ensure!(
                refusal(management.change_settings(&change).await)? == Refusal::Invalid,
                "{name} was accepted"
            );
        }
        ensure!(
            management.settings().await? == original,
            "a refused settings change changed the settings"
        );
        for (change, name) in [
            (lifetime(1), "a certificate lifetime of 1 day"),
            (lifetime(365), "a certificate lifetime of 365 days"),
            (rate(1), "1 rotation notification per second"),
            (rate(1000), "1000 rotation notifications per second"),
        ] {
            let changed = management.change_settings(&change).await.context(name)?;
            ensure!(
                changed == management.settings().await?
                    && change
                        .certificate_lifetime_days
                        .is_none_or(|days| changed.certificate_lifetime_days == days)
                    && change
                        .rotation_notifications_per_second
                        .is_none_or(|per_second| changed.rotation_notifications_per_second == per_second),
                "{name} was not applied"
            );
        }
        Ok(())
    })
    .await
}

/// The OpenAPI document: `certificateLifetimeDays` is "The lifetime of the identity certificates issued from now on, in days".
pub(crate) async fn p_settings_certificate_lifetime_applies_to_new_certificates(ctx: Context) -> anyhow::Result<()> {
    require_settings_changes(&ctx)?;
    let management = ctx.target.management();
    let original = management.settings().await?;
    if !ctx.mock() && ctx.leaf_lifetime_secs != original.certificate_lifetime_days * DAY_SECS {
        return Err(
            crate::Incomplete("requires --leaf-lifetime-secs to match the DVLS certificate lifetime in days").into(),
        );
    }
    let (_, earlier) = issued(&ctx, "lifetime-before").await?;
    let earlier_expiry = identity_record(&ctx.target, &earlier.identity_id)
        .await?
        .not_after()
        .context("identity has no current certificate")?;
    let days = if original.certificate_lifetime_days == 7 { 8 } else { 7 };
    restoring_settings(&ctx, &original, async {
        let changed = management
            .change_settings(&SettingsChange {
                certificate_lifetime_days: Some(days),
                ..SettingsChange::default()
            })
            .await?;
        ensure!(
            changed.certificate_lifetime_days == days && management.settings().await? == changed,
            "the certificate lifetime change was not applied"
        );
        let issued_from = time::OffsetDateTime::now_utc();
        let (_, later) = issued(&ctx, "lifetime-after").await?;
        expect_status(
            &ctx.target.renew(&earlier, &KeyPair::generate()?, &json!({})).await?,
            200,
        )?;
        let issued_until = time::OffsetDateTime::now_utc();
        // The tolerance covers the clock difference between the runner and the authority; a lifetime one day off falls outside it.
        let tolerance = time::Duration::minutes(5);
        let lifetime = time::Duration::days(i64::try_from(days)?);
        let expected = (issued_from + lifetime - tolerance)..=(issued_until + lifetime + tolerance);
        let later = identity_record(&ctx.target, &later.identity_id).await?;
        let earlier = identity_record(&ctx.target, &earlier.identity_id).await?;
        for (certificate, name) in [
            (
                later.certificate_with(CertificateStatus::Current),
                "an enrolled certificate",
            ),
            (
                earlier.certificate_with(CertificateStatus::Pending),
                "a renewed certificate",
            ),
        ] {
            let not_after = certificate.with_context(|| format!("{name} is missing"))?.not_after;
            ensure!(
                expected.contains(&not_after),
                "{name} issued after the change expires at {not_after} instead of {days} days after its issuance"
            );
        }
        ensure!(
            earlier.not_after() == Some(earlier_expiry),
            "the certificate lifetime change altered a certificate issued before it"
        );
        Ok(())
    })
    .await
}

/// The OpenAPI document: `isAgentChannelEnabled` "turns the agent channel off behind a reverse proxy that breaks gRPC", and `isAgentChannelAvailable` is "Whether DVLS offers the agent channel: it is enabled and the hosting supports it".
/// DVLS's intent, "Certificates and channel", offers the channel as `config.agent_channel_url`.
pub(crate) async fn p_settings_channel_switch_withdraws_and_restores_channel_url(ctx: Context) -> anyhow::Result<()> {
    require_settings_changes(&ctx)?;
    let management = ctx.target.management();
    let original = management.settings().await?;
    let (_, identity) = issued(&ctx, "channel-switch").await?;
    let url = identity
        .agent_channel_url
        .clone()
        .context("enrollment offered no agent channel")?;
    ensure!(
        original.channel_enabled && original.channel_available,
        "the settings do not report the agent channel that enrollment offered"
    );
    restoring_settings(&ctx, &original, async {
        let switch = |enabled| SettingsChange {
            channel_enabled: Some(enabled),
            ..SettingsChange::default()
        };
        let disabled = management.change_settings(&switch(false)).await?;
        ensure!(
            !disabled.channel_enabled && !disabled.channel_available,
            "the agent channel is still offered after it was disabled"
        );
        ensure!(
            check_in_config(&ctx.target, &identity)
                .await?
                .get("agent_channel_url")
                .is_none(),
            "check-in config kept the agent channel URL after the channel was disabled"
        );
        let enabled = management.change_settings(&switch(true)).await?;
        ensure!(
            enabled.channel_enabled && enabled.channel_available,
            "the agent channel is not offered after it was enabled again"
        );
        ensure!(
            check_in_config(&ctx.target, &identity).await?["agent_channel_url"] == url.as_str(),
            "check-in config did not restore the agent channel URL"
        );
        Ok(())
    })
    .await
}

const DAY_SECS: u64 = 24 * 3600;

/// Changing the settings of a DVLS target affects every agent it serves, so only a disposable one allows it.
fn require_settings_changes(ctx: &Context) -> anyhow::Result<()> {
    if ctx.mock() || ctx.disposable_dvls_target {
        Ok(())
    } else {
        Err(crate::Incomplete("changing settings requires --disposable-dvls-target").into())
    }
}

/// Runs `test`, then restores `original`, so that a failing test leaves the target's settings as it found them.
async fn restoring_settings(
    ctx: &Context,
    original: &Settings,
    test: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let result = test.await;
    let restored = ctx
        .target
        .management()
        .change_settings(&SettingsChange {
            channel_enabled: Some(original.channel_enabled),
            certificate_lifetime_days: Some(original.certificate_lifetime_days),
            rotation_notifications_per_second: Some(original.rotation_notifications_per_second),
        })
        .await;
    result?;
    ensure!(
        restored? == *original,
        "restoring the settings did not return them to their original values"
    );
    Ok(())
}

pub(crate) async fn p_error_body_shape(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 2).await?;
    let invalid = ctx
        .target
        .agent(
            Method::POST,
            "/enroll",
            Some(&json!({ "csr": "not valid base64!" })),
            Some(&token.text),
        )
        .await?;
    expect_error(&invalid, 400, "invalid_request")?;
    let unknown = ctx
        .target
        .enroll(
            &format!(
                "{}.{}",
                token.text.rsplit_once('.').context("token structure")?.0,
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x19; 32])
            ),
            &KeyPair::generate()?,
            &json!({}),
        )
        .await?;
    expect_error(&unknown, 401, "token_invalid")?;
    let issued = identity(&ctx.target, &token, "errors").await?;
    let key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": key.csr, "metadata": {} }))?;
    let mut wrong_tag = issued.key.sign_now(&issued.thumbprint, "connect", None);
    attach_content_digest(&mut wrong_tag, &body);
    expect_error(
        &ctx.target.signed_renew(&body, &wrong_tag, None).await?,
        401,
        "signature_invalid",
    )?;
    for (method, path, body, status) in [
        (
            Method::POST,
            "/api/agent-identity/v1/enroll",
            Some(b"{".as_slice()),
            400,
        ),
        (Method::GET, "/api/agent-identity/v1/enroll", None, 405),
        (Method::GET, "/api/agent-identity/v1/unknown", None, 404),
    ] {
        expect_error(
            &ctx.target.send(method, path, body, Some(&token.text), None).await?,
            status,
            "invalid_request",
        )?;
    }
    if ctx.mock() {
        let oversized = vec![b' '; 64 * 1024 + 1];
        expect_error(
            &ctx.target
                .send(
                    Method::POST,
                    "/api/agent-identity/v1/enroll",
                    Some(&oversized),
                    Some(&token.text),
                    None,
                )
                .await?,
            413,
            "invalid_request",
        )?;
        let signed = issued.key.sign_now(&issued.thumbprint, "renew", Some(&oversized));
        expect_error(
            &ctx.target.signed_renew(&oversized, &signed, None).await?,
            413,
            "invalid_request",
        )?;
    }
    Ok(())
}

pub(crate) async fn p_enroll_malformed_authorization_rejected(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 1).await?;
    let key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": key.csr, "metadata": {} }))?;
    let bearer = format!("Bearer {}", token.text);
    for (variant, values) in [
        ("missing", Vec::new()),
        ("repeated", vec![bearer.clone(), bearer.clone()]),
        ("Basic scheme", vec![format!("Basic {}", token.text)]),
        ("token without a scheme", vec![token.text.clone()]),
    ] {
        let mut headers = http::HeaderMap::new();
        for value in values {
            headers.append(http::header::AUTHORIZATION, value.parse()?);
        }
        expect_error(
            &post_with_headers(&ctx.target, "enroll", headers, body.clone()).await?,
            401,
            "token_invalid",
        )
        .with_context(|| format!("{variant} Authorization header"))?;
    }
    ensure!(
        ctx.target.management().token(&token.id).await?.used_count == 0
            && ctx.target.management().identity_count(&token).await? == 0,
        "malformed Authorization header consumed a token use or created an identity"
    );
    expect_status(&ctx.target.enroll(&token.text, &key, &json!({})).await?, 200)
        .context("well-formed Authorization header was not accepted after the malformed ones")
}

pub(crate) async fn p_authentication_error_precedes_invalid_body(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 2).await?;
    let unknown_token = format!(
        "{}.{}",
        token.text.rsplit_once('.').context("token structure")?.0,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a; 32])
    );
    let invalid_enroll = serde_json::to_vec(&json!({ "csr": "not base64!", "metadata": [] }))?;
    for (variant, body, bearer) in [
        (
            "invalid fields with an unknown token",
            invalid_enroll.as_slice(),
            Some(unknown_token.as_str()),
        ),
        ("invalid fields without Authorization", invalid_enroll.as_slice(), None),
        (
            "malformed JSON with an unknown token",
            b"{".as_slice(),
            Some(unknown_token.as_str()),
        ),
    ] {
        expect_error(
            &ctx.target
                .send(Method::POST, "/api/agent-identity/v1/enroll", Some(body), bearer, None)
                .await?,
            401,
            "token_invalid",
        )
        .with_context(|| format!("enroll body with {variant}"))?;
    }
    ensure!(
        ctx.target.management().token(&token.id).await?.used_count == 0,
        "rejected enrollments consumed a token use"
    );

    let revoked = identity(&ctx.target, &token, "auth-precedence-revoked").await?;
    let identity = identity(&ctx.target, &token, "auth-precedence").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let invalid_renew = serde_json::to_vec(&json!({ "csr": "not base64!", "metadata": { "Bad Key": 1 } }))?;
    let impostor = KeyPair::generate()?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let unknown_keyid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x33; 32]);
    for (variant, headers, status, code) in [
        (
            "a signature by another key",
            impostor.sign_now(&identity.thumbprint, "renew", Some(&invalid_renew)),
            401,
            "signature_invalid",
        ),
        (
            "an unregistered keyid",
            impostor.sign_now(&unknown_keyid, "renew", Some(&invalid_renew)),
            401,
            "identity_unknown",
        ),
        (
            "an expired signature window",
            identity.key.sign(
                &identity.thumbprint,
                "renew",
                Some(&invalid_renew),
                now - 600,
                now - 540,
                &fresh_nonce(),
            ),
            401,
            "clock_skew",
        ),
    ] {
        expect_error(
            &ctx.target.signed_renew(&invalid_renew, &headers, None).await?,
            status,
            code,
        )
        .with_context(|| format!("invalid renew body with {variant}"))?;
    }
    ensure!(
        identity_record(&ctx.target, &identity.identity_id).await? == before,
        "rejected renewals changed identity state"
    );

    ctx.target.management().revoke(&revoked.identity_id).await?;
    let invalid_check_in = serde_json::to_vec(&json!({ "metadata": "not an object" }))?;
    let headers = revoked
        .key
        .sign_now(&revoked.thumbprint, "check-in", Some(&invalid_check_in));
    expect_error(
        &ctx.target.signed_check_in(&invalid_check_in, &headers).await?,
        403,
        "identity_revoked",
    )
    .context("invalid check-in body from a revoked identity")
}

pub(crate) async fn p_oversized_body_precedes_authentication(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "oversized-precedence").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let oversized = vec![b' '; 64 * 1024 + 1];
    expect_error(
        &ctx.target
            .send(
                Method::POST,
                "/api/agent-identity/v1/enroll",
                Some(&oversized),
                None,
                None,
            )
            .await?,
        413,
        "invalid_request",
    )
    .context("oversized enroll without Authorization")?;
    let impostor = KeyPair::generate()?;
    expect_error(
        &ctx.target
            .signed_renew(
                &oversized,
                &impostor.sign_now(&identity.thumbprint, "renew", Some(&oversized)),
                None,
            )
            .await?,
        413,
        "invalid_request",
    )
    .context("oversized renew signed by another key")?;
    let unknown_keyid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x44; 32]);
    expect_error(
        &ctx.target
            .signed_check_in(
                &oversized,
                &impostor.sign_now(&unknown_keyid, "check-in", Some(&oversized)),
            )
            .await?,
        413,
        "invalid_request",
    )
    .context("oversized check-in with an unregistered keyid")?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id).await? == before,
        "oversized requests changed identity state"
    );
    Ok(())
}

async fn post_with_headers(
    target: &Target,
    endpoint: &str,
    headers: http::HeaderMap,
    body: Vec<u8>,
) -> anyhow::Result<Reply> {
    let response = target
        .http
        .post(format!("{}/api/agent-identity/v1/{endpoint}", target.base_url))
        .headers(headers)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .context("send HTTP request")?;
    Ok(Reply {
        status: response.status().as_u16(),
        body: response.json().await.context("decode JSON response")?,
    })
}

pub(crate) async fn p_mock_fault_response_not_processed(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 1).await?;
    let key = KeyPair::generate()?;
    ctx.target
        .faults(&json!({ "fail_next_response": { "endpoint": "enroll", "status": 503 } }))
        .await?;
    let failed = ctx.target.enroll(&token.text, &key, &json!({})).await?;
    expect_status(&failed, 503)?;
    ensure!(failed.body.is_null(), "fault without an error code returned a body");
    ensure!(
        count(&ctx.target.requests(Some(&token)).await?, "enroll")? == 1
            && ctx.target.management().token(&token.id).await?.used_count == 0
            && ctx.target.management().identity_count(&token).await? == 0,
        "failed enrollment was processed or not counted"
    );
    ctx.target
        .faults(&json!({ "fail_next_response": { "endpoint": "enroll", "status": 400 } }))
        .await?;
    let empty_bad_request = ctx.target.enroll(&token.text, &key, &json!({})).await?;
    expect_status(&empty_bad_request, 400)?;
    ensure!(
        empty_bad_request.body.is_null(),
        "injected empty 400 gained a framework error body"
    );
    ensure!(
        ctx.target.management().token(&token.id).await?.used_count == 0,
        "injected empty 400 processed an enrollment"
    );
    let enrolled = ctx.target.enroll(&token.text, &key, &json!({})).await?;
    let identity = Identity::from_enrollment(key, &enrolled)?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let next_key = KeyPair::generate()?;
    ctx.target
        .faults(&json!({
            "fail_next_response": { "endpoint": "renew", "status": 400, "error": "token_invalid" }
        }))
        .await?;
    expect_error(
        &ctx.target
            .renew(&identity, &next_key, &json!({ "hostname": "unprocessed" }))
            .await?,
        400,
        "token_invalid",
    )?;
    ctx.target
        .faults(&json!({
            "fail_next_response": { "endpoint": "renew", "status": 400, "error": "invalid_request" }
        }))
        .await?;
    expect_error(
        &ctx.target
            .renew(&identity, &next_key, &json!({ "hostname": "unprocessed" }))
            .await?,
        400,
        "invalid_request",
    )?;
    ensure!(
        identity_record(&ctx.target, &identity.identity_id).await? == before,
        "injected renewal error processed a certificate or metadata"
    );
    expect_status(&ctx.target.renew(&identity, &next_key, &json!({})).await?, 200)?;
    ensure!(
        ctx.target.control("faults", &json!({})).await?.body["fail_next_response"].is_null(),
        "one-shot fault was not consumed"
    );
    Ok(())
}

/// Sends `body` to `enroll` exactly as given.
async fn enroll_raw(target: &Target, token: &Token, body: &[u8]) -> anyhow::Result<Reply> {
    target
        .send(
            Method::POST,
            "/api/agent-identity/v1/enroll",
            Some(body),
            Some(&token.text),
            None,
        )
        .await
}

/// Signs `body` with `identity`'s current key and sends it to `endpoint` (`renew` or `check-in`) exactly as given.
async fn signed_raw(target: &Target, identity: &Identity, endpoint: &str, body: &[u8]) -> anyhow::Result<Reply> {
    let headers = identity.key.sign_now(&identity.thumbprint, endpoint, Some(body));
    match endpoint {
        "renew" => target.signed_renew(body, &headers, None).await,
        "check-in" => target.signed_check_in(body, &headers).await,
        _ => anyhow::bail!("{endpoint} takes no body"),
    }
}

/// CONTRACT.agent-identity.md §1: "A JSON request body that repeats a member name at any depth, such as `csr` twice or one metadata key twice, → `invalid_request`".
///
/// Every repeated member holds a valid value, so a parser that keeps either occurrence would accept the request.
pub(crate) async fn p_duplicate_json_members_rejected(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 2).await?;
    let (first, second) = (KeyPair::generate()?, KeyPair::generate()?);
    let (a, b) = (&first.csr, &second.csr);
    for (variant, body) in [
        ("csr", format!(r#"{{"csr":"{a}","csr":"{b}","metadata":{{}}}}"#)),
        (
            "metadata",
            format!(r#"{{"csr":"{a}","metadata":{{}},"metadata":{{}}}}"#),
        ),
        (
            "metadata key",
            format!(r#"{{"csr":"{a}","metadata":{{"hostname":"one","hostname":"two"}}}}"#),
        ),
        (
            "unknown member",
            format!(r#"{{"csr":"{a}","metadata":{{}},"extra":1,"extra":2}}"#),
        ),
        (
            "nested unknown member",
            format!(r#"{{"csr":"{a}","metadata":{{}},"extra":{{"inner":1,"inner":2}}}}"#),
        ),
    ] {
        expect_error(
            &enroll_raw(&ctx.target, &token, body.as_bytes()).await?,
            400,
            "invalid_request",
        )
        .with_context(|| format!("enroll body repeating {variant}"))?;
    }
    let management = ctx.target.management();
    ensure!(
        management.token(&token.id).await?.used_count == 0 && management.identity_count(&token).await? == 0,
        "an enrollment body with a repeated member created an identity"
    );
    let identity = identity(&ctx.target, &token, "duplicates").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    for (endpoint, variant, body) in [
        (
            "renew",
            "csr",
            format!(r#"{{"csr":"{a}","csr":"{b}","metadata":{{}}}}"#),
        ),
        (
            "renew",
            "metadata key",
            format!(r#"{{"csr":"{a}","metadata":{{"hostname":"one","hostname":"two"}}}}"#),
        ),
        ("check-in", "metadata", r#"{"metadata":{},"metadata":{}}"#.to_owned()),
        (
            "check-in",
            "metadata key",
            r#"{"metadata":{"hostname":"one","hostname":"two"}}"#.to_owned(),
        ),
    ] {
        expect_error(
            &signed_raw(&ctx.target, &identity, endpoint, body.as_bytes()).await?,
            400,
            "invalid_request",
        )
        .with_context(|| format!("{endpoint} body repeating {variant}"))?;
    }
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &before).await?;
    expect_status(&ctx.target.enroll(&token.text, &first, &json!({})).await?, 200)
        .context("the repeated members' values were not themselves valid")
}

/// A body for `csr` whose unknown member `extra` nests arrays and objects until the body holds `depth` of them, counting the top-level object.
///
/// The nesting alternates arrays and objects, so a limit that counts only one kind accepts the deeper body.
fn nested_body(csr: &str, depth: usize) -> String {
    let mut extra = "0".to_owned();
    for level in 1..depth {
        extra = if level % 2 == 0 {
            format!(r#"{{"n":{extra}}}"#)
        } else {
            format!("[{extra}]")
        };
    }
    format!(r#"{{"csr":"{csr}","metadata":{{}},"extra":{extra}}}"#)
}

/// CONTRACT.agent-identity.md §1: "A JSON request body with more than 64 nested objects and arrays, counting the top-level object, [...] → `invalid_request`".
pub(crate) async fn p_json_body_nesting_limit(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    let token = token(&ctx, 2).await?;
    let (enrolled, renewed) = (KeyPair::generate()?, KeyPair::generate()?);
    expect_error(
        &enroll_raw(&ctx.target, &token, nested_body(&enrolled.csr, 65).as_bytes()).await?,
        400,
        "invalid_request",
    )
    .context("enroll body nested 65 deep")?;
    let management = ctx.target.management();
    ensure!(
        management.token(&token.id).await?.used_count == 0 && management.identity_count(&token).await? == 0,
        "an enrollment body nested 65 deep created an identity"
    );
    let identity = identity(&ctx.target, &token, "nesting").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    expect_error(
        &signed_raw(
            &ctx.target,
            &identity,
            "renew",
            nested_body(&renewed.csr, 65).as_bytes(),
        )
        .await?,
        400,
        "invalid_request",
    )
    .context("renew body nested 65 deep")?;
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &before)
        .await
        .context("a renew body nested 65 deep changed the identity")?;
    expect_status(
        &enroll_raw(&ctx.target, &token, nested_body(&enrolled.csr, 64).as_bytes()).await?,
        200,
    )
    .context("enroll body nested 64 deep")?;
    expect_status(
        &signed_raw(
            &ctx.target,
            &identity,
            "renew",
            nested_body(&renewed.csr, 64).as_bytes(),
        )
        .await?,
        200,
    )
    .context("renew body nested 64 deep")
}

/// Strings that are not valid Unicode, as JSON escapes and as raw bytes that are not UTF-8.
const INVALID_UNICODE: [(&str, &[u8]); 6] = [
    ("escaped lone high surrogate", br"\ud800"),
    ("escaped lone low surrogate", br"\udc00"),
    ("escaped reversed surrogate pair", br"\udc00\ud800"),
    // oracle: spec RFC 3629 §1
    ("raw byte 0xFF", b"\xff"),
    // oracle: spec RFC 3629 §3
    ("raw UTF-8 form of a surrogate", b"\xed\xa0\x80"),
    // oracle: spec RFC 3629 §3
    ("raw overlong encoding", b"\xc0\xaf"),
];

/// Bodies for `csr` holding `content` inside a string, in the unknown member `extra` and in the `hostname` metadata value, which takes any valid string.
fn bodies_with_string(csr: &str, content: &[u8]) -> [(&'static str, Vec<u8>); 2] {
    let unknown = format!(r#"{{"csr":"{csr}","metadata":{{}},"extra":""#);
    let hostname = format!(r#"{{"csr":"{csr}","metadata":{{"hostname":"host"#);
    [
        (
            "unknown member",
            [unknown.as_bytes(), content, br#""}"#.as_slice()].concat(),
        ),
        (
            "hostname metadata value",
            [hostname.as_bytes(), content, br#""}}"#.as_slice()].concat(),
        ),
    ]
}

/// CONTRACT.agent-identity.md §1: "A JSON request body [...] holding a string that is not valid Unicode, such as an escaped lone surrogate, in any member, including an unknown one → `invalid_request`".
pub(crate) async fn p_invalid_unicode_json_strings_rejected(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    let token = token(&ctx, 2).await?;
    let (enrolled, renewed) = (KeyPair::generate()?, KeyPair::generate()?);
    for (variant, content) in INVALID_UNICODE {
        for (member, body) in bodies_with_string(&enrolled.csr, content) {
            expect_error(&enroll_raw(&ctx.target, &token, &body).await?, 400, "invalid_request")
                .with_context(|| format!("enroll body with {variant} in the {member}"))?;
        }
    }
    let management = ctx.target.management();
    ensure!(
        management.token(&token.id).await?.used_count == 0 && management.identity_count(&token).await? == 0,
        "an enrollment body holding a string that is not valid Unicode created an identity"
    );
    let identity = identity(&ctx.target, &token, "unicode").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    for (variant, content) in INVALID_UNICODE {
        for (member, body) in bodies_with_string(&renewed.csr, content) {
            expect_error(
                &signed_raw(&ctx.target, &identity, "renew", &body).await?,
                400,
                "invalid_request",
            )
            .with_context(|| format!("renew body with {variant} in the {member}"))?;
        }
    }
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &before)
        .await
        .context("a renew body holding a string that is not valid Unicode changed the identity")?;
    // oracle: spec RFC 8259 §7
    // RFC 8259's example escapes U+1D11E as this surrogate pair, so the same members holding a valid escape are accepted and decoded.
    let pair = br"\uD834\uDD1E";
    let [_, (_, body)] = bodies_with_string(&enrolled.csr, pair);
    let control = Identity::from_enrollment(enrolled, &enroll_raw(&ctx.target, &token, &body).await?)
        .context("enroll body with an escaped surrogate pair in the hostname metadata value")?;
    let [_, (_, body)] = bodies_with_string(&renewed.csr, pair);
    expect_status(&signed_raw(&ctx.target, &identity, "renew", &body).await?, 200)
        .context("renew body with an escaped surrogate pair in the hostname metadata value")?;
    for id in [&control.identity_id, &identity.identity_id] {
        ensure!(
            identity_record(&ctx.target, id).await?.metadata_value("hostname") == Some("host\u{1D11E}"),
            "an escaped surrogate pair in the hostname was not stored as U+1D11E"
        );
    }
    Ok(())
}

/// A CSR whose canonical `base64` encoding has padding and uses both `+` or `/` characters, so that every non-canonical rewrite applies.
fn key_with_rewritable_csr() -> anyhow::Result<KeyPair> {
    for _ in 0..64 {
        let key = KeyPair::generate()?;
        if key.csr.ends_with('=') && key.csr.contains(['+', '/']) {
            return Ok(key);
        }
    }
    anyhow::bail!("no generated CSR had a padded encoding with '+' or '/'")
}

/// Other encodings of the bytes `canonical` encodes, each of which a lenient decoder accepts.
fn noncanonical_base64(canonical: &str) -> anyhow::Result<Vec<(&'static str, String)>> {
    let wrapped = format!("csr:{canonical}:");
    let unwrap = |value: String| -> anyhow::Result<String> { Ok(split_byte_sequence(&value)?.1.to_owned()) };
    let (head, tail) = canonical.split_at(canonical.len() / 2);
    Ok(vec![
        ("non-zero padding bits", unwrap(with_nonzero_pad_bits(&wrapped)?)?),
        ("missing padding", unwrap(without_padding(&wrapped)?)?),
        ("line break", format!("{head}\n{tail}")),
        ("URL-safe alphabet", canonical.replace('+', "-").replace('/', "_")),
    ])
}

/// CONTRACT.agent-identity.md §1: "Senders use the canonical form of every `base64` and `base64url` value, so that each byte string has one encoding; a request body holding another form → `invalid_request`."
pub(crate) async fn p_noncanonical_base64_csr_rejected(ctx: Context) -> anyhow::Result<()> {
    let (token, identity) = issued(&ctx, "noncanonical-csr").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let key = key_with_rewritable_csr()?;
    for (variant, csr) in noncanonical_base64(&key.csr)? {
        let body = serde_json::to_vec(&json!({ "csr": csr, "metadata": {} }))?;
        expect_error(&enroll_raw(&ctx.target, &token, &body).await?, 400, "invalid_request")
            .with_context(|| format!("enroll CSR with {variant}"))?;
        expect_error(
            &signed_raw(&ctx.target, &identity, "renew", &body).await?,
            400,
            "invalid_request",
        )
        .with_context(|| format!("renew CSR with {variant}"))?;
    }
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &before).await?;
    ensure!(
        ctx.target.management().token(&token.id).await?.used_count == 1,
        "a non-canonical CSR consumed a token use"
    );
    expect_status(&ctx.target.enroll(&token.text, &key, &json!({})).await?, 200)
        .context("the canonical CSR of the same key was not accepted")
}

/// CONTRACT.agent-identity.md §2: "The authority authenticates a token by its exact `secret` text alone and never checks the `bag`, which carries only routing data."
///
/// The rewritten secrets decode to the same 32 bytes, so only a comparison of the exact text refuses them.
pub(crate) async fn p_token_secret_must_match_exactly(ctx: Context) -> anyhow::Result<()> {
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let token = token(&ctx, 2).await?;
    let (prefix_and_bag, secret) = token.text.rsplit_once('.').context("token secret")?;
    let (prefix, bag) = prefix_and_bag.split_once('.').context("token bag")?;
    // 32 bytes leave two unused low bits in the last of the 43 secret characters.
    let (secret_head, last) = secret.split_at(secret.len() - 1);
    let index = URL_SAFE
        .iter()
        .position(|symbol| last.as_bytes() == [*symbol])
        .context("token secret is not base64url")?;
    ensure!(index & 3 == 0, "token secret is not canonical base64url");
    let noisy_secret = format!("{secret_head}{}", char::from(URL_SAFE[index | 1]));
    for (variant, text) in [
        (
            "non-zero unused secret bits",
            format!("{prefix_and_bag}.{noisy_secret}"),
        ),
        ("padded secret", format!("{prefix_and_bag}.{secret}=")),
    ] {
        expect_error(
            &ctx.target.enroll(&text, &KeyPair::generate()?, &json!({})).await?,
            401,
            "token_invalid",
        )
        .with_context(|| format!("token with {variant}"))?;
    }
    let management = ctx.target.management();
    ensure!(
        management.token(&token.id).await?.used_count == 0 && management.identity_count(&token).await? == 0,
        "a token whose secret text differs from the issued one created an identity"
    );
    let route: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(bag)
            .context("decode token bag")?,
    )?;
    let reencoded_bag = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec_pretty(&route)?);
    ensure!(reencoded_bag != bag, "re-encoding the token bag did not change it");
    expect_status(
        &ctx.target
            .enroll(
                &format!("{prefix}.{reencoded_bag}.{secret}"),
                &KeyPair::generate()?,
                &json!({}),
            )
            .await?,
        200,
    )
    .context("a token with another bag and the exact secret text was not accepted")?;
    expect_status(
        &ctx.target
            .enroll(&token.text, &KeyPair::generate()?, &json!({}))
            .await?,
        200,
    )
    .context("the issued token string was not accepted")?;
    ensure!(
        management.token(&token.id).await?.used_count == 2,
        "the exact secret text did not authenticate the token's uses"
    );
    Ok(())
}

/// A CSR for `key` whose public key is the compressed form of its point, validly self-signed.
fn compressed_point_csr(key: &KeyPair) -> anyhow::Result<String> {
    let mut request = x509_cert::request::CertReq::from_der(&decoded_certificate(&key.csr)?)?;
    let point = request.info.public_key.subject_public_key.raw_bytes();
    ensure!(
        point.len() == 65 && point[0] == 4,
        "generated CSR does not hold an uncompressed P-256 point"
    );
    let mut compressed = vec![2 | (point[64] & 1)];
    compressed.extend_from_slice(&point[1..33]);
    request.info.public_key.subject_public_key = der::asn1::BitString::from_bytes(&compressed)?;
    let signature: p256::ecdsa::DerSignature = key.key.try_sign(&request.info.to_der()?)?;
    request.signature = der::asn1::BitString::from_bytes(signature.as_bytes())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(request.to_der()?))
}

/// CONTRACT.agent-identity.md §4: the server "only takes the public key (an uncompressed P-256 point required, else `invalid_request`, so that each key has exactly one SPKI SHA-256)".
pub(crate) async fn p_compressed_point_csr_rejected(ctx: Context) -> anyhow::Result<()> {
    let (token, identity) = issued(&ctx, "compressed-point").await?;
    let before = identity_record(&ctx.target, &identity.identity_id).await?;
    let key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": compressed_point_csr(&key)?, "metadata": {} }))?;
    expect_error(&enroll_raw(&ctx.target, &token, &body).await?, 400, "invalid_request")
        .context("enroll CSR with a compressed point")?;
    expect_error(
        &signed_raw(&ctx.target, &identity, "renew", &body).await?,
        400,
        "invalid_request",
    )
    .context("renew CSR with a compressed point")?;
    assert_identity_metadata_and_certificates_unchanged(&ctx.target, &identity.identity_id, &before).await?;
    expect_status(&ctx.target.enroll(&token.text, &key, &json!({})).await?, 200)
        .context("the uncompressed CSR of the same key was not accepted")
}

/// Shared intent, "Enrollment": "The result is trimmed, truncated to 255 Unicode scalar values without splitting one, and trimmed again, so a stored name never starts or ends with white space (Unicode `White_Space`)".
pub(crate) async fn p_friendly_name_white_space_and_truncation(ctx: Context) -> anyhow::Result<()> {
    let cases = [
        ("\u{3000}\u{a0}name\u{2003}\u{1680}", "name".to_owned()),
        // U+200B ZERO WIDTH SPACE is not `White_Space`.
        ("\u{200b}name\u{200b}", "\u{200b}name\u{200b}".to_owned()),
        (&*format!("{}{}", " ".repeat(10), "x".repeat(300)), "x".repeat(255)),
        (
            &*format!("{}\u{3000}{}", "a".repeat(254), "b".repeat(10)),
            "a".repeat(254),
        ),
        (
            &*format!("{}{}", "a".repeat(200), "\u{1f600}".repeat(60)),
            format!("{}{}", "a".repeat(200), "\u{1f600}".repeat(55)),
        ),
    ];
    let token = ctx
        .target
        .management()
        .create_token(cases.len() as u64, TOKEN_LIFETIME, Some("{hostname}"))
        .await?;
    for (hostname, expected) in cases {
        let enrolled = identity(&ctx.target, &token, hostname).await?;
        let name = identity_record(&ctx.target, &enrolled.identity_id).await?.friendly_name;
        ensure!(
            name == expected,
            "hostname {hostname:?} produced friendly name {name:?} instead of {expected:?}"
        );
    }
    Ok(())
}

/// DVLS's intent, "Terminology": an identity is `active` while it "holds an unexpired current or pending certificate", in `grace` while it "holds no unexpired certificate but one within renewal grace", `expired` "beyond renewal grace", or `revoked`.
///
/// A certificate is unexpired while `now <= notAfter` (CONTRACT.agent-identity.md §6), and renewal grace lasts while `now < notAfter + (notAfter − notBefore)`.
pub(crate) async fn p_identity_statuses(ctx: Context) -> anyhow::Result<()> {
    let management = ctx.target.management();
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 60 })).await?;
    let (_, pending_only) = issued(&ctx, "pending-only").await?;
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 600 })).await?;
    expect_status(
        &ctx.target
            .renew(&pending_only, &KeyPair::generate()?, &json!({}))
            .await?,
        200,
    )?;
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 60 })).await?;
    let (token, current_only) = issued(&ctx, "current-only").await?;
    let pending_only_expiry = identity_record(&ctx.target, &pending_only.identity_id)
        .await?
        .not_after()
        .context("pending-only identity has no current certificate")?
        .unix_timestamp();
    let current = identity_record(&ctx.target, &current_only.identity_id)
        .await?
        .certificate_with(CertificateStatus::Current)
        .context("identity has no current certificate")?
        .clone();
    let not_after = current.not_after.unix_timestamp();
    let lifetime = not_after - current.not_before.unix_timestamp();
    ensure!(
        pending_only_expiry <= not_after && lifetime > 1,
        "status fixture certificates have unexpected validity"
    );
    for (now, status) in [
        (not_after, IdentityStatus::Active),
        (not_after + 1, IdentityStatus::Grace),
        (not_after + lifetime - 1, IdentityStatus::Grace),
        (not_after + lifetime, IdentityStatus::Expired),
    ] {
        expect_status(&ctx.target.control("time/freeze", &json!({ "now": now })).await?, 200)?;
        let record = identity_record(&ctx.target, &current_only.identity_id).await?;
        let listed = management
            .identities(&IdentityQuery::enrolled_with(&token).status(status))
            .await?;
        ensure!(
            record.status == status && listed.items.iter().any(|row| row.id == current_only.identity_id),
            "{}s after notAfter, the identity is {:?} instead of {status:?}",
            now - not_after,
            record.status
        );
        if now == not_after + 1 {
            ensure!(
                identity_record(&ctx.target, &pending_only.identity_id).await?.status == IdentityStatus::Active,
                "an identity with an expired current certificate and an unexpired pending one is not active"
            );
        }
    }
    management.revoke(&current_only.identity_id).await?;
    ensure!(
        identity_record(&ctx.target, &current_only.identity_id).await?.status == IdentityStatus::Revoked
            && management
                .identities(&IdentityQuery::enrolled_with(&token).status(IdentityStatus::Expired))
                .await?
                .items
                .iter()
                .all(|row| row.id != current_only.identity_id),
        "a revoked identity is not reported as revoked only"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use prost::Message as _;

    use super::*;

    #[test]
    fn only_the_defective_frames_fail_a_reference_decoder() -> anyhow::Result<()> {
        // oracle: reference prost
        let message = agent_channel_proto::AgentMessage {
            id: String::new(),
            correlation_id: Some("challenge".to_owned()),
            payload: Some(agent_channel_proto::agent_message::Payload::Ack(
                agent_channel_proto::Ack {},
            )),
        };
        let valid = |id: &[u8], len| channel::agent_message_frame(id, &message, len);
        let frame = valid(b"id", channel::MAX_ENVELOPE_LEN)?;
        ensure!(
            frame.len() == channel::MAX_ENVELOPE_LEN
                && agent_channel_proto::AgentMessage::decode(frame.as_slice())?
                    == agent_channel_proto::AgentMessage {
                        id: "id".to_owned(),
                        ..message.clone()
                    },
            "the padded frame is not its message at the envelope limit"
        );
        for undecodable in [Undecodable::InvalidUtf8, Undecodable::Truncated] {
            ensure!(
                agent_channel_proto::AgentMessage::decode(undecodable.frame(valid)?.as_slice()).is_err(),
                "the {undecodable:?} frame decodes"
            );
        }
        let oversized = Undecodable::Oversized.frame(valid)?;
        ensure!(
            oversized.len() == channel::MAX_ENVELOPE_LEN + 1
                && agent_channel_proto::AgentMessage::decode(oversized.as_slice()).is_ok(),
            "the oversized frame is not a valid message one byte over the envelope limit"
        );
        Ok(())
    }

    #[test]
    fn byte_sequence_rewrites_keep_lenient_bytes_but_lose_canonical_form() -> anyhow::Result<()> {
        use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

        let lenient = GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(DecodePaddingMode::Indifferent),
        );
        // A 64-byte signature ends with two padding characters and a 32-byte digest with one.
        for bytes in [vec![0x5a; 64], vec![0xa5; 32]] {
            let value = format!("sig=:{}:", STANDARD.encode(&bytes));
            for rewritten in [with_nonzero_pad_bits(&value)?, without_padding(&value)?] {
                let (prefix, encoded) = split_byte_sequence(&rewritten)?;
                ensure!(
                    prefix == "sig=" && lenient.decode(encoded)? == bytes && STANDARD.decode(encoded).is_err(),
                    "{rewritten} does not decode leniently to the original bytes while failing strict decoding"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn disposable_rotation_requires_an_isolated_old_root() -> anyhow::Result<()> {
        let active = HashSet::from(["own".to_owned(), "other".to_owned()]);
        let error = require_isolated_old_root_fixture(&active, &["own"], false)
            .expect_err("occupied disposable DVLS fixture must be incomplete");
        ensure!(
            error.downcast_ref::<crate::Incomplete>().is_some(),
            "occupied disposable DVLS fixture did not report SKIP"
        );
        ensure!(
            require_isolated_old_root_fixture(&active, &["own"], true).is_err(),
            "mock reset left an unexpected active old-root identity"
        );
        require_isolated_old_root_fixture(&HashSet::from(["own".to_owned()]), &["own"], false)?;
        require_isolated_old_root_fixture(&HashSet::new(), &[], false)?;
        Ok(())
    }

    #[test]
    fn trust_anchor_snapshot_ignores_unknown_fields() -> anyhow::Result<()> {
        let roots = json!({
            "roots": [{
                "certificate": "root",
                "thumbprint": "root-id",
                "not_before": "start",
                "not_after": "end"
            }]
        });
        let mut noisy_roots = roots.clone();
        noisy_roots["request_id"] = json!("one");
        noisy_roots["roots"][0]["request_id"] = json!("two");
        ensure!(
            trust_anchor_snapshot(&roots)? == trust_anchor_snapshot(&noisy_roots)?,
            "unknown trust-anchor fields changed the published-root snapshot"
        );
        noisy_roots["roots"][0]["thumbprint"] = json!("other-root");
        ensure!(
            trust_anchor_snapshot(&roots)? != trust_anchor_snapshot(&noisy_roots)?,
            "changed root identity was ignored"
        );
        noisy_roots["roots"][0]["thumbprint"] = Value::Null;
        ensure!(
            trust_anchor_snapshot(&noisy_roots).is_err(),
            "explicit null root thumbprint was accepted"
        );
        Ok(())
    }

    #[test]
    fn chain_requires_published_root_validity_and_signed_p256_links() -> anyhow::Result<()> {
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let leaf = field(&vectors["keys"][0], "certificate")?.to_owned();
        let root = field(&vectors["root"], "certificate")?.to_owned();
        let chain = vec![leaf.clone(), root.clone()];
        let anchors = json!({ "roots": [{ "certificate": root }] });
        verify_chain(&chain, &anchors, 1_790_000_000)?;
        ensure!(
            verify_chain(&chain, &anchors, 1_790_000_000 + 10_000_000).is_err(),
            "expired leaf was accepted"
        );
        ensure!(
            verify_chain(&chain, &json!({ "roots": [] }), 1_790_000_000).is_err(),
            "unpublished root was accepted"
        );
        ensure!(
            verify_chain(std::slice::from_ref(&root), &anchors, 1_790_000_000).is_err(),
            "root-only chain was accepted"
        );
        let mut tampered_leaf = decoded_certificate(&leaf)?;
        *tampered_leaf.last_mut().context("missing certificate signature")? ^= 1;
        let tampered = vec![STANDARD.encode(tampered_leaf), root];
        ensure!(
            verify_chain(&tampered, &anchors, 1_790_000_000).is_err(),
            "invalid P-256 certificate signature was accepted"
        );
        Ok(())
    }

    #[test]
    fn chain_verifies_p384_intermediate_and_rejects_unknown_curve() -> anyhow::Result<()> {
        let ca = |name: &str| -> anyhow::Result<rcgen::CertificateParams> {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            params.distinguished_name.push(rcgen::DnType::CommonName, name);
            Ok(params)
        };
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let root = ca("root")?.self_signed(&root_key)?;
        let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?;
        let issuer = ca("p384 issuer")?.signed_by(&issuer_key, &root, &root_key)?;
        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let leaf =
            rcgen::CertificateParams::new(vec!["leaf.local".to_owned()])?.signed_by(&leaf_key, &issuer, &issuer_key)?;
        let chain = vec![
            STANDARD.encode(leaf.der()),
            STANDARD.encode(issuer.der()),
            STANDARD.encode(root.der()),
        ];
        let roots = json!({ "roots": [{ "certificate": chain[2] }] });
        verify_chain(&chain, &roots, time::OffsetDateTime::now_utc().unix_timestamp())?;
        let mut bad_leaf = leaf.der().as_ref().to_vec();
        *bad_leaf.last_mut().context("leaf signature missing")? ^= 1;
        let tampered = vec![STANDARD.encode(bad_leaf), chain[1].clone(), chain[2].clone()];
        ensure!(
            verify_chain(&tampered, &roots, time::OffsetDateTime::now_utc().unix_timestamp()).is_err(),
            "invalid P-384-signed certificate was accepted"
        );
        let mut unknown_curve = issuer.der().as_ref().to_vec();
        let p384_oid = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        let offset = unknown_curve
            .windows(p384_oid.len())
            .position(|window| window == p384_oid)
            .context("issuer does not use secp384r1")?;
        unknown_curve[offset + p384_oid.len() - 1] = 0x23;
        let unsupported = vec![chain[0].clone(), STANDARD.encode(unknown_curve), chain[2].clone()];
        ensure!(
            verify_chain(&unsupported, &roots, time::OffsetDateTime::now_utc().unix_timestamp())
                .expect_err("unverifiable issuer curve was accepted")
                .downcast_ref::<crate::Incomplete>()
                .is_some(),
            "an issuer algorithm the tester cannot verify was reported as a conformance failure"
        );
        Ok(())
    }

    #[test]
    fn chain_requires_ca_intermediates_but_no_root_profile() -> anyhow::Result<()> {
        let plain = |name: &str| -> anyhow::Result<rcgen::CertificateParams> {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
            params.distinguished_name.push(rcgen::DnType::CommonName, name);
            Ok(params)
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let root = plain("root without extensions")?.self_signed(&root_key)?;
        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let leaf = plain("leaf")?.signed_by(&leaf_key, &root, &root_key)?;
        let roots = json!({ "roots": [{ "certificate": STANDARD.encode(root.der()) }] });
        verify_chain(&[STANDARD.encode(leaf.der()), STANDARD.encode(root.der())], &roots, now)
            .context("a root without CA extensions was rejected")?;
        let intermediate_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let intermediate = plain("non-CA intermediate")?.signed_by(&intermediate_key, &root, &root_key)?;
        let leaf = plain("leaf")?.signed_by(&leaf_key, &intermediate, &intermediate_key)?;
        let chain = [
            STANDARD.encode(leaf.der()),
            STANDARD.encode(intermediate.der()),
            STANDARD.encode(root.der()),
        ];
        ensure!(
            verify_chain(&chain, &roots, now).is_err(),
            "a non-CA intermediate was accepted"
        );
        Ok(())
    }

    /// The conformance runs show the check passing a conforming leaf, but only a leaf with another extension shows it can fail.
    #[test]
    fn leaf_extensions_outside_the_profile_are_named() -> anyhow::Result<()> {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
        let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut issuer = rcgen::CertificateParams::new(Vec::<String>::new())?;
        issuer.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer = issuer.self_signed(&issuer_key)?;
        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let leaf = |is_ca: rcgen::IsCa| -> anyhow::Result<Certificate> {
            let mut params = rcgen::CertificateParams::new(vec!["leaf.local".to_owned()])?;
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            params.use_authority_key_identifier_extension = true;
            params.is_ca = is_ca;
            Ok(Certificate::from_der(
                params.signed_by(&leaf_key, &issuer, &issuer_key)?.der(),
            )?)
        };
        assert_leaf_extensions(&leaf(rcgen::IsCa::NoCa)?).context("SAN, EKU, KeyUsage and AKI were refused")?;
        // `ExplicitNoCa` adds a subject key identifier and a basicConstraints without cA.
        let error = assert_leaf_extensions(&leaf(rcgen::IsCa::ExplicitNoCa)?)
            .expect_err("a leaf with basicConstraints was accepted")
            .to_string();
        // oracle: spec RFC 5280 §4.2.1.9
        ensure!(
            error.ends_with(": 2.5.29.19"),
            "the failure does not name basicConstraints alone: {error}"
        );
        Ok(())
    }
}
