use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use der::{Decode as _, Encode as _};
use http::Method;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::{DecodePublicKey as _, EncodePublicKey as _};
use rand::RngExt as _;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use tonic::Code;
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName};

use crate::client::{Identity, Reply, Target, Token, count, decoded_certificate, expect_error, expect_status, field};
use crate::signer::{KeyPair, thumbprint};
use crate::{Context, channel};

const TOKEN_LIFETIME: Duration = Duration::from_secs(3600);

async fn token(ctx: &Context, max_uses: u32) -> anyhow::Result<Token> {
    ctx.target.create_token(max_uses, TOKEN_LIFETIME, None).await
}

async fn identity(target: &Target, token: &Token, hostname: &str) -> anyhow::Result<Identity> {
    let key = KeyPair::generate()?;
    let reply = target
        .enroll(&token.text, &key, &json!({ "hostname": hostname }))
        .await?;
    Identity::from_enrollment(key, &reply)
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

pub(crate) async fn wait_rotation_idle(target: &Target) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        let status = target.admin(Method::GET, "/ca/rotation", None).await?;
        expect_status(&status, 200)?;
        if status.body["phase"] == "idle" {
            return Ok(());
        }
        ensure!(
            started.elapsed() < Duration::from_secs(15),
            "rotation is already in progress; use a disposable DVLS target"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn begin_rotation(ctx: &Context) -> anyhow::Result<Reply> {
    if ctx.mock() {
        return ctx.target.rotate(None).await;
    }
    ensure!(
        ctx.disposable_dvls_target,
        "DVLS rotation requires --disposable-dvls-target"
    );
    wait_rotation_idle(&ctx.target).await?;
    let deadline = (time::OffsetDateTime::now_utc() + time::Duration::seconds(8)).format(&Rfc3339)?;
    ctx.target.rotate(Some(&deadline)).await
}

async fn finish_rotation(ctx: &Context) -> anyhow::Result<()> {
    if !ctx.mock() {
        wait_rotation_idle(&ctx.target).await?;
    }
    Ok(())
}

fn has_certificate(device: &Value, thumbprint: &str, status: &str) -> bool {
    device["certificates"].as_array().is_some_and(|certs| {
        certs
            .iter()
            .any(|cert| cert["thumbprint"] == thumbprint && cert["status"] == status)
    })
}

async fn device(target: &Target, id: &str) -> anyhow::Result<Value> {
    let reply = target.device(id).await?;
    expect_status(&reply, 200)?;
    Ok(reply.body)
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
    let (_, basic) = cert
        .tbs_certificate()
        .get_extension::<BasicConstraints>()?
        .context("root lacks basic constraints")?;
    ensure!(basic.ca, "trust anchor is not a CA");
    let (_, usage) = cert
        .tbs_certificate()
        .get_extension::<KeyUsage>()?
        .context("root lacks key usage")?;
    ensure!(usage.key_cert_sign(), "trust anchor lacks keyCertSign");
    let key = VerifyingKey::from_public_key_der(&cert.tbs_certificate().subject_public_key_info().to_der()?)?;
    let signature = Signature::from_der(cert.signature().as_bytes().context("root signature")?)?;
    key.verify(&cert.tbs_certificate().to_der()?, &signature)?;
    ensure!(
        cert.tbs_certificate().issuer() == cert.tbs_certificate().subject(),
        "root is not self-issued"
    );
    let subject = cert.tbs_certificate().subject().to_string();
    let name = subject.strip_prefix("CN=").context("root subject is not a CN")?;
    let (product, generation) = name
        .rsplit_once(" Agent Identity Root ")
        .context("root subject does not match the identity-root profile")?;
    ensure!(
        !product.is_empty() && generation.parse::<u32>().is_ok(),
        "invalid identity-root CN"
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
    let root_lifetime = cert_after - cert_before;
    ensure!(
        (10 * 365 * 24 * 3600..=10 * 366 * 24 * 3600).contains(&root_lifetime),
        "root certificate lifetime is not ten years"
    );
    Ok(())
}

fn assert_leaf_profile(leaf: &str, root: &str, device_id: &str, key: &KeyPair) -> anyhow::Result<()> {
    let cert = Certificate::from_der(&decoded_certificate(leaf)?)?;
    let root = Certificate::from_der(&decoded_certificate(root)?)?;
    let expected = format!("CN={device_id}").parse::<x509_cert::name::Name>()?;
    ensure!(
        cert.tbs_certificate().subject() == &expected,
        "leaf subject does not match device ID"
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
    let uri = format!("urn:uuid:{device_id}");
    ensure!(
        san.0
            .iter()
            .any(|name| matches!(name, GeneralName::UniformResourceIdentifier(value) if value.as_str() == uri)),
        "leaf SAN lacks the device URI"
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
    let validity = cert.tbs_certificate().validity();
    ensure!(
        validity.not_before.to_unix_duration() < validity.not_after.to_unix_duration(),
        "leaf validity has empty lifetime"
    );
    ensure!(
        validity.not_after.to_unix_duration() <= root.tbs_certificate().validity().not_after.to_unix_duration(),
        "leaf outlives issuing root"
    );
    let expected_end = (validity.not_before.to_unix_duration() + Duration::from_secs(90 * 24 * 3600))
        .min(root.tbs_certificate().validity().not_after.to_unix_duration());
    ensure!(
        validity.not_after.to_unix_duration() == expected_end,
        "leaf lifetime is not 90 days capped at the issuing root"
    );
    Ok(())
}

fn verify_chain(chain: &[String], roots: &Value) -> anyhow::Result<()> {
    ensure!(chain.len() >= 2, "certificate chain has no issuer");
    let certs = chain
        .iter()
        .map(|encoded| Certificate::from_der(&decoded_certificate(encoded)?).map_err(anyhow::Error::from))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for issuer in &certs[1..] {
        let (_, basic) = issuer
            .tbs_certificate()
            .get_extension::<BasicConstraints>()?
            .context("chain issuer lacks basic constraints")?;
        ensure!(basic.ca, "chain issuer is not a CA");
        let (_, usage) = issuer
            .tbs_certificate()
            .get_extension::<KeyUsage>()?
            .context("chain issuer lacks key usage")?;
        ensure!(usage.key_cert_sign(), "chain issuer lacks keyCertSign");
    }
    for pair in certs.windows(2) {
        ensure!(
            pair[0].tbs_certificate().issuer() == pair[1].tbs_certificate().subject(),
            "certificate issuer mismatch"
        );
        let issuance_time = pair[0].tbs_certificate().validity().not_before.to_unix_duration();
        let issuer_validity = pair[1].tbs_certificate().validity();
        ensure!(
            issuer_validity.not_before.to_unix_duration() <= issuance_time
                && issuance_time < issuer_validity.not_after.to_unix_duration(),
            "chain issuer was not valid when it issued its child"
        );
        let key = VerifyingKey::from_public_key_der(&pair[1].tbs_certificate().subject_public_key_info().to_der()?)?;
        let signature = Signature::from_der(pair[0].signature().as_bytes().context("certificate signature")?)?;
        key.verify(&pair[0].tbs_certificate().to_der()?, &signature)?;
    }
    let anchors = roots["roots"].as_array().context("missing trust anchors")?;
    ensure!(
        anchors.iter().any(|root| root["certificate"] == chain[chain.len() - 1]),
        "chain does not end at a published root"
    );
    Ok(())
}

pub(crate) async fn p_trust_anchor_lists_roots(ctx: Context) -> anyhow::Result<()> {
    let roots = ctx.target.trust_anchor().await?;
    let entries = roots["roots"].as_array().context("missing roots")?;
    ensure!(!entries.is_empty(), "no trust anchors");
    for root in entries {
        assert_root(root)?;
    }
    let (_, identity) = issued(&ctx, "anchor").await?;
    verify_chain(&identity.certificate_chain, &roots)?;
    ensure!(
        uuid::Uuid::parse_str(&identity.authority_id).is_ok(),
        "invalid authority ID"
    );
    ensure!(uuid::Uuid::parse_str(&identity.device_id).is_ok(), "invalid device ID");
    assert_leaf_profile(
        &identity.certificate_chain[0],
        identity.certificate_chain.last().context("missing issuer")?,
        &identity.device_id,
        &identity.key,
    )?;
    Ok(())
}

pub(crate) async fn p_token_n_uses_consumed_then_exhausted(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 3).await?;
    for n in 1..=3 {
        let _ = identity(&ctx.target, &token, &format!("host-{n}")).await?;
        let record = ctx.target.token_record(&token.id).await?;
        expect_status(&record, 200)?;
        ensure!(
            count(&record.body, "usedCount")? == n,
            "enrollment did not consume exactly one use"
        );
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
    for index in 0..20 {
        let target = ctx.target.clone();
        let secret = token.text.clone();
        let key = KeyPair::generate()?;
        tasks.spawn(async move {
            target
                .enroll(&secret, &key, &json!({ "hostname": format!("c-{index}") }))
                .await
        });
    }
    let mut success = 0;
    let mut exhausted = 0;
    while let Some(outcome) = tasks.join_next().await {
        let reply = outcome??;
        match reply.status {
            200 => {
                ensure!(
                    reply.body["device_id"].as_str().is_some(),
                    "enrollment response missing device ID"
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
    let record = ctx.target.token_record(&token.id).await?;
    ensure!(
        count(&record.body, "usedCount")? == 5,
        "concurrent use count is incorrect"
    );
    let devices = ctx.target.devices_for(&token, "").await?;
    ensure!(
        count(&devices.body, "totalCount")? == 5,
        "concurrent enrollment created unexpected devices"
    );
    Ok(())
}

pub(crate) async fn p_failed_enrollment_consumes_nothing(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 2).await?;
    let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
    let bad_csr = field(&vectors["csr"]["bad_self_signature"], "csr")?;
    let bad = ctx
        .target
        .agent(
            Method::POST,
            "/enroll",
            Some(&json!({ "csr": bad_csr, "metadata": {} })),
            Some(&token.text),
        )
        .await?;
    expect_error(&bad, 400, "invalid_request")?;
    let invalid = ctx
        .target
        .enroll(&token.text, &KeyPair::generate()?, &json!({ "hostname": 3 }))
        .await?;
    expect_error(&invalid, 400, "invalid_request")?;
    let record = ctx.target.token_record(&token.id).await?;
    ensure!(
        count(&record.body, "usedCount")? == 0,
        "invalid enrollment consumed a use"
    );
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
    expect_status(
        &ctx.target
            .admin(Method::DELETE, &format!("/enrollment-tokens/{}", other.id), None)
            .await?,
        204,
    )?;
    let deleted = ctx
        .target
        .enroll(&other.text, &KeyPair::generate()?, &json!({}))
        .await?;
    expect_error(&deleted, 401, "token_invalid")?;
    Ok(())
}

pub(crate) async fn p_token_expired(ctx: Context) -> anyhow::Result<()> {
    let token = ctx.target.create_token(1, Duration::from_secs(3), None).await?;
    ctx.target.advance(5).await?;
    let expired = ctx
        .target
        .enroll(&token.text, &KeyPair::generate()?, &json!({}))
        .await?;
    expect_error(&expired, 401, "token_expired")?;
    let record = ctx.target.token_record(&token.id).await?;
    ensure!(record.body["state"] == "expired", "token not marked expired");
    ensure!(count(&record.body, "usedCount")? == 0, "expired token consumed a use");
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
    let replay = ctx
        .target
        .enroll(&token.text, &key, &json!({ "hostname": "changed" }))
        .await?;
    expect_status(&replay, 200)?;
    ensure!(
        first.body["device_id"] == replay.body["device_id"]
            && first.body["certificate_chain"] == replay.body["certificate_chain"],
        "same-key replay was not idempotent"
    );
    let record = ctx.target.token_record(&token.id).await?;
    ensure!(
        count(&record.body, "usedCount")? == 1,
        "idempotent replay consumed a use"
    );
    if ctx.mock() {
        ensure!(
            count(&ctx.target.requests(Some(&token)).await?, "enroll")? == 2,
            "mock did not observe both enrollment requests"
        );
    }
    Ok(())
}

pub(crate) async fn p_enroll_revoked_same_key_rejected(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 2).await?;
    let key = KeyPair::generate()?;
    let enrolled = ctx.target.enroll(&token.text, &key, &json!({})).await?;
    let identity = Identity::from_enrollment(key, &enrolled)?;
    ctx.target.revoke(&identity.device_id).await?;
    let refused = ctx.target.enroll(&token.text, &identity.key, &json!({})).await?;
    expect_error(&refused, 403, "device_revoked")?;
    let record = ctx.target.token_record(&token.id).await?;
    ensure!(count(&record.body, "usedCount")? == 1, "revoked replay consumed a use");
    Ok(())
}

pub(crate) async fn p_metadata_limits(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 12).await?;
    let many = (0..33)
        .map(|n| (format!("k{n}"), json!("v")))
        .collect::<serde_json::Map<_, _>>();
    let oversized_object = (0..9)
        .map(|n| (format!("field{n}"), json!("a".repeat(1000))))
        .collect::<serde_json::Map<_, _>>();
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
    let record = ctx.target.token_record(&token.id).await?;
    ensure!(
        count(&record.body, "usedCount")? == 0,
        "invalid metadata consumed a use"
    );
    let key = KeyPair::generate()?;
    let enrolled = ctx
        .target
        .enroll(&token.text, &key, &json!({ "custom_key": "kept" }))
        .await?;
    let identity = Identity::from_enrollment(key, &enrolled)?;
    let device = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        device["metadata"]["custom_key"] == "kept",
        "unknown metadata key was not retained"
    );
    Ok(())
}

pub(crate) async fn p_friendly_name_format(ctx: Context) -> anyhow::Result<()> {
    let token = ctx
        .target
        .create_token(2, TOKEN_LIFETIME, Some("  {hostname}-{{ok}}-{token_name}-{fqdn}  "))
        .await?;
    let record = ctx.target.token_record(&token.id).await?;
    let name = field(&record.body, "name")?;
    let first_identity = identity(&ctx.target, &token, "hello").await?;
    ensure!(
        first_identity.friendly_name == format!("hello-{{ok}}-{name}-"),
        "friendly name formatting incorrect: {}",
        first_identity.friendly_name
    );
    let empty_token = ctx.target.create_token(1, TOKEN_LIFETIME, Some("{hostname}")).await?;
    let empty = identity(&ctx.target, &empty_token, "").await?;
    ensure!(
        empty.friendly_name == empty.device_id,
        "empty friendly name did not fall back to device ID"
    );
    let long_token = ctx.target.create_token(1, TOKEN_LIFETIME, Some("{hostname}")).await?;
    let long = identity(&ctx.target, &long_token, &"é".repeat(260)).await?;
    ensure!(
        long.friendly_name.chars().count() == 255,
        "friendly name not limited to 255 characters"
    );
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).format(&Rfc3339)?;
    let bad = ctx
        .target
        .admin(
            Method::POST,
            "/enrollment-tokens",
            Some(&json!({
                "name": "bad-format",
                "maxUses": 1,
                "expiresAt": expires,
                "friendlyNameFormat": "{not_a_known_key}"
            })),
        )
        .await?;
    expect_status(&bad, 400)?;
    Ok(())
}

pub(crate) async fn p_device_cannot_impersonate_another(ctx: Context) -> anyhow::Result<()> {
    let (_, a) = issued(&ctx, "alpha").await?;
    let (b_token, b) = issued(&ctx, "bravo").await?;
    let b_before = device(&ctx.target, &b.device_id).await?;
    let new_key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": new_key.csr, "metadata": { "hostname": "changed" } }))?;
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
    let a_record = device(&ctx.target, &a.device_id).await?;
    let b_record = device(&ctx.target, &b.device_id).await?;
    ensure!(
        a_record["metadata"]["hostname"] == "changed",
        "A's renewal did not update A"
    );
    ensure!(b_record["metadata"]["hostname"] == "bravo", "A modified B's metadata");
    ensure!(
        b_record["certificates"] == b_before["certificates"],
        "A changed B's certificates"
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
    for (created, expires) in [(now + 62, now + 122), (now - 123, now - 63), (now, now + 301)] {
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
    let wrong_tag = identity.key.sign(
        &identity.thumbprint,
        "connect",
        Some(&body),
        old_created,
        old_created + 60,
        &fresh_nonce(),
    );
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
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let _ = stream.challenge().await?;
    let new_key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": new_key.csr, "metadata": {} }))?;
    let rejected = ctx.target.signed_renew(&body, &stream.headers, None).await?;
    expect_error(&rejected, 401, "signature_invalid")?;
    Ok(())
}

pub(crate) async fn p_renew_happy_path(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "unchanged").await?;
    let original_name = identity.friendly_name.clone();
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
    verify_chain(&new_chain, &ctx.target.trust_anchor().await?)?;
    assert_leaf_profile(
        &new_chain[0],
        new_chain.last().context("missing renewal issuer")?,
        &identity.device_id,
        &new_key,
    )?;
    identity.adopt_certificate(&reply.body["certificate_chain"], new_key)?;
    let pending = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&pending, &identity.thumbprint, "pending"),
        "new certificate not pending"
    );
    ensure!(
        pending["friendlyName"] == original_name,
        "friendly name changed on renewal"
    );
    ensure!(
        pending["metadata"]["hostname"] == "updated",
        "renewal metadata not updated"
    );
    let mut stream = channel::open(&ctx.target, &identity).await?;
    stream.hello(&identity, &[("hostname", "updated")]).await?;
    ensure!(
        has_certificate(
            &device(&ctx.target, &identity.device_id).await?,
            &identity.thumbprint,
            "current"
        ),
        "pending certificate was not promoted on authentication"
    );
    Ok(())
}

pub(crate) async fn p_renew_idempotent_lost_response(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "lost-renew").await?;
    let new_key = KeyPair::generate()?;
    ctx.target.faults(&json!({ "drop_next_response": "renew" })).await?;
    let first = ctx.target.renew(&identity, &new_key, &json!({})).await;
    ensure!(first.is_err(), "fault did not drop the renew response");
    let pending = device(&ctx.target, &identity.device_id).await?;
    let pending_certs = pending["certificates"]
        .as_array()
        .context("missing certificates")?
        .iter()
        .filter(|cert| cert["status"] == "pending")
        .collect::<Vec<_>>();
    ensure!(
        pending_certs.len() == 1,
        "lost response did not commit exactly one pending certificate"
    );
    let retry = ctx.target.renew(&identity, &new_key, &json!({})).await?;
    expect_status(&retry, 200)?;
    let retry_thumbprint = thumbprint(retry.body["certificate_chain"][0].as_str().context("retry leaf")?)?;
    ensure!(
        pending_certs[0]["thumbprint"] == retry_thumbprint,
        "renew retry issued a second certificate"
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
    let current = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&current, &first_thumb, "retired"),
        "first pending certificate was not retired"
    );
    ensure!(
        has_certificate(&current, &second_thumb, "pending"),
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
    let error = match channel::open(&ctx.target, &old).await {
        Ok(_) => anyhow::bail!("retired pending certificate opened a channel"),
        Err(error) => error,
    };
    let status = error
        .downcast_ref::<tonic::Status>()
        .context("no gRPC status for retired certificate")?;
    channel::expect_status(status, Code::Unauthenticated, "device_unknown")?;
    Ok(())
}

pub(crate) async fn p_renew_within_grace(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 4 })).await?;
    let (_, identity) = issued(&ctx, "grace").await?;
    ctx.target.advance(5).await?;
    let reply = ctx.target.renew(&identity, &KeyPair::generate()?, &json!({})).await?;
    expect_status(&reply, 200)?;
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
    ctx.target.revoke(&identity.device_id).await?;
    let reply = ctx.target.renew(&identity, &KeyPair::generate()?, &json!({})).await?;
    expect_error(&reply, 403, "device_revoked")?;
    let next = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": next.csr, "metadata": { "hostname": "correct" } }))?;
    let signed = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
    let altered = serde_json::to_vec(&json!({ "csr": next.csr, "metadata": { "hostname": "tampered" } }))?;
    expect_error(
        &ctx.target.signed_renew(&altered, &signed, None).await?,
        403,
        "device_revoked",
    )?;
    let wrong_signer = KeyPair::generate()?.sign_now(&identity.thumbprint, "renew", Some(&body));
    expect_error(
        &ctx.target.signed_renew(&body, &wrong_signer, None).await?,
        403,
        "device_revoked",
    )?;
    let status = channel::open(&ctx.target, &identity)
        .await
        .err()
        .context("revoked cert connected")?;
    channel::expect_status(
        status
            .downcast_ref::<tonic::Status>()
            .context("revoked open did not yield gRPC status")?,
        Code::PermissionDenied,
        "device_revoked",
    )?;
    Ok(())
}

pub(crate) async fn p_delete_only_when_revoked_then_unknown(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "delete").await?;
    let path = format!("/devices/{}", identity.device_id);
    expect_status(&ctx.target.admin(Method::DELETE, &path, None).await?, 409)?;
    ctx.target.revoke(&identity.device_id).await?;
    expect_status(&ctx.target.admin(Method::DELETE, &path, None).await?, 204)?;
    let reply = ctx.target.renew(&identity, &KeyPair::generate()?, &json!({})).await?;
    expect_error(&reply, 401, "device_unknown")?;
    let next = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": next.csr, "metadata": { "hostname": "correct" } }))?;
    let signed = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
    let altered = serde_json::to_vec(&json!({ "csr": next.csr, "metadata": { "hostname": "tampered" } }))?;
    expect_error(
        &ctx.target.signed_renew(&altered, &signed, None).await?,
        401,
        "device_unknown",
    )?;
    let wrong_signer = KeyPair::generate()?.sign_now(&identity.thumbprint, "renew", Some(&body));
    expect_error(
        &ctx.target.signed_renew(&body, &wrong_signer, None).await?,
        401,
        "device_unknown",
    )?;
    let status = channel::open(&ctx.target, &identity)
        .await
        .err()
        .context("deleted cert connected")?;
    channel::expect_status(
        status
            .downcast_ref::<tonic::Status>()
            .context("deleted open did not yield gRPC status")?,
        Code::Unauthenticated,
        "device_unknown",
    )?;
    Ok(())
}

pub(crate) async fn p_channel_hello_updates_metadata_and_connected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "initial").await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let challenge = stream.challenge().await?;
    let before = device(&ctx.target, &identity.device_id).await?;
    ensure!(before["connected"] == false, "device connected before Hello");
    ensure!(
        before["metadata"]["hostname"] == "initial",
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
    let Some(agent_identity_channel_proto::server_message::Payload::Welcome(payload)) = welcome.payload else {
        anyhow::bail!("channel did not send Welcome");
    };
    ensure!(
        welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "Welcome correlation is wrong"
    );
    let server_time = payload.server_time.context("Welcome omitted server_time")?;
    let after = device(&ctx.target, &identity.device_id).await?;
    ensure!(after["connected"] == true, "device not connected after Hello");
    ensure!(
        after["metadata"]["hostname"] == "channel" && after["metadata"]["arch"] == "x86_64",
        "Hello metadata not stored"
    );
    let after_time = time::OffsetDateTime::parse(field(&after, "lastSeenAt")?, &Rfc3339)?.unix_timestamp();
    if let Some(before_time) = before["lastSeenAt"].as_str() {
        ensure!(
            after_time > time::OffsetDateTime::parse(before_time, &Rfc3339)?.unix_timestamp(),
            "Hello did not advance lastSeenAt"
        );
    }
    ensure!(
        server_time.seconds.abs_diff(after_time) <= 2,
        "Welcome server_time disagrees with lastSeenAt"
    );
    Ok(())
}

pub(crate) async fn p_channel_proof_replay_fails(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "untouched").await?;
    let (_, other) = issued(&ctx, "other-device").await?;
    let mut first = channel::open(&ctx.target, &identity).await?;
    let first_challenge = first.challenge().await?;
    let Some(agent_identity_channel_proto::server_message::Payload::Challenge(first_challenge_bytes)) =
        first_challenge.payload.as_ref()
    else {
        anyhow::bail!("first stream missing challenge");
    };
    let original_challenge = first_challenge_bytes.challenge.clone();
    let original_nonce = first.headers.nonce.clone();
    let captured = identity.key.channel_proof(&original_challenge, &original_nonce);
    drop(first);

    if ctx.mock() {
        ctx.target.advance(2).await?;
    } else {
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }
    let initial = device(&ctx.target, &identity.device_id).await?;
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
        let Some(agent_identity_channel_proto::server_message::Payload::Challenge(payload)) =
            challenge.payload.as_ref()
        else {
            anyhow::bail!("stream missing challenge");
        };
        ensure!(payload.challenge != original_challenge, "channel reused a challenge");
        ensure!(stream.headers.nonce != original_nonce, "channel reused a nonce");
        let proof = match variant {
            "wrong_challenge" => identity.key.channel_proof(&original_challenge, &stream.headers.nonce),
            "wrong_nonce" => identity.key.channel_proof(&payload.challenge, &original_nonce),
            "wrong_key" => other.key.channel_proof(&payload.challenge, &stream.headers.nonce),
            "wrong_correlation" => identity.key.channel_proof(&payload.challenge, &stream.headers.nonce),
            _ => captured.clone(),
        };
        if variant == "wrong_correlation" {
            stream
                .sender
                .send(agent_identity_channel_proto::AgentMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    correlation_id: Some(uuid::Uuid::new_v4().to_string()),
                    payload: Some(agent_identity_channel_proto::agent_message::Payload::Hello(
                        agent_identity_channel_proto::Hello {
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
        let record = device(&ctx.target, &identity.device_id).await?;
        ensure!(record["connected"] == false, "{variant} connected the device");
        ensure!(
            record["lastSeenAt"] == initial["lastSeenAt"],
            "{variant} updated lastSeenAt"
        );
        ensure!(record["metadata"] == initial["metadata"], "{variant} changed metadata");
        replay_headers = Some(stream.headers);
    }
    let replayed = channel::open_with_headers(&ctx.target, &identity, replay_headers.context("no opening headers")?)
        .await
        .err()
        .context("reused opening headers were accepted")?;
    channel::expect_status(
        replayed
            .downcast_ref::<tonic::Status>()
            .context("missing replay gRPC status")?,
        Code::Unauthenticated,
        "signature_invalid",
    )?;
    Ok(())
}

pub(crate) async fn p_channel_no_hello_timeout(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "no-hello").await?;
    let initial = device(&ctx.target, &identity.device_id).await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let _ = stream.challenge().await?;
    let started = Instant::now();
    let rejected = stream.closing_status(Duration::from_secs(11)).await?;
    channel::expect_status(&rejected, Code::Unauthenticated, "signature_invalid")?;
    ensure!(
        started.elapsed() <= Duration::from_millis(10_800),
        "channel exceeded the ten-second Hello deadline"
    );
    let record = device(&ctx.target, &identity.device_id).await?;
    ensure!(record["connected"] == false, "device connected without Hello");
    ensure!(
        record["lastSeenAt"] == initial["lastSeenAt"],
        "lastSeenAt updated without Hello"
    );
    Ok(())
}

pub(crate) async fn p_channel_unavailable_no_channel_url(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "channel_available": false })).await?;
    let (_, identity) = issued(&ctx, "unavailable").await?;
    ensure!(
        identity.channel_url.is_none(),
        "enroll returned channel_url for unavailable channel"
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

pub(crate) async fn p_request_renewal_connected_and_on_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "push").await?;
    let mut connected = channel::open(&ctx.target, &identity).await?;
    connected.hello(&identity, &[("hostname", "push")]).await?;
    expect_status(
        &ctx.target
            .admin(
                Method::POST,
                &format!("/devices/{}/request-renewal", identity.device_id),
                None,
            )
            .await?,
        202,
    )?;
    let pushed = connected.next().await?;
    ensure!(
        matches!(
            pushed.payload,
            Some(agent_identity_channel_proto::server_message::Payload::RenewRequested(ref reason))
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
            Some(agent_identity_channel_proto::server_message::Payload::RenewRequested(ref reason))
                if reason.reason == "admin"
        ),
        "renewal request was not repeated on connect"
    );
    reconnect.ack(&repeated).await?;
    ensure!(
        device(&ctx.target, &identity.device_id).await?["renewalRequested"] == true,
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
            .control("reconnect", &json!({ "device_id": identity.device_id }))
            .await?,
        202,
    )?;
    let pushed = old.next().await?;
    ensure!(
        matches!(
            pushed.payload,
            Some(agent_identity_channel_proto::server_message::Payload::Reconnect(ref message))
                if message.reason == "mock"
        ),
        "mock did not push Reconnect"
    );
    let mut replacement = channel::open(&ctx.target, &identity).await?;
    let challenge = replacement.challenge().await?;
    ensure!(
        count(&ctx.target.requests(None).await?, "overlap_open")? > count(&before, "overlap_open")?,
        "new opening did not overlap old stream"
    );
    let hello_id = replacement.send_hello(&identity, &challenge, &[], None).await?;
    let welcome = replacement.next().await?;
    ensure!(
        matches!(
            welcome.payload,
            Some(agent_identity_channel_proto::server_message::Payload::Welcome(_))
        ) && welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "replacement did not receive correlated Welcome"
    );
    ensure!(
        count(&ctx.target.requests(None).await?, "authenticated_connects")? > count(&before, "authenticated_connects")?,
        "replacement channel did not authenticate"
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
        device(&ctx.target, &identity.device_id).await?["connected"] == true,
        "replacement did not preserve connection"
    );
    Ok(())
}

pub(crate) async fn p_request_renewal_flag_cleared_after_new_cert(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "clear-flag").await?;
    let mut old = channel::open(&ctx.target, &identity).await?;
    old.hello(&identity, &[]).await?;
    expect_status(
        &ctx.target
            .admin(
                Method::POST,
                &format!("/devices/{}/request-renewal", identity.device_id),
                None,
            )
            .await?,
        202,
    )?;
    let request = old.next().await?;
    old.ack(&request).await?;
    let next_key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &next_key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], next_key)?;
    let pending = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        pending["renewalRequested"] == true && has_certificate(&pending, &identity.thumbprint, "pending"),
        "renewal request cleared before new certificate authentication"
    );
    let mut new_stream = channel::open(&ctx.target, &identity).await?;
    let challenge = new_stream.challenge().await?;
    ensure!(
        device(&ctx.target, &identity.device_id).await?["renewalRequested"] == true,
        "opening headers cleared the renewal request"
    );
    let hello_id = new_stream.send_hello(&identity, &challenge, &[], None).await?;
    let welcome = new_stream.next().await?;
    ensure!(
        matches!(
            welcome.payload,
            Some(agent_identity_channel_proto::server_message::Payload::Welcome(_))
        ) && welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "new certificate did not receive its correlated Welcome"
    );
    ensure!(
        device(&ctx.target, &identity.device_id).await?["renewalRequested"] == false,
        "request flag not cleared on new certificate authentication"
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
    ctx.target.revoke(&identity.device_id).await?;
    let status = stream.closing_status(Duration::from_secs(3)).await?;
    channel::expect_status(&status, Code::PermissionDenied, "device_revoked")?;
    ensure!(
        device(&ctx.target, &identity.device_id).await?["connected"] == false,
        "revoked stream still connected"
    );
    Ok(())
}

pub(crate) async fn p_stream_closes_at_not_after(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 4 })).await?;
    let (_, identity) = issued(&ctx, "expires").await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    stream.hello(&identity, &[]).await?;
    ctx.target.advance(5).await?;
    let status = stream.closing_status(Duration::from_secs(3)).await?;
    channel::expect_status(&status, Code::Unauthenticated, "certificate_expired")?;
    ensure!(
        device(&ctx.target, &identity.device_id).await?["connected"] == false,
        "expired stream still connected"
    );
    Ok(())
}

pub(crate) async fn p_pending_cert_auth_retires_old_and_closes_streams(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "make-before-break").await?;
    let old_thumb = identity.thumbprint.clone();
    let mut old = channel::open(&ctx.target, &identity).await?;
    old.hello(&identity, &[]).await?;
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let before = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&before, &old_thumb, "current")
            && has_certificate(&before, &identity.thumbprint, "pending")
            && before["connected"] == true,
        "renewal promoted the pending certificate before authentication"
    );
    let mut unauthenticated = channel::open(&ctx.target, &identity).await?;
    let challenge = unauthenticated.challenge().await?;
    let opened = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&opened, &old_thumb, "current") && has_certificate(&opened, &identity.thumbprint, "pending"),
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
    let rejected = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&rejected, &old_thumb, "current")
            && has_certificate(&rejected, &identity.thumbprint, "pending")
            && rejected["connected"] == true,
        "bad proof promoted the pending certificate"
    );
    ensure!(
        rejected["metadata"] == before["metadata"],
        "bad proof changed device metadata"
    );
    ensure!(
        tokio::time::timeout(Duration::from_millis(200), old.stream.message())
            .await
            .is_err(),
        "bad proof closed the old authenticated stream"
    );
    let mut current = channel::open(&ctx.target, &identity).await?;
    current.hello(&identity, &[]).await?;
    ensure!(
        tokio::time::timeout(Duration::from_secs(3), old.stream.message())
            .await
            .context("old stream not closed")??
            .is_none(),
        "old stream did not close with OK"
    );
    let record = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        record["connected"] == true,
        "new certificate did not keep device connected"
    );
    ensure!(
        has_certificate(&record, &old_thumb, "retired"),
        "old certificate not retired"
    );
    ensure!(
        has_certificate(&record, &identity.thumbprint, "current"),
        "new certificate not current"
    );
    Ok(())
}

pub(crate) async fn p_rotation_publishes_both_roots_and_issues_from_new(ctx: Context) -> anyhow::Result<()> {
    let before = ctx.target.trust_anchor().await?;
    let old = before["roots"].as_array().context("old roots")?;
    ensure!(!old.is_empty(), "no old root");
    let old_thumb = field(&old[0], "thumbprint")?.to_owned();
    let _ = issued(&ctx, "old-root").await?;
    expect_status(&begin_rotation(&ctx).await?, 202)?;
    let roots = ctx.target.trust_anchor().await?;
    let published = roots["roots"].as_array().context("rotation roots")?;
    ensure!(published.len() >= 2, "rotation did not publish two roots");
    ensure!(
        published.iter().any(|root| root["thumbprint"] == old_thumb),
        "old root disappeared before rotation deadline"
    );
    for root in published {
        assert_root(root)?;
    }
    let (_, identity) = issued(&ctx, "new-root").await?;
    verify_chain(&identity.certificate_chain, &roots)?;
    let new_root = thumbprint(identity.certificate_chain.last().context("missing issued root")?)?;
    ensure!(new_root != old_thumb, "rotation issued from the old root");
    let record = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        record["certificate"]["issuer"] == new_root,
        "device issuer did not switch to new root"
    );
    finish_rotation(&ctx).await?;
    Ok(())
}

pub(crate) async fn p_rotation_status_counts(ctx: Context) -> anyhow::Result<()> {
    let (_, mut a) = issued(&ctx, "old-a").await?;
    let (_, b) = issued(&ctx, "old-b").await?;
    let started = begin_rotation(&ctx).await?;
    expect_status(&started, 202)?;
    ensure!(started.body["phase"] == "rotating", "rotation not in progress");
    let initial = count(&started.body, "activeDevicesOnOldRoot")?;
    ensure!(initial >= 2, "our two devices were not counted on the old root");
    let new_key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&a, &new_key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    a.adopt_certificate(&renewed.body["certificate_chain"], new_key)?;
    let mut channel = channel::open(&ctx.target, &a).await?;
    channel.hello(&a, &[]).await?;
    let status = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
    ensure!(
        count(&status.body, "activeDevicesOnOldRoot")? == initial - 1,
        "migration did not reduce old-root count"
    );
    ctx.target.revoke(&b.device_id).await?;
    let status = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
    ensure!(
        count(&status.body, "activeDevicesOnOldRoot")? == initial - 2,
        "revoked device remained in old-root count"
    );
    finish_rotation(&ctx).await?;
    Ok(())
}

pub(crate) async fn p_rotation_conflict_409(ctx: Context) -> anyhow::Result<()> {
    let _ = issued(&ctx, "rotation").await?;
    expect_status(&begin_rotation(&ctx).await?, 202)?;
    expect_status(&ctx.target.rotate(None).await?, 409)?;
    finish_rotation(&ctx).await?;
    Ok(())
}

pub(crate) async fn p_rotation_deadline_removes_old_root(ctx: Context) -> anyhow::Result<()> {
    let original = ctx.target.trust_anchor().await?;
    let old_thumb = field(&original["roots"][0], "thumbprint")?.to_owned();
    let deadline = (time::OffsetDateTime::now_utc() + time::Duration::seconds(10)).format(&Rfc3339)?;
    expect_status(&ctx.target.rotate(Some(&deadline)).await?, 202)?;
    ensure!(
        ctx.target.trust_anchor().await?["roots"]
            .as_array()
            .context("roots")?
            .len()
            == 2,
        "old root not published"
    );
    ctx.target.advance(20).await?;
    let after = ctx.target.trust_anchor().await?;
    let entries = after["roots"].as_array().context("roots after deadline")?;
    ensure!(entries.len() == 1, "old root remained after deadline");
    ensure!(entries[0]["thumbprint"] != old_thumb, "old root still trusted");
    Ok(())
}

pub(crate) async fn p_rotation_old_root_cert_renewable_after_deadline(ctx: Context) -> anyhow::Result<()> {
    let (_, old) = issued(&ctx, "still-allowed").await?;
    let original_root = thumbprint(old.certificate_chain.last().context("missing old root")?)?;
    expect_status(&ctx.target.rotate(Some("now")).await?, 202)?;
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
    verify_chain(&new_chain, &roots)?;
    ensure!(
        thumbprint(new_chain.last().context("root")?)? != original_root,
        "renewal issued under old root"
    );
    Ok(())
}

pub(crate) async fn p_rotation_emergency_deadline(ctx: Context) -> anyhow::Result<()> {
    let before = ctx.target.trust_anchor().await?;
    let old_thumb = field(&before["roots"][0], "thumbprint")?.to_owned();
    let started = ctx.target.rotate(Some("now")).await?;
    expect_status(&started, 202)?;
    let after = ctx.target.trust_anchor().await?;
    let published = after["roots"].as_array().context("emergency roots")?;
    ensure!(published.len() == 1, "emergency deadline did not remove old root");
    ensure!(
        published[0]["thumbprint"] != old_thumb,
        "emergency deadline retained old root"
    );
    Ok(())
}

pub(crate) async fn p_rotation_request_renewal_pushed(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "rotation-push").await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    stream.hello(&identity, &[]).await?;
    expect_status(&begin_rotation(&ctx).await?, 202)?;
    let push = stream.next().await?;
    ensure!(
        matches!(
            push.payload,
            Some(agent_identity_channel_proto::server_message::Payload::RenewRequested(ref reason))
                if reason.reason == "rotation"
        ),
        "rotation did not push RenewRequested(rotation)"
    );
    stream.ack(&push).await?;
    finish_rotation(&ctx).await?;
    Ok(())
}

pub(crate) async fn p_listing_pagination_stable_during_concurrent_enrollment(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 15).await?;
    for n in 0..4 {
        let _ = identity(&ctx.target, &token, &format!("initial-{n}")).await?;
    }
    let first = ctx.target.devices_for(&token, "&pageSize=2&pageNumber=1").await?;
    expect_status(&first, 200)?;
    let first_ids = first.body["data"]
        .as_array()
        .context("first page")?
        .iter()
        .map(|v| v["id"].clone())
        .collect::<Vec<_>>();
    ensure!(first_ids.len() == 2, "first page is not two devices");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut tasks = tokio::task::JoinSet::new();
    for n in 0..6 {
        let target = ctx.target.clone();
        let secret = token.text.clone();
        let key = KeyPair::generate()?;
        tasks.spawn(async move {
            target
                .enroll(&secret, &key, &json!({ "hostname": format!("later-{n}") }))
                .await
        });
    }
    while let Some(result) = tasks.join_next().await {
        expect_status(&result??, 200)?;
    }
    let next = ctx.target.devices_for(&token, "&pageSize=2&pageNumber=1").await?;
    let ids = next.body["data"]
        .as_array()
        .context("first page after inserts")?
        .iter()
        .map(|v| v["id"].clone())
        .collect::<Vec<_>>();
    ensure!(ids == first_ids, "new enrollments shifted earlier pages");
    let all = ctx.target.devices_for(&token, "&view=full").await?;
    expect_status(&all, 200)?;
    ensure!(
        count(&all.body, "totalCount")? == 10,
        "listing omitted or duplicated devices"
    );
    let data = all.body["data"].as_array().context("listing data")?;
    let pairs = data
        .iter()
        .map(|device| Ok((field(device, "createdAt")?.to_owned(), field(device, "id")?.to_owned())))
        .collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(
        pairs.windows(2).all(|pair| pair[0] <= pair[1]),
        "listing not ordered by createdAt and id"
    );
    Ok(())
}

pub(crate) async fn p_listing_views_filters_and_bounds(ctx: Context) -> anyhow::Result<()> {
    let decoy_token = token(&ctx, 1).await?;
    let token = token(&ctx, 5).await?;
    let active = identity(&ctx.target, &token, "filter-host").await?;
    let revoked = identity(&ctx.target, &token, "other-host").await?;
    let decoy = identity(&ctx.target, &decoy_token, "decoy-host").await?;
    ensure!(
        count(&ctx.target.devices_for(&decoy_token, "").await?.body, "totalCount")? == 1,
        "decoy token device not listed"
    );
    ensure!(
        device(&ctx.target, &decoy.device_id).await?["id"] == decoy.device_id,
        "decoy device missing"
    );
    ctx.target.revoke(&revoked.device_id).await?;
    let path = format!("/devices/{}", active.device_id);
    let renamed = ctx
        .target
        .admin(
            Method::PATCH,
            &path,
            Some(&json!({ "friendlyName": "Filter-Host-Renamed" })),
        )
        .await?;
    expect_status(&renamed, 200)?;
    ensure!(
        renamed.body["friendlyName"] == "Filter-Host-Renamed",
        "device rename was not persisted"
    );
    for invalid in ["".to_owned(), "x".repeat(256)] {
        expect_status(
            &ctx.target
                .admin(Method::PATCH, &path, Some(&json!({ "friendlyName": invalid })))
                .await?,
            400,
        )?;
    }
    let summary = ctx
        .target
        .devices_for(&token, "&view=summary&metadata=hostname,os_name&status=active")
        .await?;
    expect_status(&summary, 200)?;
    ensure!(
        count(&summary.body, "totalCount")? == 1,
        "active filter returned wrong count"
    );
    let row = &summary.body["data"][0];
    ensure!(row["id"] == active.device_id, "active filter selected wrong device");
    ensure!(
        row["friendlyName"] == "Filter-Host-Renamed",
        "summary did not reflect renamed device"
    );
    ensure!(
        row["metadata"]["hostname"] == "filter-host",
        "metadata subset missing hostname"
    );
    ensure!(
        row["metadata"]["os_name"].is_null(),
        "metadata subset included an absent key"
    );
    ensure!(row["certificates"].is_null(), "summary included full certificates");
    let full = ctx.target.devices_for(&token, "&view=full&status=revoked").await?;
    ensure!(
        count(&full.body, "totalCount")? == 1,
        "revoked filter returned wrong count"
    );
    ensure!(
        full.body["data"][0]["id"] == revoked.device_id,
        "revoked filter selected wrong device"
    );
    ensure!(
        full.body["data"][0]["certificates"].is_array(),
        "full view has no certificates"
    );
    let by_name = ctx.target.devices_for(&token, "&q=FILTER-HOST").await?;
    ensure!(
        count(&by_name.body, "totalCount")? == 1,
        "friendly-name substring filter failed"
    );
    let issuer = field(&summary.body["data"][0]["certificate"], "issuer")?;
    let by_issuer = ctx.target.devices_for(&token, &format!("&issuer={issuer}")).await?;
    ensure!(count(&by_issuer.body, "totalCount")? == 2, "issuer filter failed");
    let paged = ctx.target.devices_for(&token, "&pageSize=1&pageNumber=2").await?;
    ensure!(
        count(&paged.body, "pageSize")? == 1
            && count(&paged.body, "currentPage")? == 2
            && count(&paged.body, "totalCount")? == 2
            && count(&paged.body, "totalPages")? == 2,
        "DVLS page fields incorrect"
    );
    for query in ["&pageSize=0", "&pageSize=101", "&pageNumber=0"] {
        expect_status(&ctx.target.devices_for(&token, query).await?, 400)?;
    }
    let mut stream = channel::open(&ctx.target, &active).await?;
    stream.hello(&active, &[("hostname", "filter-host")]).await?;
    let observed = device(&ctx.target, &active.device_id).await?;
    let last_seen = field(&observed, "lastSeenAt")?;
    let instant = time::OffsetDateTime::parse(last_seen, &Rfc3339)?;
    let after = (instant - time::Duration::seconds(1)).format(&Rfc3339)?;
    let before = (instant + time::Duration::seconds(1)).format(&Rfc3339)?;
    ensure!(
        count(
            &ctx.target
                .devices_for(&token, &format!("&status=active&lastSeenAfter={after}"))
                .await?
                .body,
            "totalCount"
        )? == 1,
        "lastSeenAfter filter failed"
    );
    ensure!(
        count(
            &ctx.target
                .devices_for(&token, &format!("&status=active&lastSeenBefore={before}"))
                .await?
                .body,
            "totalCount"
        )? == 1,
        "lastSeenBefore filter failed"
    );
    ensure!(
        count(
            &ctx.target
                .devices_for(&token, &format!("&status=active&lastSeenAfter={before}"))
                .await?
                .body,
            "totalCount"
        )? == 0,
        "lastSeenAfter did not exclude an earlier visit"
    );
    if ctx.mock() {
        ctx.target.advance(91 * 24 * 3600).await?;
        ensure!(
            count(
                &ctx.target.devices_for(&token, "&status=expired").await?.body,
                "totalCount"
            )? == 1,
            "expired status filter selected wrong devices"
        );
    }
    Ok(())
}

pub(crate) async fn p_admin_tokens_crud_and_states(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 1).await?;
    let record = ctx.target.token_record(&token.id).await?;
    expect_status(&record, 200)?;
    ensure!(
        record.body["state"] == "active" && count(&record.body, "usedCount")? == 0,
        "new token not active"
    );
    ensure!(
        record.body["token"].is_null(),
        "token secret leaked in its admin record"
    );
    let first_page = ctx
        .target
        .admin(Method::GET, "/enrollment-tokens?pageNumber=1&pageSize=100", None)
        .await?;
    expect_status(&first_page, 200)?;
    let pages = count(&first_page.body, "totalPages")?;
    let mut found = first_page.body["data"]
        .as_array()
        .context("token page")?
        .iter()
        .any(|record| record["id"] == token.id);
    for page in 2..=pages {
        if found {
            break;
        }
        let listed = ctx
            .target
            .admin(
                Method::GET,
                &format!("/enrollment-tokens?pageNumber={page}&pageSize=100"),
                None,
            )
            .await?;
        expect_status(&listed, 200)?;
        found = listed.body["data"]
            .as_array()
            .context("token page")?
            .iter()
            .any(|record| record["id"] == token.id);
    }
    ensure!(found, "created token not listed");
    let _ = identity(&ctx.target, &token, "exhaust").await?;
    let record = ctx.target.token_record(&token.id).await?;
    ensure!(
        record.body["state"] == "exhausted" && count(&record.body, "usedCount")? == 1,
        "exhausted state incorrect"
    );
    if ctx.mock() {
        let expiring = ctx.target.create_token(1, Duration::from_secs(2), None).await?;
        ctx.target.advance(4).await?;
        ensure!(
            ctx.target.token_record(&expiring.id).await?.body["state"] == "expired",
            "expired token did not enter expired state"
        );
    }
    expect_status(
        &ctx.target
            .admin(Method::DELETE, &format!("/enrollment-tokens/{}", token.id), None)
            .await?,
        204,
    )?;
    expect_status(&ctx.target.token_record(&token.id).await?, 404)?;
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).format(&Rfc3339)?;
    for uses in [0, 1_000_001] {
        let invalid = ctx
            .target
            .admin(
                Method::POST,
                "/enrollment-tokens",
                Some(&json!({ "name": "invalid", "maxUses": uses, "expiresAt": expires })),
            )
            .await?;
        expect_status(&invalid, 400)?;
    }
    let too_late = (time::OffsetDateTime::now_utc() + time::Duration::days(366)).format(&Rfc3339)?;
    expect_status(
        &ctx.target
            .admin(
                Method::POST,
                "/enrollment-tokens",
                Some(&json!({ "name": "too-late", "maxUses": 1, "expiresAt": too_late })),
            )
            .await?,
        400,
    )?;
    Ok(())
}

pub(crate) async fn p_admin_requires_auth(ctx: Context) -> anyhow::Result<()> {
    let path = "/api/v3/agent-identity/enrollment-tokens";
    let missing = ctx.target.send(Method::GET, path, None, None, None).await?;
    expect_status(&missing, 401)?;
    ensure!(missing.body["error"].as_str().is_some(), "admin error code missing");
    let wrong = ctx
        .target
        .send(Method::GET, path, None, Some("wrong-admin-token"), None)
        .await?;
    expect_status(&wrong, 401)?;
    ensure!(wrong.body["message"].as_str().is_some(), "admin error message missing");
    Ok(())
}

pub(crate) async fn p_admin_permission_denied(ctx: Context) -> anyhow::Result<()> {
    let unprivileged = ctx
        .unprivileged_admin_token
        .as_deref()
        .context("unprivileged admin fixture missing")?;
    let forbidden = ctx
        .target
        .send(
            Method::GET,
            "/api/v3/agent-identity/enrollment-tokens",
            None,
            Some(unprivileged),
            None,
        )
        .await?;
    expect_status(&forbidden, 403)?;
    ensure!(
        forbidden.body["error"].as_str().is_some(),
        "permission error code missing"
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
    let wrong_tag = issued.key.sign_now(&issued.thumbprint, "connect", Some(&body));
    expect_error(
        &ctx.target.signed_renew(&body, &wrong_tag, None).await?,
        401,
        "signature_invalid",
    )?;
    Ok(())
}
