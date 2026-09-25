use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use der::asn1::ObjectIdentifier;
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
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName};

use crate::client::{Identity, Reply, Target, Token, count, decoded_certificate, expect_error, expect_status, field};
use crate::signer::{KeyPair, SignedHeaders, thumbprint};
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
        let status = target.admin(Method::GET, "/ca/rotation", None).await?;
        expect_status(&status, 200)?;
        if status.body["phase"] == "idle" {
            return Ok(());
        }
        ensure!(
            started.elapsed() < Duration::from_secs(window_secs.saturating_add(5)),
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
    wait_rotation_idle(&ctx.target, ctx.dvls_rotation_window_secs).await?;
    let deadline = (time::OffsetDateTime::now_utc()
        + time::Duration::seconds(i64::try_from(ctx.dvls_rotation_window_secs)?))
    .format(&Rfc3339)?;
    ctx.target.rotate(Some(&deadline)).await
}

async fn finish_rotation(ctx: &Context) -> anyhow::Result<()> {
    if !ctx.mock() {
        wait_rotation_idle(&ctx.target, ctx.dvls_rotation_window_secs).await?;
    }
    Ok(())
}

pub(crate) fn has_certificate(device: &Value, thumbprint: &str, status: &str) -> bool {
    device["certificates"].as_array().is_some_and(|certs| {
        certs
            .iter()
            .any(|cert| cert["thumbprint"] == thumbprint && cert["status"] == status)
    })
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

async fn device(target: &Target, id: &str) -> anyhow::Result<Value> {
    let reply = target.device(id).await?;
    expect_status(&reply, 200)?;
    Ok(reply.body)
}

async fn assert_device_metadata_and_certificates_unchanged(
    target: &Target,
    id: &str,
    before: &Value,
) -> anyhow::Result<()> {
    let after = device(target, id).await?;
    ensure!(
        after["metadata"] == before["metadata"] && after["certificates"] == before["certificates"],
        "rejected key reuse changed device metadata or certificate identities/statuses"
    );
    Ok(())
}

async fn active_old_root_ids(ctx: &Context, issuer: &str) -> anyhow::Result<HashSet<String>> {
    let now = chain_evaluation_time(ctx).await?;
    let mut page = 1;
    let mut ids = HashSet::new();
    let mut seen = HashSet::new();
    loop {
        let reply = ctx
            .target
            .admin(
                Method::GET,
                &format!("/devices?view=full&pageSize=100&pageNumber={page}"),
                None,
            )
            .await?;
        expect_status(&reply, 200)?;
        let rows = reply.body["data"].as_array().context("old-root device page")?;
        for row in rows {
            let id = field(row, "id")?.to_owned();
            ensure!(seen.insert(id.clone()), "old-root listing repeated a device ID");
            if row["status"] != "revoked" {
                let certificates = row["certificates"]
                    .as_array()
                    .context("full device has no certificates")?;
                for cert in certificates {
                    if matches!(field(cert, "status")?, "current" | "pending")
                        && field(cert, "issuer")? == issuer
                        && time::OffsetDateTime::parse(field(cert, "notAfter")?, &Rfc3339)?.unix_timestamp() > now
                    {
                        ids.insert(id);
                        break;
                    }
                }
            }
        }
        if page >= count(&reply.body, "totalPages")? {
            ensure!(
                seen.len() as u64 == count(&reply.body, "totalCount")?,
                "old-root listing count disagrees with all pages"
            );
            return Ok(ids);
        }
        page += 1;
    }
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

fn assert_leaf_profile(
    leaf: &str,
    root: &str,
    device_id: &str,
    key: &KeyPair,
    lifetime_secs: u64,
) -> anyhow::Result<()> {
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
    let expected_end = (validity.not_before.to_unix_duration() + Duration::from_secs(lifetime_secs))
        .min(root.tbs_certificate().validity().not_after.to_unix_duration());
    ensure!(
        validity.not_after.to_unix_duration() == expected_end,
        "leaf lifetime is not {lifetime_secs} seconds capped at the issuing root"
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

fn verify_chain(chain: &[String], roots: &Value, now: i64) -> anyhow::Result<()> {
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
            before <= now && now < after,
            "certificate chain element is not valid at evaluation time"
        );
    }
    for pair in certs.windows(2) {
        ensure!(
            pair[0].tbs_certificate().issuer() == pair[1].tbs_certificate().subject(),
            "certificate issuer mismatch"
        );
        let issuer_key = pair[1].tbs_certificate().subject_public_key_info();
        let ec = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        ensure!(
            issuer_key.algorithm.oid == ec,
            "unsupported certificate issuer key algorithm"
        );
        let curve = issuer_key
            .algorithm
            .parameters
            .as_ref()
            .context("certificate issuer has no curve")?
            .decode_as::<ObjectIdentifier>()?;
        let signed_bytes = pair[0].tbs_certificate().to_der()?;
        let signature = pair[0].signature().as_bytes().context("certificate signature")?;
        if curve == ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7") {
            ensure!(
                pair[0].signature_algorithm().oid == ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
                "P-256 certificate used an unsupported signature algorithm"
            );
            let key = VerifyingKey::from_public_key_der(&issuer_key.to_der()?)?;
            key.verify(&signed_bytes, &Signature::from_der(signature)?)?;
        } else if curve == ObjectIdentifier::new_unwrap("1.3.132.0.34") {
            ensure!(
                pair[0].signature_algorithm().oid == ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
                "P-384 certificate used an unsupported signature algorithm"
            );
            let key = VerifyingKey384::from_public_key_der(&issuer_key.to_der()?)?;
            key.verify(&signed_bytes, &Signature384::from_der(signature)?)?;
        } else {
            anyhow::bail!("unsupported certificate issuer curve {curve}");
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
    ensure!(uuid::Uuid::parse_str(&identity.device_id).is_ok(), "invalid device ID");
    assert_leaf_profile(
        &identity.certificate_chain[0],
        identity.certificate_chain.last().context("missing issuer")?,
        &identity.device_id,
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
        ensure!(
            reqwest::Url::parse(channel_url)?.scheme() == "https",
            "config.agent_channel_url must use HTTPS"
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
                let id = field(&reply.body, "device_id")?;
                ensure!(
                    ids.insert(id.to_owned()),
                    "concurrent enrollments returned duplicate device IDs"
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
            && replies[0].body["device_id"] == replies[1].body["device_id"]
            && replies[0].body["certificate_chain"] == replies[1].body["certificate_chain"]
            && count(&ctx.target.token_record(&token.id).await?.body, "usedCount")? == 1
            && count(&ctx.target.devices_for(&token, "").await?.body, "totalCount")? == 1,
        "concurrent same-key enrolls did not replay one winning device and consume one use"
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
    let record = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        replies.len() == 2
            && replies[0].body["certificate_chain"] == replies[1].body["certificate_chain"]
            && record["certificates"].as_array().is_some_and(|certs| certs
                .iter()
                .filter(|cert| cert["status"] == "pending")
                .count()
                == 1)
            && count(&ctx.target.token_record(&token.id).await?.body, "usedCount")? == 1,
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
    let before = device(&ctx.target, field(&first.body, "device_id")?).await?;
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
    let replayed_device = device(&ctx.target, field(&first.body, "device_id")?).await?;
    ensure!(
        replayed_device["metadata"] == before["metadata"] && replayed_device["lastSeenAt"] == before["lastSeenAt"],
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
            expired_replay.body["device_id"] == first.body["device_id"]
                && expired_replay.body["certificate_chain"] == first.body["certificate_chain"]
                && count(&ctx.target.token_record(&token.id).await?.body, "usedCount")? == 1
                && device(&ctx.target, field(&first.body, "device_id")?).await?["metadata"] == before["metadata"],
            "expired-token current-key replay created, consumed or changed a device"
        );
    }
    Ok(())
}

pub(crate) async fn p_deleted_token_replays_own_key_only(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 2).await?;
    let key = KeyPair::generate()?;
    let first = ctx
        .target
        .enroll(&token.text, &key, &json!({ "hostname": "original" }))
        .await?;
    expect_status(&first, 200)?;
    let device_id = field(&first.body, "device_id")?;
    let before = device(&ctx.target, device_id).await?;
    expect_status(
        &ctx.target
            .admin(Method::DELETE, &format!("/enrollment-tokens/{}", token.id), None)
            .await?,
        204,
    )?;
    expect_status(&ctx.target.token_record(&token.id).await?, 404)?;
    let replay = ctx
        .target
        .enroll(&token.text, &key, &json!({ "hostname": "must-not-replace" }))
        .await?;
    expect_status(&replay, 200)?;
    ensure!(
        replay.body["device_id"] == first.body["device_id"]
            && replay.body["certificate_chain"] == first.body["certificate_chain"],
        "deleted token could not recover its own committed enrollment"
    );
    let after = device(&ctx.target, device_id).await?;
    ensure!(
        after["metadata"] == before["metadata"] && after["lastSeenAt"] == before["lastSeenAt"],
        "deleted-token replay changed device state"
    );
    expect_error(
        &ctx.target
            .enroll(&token.text, &KeyPair::generate()?, &json!({}))
            .await?,
        401,
        "token_invalid",
    )?;
    ensure!(
        count(&ctx.target.devices_for(&token, "").await?.body, "totalCount")? == 1,
        "deleted token issued a second device"
    );
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

pub(crate) async fn p_enroll_certificate_key_reuse_rules(ctx: Context) -> anyhow::Result<()> {
    let original_token = token(&ctx, 1).await?;
    let original_key = KeyPair::generate()?;
    let first = ctx
        .target
        .enroll(&original_token.text, &original_key, &json!({ "hostname": "original" }))
        .await?;
    let identity = Identity::from_enrollment(original_key, &first)?;
    let original_device = device(&ctx.target, &identity.device_id).await?;
    let original_name = field(&original_device, "friendlyName")?.to_owned();
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
        replay.body["device_id"] == identity.device_id
            && replay.body["certificate_chain"] == first.body["certificate_chain"],
        "current-key enrollment did not replay the existing device and current chain"
    );
    let replayed_device = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        replayed_device["metadata"] == original_device["metadata"]
            && replayed_device["lastSeenAt"] == original_device["lastSeenAt"]
            && replayed_device["friendlyName"] == original_name,
        "current-key replay changed device metadata, last_seen_at or friendly name"
    );
    let first_pending = KeyPair::generate()?;
    expect_status(&ctx.target.renew(&identity, &first_pending, &json!({})).await?, 200)?;
    expect_error(
        &ctx.target.enroll(&other_token.text, &first_pending, &json!({})).await?,
        400,
        "invalid_request",
    )?;
    let second_pending = KeyPair::generate()?;
    expect_status(&ctx.target.renew(&identity, &second_pending, &json!({})).await?, 200)?;
    expect_error(
        &ctx.target.enroll(&other_token.text, &first_pending, &json!({})).await?,
        400,
        "invalid_request",
    )?;
    ctx.target.revoke(&identity.device_id).await?;
    for key in [&identity.key, &first_pending, &second_pending] {
        expect_error(
            &ctx.target.enroll(&other_token.text, key, &json!({})).await?,
            403,
            "device_revoked",
        )?;
    }
    expect_status(
        &ctx.target
            .admin(Method::DELETE, &format!("/devices/{}", identity.device_id), None)
            .await?,
        204,
    )?;
    for key in [&identity.key, &first_pending, &second_pending] {
        expect_error(
            &ctx.target.enroll(&other_token.text, key, &json!({})).await?,
            403,
            "device_revoked",
        )?;
    }
    ensure!(
        count(&ctx.target.token_record(&other_token.id).await?.body, "usedCount")? == 0,
        "key-reuse attempts consumed the other token"
    );
    Ok(())
}

pub(crate) async fn p_renew_certificate_key_reuse_rules(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "renew-a").await?;
    let (_, other) = issued(&ctx, "renew-b").await?;
    let initial = device(&ctx.target, &identity.device_id).await?;
    for key in [&identity.key, &other.key] {
        expect_error(
            &ctx.target.renew(&identity, key, &json!({})).await?,
            400,
            "invalid_request",
        )?;
        assert_device_metadata_and_certificates_unchanged(&ctx.target, &identity.device_id, &initial).await?;
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
    let renewed = device(&ctx.target, &identity.device_id).await?;
    expect_error(
        &ctx.target.renew(&identity, &pending, &json!({})).await?,
        400,
        "invalid_request",
    )?;
    assert_device_metadata_and_certificates_unchanged(&ctx.target, &identity.device_id, &renewed).await?;
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
        assert_device_metadata_and_certificates_unchanged(&ctx.target, &identity.device_id, &renewed).await?;
    }
    ctx.target.revoke(&other.device_id).await?;
    expect_status(
        &ctx.target
            .admin(Method::DELETE, &format!("/devices/{}", other.device_id), None)
            .await?,
        204,
    )?;
    for key in [&other.key, &other_pending, &other_replacement] {
        expect_error(
            &ctx.target.renew(&identity, key, &json!({})).await?,
            400,
            "invalid_request",
        )?;
        assert_device_metadata_and_certificates_unchanged(&ctx.target, &identity.device_id, &renewed).await?;
    }
    ensure!(
        renewed["certificates"].as_array().is_some_and(
            |certs| certs.len() == 3 && certs.iter().filter(|cert| cert["status"] == "pending").count() == 1
        ),
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
    let record = ctx.target.token_record(&token.id).await?;
    ensure!(
        count(&record.body, "usedCount")? == 1,
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
    let first_name = field(&device(&ctx.target, &first_identity.device_id).await?, "friendlyName")?.to_owned();
    ensure!(
        first_name == format!("hello-{{ok}}-{name}-"),
        "friendly name formatting incorrect: {first_name}"
    );
    let empty_token = ctx.target.create_token(1, TOKEN_LIFETIME, Some("{hostname}")).await?;
    let empty = identity(&ctx.target, &empty_token, "").await?;
    let empty_name = field(&device(&ctx.target, &empty.device_id).await?, "friendlyName")?.to_owned();
    ensure!(
        empty_name == empty.device_id,
        "empty friendly name did not fall back to device ID"
    );
    let long_token = ctx.target.create_token(1, TOKEN_LIFETIME, Some("{hostname}")).await?;
    let long = identity(&ctx.target, &long_token, &"é".repeat(260)).await?;
    let long_name = field(&device(&ctx.target, &long.device_id).await?, "friendlyName")?.to_owned();
    ensure!(
        long_name.chars().count() == 255,
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
    let lone_brace = ctx
        .target
        .admin(
            Method::POST,
            "/enrollment-tokens",
            Some(&json!({
                "name": "bad-brace",
                "maxUses": 1,
                "expiresAt": expires,
                "friendlyNameFormat": "prefix}"
            })),
        )
        .await?;
    expect_status(&lone_brace, 400)?;
    Ok(())
}

pub(crate) async fn p_device_cannot_impersonate_another(ctx: Context) -> anyhow::Result<()> {
    let (_, a) = issued(&ctx, "alpha").await?;
    let (b_token, b) = issued(&ctx, "bravo").await?;
    let b_before = device(&ctx.target, &b.device_id).await?;
    let new_key = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({
        "csr": new_key.csr,
        "device_id": b.device_id,
        "metadata": { "hostname": "changed", "device_id": b.device_id }
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

pub(crate) async fn p_channel_hello_cannot_impersonate_another(ctx: Context) -> anyhow::Result<()> {
    let (_, a) = issued(&ctx, "alpha").await?;
    let (_, b) = issued(&ctx, "bravo").await?;
    let b_before = device(&ctx.target, &b.device_id).await?;
    let mut stream = channel::open(&ctx.target, &a).await?;
    stream
        .hello(&a, &[("hostname", "channel-a"), ("device_id", &b.device_id)])
        .await?;
    let a_after_hello = device(&ctx.target, &a.device_id).await?;
    ensure!(
        a_after_hello["metadata"]["hostname"] == "channel-a" && a_after_hello["metadata"]["device_id"] == b.device_id,
        "A's Hello did not update A's metadata"
    );
    let b_after_hello = device(&ctx.target, &b.device_id).await?;
    ensure!(
        b_after_hello["metadata"] == b_before["metadata"]
            && b_after_hello["certificates"] == b_before["certificates"]
            && b_after_hello["lastSeenAt"] == b_before["lastSeenAt"]
            && b_after_hello["connected"] == b_before["connected"],
        "A's Hello modified B's device"
    );
    Ok(())
}

pub(crate) async fn p_renew_digest_integrity(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "original").await?;
    let before = device(&ctx.target, &identity.device_id).await?;
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
        let after = device(&ctx.target, &identity.device_id).await?;
        ensure!(
            after["metadata"] == before["metadata"]
                && after["certificates"] == before["certificates"]
                && after["lastSeenAt"] == before["lastSeenAt"],
            "{variant} tampering changed device state"
        );
        ensure!(
            after["certificates"]
                .as_array()
                .is_some_and(|certs| certs.iter().all(|cert| cert["status"] != "pending")),
            "{variant} tampering created a pending certificate"
        );
    }
    Ok(())
}

pub(crate) async fn p_renew_rejects_sha384_csr(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "original").await?;
    let before = device(&ctx.target, &identity.device_id).await?;
    let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
    let csr = field(&vectors["csr"]["ecdsa_with_sha384"], "csr")?;
    let body = serde_json::to_vec(&json!({ "csr": csr, "metadata": { "hostname": "changed" } }))?;
    let signed = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
    expect_error(
        &ctx.target.signed_renew(&body, &signed, None).await?,
        400,
        "invalid_request",
    )?;
    let after = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        before["metadata"] == after["metadata"]
            && before["certificates"] == after["certificates"]
            && after["certificates"]
                .as_array()
                .is_some_and(|certs| certs.iter().all(|cert| cert["status"] != "pending")),
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
    channel::expect_status(
        status.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
        Code::Unauthenticated,
        "signature_invalid",
    )?;
    Ok(())
}

pub(crate) async fn p_channel_duplicate_signature_metadata_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "duplicate-channel-signature").await?;
    let before = device(&ctx.target, &identity.device_id).await?;
    for name in ["signature-input", "signature"] {
        let failure = channel::open_with_duplicate_header(&ctx.target, &identity, name)
            .await
            .err()
            .with_context(|| format!("duplicate {name} metadata opened a channel"))?;
        channel::expect_status(
            failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
            Code::Unauthenticated,
            "signature_invalid",
        )?;
    }
    let after = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        after["connected"] == false
            && after["metadata"] == before["metadata"]
            && after["lastSeenAt"] == before["lastSeenAt"],
        "duplicate signed channel metadata authenticated or changed device state"
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

    let confirm_tag = identity.key.sign_now(&identity.thumbprint, "confirm", None);
    let failure = channel::open_with_headers(&ctx.target, &identity, confirm_tag)
        .await
        .err()
        .context("confirm-tagged signature opened a channel")?;
    channel::expect_status(
        failure.downcast_ref::<tonic::Status>().context("missing gRPC status")?,
        Code::Unauthenticated,
        "signature_invalid",
    )?;
    let csr = KeyPair::generate()?;
    let body = serde_json::to_vec(&json!({ "csr": csr.csr, "metadata": {} }))?;
    let mut confirm_tag = identity.key.sign_now(&identity.thumbprint, "confirm", None);
    attach_content_digest(&mut confirm_tag, &body);
    expect_error(
        &ctx.target.signed_renew(&body, &confirm_tag, None).await?,
        401,
        "signature_invalid",
    )?;
    let unchanged = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&unchanged, &old_thumb, "current")
            && has_certificate(&unchanged, &identity.thumbprint, "pending"),
        "cross-tag probes changed certificate statuses"
    );
    Ok(())
}

pub(crate) async fn p_check_in_current_and_pending(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "check-in").await?;
    let enrolled = identity.config.clone();
    let before = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        enrolled["revision"].as_u64().is_some(),
        "enrollment did not provide an unsigned config revision"
    );
    if ctx.mock() {
        ctx.target.advance(2).await?;
    } else {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let current = ctx
        .target
        .check_in(&identity, &json!({ "hostname": "current-check-in" }))
        .await?;
    expect_status(&current, 200)?;
    let after = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        current.body["config"] == enrolled
            && current.body["renewal_requested"] == false
            && after["metadata"]["hostname"] == "current-check-in"
            && time::OffsetDateTime::parse(field(&after, "lastSeenAt")?, &Rfc3339)?
                > time::OffsetDateTime::parse(field(&before, "lastSeenAt")?, &Rfc3339)?,
        "current-certificate check-in did not return config or refresh metadata and lastSeenAt"
    );
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
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let pending = ctx
        .target
        .check_in(&identity, &json!({ "hostname": "pending-check-in" }))
        .await?;
    expect_status(&pending, 200)?;
    ensure!(
        pending.body["config"] == enrolled
            && pending.body["renewal_requested"] == true
            && has_certificate(
                &device(&ctx.target, &identity.device_id).await?,
                &identity.thumbprint,
                "pending"
            )
            && device(&ctx.target, &identity.device_id).await?["metadata"]["hostname"] == "pending-check-in",
        "pending-certificate check-in did not return config, renewal flag or metadata"
    );
    let before_invalid = device(&ctx.target, &identity.device_id).await?;
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
    let after_invalid = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        after_invalid["metadata"] == before_invalid["metadata"]
            && after_invalid["lastSeenAt"] == before_invalid["lastSeenAt"],
        "invalid check-in changed metadata or lastSeenAt"
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
        device(&ctx.target, &identity.device_id).await?["certificates"]
            .as_array()
            .is_some_and(|certs| certs.len() == 1 && certs[0]["status"] == "current"),
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
    channel::expect_status(
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

pub(crate) async fn p_signature_parser_wire_negatives(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "wire-negatives").await?;
    let original = device(&ctx.target, &identity.device_id).await?;
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
                let sha512 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
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
        let after = device(&ctx.target, &identity.device_id).await?;
        ensure!(
            after["metadata"] == original["metadata"]
                && after["certificates"] == original["certificates"]
                && after["lastSeenAt"] == original["lastSeenAt"],
            "wire-negative variant {variant} changed device state"
        );
    }
    for repeated in ["content-digest", "signature-input", "signature"] {
        let signed = identity.key.sign_now(&identity.thumbprint, "renew", Some(&body));
        let digest = signed.digest.as_deref().context("signed digest missing")?;
        let mut headers = http::HeaderMap::new();
        headers.insert("content-digest", digest.parse()?);
        headers.insert("signature-input", signed.input.parse()?);
        headers.insert("signature", signed.signature.parse()?);
        let repeated_value = match repeated {
            "content-digest" => digest,
            "signature-input" => &signed.input,
            "signature" => &signed.signature,
            _ => unreachable!("all repeated names are known"),
        };
        headers.append(repeated, repeated_value.parse()?);
        let response = ctx
            .target
            .http
            .post(format!("{}/api/agent-identity/v1/renew", ctx.target.base_url))
            .headers(headers)
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await?;
        let reply = Reply {
            status: response.status().as_u16(),
            body: response.json().await?,
        };
        expect_error(&reply, 401, "signature_invalid")?;
        let after = device(&ctx.target, &identity.device_id).await?;
        ensure!(
            after["metadata"] == original["metadata"]
                && after["certificates"] == original["certificates"]
                && after["lastSeenAt"] == original["lastSeenAt"],
            "duplicate {repeated} headers changed device state"
        );
    }
    Ok(())
}

pub(crate) async fn p_renew_happy_path(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "unchanged").await?;
    let original_name = field(&device(&ctx.target, &identity.device_id).await?, "friendlyName")?.to_owned();
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
        &identity.device_id,
        &new_key,
        ctx.leaf_lifetime_secs,
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
    let replay_key = KeyPair {
        key: identity.key.key.clone(),
        csr: identity.key.csr.clone(),
    };
    expect_status(
        &ctx.target
            .renew(&identity, &replay_key, &json!({ "hostname": "pending-replay" }))
            .await?,
        200,
    )?;
    ensure!(
        has_certificate(
            &device(&ctx.target, &identity.device_id).await?,
            &identity.thumbprint,
            "pending"
        ),
        "pending-signed renewal promoted the certificate"
    );
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    ensure!(
        has_certificate(
            &device(&ctx.target, &identity.device_id).await?,
            &identity.thumbprint,
            "current"
        ),
        "confirm did not promote the pending certificate"
    );
    Ok(())
}

pub(crate) async fn p_confirm_promotes_and_is_idempotent(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "confirm-idempotent").await?;
    let old_thumb = identity.thumbprint.clone();
    let original = device(&ctx.target, &identity.device_id).await?;
    let original_events = if ctx.mock() {
        Some(ctx.target.events(&identity.device_id).await?)
    } else {
        None
    };
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    ensure!(
        device(&ctx.target, &identity.device_id).await?["certificates"] == original["certificates"],
        "confirm with an already current certificate changed its status"
    );
    if let Some(events) = &original_events {
        ensure!(
            ctx.target.events(&identity.device_id).await? == *events,
            "confirm with an already current certificate emitted a lifecycle event"
        );
    }

    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let promoted = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&promoted, &old_thumb, "retired")
            && has_certificate(&promoted, &identity.thumbprint, "current"),
        "confirm did not promote pending and retire the previous current certificate"
    );
    let events = if ctx.mock() {
        Some(ctx.target.events(&identity.device_id).await?)
    } else {
        None
    };
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let replayed = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        replayed["certificates"] == promoted["certificates"],
        "idempotent confirm retry changed certificate statuses"
    );
    if let Some(events) = events {
        ensure!(
            ctx.target.events(&identity.device_id).await? == events,
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
    let before = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&before, &first_thumb, "retired"),
        "replacement did not retire the first pending certificate"
    );
    let signed = first_key.sign_now(&first_thumb, "confirm", None);
    expect_error(&ctx.target.signed_confirm(&signed, None).await?, 401, "device_unknown")?;
    assert_device_metadata_and_certificates_unchanged(&ctx.target, &identity.device_id, &before).await?;
    Ok(())
}

pub(crate) async fn p_confirm_expired_pending_certificate_rejected(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 20 })).await?;
    let (_, mut identity) = issued(&ctx, "expired-confirm").await?;
    let old_thumb = identity.thumbprint.clone();
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    ctx.target.advance(21).await?;
    let before = device(&ctx.target, &identity.device_id).await?;
    expect_error(&ctx.target.confirm(&identity).await?, 401, "certificate_expired")?;
    let after = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        after["certificates"] == before["certificates"]
            && has_certificate(&after, &old_thumb, "current")
            && has_certificate(&after, &identity.thumbprint, "pending"),
        "expired pending confirm changed certificate statuses"
    );
    Ok(())
}

pub(crate) async fn p_confirm_nonempty_body_rejected(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "confirm-body").await?;
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    let before = device(&ctx.target, &identity.device_id).await?;
    let signed = identity.key.sign_now(&identity.thumbprint, "confirm", None);
    expect_error(
        &ctx.target.signed_confirm(&signed, Some(b"{}")).await?,
        400,
        "invalid_request",
    )?;
    assert_device_metadata_and_certificates_unchanged(&ctx.target, &identity.device_id, &before).await?;
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
    let before = device(&ctx.target, &identity.device_id).await?;
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
    assert_device_metadata_and_certificates_unchanged(&ctx.target, &identity.device_id, &before).await?;
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
    let promoted = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&promoted, &old_thumb, "retired")
            && has_certificate(&promoted, &identity.thumbprint, "current"),
        "dropped confirm did not commit the promotion"
    );
    let events = ctx.target.events(&identity.device_id).await?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let requests = ctx.target.requests(None).await?;
    ensure!(
        device(&ctx.target, &identity.device_id).await?["certificates"] == promoted["certificates"]
            && ctx.target.events(&identity.device_id).await? == events
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
        pending_certs[0]["thumbprint"] == retry_thumbprint,
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
    let listing = ctx.target.devices_for(&token, "").await?;
    expect_status(&listing, 200)?;
    ensure!(
        count(&listing.body, "totalCount")? == 1
            && count(&ctx.target.token_record(&token.id).await?.body, "usedCount")? == 1,
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
        replay.body["device_id"] == listing.body["data"][0]["id"]
            && count(&ctx.target.token_record(&token.id).await?.body, "usedCount")? == 1,
        "replay created a second device or consumed another use"
    );
    ctx.target.revoke(field(&replay.body, "device_id")?).await?;
    expect_error(
        &ctx.target.enroll(&token.text, &key, &json!({})).await?,
        403,
        "device_revoked",
    )?;
    ensure!(
        count(&ctx.target.requests(Some(&token)).await?, "enroll_device_revoked")? == 1,
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
    expect_error(
        &ctx.target.renew(&old, &KeyPair::generate()?, &json!({})).await?,
        401,
        "device_unknown",
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
    channel::expect_status(status, Code::Unauthenticated, "device_unknown")?;
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
        &identity.device_id,
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
    Ok(())
}

pub(crate) async fn p_revocation_blocks_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "revoked-connect").await?;
    ctx.target.revoke(&identity.device_id).await?;
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
    Ok(())
}

pub(crate) async fn p_deleted_certificate_cannot_connect(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "deleted-connect").await?;
    ctx.target.revoke(&identity.device_id).await?;
    expect_status(
        &ctx.target
            .admin(Method::DELETE, &format!("/devices/{}", identity.device_id), None)
            .await?,
        204,
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
    let Some(agent_channel_proto::server_message::Payload::Welcome(payload)) = welcome.payload else {
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

pub(crate) async fn p_handshake_barrier_holds_authentication(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "barrier").await?;
    let before = device(&ctx.target, &identity.device_id).await?;
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
                .events(&identity.device_id)
                .await?
                .iter()
                .any(|event| { event["type"] == "stream_opened" && event["stream_id"] == paused[0] }),
        "mock handshake did not identify the held stream"
    );
    let waiting = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        waiting["connected"] == false
            && waiting["metadata"] == before["metadata"]
            && waiting["lastSeenAt"] == before["lastSeenAt"]
            && ctx
                .target
                .events(&identity.device_id)
                .await?
                .iter()
                .all(|event| event["type"] != "stream_authenticated"),
        "held Hello authenticated or changed device state before release"
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
        device(&ctx.target, &identity.device_id).await?["metadata"]["hostname"] == "after-pause"
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
                .sender
                .send(agent_channel_proto::AgentMessage {
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

pub(crate) async fn p_channel_revoked_before_hello(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "before-revocation").await?;
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let challenge = stream.challenge().await?;
    let before = device(&ctx.target, &identity.device_id).await?;
    ensure!(before["connected"] == false, "device connected before Hello");
    let authenticated = if ctx.mock() {
        Some(count(&ctx.target.requests(None).await?, "authenticated_connects")?)
    } else {
        None
    };
    ctx.target.revoke(&identity.device_id).await?;
    let revoked = device(&ctx.target, &identity.device_id).await?;
    stream
        .send_hello(&identity, &challenge, &[("hostname", "after-revocation")], None)
        .await?;
    let rejected = stream.closing_status(Duration::from_secs(3)).await?;
    channel::expect_status(&rejected, Code::PermissionDenied, "device_revoked")?;
    let after = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        after["connected"] == false
            && after["metadata"] == revoked["metadata"]
            && after["certificates"] == revoked["certificates"]
            && after["lastSeenAt"] == before["lastSeenAt"],
        "revoked stream changed device state before Welcome"
    );
    if let Some(authenticated) = authenticated {
        ensure!(
            count(&ctx.target.requests(None).await?, "authenticated_connects")? == authenticated,
            "revoked stream was registered as authenticated"
        );
    }
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
    let token = token(&ctx, 1).await?;
    let key = KeyPair::generate()?;
    let reply = ctx
        .target
        .enroll(&token.text, &key, &json!({ "hostname": "unavailable" }))
        .await?;
    expect_status(&reply, 200)?;
    ensure!(
        reply.body.get("channel_url").is_none() && reply.body["config"].get("agent_channel_url").is_none(),
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

pub(crate) async fn p_config_revision_monotonic_changes(ctx: Context) -> anyhow::Result<()> {
    let (_, mut identity) = issued(&ctx, "config-revisions").await?;
    let (_, other) = issued(&ctx, "second-config-revisions").await?;
    let initial = check_in_config(&ctx.target, &identity).await?;
    ensure!(
        initial == identity.config && count(&initial, "revision")? == 1,
        "enrollment did not start at config revision 1"
    );
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
    ensure!(
        count(&disabled, "revision")? == 2
            && disabled.get("agent_channel_url").is_none()
            && count(&check_in_config(&ctx.target, &other).await?, "revision")? == 2,
        "disabling the channel did not raise every device's config revision"
    );
    ctx.target.faults(&json!({ "channel_available": false })).await?;
    ensure!(
        check_in_config(&ctx.target, &identity).await? == disabled,
        "no-op channel toggle raised the config revision"
    );
    ctx.target.faults(&json!({ "channel_available": true })).await?;
    let enabled = check_in_config(&ctx.target, &identity).await?;
    ensure!(
        count(&enabled, "revision")? == 3 && enabled["agent_channel_url"] == ctx.target.base_url,
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
        changed.body["updatedDevices"] == 2,
        "config change did not update both devices"
    );
    let extended = check_in_config(&ctx.target, &identity).await?;
    ensure!(
        count(&extended, "revision")? == 4 && extended["conformance_flag"] == true,
        "extra config field did not raise the revision"
    );
    let unchanged = ctx
        .target
        .control("config", &json!({ "fields": { "conformance_flag": true } }))
        .await?;
    expect_status(&unchanged, 200)?;
    ensure!(
        unchanged.body["updatedDevices"] == 0 && check_in_config(&ctx.target, &identity).await? == extended,
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
        "reserved config field modified the device"
    );
    expect_status(
        &ctx.target
            .control("config", &json!({ "fields": { "conformance_flag": false } }))
            .await?,
        200,
    )?;
    let final_config = check_in_config(&ctx.target, &identity).await?;
    ensure!(
        count(&final_config, "revision")? == 5
            && final_config["conformance_flag"] == false
            && count(&check_in_config(&ctx.target, &other).await?, "revision")? == 5,
        "replacing a field did not advance both device revisions"
    );
    let key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&identity, &key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    identity.adopt_certificate(&renewed.body["certificate_chain"], key)?;
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    expect_status(
        &ctx.target
            .control("reconnect", &json!({ "device_id": identity.device_id }))
            .await?,
        202,
    )?;
    ensure!(
        check_in_config(&ctx.target, &identity).await? == final_config,
        "renew, confirm or reconnect changed an unaffected config revision"
    );
    Ok(())
}

pub(crate) async fn p_config_hello_reconciles_stale_revision(ctx: Context) -> anyhow::Result<()> {
    let (_, identity) = issued(&ctx, "stale-config").await?;
    let current_revision = count(&identity.config, "revision")?;
    let announced_revision = current_revision.saturating_sub(1);
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
    if current_revision == 0 {
        ensure!(
            tokio::time::timeout(Duration::from_millis(200), stale.stream.message())
                .await
                .is_err(),
            "revision zero received a ConfigUpdate despite having no lower unsigned revision"
        );
    } else {
        let (update, config) = next_config_update(&mut stale).await?;
        ensure!(
            config == identity.config,
            "stale Hello did not receive the current config immediately after Welcome"
        );
        stale.ack(&update).await?;
    }

    let mut current = channel::open(&ctx.target, &identity).await?;
    current.hello(&identity, &[]).await?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(200), current.stream.message())
            .await
            .is_err(),
        "up-to-date Hello received an unnecessary ConfigUpdate"
    );
    if ctx.mock() {
        let events = ctx.target.events(&identity.device_id).await?;
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
                    == usize::from(current_revision > 0),
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
    ensure!(
        count(&config, "revision")? == count(&identity.config, "revision")? + 1
            && config["conformance_note"] == "updated"
            && config == check_in_config(&ctx.target, &identity).await?,
        "config edit did not push the next effective revision"
    );
    stream.ack(&message).await?;
    let stale = ctx
        .target
        .control(
            "config/stale",
            &json!({ "device_id": identity.device_id, "revision": 1 }),
        )
        .await?;
    expect_status(&stale, 200)?;
    ensure!(stale.body["sent"] == 1, "stale ConfigUpdate was not delivered");
    let (stale_message, stale_config) = next_config_update(&mut stream).await?;
    ensure!(
        count(&stale_config, "revision")? == 1
            && stale_config["mock_stale_marker"] == "ignore-me"
            && check_in_config(&ctx.target, &identity).await? == config,
        "stale ConfigUpdate modified the server's effective revision"
    );
    stream.ack(&stale_message).await?;
    ctx.target.faults(&json!({ "channel_available": false })).await?;
    let (disabled, config) = next_config_update(&mut stream).await?;
    ensure!(
        count(&config, "revision")? == count(&identity.config, "revision")? + 2
            && config.get("agent_channel_url").is_none(),
        "channel toggle did not push a higher revision without agent_channel_url"
    );
    stream.ack(&disabled).await?;
    let events = ctx.target.events(&identity.device_id).await?;
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
        changed == [2, 3] && pushed == changed,
        "config change and push events did not advance in order"
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
        device(&ctx.target, &identity.device_id).await?["connected"] == true,
        "replacement did not preserve connection"
    );
    let events = ctx.target.events(&identity.device_id).await?;
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
    ensure!(
        device(&ctx.target, &identity.device_id).await?["renewalRequested"] == true,
        "offline renewal request flag was not set"
    );
    let next_key = KeyPair::generate()?;
    let pending = ctx.target.renew(&identity, &next_key, &json!({})).await?;
    expect_status(&pending, 200)?;
    identity.adopt_certificate(&pending.body["certificate_chain"], next_key)?;
    ensure!(
        device(&ctx.target, &identity.device_id).await?["renewalRequested"] == true,
        "flag cleared when pending certificate was merely issued"
    );
    let replay_key = KeyPair {
        key: identity.key.key.clone(),
        csr: identity.key.csr.clone(),
    };
    expect_status(&ctx.target.renew(&identity, &replay_key, &json!({})).await?, 200)?;
    ensure!(
        device(&ctx.target, &identity.device_id).await?["renewalRequested"] == true,
        "pending-signed renew cleared the request flag"
    );
    expect_status(&ctx.target.confirm(&identity).await?, 204)?;
    let current = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        current["renewalRequested"] == false && has_certificate(&current, &identity.thumbprint, "current"),
        "confirm did not clear the request flag"
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
        "renewal request cleared before confirmation"
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
            Some(agent_channel_proto::server_message::Payload::Welcome(_))
        ) && welcome.correlation_id.as_deref() == Some(hello_id.as_str()),
        "new certificate did not receive its correlated Welcome"
    );
    ensure!(
        device(&ctx.target, &identity.device_id).await?["renewalRequested"] == true,
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
        device(&ctx.target, &identity.device_id).await?["renewalRequested"] == false,
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
    if ctx.mock() {
        ctx.target.faults(&json!({ "leaf_lifetime_secs": 20 })).await?;
    }
    let (_, identity) = issued(&ctx, "expires").await?;
    let not_after = time::OffsetDateTime::parse(
        field(
            &device(&ctx.target, &identity.device_id).await?["certificate"],
            "notAfter",
        )?,
        &Rfc3339,
    )?
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
            device(&ctx.target, &identity.device_id).await?["connected"] == true,
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
            ctx.target.events(&identity.device_id).await?.iter().any(|event| {
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
        device(&ctx.target, &identity.device_id).await?["connected"] == false,
        "expired stream still connected"
    );
    Ok(())
}

pub(crate) async fn p_challenged_stream_expires_on_advance(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 20 })).await?;
    let (_, identity) = issued(&ctx, "challenge-expiry").await?;
    let before = device(&ctx.target, &identity.device_id).await?;
    let not_after = time::OffsetDateTime::parse(field(&before["certificate"], "notAfter")?, &Rfc3339)?.unix_timestamp();
    let mut stream = channel::open(&ctx.target, &identity).await?;
    let _ = stream.challenge().await?;
    ensure!(
        device(&ctx.target, &identity.device_id).await?["connected"] == false,
        "Challenge alone authenticated a device"
    );
    let now = ctx.target.control("time/advance", &json!({ "secs": 0 })).await?.body["now"]
        .as_i64()
        .context("mock clock is missing")?;
    ctx.target.advance(not_after - now).await?;
    let status = stream.closing_status(Duration::from_millis(900)).await?;
    channel::expect_status(&status, Code::Unauthenticated, "certificate_expired")?;
    let after = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        after["connected"] == false
            && after["metadata"] == before["metadata"]
            && after["lastSeenAt"] == before["lastSeenAt"],
        "expired unproven stream changed device state"
    );
    let events = ctx.target.events(&identity.device_id).await?;
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
        Some(ctx.target.events(&identity.device_id).await?)
    } else {
        None
    };
    let replay_key = KeyPair {
        key: identity.key.key.clone(),
        csr: identity.key.csr.clone(),
    };
    expect_status(&ctx.target.renew(&identity, &replay_key, &json!({})).await?, 200)?;
    if let Some(events) = events_before_replay {
        let after = ctx.target.events(&identity.device_id).await?;
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
    let before = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&before, &old_thumb, "current")
            && has_certificate(&before, &identity.thumbprint, "pending")
            && before["connected"] == true,
        "renewal promoted the pending certificate before confirmation"
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
    let mut pending_stream = channel::open(&ctx.target, &identity).await?;
    pending_stream.hello(&identity, &[]).await?;
    let after_hello = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&after_hello, &old_thumb, "current")
            && has_certificate(&after_hello, &identity.thumbprint, "pending")
            && after_hello["connected"] == true,
        "authenticated pending certificate promoted before confirm"
    );
    ensure!(
        tokio::time::timeout(Duration::from_millis(200), old.stream.message())
            .await
            .is_err(),
        "pending-certificate Hello closed the old authenticated stream"
    );
    if ctx.mock() {
        let events = ctx.target.events(&identity.device_id).await?;
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
    let confirmed = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&confirmed, &old_thumb, "retired")
            && has_certificate(&confirmed, &identity.thumbprint, "current"),
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
    let record = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        has_certificate(&record, &old_thumb, "retired")
            && has_certificate(&record, &identity.thumbprint, "current")
            && record["connected"] == true,
        "confirm did not promote while keeping the replacement stream connected"
    );
    let events = ctx.target.events(&identity.device_id).await?;
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
            .events(&identity.device_id)
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
    let events = ctx.target.events(&identity.device_id).await?;
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
            && device(&ctx.target, &identity.device_id).await?["connected"] == true,
        "retired stream closed before reconnect or replacement authentication"
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
    expect_status(&begin_rotation(&ctx).await?, 202)?;
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
    let old_root = field(&device(&ctx.target, &a.device_id).await?["certificate"], "issuer")?.to_owned();
    let expected = active_old_root_ids(&ctx, &old_root).await?;
    ensure!(
        expected.contains(&a.device_id) && expected.contains(&b.device_id),
        "new devices are missing from the full old-root listing"
    );
    let started = begin_rotation(&ctx).await?;
    expect_status(&started, 202)?;
    ensure!(started.body["phase"] == "rotating", "rotation not in progress");
    ensure!(
        count(&started.body, "activeDevicesOnOldRoot")? == expected.len() as u64,
        "rotation did not count all active old-root devices"
    );
    ensure!(
        device(&ctx.target, &a.device_id).await?["renewalRequested"] == true
            && device(&ctx.target, &b.device_id).await?["renewalRequested"] == true,
        "rotation did not flag offline old-root devices"
    );
    let new_key = KeyPair::generate()?;
    let renewed = ctx.target.renew(&a, &new_key, &json!({})).await?;
    expect_status(&renewed, 200)?;
    a.adopt_certificate(&renewed.body["certificate_chain"], new_key)?;
    expect_status(&ctx.target.confirm(&a).await?, 204)?;
    ensure!(
        device(&ctx.target, &a.device_id).await?["renewalRequested"] == false,
        "confirm did not clear the rotation flag"
    );
    let status = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
    ensure!(
        count(&status.body, "activeDevicesOnOldRoot")? == active_old_root_ids(&ctx, &old_root).await?.len() as u64,
        "migration old-root count disagrees with all listing pages"
    );
    ctx.target.revoke(&b.device_id).await?;
    let status = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
    ensure!(
        count(&status.body, "activeDevicesOnOldRoot")? == active_old_root_ids(&ctx, &old_root).await?.len() as u64,
        "revoked device remained in the old-root count"
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

pub(crate) async fn p_rotation_completes_early_when_last_device_migrates(ctx: Context) -> anyhow::Result<()> {
    let (_, mut first) = issued(&ctx, "first-old-root").await?;
    let (_, mut last) = issued(&ctx, "last-old-root").await?;
    let old_root = thumbprint(first.certificate_chain.last().context("missing old root")?)?;
    ensure!(
        thumbprint(last.certificate_chain.last().context("missing old root")?)? == old_root,
        "devices were not enrolled under the same old root"
    );

    let started = ctx.target.rotate(None).await?;
    expect_status(&started, 202)?;
    ensure!(
        started.body["phase"] == "rotating" && count(&started.body, "activeDevicesOnOldRoot")? == 2,
        "rotation did not start with both old-root devices"
    );
    let deadline = time::OffsetDateTime::parse(field(&started.body, "deadline")?, &Rfc3339)?.unix_timestamp();
    ensure!(
        deadline - chain_evaluation_time(&ctx).await? > 60,
        "rotation deadline is not far enough away to test early completion"
    );
    let new_root = field(&started.body["newRoot"], "thumbprint")?.to_owned();
    ensure!(new_root != old_root, "rotation did not create a new root");

    for (remaining, identity) in [(1, &mut first), (0, &mut last)] {
        let new_key = KeyPair::generate()?;
        let renewed = ctx.target.renew(identity, &new_key, &json!({})).await?;
        expect_status(&renewed, 200)?;
        identity.adopt_certificate(&renewed.body["certificate_chain"], new_key)?;
        let pending = device(&ctx.target, &identity.device_id).await?;
        ensure!(
            has_certificate(&pending, &identity.thumbprint, "pending") && pending["certificate"]["issuer"] == old_root,
            "renewal migrated the device before confirmation"
        );
        let before_auth = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
        ensure!(
            before_auth.body["phase"] == "rotating"
                && count(&before_auth.body, "activeDevicesOnOldRoot")? == remaining + 1,
            "rotation completed before the old-root certificate was replaced"
        );

        expect_status(&ctx.target.confirm(identity).await?, 204)?;
        let migrated = device(&ctx.target, &identity.device_id).await?;
        ensure!(
            has_certificate(&migrated, &identity.thumbprint, "current")
                && migrated["certificate"]["issuer"] == new_root,
            "confirm did not migrate the device to the new root"
        );
        let status = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
        let roots = ctx.target.trust_anchor().await?;
        let published = roots["roots"].as_array().context("published roots")?;
        ensure!(
            count(&status.body, "activeDevicesOnOldRoot")? == remaining,
            "migration did not update the old-root device count"
        );
        if remaining == 1 {
            ensure!(
                status.body["phase"] == "rotating"
                    && published.len() == 2
                    && published.iter().any(|root| root["thumbprint"] == old_root),
                "rotation stopped while an old-root device was still active"
            );
        } else {
            ensure!(
                status.body["phase"] == "idle"
                    && published.len() == 1
                    && published[0]["thumbprint"] == new_root
                    && chain_evaluation_time(&ctx).await? < deadline - 30,
                "rotation did not finish early with only the new root published"
            );
        }
    }
    Ok(())
}

pub(crate) async fn p_rotation_completes_immediately_without_old_root_devices(ctx: Context) -> anyhow::Result<()> {
    let original = ctx.target.trust_anchor().await?;
    let original_roots = original["roots"].as_array().context("original roots")?;
    ensure!(original_roots.len() == 1, "expected one root before rotation");
    let old_root = field(&original_roots[0], "thumbprint")?;

    let started = ctx.target.rotate(None).await?;
    expect_status(&started, 202)?;
    ensure!(
        started.body["phase"] == "idle"
            && count(&started.body, "activeDevicesOnOldRoot")? == 0
            && started.body.get("deadline").is_none()
            && started.body.get("oldRoot").is_none()
            && started.body.get("newRoot").is_none(),
        "rotation without old-root devices did not complete in the POST response"
    );
    let status = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
    expect_status(&status, 200)?;
    ensure!(status.body == started.body, "completed rotation did not remain idle");
    let roots = ctx.target.trust_anchor().await?;
    let published = roots["roots"].as_array().context("published roots")?;
    ensure!(
        published.len() == 1 && published[0]["thumbprint"] != old_root,
        "rotation without old-root devices did not replace the published root"
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
    ctx.target.revoke(&revoked.device_id).await?;
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

    let expired_record = device(&ctx.target, &expired.device_id).await?;
    ensure!(
        expired_record["status"] == "expired",
        "fixture certificate did not expire"
    );
    let pending_record = device(&ctx.target, &pending_only.device_id).await?;
    ensure!(
        pending_record["status"] == "expired"
            && pending_record["certificates"]
                .as_array()
                .is_some_and(|certs| certs.iter().any(|cert| cert["status"] == "pending")),
        "fixture lacks a live pending old-root certificate with an expired current certificate"
    );
    let both_record = device(&ctx.target, &both.device_id).await?;
    ensure!(
        both_record["status"] == "active"
            && both_record["certificates"]
                .as_array()
                .is_some_and(|certs| certs.iter().any(|cert| cert["status"] == "pending")),
        "fixture lacks both current and pending old-root certificates"
    );
    let pending_cert = pending_record["certificates"]
        .as_array()
        .context("pending device certificates")?
        .iter()
        .find(|cert| cert["status"] == "pending")
        .context("pending old-root certificate")?;
    let maximum = time::OffsetDateTime::parse(field(pending_cert, "notAfter")?, &Rfc3339)?;
    ensure!(
        time::OffsetDateTime::parse(
            field(
                &device(&ctx.target, &active.device_id).await?["certificate"],
                "notAfter"
            )?,
            &Rfc3339
        )? < maximum,
        "pending certificate does not determine the rotation maximum"
    );
    let too_late = (maximum + time::Duration::seconds(1)).format(&Rfc3339)?;
    expect_status(&ctx.target.rotate(Some(&too_late)).await?, 400)?;
    ensure!(
        ctx.target.admin(Method::GET, "/ca/rotation", None).await?.body["phase"] == "idle"
            && ctx.target.trust_anchor().await?["roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 1),
        "rejected late deadline started a rotation"
    );
    let started = ctx.target.rotate(None).await?;
    expect_status(&started, 202)?;
    ensure!(
        started.body["deadline"] == maximum.format(&Rfc3339)?
            && count(&started.body, "activeDevicesOnOldRoot")? == 3
            && active_old_root_ids(&ctx, field(&started.body["oldRoot"], "thumbprint")?)
                .await?
                .len()
                == 3,
        "rotation maximum or device count excluded a pending certificate or counted one device twice"
    );
    Ok(())
}

pub(crate) async fn p_rotation_grace_renewal_after_early_completion(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 60 })).await?;
    let (_, expired) = issued(&ctx, "grace-old-root").await?;
    let old_root = thumbprint(expired.certificate_chain.last().context("missing old root")?)?;
    let expiry = time::OffsetDateTime::parse(
        field(
            &device(&ctx.target, &expired.device_id).await?["certificate"],
            "notAfter",
        )?,
        &Rfc3339,
    )?
    .unix_timestamp();
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 600 })).await?;
    let (_, revoked) = issued(&ctx, "long-lived-old-root").await?;

    let started = ctx.target.rotate(None).await?;
    expect_status(&started, 202)?;
    ensure!(
        started.body["phase"] == "rotating" && count(&started.body, "activeDevicesOnOldRoot")? == 2,
        "rotation did not count both old-root devices"
    );
    let deadline = time::OffsetDateTime::parse(field(&started.body, "deadline")?, &Rfc3339)?.unix_timestamp();
    let new_root = field(&started.body["newRoot"], "thumbprint")?;
    ctx.target.revoke(&revoked.device_id).await?;
    let remaining = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
    ensure!(
        remaining.body["phase"] == "rotating"
            && count(&remaining.body, "activeDevicesOnOldRoot")? == 1
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
    ctx.target.advance(until_expiry).await?;
    let now = chain_evaluation_time(&ctx).await?;
    ensure!(
        now >= expiry && now < expiry + 60 && now < deadline - 60,
        "certificate is not expired within grace and before the rotation deadline"
    );
    let completed = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
    let roots = ctx.target.trust_anchor().await?;
    ensure!(
        completed.body["phase"] == "idle"
            && count(&completed.body, "activeDevicesOnOldRoot")? == 0
            && roots["roots"]
                .as_array()
                .is_some_and(|entries| entries.len() == 1 && entries[0]["thumbprint"] == new_root),
        "expiry of the last active old-root certificate did not finish the rotation early"
    );
    ensure!(
        device(&ctx.target, &expired.device_id).await?["status"] == "expired",
        "old-root certificate was not expired before grace renewal"
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
            && ctx.target.admin(Method::GET, "/ca/rotation", None).await?.body["phase"] == "idle",
        "expired old-root certificate did not renew onto the new root after early completion"
    );
    Ok(())
}

pub(crate) async fn p_rotation_completes_early_at_certificate_expiry_via_freeze(ctx: Context) -> anyhow::Result<()> {
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 30 })).await?;
    let (_, short) = issued(&ctx, "freeze-short-old-root").await?;
    let expiry = time::OffsetDateTime::parse(
        field(&device(&ctx.target, &short.device_id).await?["certificate"], "notAfter")?,
        &Rfc3339,
    )?
    .unix_timestamp();
    let old_root = thumbprint(short.certificate_chain.last().context("missing old root")?)?;
    ctx.target.faults(&json!({ "leaf_lifetime_secs": 180 })).await?;
    let (_, long) = issued(&ctx, "freeze-long-old-root").await?;
    let started = ctx.target.rotate(None).await?;
    expect_status(&started, 202)?;
    ensure!(
        started.body["phase"] == "rotating" && count(&started.body, "activeDevicesOnOldRoot")? == 2,
        "rotation did not start with two active old-root certificates"
    );
    let deadline = time::OffsetDateTime::parse(field(&started.body, "deadline")?, &Rfc3339)?.unix_timestamp();
    ctx.target.revoke(&long.device_id).await?;

    let before = ctx.target.control("time/freeze", &json!({ "now": expiry - 1 })).await?;
    expect_status(&before, 200)?;
    ensure!(
        before.body["published_roots"]
            .as_array()
            .is_some_and(|roots| roots.len() == 2)
            && ctx.target.admin(Method::GET, "/ca/rotation", None).await?.body["activeDevicesOnOldRoot"] == 1,
        "old root was removed before the last certificate expired"
    );
    let at_expiry = ctx.target.control("time/freeze", &json!({ "now": expiry })).await?;
    expect_status(&at_expiry, 200)?;
    ensure!(
        expiry < deadline
            && at_expiry.body["published_roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 1 && roots[0] != old_root)
            && ctx.target.admin(Method::GET, "/ca/rotation", None).await?.body["phase"] == "idle",
        "freezing the clock at certificate expiry did not complete the rotation immediately"
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
    expect_status(&ctx.target.rotate(Some("now")).await?, 202)?;
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
        let deadline = time::OffsetDateTime::from_unix_timestamp(now + 20)?.format(&Rfc3339)?;
        ctx.target.rotate(Some(&deadline)).await?
    } else {
        begin_rotation(&ctx).await?
    };
    expect_status(&started, 202)?;
    let deadline = time::OffsetDateTime::parse(field(&started.body, "deadline")?, &Rfc3339)?.unix_timestamp();
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
    verify_chain(&new_chain, &roots, chain_evaluation_time(&ctx).await?)?;
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
    let current_expiry = time::OffsetDateTime::parse(
        field(
            &device(&ctx.target, &identity.device_id).await?["certificate"],
            "notAfter",
        )?,
        &Rfc3339,
    )?
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
    ctx.target.advance(until_expiry).await?;
    let record = device(&ctx.target, &identity.device_id).await?;
    ensure!(
        record["status"] == "expired"
            && record["connected"] == true
            && has_certificate(&record, &identity.thumbprint, "pending"),
        "pending-only old-root stream was not connected after current expiry"
    );
    let started = ctx.target.rotate(None).await?;
    expect_status(&started, 202)?;
    ensure!(
        started.body["phase"] == "rotating"
            && count(&started.body, "activeDevicesOnOldRoot")? == 1
            && ctx.target.trust_anchor().await?["roots"]
                .as_array()
                .is_some_and(|roots| roots.len() == 2),
        "rotation omitted the pending-only old-root device"
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
        device(&ctx.target, &identity.device_id).await?["renewalRequested"] == true,
        "rotation did not persist the request-renewal flag for the pending-only device"
    );
    Ok(())
}

pub(crate) async fn p_listing_pagination_stable_during_concurrent_enrollment(ctx: Context) -> anyhow::Result<()> {
    let token = token(&ctx, 15).await?;
    let mut expected = Vec::new();
    for n in 0..4 {
        expected.push(identity(&ctx.target, &token, &format!("initial-{n}")).await?.device_id);
    }
    let first = ctx
        .target
        .devices_for(&token, "&pageSize=2&pageNumber=1&view=full")
        .await?;
    expect_status(&first, 200)?;
    let first_ids = first.body["data"]
        .as_array()
        .context("first page")?
        .iter()
        .map(|row| field(row, "id").map(str::to_owned))
        .collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(first_ids == expected[..2], "initial page is not in creation order");
    let mut seen = first_ids.clone();
    let mut timestamps = first.body["data"]
        .as_array()
        .context("first page")?
        .iter()
        .map(|row| field(row, "createdAt").map(str::to_owned))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for page in 2..=5 {
        if page <= 4 {
            for n in 0..2 {
                expected.push(
                    identity(&ctx.target, &token, &format!("later-{page}-{n}"))
                        .await?
                        .device_id,
                );
            }
        }
        let repeat_first = ctx.target.devices_for(&token, "&pageSize=2&pageNumber=1").await?;
        expect_status(&repeat_first, 200)?;
        ensure!(
            repeat_first.body["data"]
                .as_array()
                .context("repeated first page")?
                .iter()
                .map(|row| field(row, "id").map(str::to_owned))
                .collect::<anyhow::Result<Vec<_>>>()?
                == first_ids,
            "new enrollments shifted the already-fetched first page"
        );
        let next = ctx
            .target
            .devices_for(&token, &format!("&pageSize=2&pageNumber={page}&view=full"))
            .await?;
        expect_status(&next, 200)?;
        ensure!(
            count(&next.body, "totalCount")? == expected.len() as u64 && count(&next.body, "currentPage")? == page,
            "page {page} has incorrect paging metadata"
        );
        let rows = next.body["data"].as_array().context("page rows")?;
        ensure!(rows.len() == 2, "page {page} has the wrong number of rows");
        for row in rows {
            seen.push(field(row, "id")?.to_owned());
            timestamps.push(field(row, "createdAt")?.to_owned());
        }
    }
    ensure!(
        seen == expected,
        "page traversal omitted, duplicated or reordered device IDs"
    );
    ensure!(
        seen.iter().collect::<HashSet<_>>().len() == expected.len(),
        "page traversal repeated a device ID"
    );
    ensure!(
        timestamps.windows(2).all(|pair| pair[0] <= pair[1]),
        "createdAt decreased in creation order"
    );
    let beyond = ctx.target.devices_for(&token, "&pageSize=2&pageNumber=6").await?;
    expect_status(&beyond, 200)?;
    ensure!(
        beyond.body["data"].as_array().is_some_and(Vec::is_empty),
        "page beyond the last page is not empty"
    );
    Ok(())
}

pub(crate) async fn p_listing_views_filters_and_bounds(ctx: Context) -> anyhow::Result<()> {
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
        .devices_for(&token, "&view=summary&metadata=hostname,arch&status=active")
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
        row["metadata"]["arch"].is_null(),
        "metadata subset included an absent key"
    );
    ensure!(row["certificates"].is_null(), "summary included full certificates");
    let full = ctx.target.devices_for(&token, "&view=full&status=revoked").await?;
    expect_status(&full, 200)?;
    ensure!(
        count(&full.body, "totalCount")? == 1,
        "revoked filter returned wrong count"
    );
    ensure!(
        full.body["data"][0]["id"] == revoked.device_id,
        "revoked filter selected wrong device"
    );
    ensure!(
        full.body["data"][0]["status"] == "revoked",
        "revoked filter reported the wrong status"
    );
    ensure!(
        full.body["data"][0]["certificates"].is_array(),
        "full view has no certificates"
    );
    let by_name = ctx.target.devices_for(&token, "&q=FILTER-HOST").await?;
    expect_status(&by_name, 200)?;
    ensure!(
        count(&by_name.body, "totalCount")? == 1 && by_name.body["data"][0]["id"] == active.device_id,
        "friendly-name substring filter failed"
    );
    let all_metadata = ctx
        .target
        .devices_for(&token, "&view=full&metadata=hostname&status=active")
        .await?;
    expect_status(&all_metadata, 200)?;
    ensure!(
        all_metadata.body["data"][0]["metadata"]["os_name"] == "Linux",
        "full view filtered metadata despite requesting all fields"
    );
    let issuer = field(&summary.body["data"][0]["certificate"], "issuer")?;
    let by_issuer = ctx.target.devices_for(&token, &format!("&issuer={issuer}")).await?;
    expect_status(&by_issuer, 200)?;
    ensure!(
        count(&by_issuer.body, "totalCount")? == 2
            && by_issuer.body["data"].as_array().is_some_and(|rows| {
                rows.iter().map(|row| row["id"].as_str()).collect::<Vec<_>>()
                    == [Some(active.device_id.as_str()), Some(revoked.device_id.as_str())]
            }),
        "issuer filter returned incorrect device IDs"
    );
    let paged = ctx.target.devices_for(&token, "&pageSize=1&pageNumber=2").await?;
    expect_status(&paged, 200)?;
    ensure!(
        count(&paged.body, "pageSize")? == 1
            && count(&paged.body, "currentPage")? == 2
            && count(&paged.body, "totalCount")? == 2
            && count(&paged.body, "totalPages")? == 2
            && paged.body["data"][0]["id"] == revoked.device_id,
        "DVLS page fields incorrect"
    );
    let beyond = ctx.target.devices_for(&token, "&pageSize=1&pageNumber=3").await?;
    expect_status(&beyond, 200)?;
    ensure!(
        beyond.body["data"].as_array().is_some_and(Vec::is_empty),
        "page beyond the last page was not empty"
    );
    for query in ["&pageSize=0", "&pageSize=101", "&pageNumber=0"] {
        expect_status(&ctx.target.devices_for(&token, query).await?, 400)?;
    }
    if ctx.mock() {
        let huge = ctx
            .target
            .devices_for(&token, "&pageSize=100&pageNumber=18446744073709551615")
            .await?;
        expect_status(&huge, 200)?;
        ensure!(
            huge.body["data"].as_array().is_some_and(Vec::is_empty),
            "huge pageNumber overflowed instead of returning an empty page"
        );
    }
    expect_status(
        &ctx.target
            .renew(&active, &KeyPair::generate()?, &json!({ "hostname": "filter-host" }))
            .await?,
        200,
    )?;
    let observed = device(&ctx.target, &active.device_id).await?;
    let last_seen = field(&observed, "lastSeenAt")?;
    let instant = time::OffsetDateTime::parse(last_seen, &Rfc3339)?;
    let after = (instant - time::Duration::seconds(1)).format(&Rfc3339)?;
    let before = (instant + time::Duration::seconds(1)).format(&Rfc3339)?;
    for (query, expected) in [
        (format!("&status=active&lastSeenAfter={after}"), true),
        (format!("&status=active&lastSeenBefore={before}"), true),
        (format!("&status=active&lastSeenAfter={before}"), false),
    ] {
        let result = ctx.target.devices_for(&token, &query).await?;
        expect_status(&result, 200)?;
        let rows = result.body["data"].as_array().context("lastSeen filter page")?;
        ensure!(
            count(&result.body, "totalCount")? == u64::from(expected)
                && if expected {
                    rows.len() == 1 && rows[0]["id"] == active.device_id && rows[0]["status"] == "active"
                } else {
                    rows.is_empty()
                },
            "lastSeen filter returned the wrong device IDs or statuses for {query}"
        );
    }
    if ctx.mock() {
        ctx.target.advance(91 * 24 * 3600).await?;
        let expired = ctx.target.devices_for(&token, "&status=expired").await?;
        expect_status(&expired, 200)?;
        ensure!(
            count(&expired.body, "totalCount")? == 1
                && expired.body["data"][0]["id"] == active.device_id
                && expired.body["data"][0]["status"] == "expired",
            "expired status filter selected wrong device ID or status"
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
    assert_admin_routes_denied(&ctx, None, 401).await?;
    let invalid = format!("invalid-admin-{}", uuid::Uuid::new_v4());
    assert_admin_routes_denied(&ctx, Some(&invalid), 401).await?;
    Ok(())
}

async fn assert_token_name_absent(target: &Target, name: &str) -> anyhow::Result<()> {
    let mut page = 1;
    loop {
        let listing = target
            .admin(
                Method::GET,
                &format!("/enrollment-tokens?pageNumber={page}&pageSize=100"),
                None,
            )
            .await?;
        expect_status(&listing, 200)?;
        ensure!(
            listing.body["data"]
                .as_array()
                .context("token listing is missing data")?
                .iter()
                .all(|record| record["name"] != name),
            "unauthorized token creation changed server state"
        );
        if page >= count(&listing.body, "totalPages")? {
            break;
        }
        page += 1;
    }
    Ok(())
}

async fn assert_admin_routes_denied(ctx: &Context, bearer: Option<&str>, expected: u16) -> anyhow::Result<()> {
    let token = token(ctx, 1).await?;
    let identity = identity(&ctx.target, &token, "untouched").await?;
    let mut stream = if ctx.mock() && ctx.channel_available {
        let mut stream = channel::open(&ctx.target, &identity).await?;
        stream.hello(&identity, &[]).await?;
        Some(stream)
    } else {
        None
    };
    let before = device(&ctx.target, &identity.device_id).await?;
    let token_record_before = ctx.target.token_record(&token.id).await?;
    expect_status(&token_record_before, 200)?;
    let roots_before = ctx.target.trust_anchor().await?;
    let rotation_before = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
    expect_status(&rotation_before, 200)?;
    let events_before = if ctx.mock() {
        Some(ctx.target.events(&identity.device_id).await?)
    } else {
        None
    };
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).format(&Rfc3339)?;
    let unauthorized_name = format!("unauthorized-{}", uuid::Uuid::new_v4());
    let create = serde_json::to_vec(&json!({
        "name": &unauthorized_name,
        "maxUses": 1,
        "expiresAt": expires,
    }))?;
    let rename_payload = serde_json::to_vec(&json!({ "friendlyName": "unauthorized" }))?;
    let rotation = if ctx.mock() {
        serde_json::to_vec(&json!({ "deadline": "now" }))?
    } else {
        // A malformed request cannot rotate a non-disposable DVLS target even if authorization is broken.
        b"{".to_vec()
    };
    let token_path = format!("/enrollment-tokens/{}", token.id);
    let device_path = format!("/devices/{}", identity.device_id);
    let routes = [
        (Method::POST, "/enrollment-tokens".to_owned(), Some(create.as_slice())),
        (Method::GET, "/enrollment-tokens".to_owned(), None),
        (Method::GET, token_path.clone(), None),
        (Method::DELETE, token_path, None),
        (Method::GET, format!("/devices?enrollmentTokenId={}", token.id), None),
        (Method::GET, device_path.clone(), None),
        (Method::PATCH, device_path.clone(), Some(rename_payload.as_slice())),
        (Method::DELETE, device_path.clone(), None),
        (Method::POST, format!("{device_path}/revoke"), None),
        (Method::POST, format!("{device_path}/request-renewal"), None),
        (Method::GET, "/ca/rotation".to_owned(), None),
        (Method::POST, "/ca/rotation".to_owned(), Some(rotation.as_slice())),
    ];
    for (method, route, body) in routes {
        let route_path = format!("/api/v3/agent-identity{route}");
        ensure!(
            ctx.target
                .send(method.clone(), &route_path, body, bearer, None)
                .await?
                .status
                == expected,
            "unauthorized {method} {route} was not denied with HTTP {expected}"
        );
        let after_token = ctx.target.token_record(&token.id).await?;
        expect_status(&after_token, 200)?;
        ensure!(
            after_token.body == token_record_before.body,
            "unauthorized {method} {route} changed the enrollment token"
        );
        if method == Method::POST && route == "/enrollment-tokens" {
            assert_token_name_absent(&ctx.target, &unauthorized_name).await?;
        }
        ensure!(
            device(&ctx.target, &identity.device_id).await? == before,
            "unauthorized {method} {route} changed the device"
        );
        let after_rotation = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
        expect_status(&after_rotation, 200)?;
        ensure!(
            after_rotation.body == rotation_before.body && ctx.target.trust_anchor().await? == roots_before,
            "unauthorized {method} {route} changed CA rotation state"
        );
        if let Some(events) = &events_before {
            ensure!(
                ctx.target.events(&identity.device_id).await? == *events,
                "unauthorized {method} {route} changed the channel or certificate events"
            );
        }
    }
    if let Some(stream) = stream.as_mut() {
        ensure!(
            tokio::time::timeout(Duration::from_millis(100), stream.stream.message())
                .await
                .is_err(),
            "unauthorized admin route pushed a channel message"
        );
    }
    Ok(())
}

pub(crate) async fn p_admin_permission_denied(ctx: Context) -> anyhow::Result<()> {
    let unprivileged = ctx
        .unprivileged_admin_token
        .as_deref()
        .context("unprivileged admin fixture missing")?;
    assert_admin_routes_denied(&ctx, Some(unprivileged), 403).await?;
    Ok(())
}

pub(crate) async fn p_rotation_admin_write_requires_auth(ctx: Context) -> anyhow::Result<()> {
    ensure!(
        ctx.mock() || ctx.disposable_dvls_target,
        "rotation authorization requires a disposable DVLS target"
    );
    let before = ctx.target.trust_anchor().await?;
    let rotation = ctx.target.admin(Method::GET, "/ca/rotation", None).await?;
    expect_status(&rotation, 200)?;
    let body = serde_json::to_vec(&json!({ "deadline": "now" }))?;
    let invalid = format!("invalid-admin-{}", uuid::Uuid::new_v4());
    for (bearer, expected) in [
        (None, 401),
        (Some(invalid.as_str()), 401),
        (ctx.unprivileged_admin_token.as_deref(), 403),
    ] {
        if expected == 403 && bearer.is_none() {
            continue;
        }
        expect_status(
            &ctx.target
                .send(
                    Method::POST,
                    "/api/v3/agent-identity/ca/rotation",
                    Some(&body),
                    bearer,
                    None,
                )
                .await?,
            expected,
        )?;
        ensure!(
            ctx.target.trust_anchor().await? == before,
            "unauthorized rotation changed published roots"
        );
        ensure!(
            ctx.target.admin(Method::GET, "/ca/rotation", None).await?.body == rotation.body,
            "unauthorized rotation changed state"
        );
    }
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
            && count(&ctx.target.token_record(&token.id).await?.body, "usedCount")? == 0
            && count(&ctx.target.devices_for(&token, "").await?.body, "totalCount")? == 0,
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
        count(&ctx.target.token_record(&token.id).await?.body, "usedCount")? == 0,
        "injected empty 400 processed an enrollment"
    );
    let enrolled = ctx.target.enroll(&token.text, &key, &json!({})).await?;
    let identity = Identity::from_enrollment(key, &enrolled)?;
    let before = device(&ctx.target, &identity.device_id).await?;
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
        device(&ctx.target, &identity.device_id).await? == before,
        "injected renewal error processed a certificate or metadata"
    );
    expect_status(&ctx.target.renew(&identity, &next_key, &json!({})).await?, 200)?;
    ensure!(
        ctx.target.control("faults", &json!({})).await?.body["fail_next_response"].is_null(),
        "one-shot fault was not consumed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;

    use super::*;

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
            format!(
                "{:#}",
                verify_chain(&unsupported, &roots, time::OffsetDateTime::now_utc().unix_timestamp())
                    .expect_err("unsupported issuer curve was accepted")
            )
            .contains("unsupported"),
            "unsupported issuer curve was not a conformance failure"
        );
        Ok(())
    }
}
