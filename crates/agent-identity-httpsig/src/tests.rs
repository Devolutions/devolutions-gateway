use std::sync::atomic::{AtomicBool, Ordering};

use p256::ecdsa::{Signature, SigningKey as P256SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use serde_json::Value;
use signature::Verifier as _;
use tower::ServiceExt as _;

use super::*;

struct TestKey {
    name: String,
    key: P256SigningKey,
    fail_signing: bool,
}

impl DeviceKey for TestKey {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key(&self) -> VerifyingKey {
        *self.key.verifying_key()
    }

    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        if self.fail_signing {
            return Err(signature::Error::new());
        }
        signature::Signer::<Signature>::try_sign(&self.key, message)
    }
}

fn vectors() -> anyhow::Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../docs/agent-identity/test-vectors.json"
    ))?)
}

fn field<'a>(value: &'a Value, name: &str) -> anyhow::Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing vector field {name}"))
}

fn vector_signer(vectors: &Value, name: &str) -> anyhow::Result<(RequestSigner, VerifyingKey)> {
    let vector = vectors["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|key| key["name"] == name))
        .ok_or_else(|| anyhow!("missing vector key {name}"))?;
    let private_key = general_purpose::STANDARD.decode(field(vector, "private_key_pkcs8")?)?;
    let key = P256SigningKey::from_pkcs8_der(&private_key).context("decode vector device key")?;
    let public_key = *key.verifying_key();
    let certificate = general_purpose::STANDARD.decode(field(vector, "certificate")?)?;
    let signer = RequestSigner::new(
        Arc::new(TestKey {
            name: name.to_owned(),
            key,
            fail_signing: false,
        }),
        &certificate,
    );
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    assert_eq!(signer.keyid, field(vector, "thumbprint")?);
    Ok((signer, public_key))
}

#[test]
fn signs_all_four_profile_tags_exactly_as_vectored() -> anyhow::Result<()> {
    struct Case {
        name: &'static str,
        tag: Tag,
        key: &'static str,
        nonce_start: u8,
    }

    let cases = [
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
        Case {
            name: "valid_renew_alg_before_keyid",
            tag: Tag::Renew,
            key: "device-a",
            nonce_start: 144,
        },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
        Case {
            name: "valid_connect_alg_before_keyid",
            tag: Tag::Connect,
            key: "device-a",
            nonce_start: 160,
        },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
        Case {
            name: "valid_confirm_alg_before_keyid",
            tag: Tag::Confirm,
            key: "device-g",
            nonce_start: 176,
        },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
        Case {
            name: "valid_check_in_alg_before_keyid",
            tag: Tag::CheckIn,
            key: "device-a",
            nonce_start: 192,
        },
    ];

    let vectors = vectors()?;
    for case in cases {
        let vector = vectors["http_signature"]["cases"]
            .as_array()
            .and_then(|cases| cases.iter().find(|vector| vector["name"] == case.name))
            .ok_or_else(|| anyhow!("missing vector case {}", case.name))?;
        let (signer, public_key) = vector_signer(&vectors, case.key)?;
        let created = vector["now"]
            .as_u64()
            .ok_or_else(|| anyhow!("missing vector timestamp"))?;
        let nonce = std::array::from_fn(|index| case.nonce_start + u8::try_from(index).expect("16 nonce bytes"));
        let body = vector["body"].as_str().map(str::as_bytes);
        let headers = signer.sign_with_nonce(case.tag, &Method::POST, body, created, &nonce)?;
        assert_eq!(
            headers.nonce,
            general_purpose::URL_SAFE_NO_PAD.encode(nonce),
            "{}",
            case.name
        );
        // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Conformance
        assert_eq!(
            headers.signature_input.to_str()?,
            field(&vector["headers"], "signature-input")?,
            "{}",
            case.name
        );
        assert_eq!(
            headers.content_digest.as_ref().map(HeaderValue::to_str).transpose()?,
            vector["headers"]["content-digest"].as_str(),
            "{}",
            case.name
        );
        // oracle: spec RFC 6979 §3.2
        // The test key signs deterministically, as the vectors' generator did, so the signature bytes match.
        assert_eq!(
            headers.signature.to_str()?,
            field(&vector["headers"], "signature")?,
            "{}",
            case.name
        );

        let base = signer.signature_base(
            case.tag,
            &Method::POST,
            headers.content_digest.as_ref(),
            created,
            &headers.nonce,
        )?;
        // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Conformance
        assert_eq!(base.to_string(), field(vector, "signature_base")?, "{}", case.name);
        let encoded_signature = headers
            .signature
            .to_str()?
            .strip_prefix("sig=:")
            .and_then(|value| value.strip_suffix(':'))
            .ok_or_else(|| anyhow!("invalid signed test header"))?;
        let bytes = general_purpose::STANDARD.decode(encoded_signature)?;
        let signature = Signature::from_slice(&bytes)?;
        public_key.verify(&base.as_bytes(), &signature)?;
    }
    Ok(())
}

// oracle: spec RFC 9421 §B.2.4
#[test]
fn builds_and_signs_rfc_9421_b_2_4_response_base() -> anyhow::Result<()> {
    let vectors = vectors()?;
    let vector = &vectors["rfc9421_b_2_4"];
    let components = [
        ("@status", "200"),
        ("content-type", "application/json"),
        (
            "content-digest",
            "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
        ),
        ("content-length", "23"),
    ]
    .into_iter()
    .map(|(name, value)| {
        let id = HttpMessageComponentId::try_from(name)?;
        let values = [value.to_owned()];
        HttpMessageComponent::try_from((&id, values.as_slice()))
    })
    .collect::<HttpSigResult<Vec<_>>>()?;
    let covered = components
        .iter()
        .map(|component| component.id.clone())
        .collect::<Vec<_>>();
    let mut params = HttpSignatureParams::try_new(&covered)?;
    params.set_created(1_618_884_473).set_keyid("test-key-ecc-p256");
    let base = HttpSignatureBase::try_new(&components, &params)?;
    assert_eq!(base.to_string(), field(vector, "signature_base")?);

    // RFC 9421 Appendix B.1.3 publishes this test private scalar in its JWK.
    let private_key = general_purpose::URL_SAFE_NO_PAD.decode("UpuF81l-kOxbjf7T4mNSv0r5tN67Gim7rnf6EFpcYDs")?;
    let signing_key = P256SigningKey::from_slice(&private_key)?;
    let key = TestKey {
        name: "test-key-ecc-p256".to_owned(),
        key: signing_key,
        fail_signing: false,
    };
    let public_key_der = general_purpose::STANDARD.decode(field(vector, "public_key_spki")?)?;
    let public_key = VerifyingKey::from_public_key_der(&public_key_der)?;
    let signature = base.build_raw_signature(&DeviceSigningKey(&key, "test-key-ecc-p256"))?;
    public_key.verify(&base.as_bytes(), &Signature::from_slice(&signature)?)?;
    let published_signature = general_purpose::STANDARD.decode(field(vector, "signature")?)?;
    public_key.verify(&base.as_bytes(), &Signature::from_slice(&published_signature)?)?;
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
// A request signature is the device key's raw r‖s, so a key that fails to sign leaves no valid request to return.
#[test]
fn signing_failure_is_returned_instead_of_panicking() -> anyhow::Result<()> {
    let vectors = vectors()?;
    let vector = &vectors["keys"][0];
    let key_bytes = general_purpose::STANDARD.decode(field(vector, "private_key_pkcs8")?)?;
    let key = P256SigningKey::from_pkcs8_der(&key_bytes)?;
    let leaf = general_purpose::STANDARD.decode(field(vector, "certificate")?)?;
    let signer = RequestSigner::new(
        Arc::new(TestKey {
            name: "device-a".to_owned(),
            key,
            fail_signing: true,
        }),
        &leaf,
    );
    assert!(signer.sign(Tag::Connect, &Method::POST, None, 1_790_000_000).is_err());
    Ok(())
}

#[tokio::test]
async fn channel_layer_prefixes_once_and_signs_each_opening() -> anyhow::Result<()> {
    let vectors = vectors()?;
    let (signer, _) = vector_signer(&vectors, "device-a")?;
    let base_url = url::Url::parse("https://example.test/dvls/")?;
    let layer = ChannelLayer::new(signer, &base_url);
    let service = layer.layer(tower::service_fn(|request: Request<()>| async move {
        Ok::<_, std::io::Error>(request)
    }));

    let (first_handoff, first_nonce) = OpeningNonce::new();
    let mut first_request = Request::builder().method(Method::POST).uri(CONNECT_RPC_PATH).body(())?;
    first_request.extensions_mut().insert(first_handoff);
    let (second_handoff, second_nonce) = OpeningNonce::new();
    let mut second_request = Request::builder()
        .method(Method::POST)
        .uri(format!("/dvls{CONNECT_RPC_PATH}"))
        .body(())?;
    second_request.extensions_mut().insert(second_handoff);

    let (first, second) = tokio::join!(service.clone().oneshot(first_request), service.oneshot(second_request));
    let first = first.map_err(|error| anyhow!("{error}"))?;
    let second = second.map_err(|error| anyhow!("{error}"))?;
    let first_nonce = first_nonce.await?;
    let second_nonce = second_nonce.await?;

    for request in [&first, &second] {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
        assert_eq!(request.uri().path(), format!("/dvls{CONNECT_RPC_PATH}"));
        let signature_input = request
            .headers()
            .get("signature-input")
            .ok_or_else(|| anyhow!("missing signature input"))?
            .to_str()?;
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
        assert!(signature_input.starts_with(r#"sig=("@method");"#), "{signature_input}");
        assert!(signature_input.contains(r#";tag="connect""#), "{signature_input}");
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
        assert!(request.headers().get("signature").is_some());
    }
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    assert_eq!(
        first_nonce,
        nonce(
            first
                .headers()
                .get("signature-input")
                .ok_or_else(|| anyhow!("missing signature input"))?,
        )?
    );
    assert_eq!(
        second_nonce,
        nonce(
            second
                .headers()
                .get("signature-input")
                .ok_or_else(|| anyhow!("missing signature input"))?,
        )?
    );
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    assert_ne!(first_nonce, second_nonce);
    assert_eq!(general_purpose::URL_SAFE_NO_PAD.decode(&first_nonce)?.len(), 16);
    assert_eq!(general_purpose::URL_SAFE_NO_PAD.decode(&second_nonce)?.len(), 16);

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
    for (base_url, expected_path) in [
        ("https://example.test/dvls//", format!("/dvls{CONNECT_RPC_PATH}")),
        ("https://example.test//", CONNECT_RPC_PATH.to_owned()),
    ] {
        let (signer, _) = vector_signer(&vectors, "device-a")?;
        let service = ChannelLayer::new(signer, &url::Url::parse(base_url)?).layer(tower::service_fn(
            |request: Request<()>| async move { Ok::<_, std::io::Error>(request) },
        ));
        let (handoff, _received_nonce) = OpeningNonce::new();
        let mut opening = Request::builder().method(Method::POST).uri(CONNECT_RPC_PATH).body(())?;
        opening.extensions_mut().insert(handoff);
        let request = service.oneshot(opening).await.map_err(|error| anyhow!("{error}"))?;
        assert_eq!(request.uri().path(), expected_path, "{base_url}");
    }
    Ok(())
}

#[tokio::test]
async fn channel_layer_prefixes_an_rpc_path_that_matches_the_base_path() -> anyhow::Result<()> {
    let vectors = vectors()?;
    let (signer, _) = vector_signer(&vectors, "device-a")?;
    let base_url = url::Url::parse("https://example.test/devolutions.agent.channel.v1.AgentChannel")?;
    let service = ChannelLayer::new(signer, &base_url).layer(tower::service_fn(|request: Request<()>| async move {
        Ok::<_, std::io::Error>(request)
    }));
    let (handoff, received_nonce) = OpeningNonce::new();
    let mut opening = Request::builder().method(Method::POST).uri(CONNECT_RPC_PATH).body(())?;
    opening.extensions_mut().insert(handoff);

    let request = service.oneshot(opening).await.map_err(|error| anyhow!("{error}"))?;
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
    assert_eq!(
        request.uri().path(),
        format!("/devolutions.agent.channel.v1.AgentChannel{CONNECT_RPC_PATH}")
    );
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    assert_eq!(
        received_nonce.await?,
        nonce(
            request
                .headers()
                .get("signature-input")
                .ok_or_else(|| anyhow!("missing signature input"))?
        )?
    );
    Ok(())
}

#[tokio::test]
async fn channel_layer_preserves_root_path_and_applies_clock_offset() -> anyhow::Result<()> {
    let vectors = vectors()?;
    let (signer, _) = vector_signer(&vectors, "device-a")?;
    let base_url = url::Url::parse("https://example.test/")?;
    let layer = ChannelLayer::new(signer, &base_url).with_clock_offset(3_600);
    let mut service = layer.layer(tower::service_fn(|request: Request<()>| async move {
        Ok::<_, std::io::Error>(request)
    }));
    let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3_600;
    let (handoff, received_nonce) = OpeningNonce::new();
    let mut opening = Request::builder().method(Method::POST).uri(CONNECT_RPC_PATH).body(())?;
    opening.extensions_mut().insert(handoff);
    let request = service
        .ready()
        .await
        .map_err(|error| anyhow!("{error}"))?
        .call(opening)
        .await
        .map_err(|error| anyhow!("{error}"))?;
    let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3_600;
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
    assert_eq!(request.uri().path(), CONNECT_RPC_PATH);
    let signature_input = request
        .headers()
        .get("signature-input")
        .ok_or_else(|| anyhow!("missing signature input"))?
        .to_str()?;
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    assert_eq!(
        received_nonce.await?,
        nonce(
            request
                .headers()
                .get("signature-input")
                .ok_or_else(|| anyhow!("missing signature input"))?
        )?
    );
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    assert!((before..=after).any(|created| signature_input.contains(&format!(";created={created};"))));
    Ok(())
}

// oracle: spec RFC 9421 §2.2.1
#[test]
fn signature_covers_the_request_method() -> anyhow::Result<()> {
    let vectors = vectors()?;
    let (signer, public_key) = vector_signer(&vectors, "device-a")?;
    let headers = signer.sign(Tag::Connect, &Method::PUT, None, 1_790_000_000)?;
    let params = headers
        .signature_input
        .to_str()?
        .strip_prefix("sig=")
        .ok_or_else(|| anyhow!("unlabelled signature input"))?;
    let base = format!("\"@method\": PUT\n\"@signature-params\": {params}");
    let encoded_signature = headers
        .signature
        .to_str()?
        .strip_prefix("sig=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or_else(|| anyhow!("invalid signed test header"))?;
    let signature = Signature::from_slice(&general_purpose::STANDARD.decode(encoded_signature)?)?;
    public_key.verify(base.as_bytes(), &signature)?;
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
#[test]
fn confirm_covers_only_the_method_when_given_a_body() -> anyhow::Result<()> {
    let vectors = vectors()?;
    let (signer, _) = vector_signer(&vectors, "device-g")?;
    let headers = signer.sign(Tag::Confirm, &Method::POST, Some(b"".as_slice()), 1_790_000_000)?;
    let signature_input = headers.signature_input.to_str()?;
    assert!(signature_input.starts_with(r#"sig=("@method");"#), "{signature_input}");
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
#[test]
fn signature_expiry_stays_within_structured_field_integers() -> anyhow::Result<()> {
    let vectors = vectors()?;
    let (signer, _) = vector_signer(&vectors, "device-a")?;
    let last = signer.sign(Tag::Connect, &Method::POST, None, 999_999_999_999_939)?;
    let signature_input = last.signature_input.to_str()?;
    // oracle: spec RFC 8941 §3.3.1
    assert!(
        signature_input.contains(";expires=999999999999999"),
        "{signature_input}"
    );
    // oracle: spec RFC 8941 §4.1.4
    assert!(
        signer
            .sign(Tag::Connect, &Method::POST, None, 999_999_999_999_940)
            .is_err()
    );
    Ok(())
}

// oracle: spec tower-service Service §Backpressure
#[test]
fn channel_service_is_not_ready_before_its_inner_service() -> anyhow::Result<()> {
    struct NotReady;

    impl Service<Request<()>> for NotReady {
        type Response = Request<()>;
        type Error = std::io::Error;
        type Future = std::future::Ready<Result<Request<()>, std::io::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn call(&mut self, request: Request<()>) -> Self::Future {
            std::future::ready(Ok(request))
        }
    }

    let vectors = vectors()?;
    let (signer, _) = vector_signer(&vectors, "device-a")?;
    let base_url = url::Url::parse("https://example.test/dvls")?;
    let mut service = ChannelLayer::new(signer, &base_url).layer(NotReady);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(service.poll_ready(&mut cx).is_pending());
    Ok(())
}

// oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
#[tokio::test]
async fn channel_opening_is_not_sent_when_signing_fails() -> anyhow::Result<()> {
    let key = TestKey {
        name: "failing".to_owned(),
        key: P256SigningKey::from_slice(&[1; 32])?,
        fail_signing: true,
    };
    let signer = RequestSigner::new(Arc::new(key), b"leaf certificate");
    let base_url = url::Url::parse("https://example.test/dvls")?;
    let forwarded = Arc::new(AtomicBool::new(false));
    let service = ChannelLayer::new(signer, &base_url).layer(tower::service_fn({
        let forwarded = Arc::clone(&forwarded);
        move |request: Request<()>| {
            forwarded.store(true, Ordering::SeqCst);
            async move { Ok::<_, std::io::Error>(request) }
        }
    }));
    let (handoff, _received_nonce) = OpeningNonce::new();
    let mut opening = Request::builder().method(Method::POST).uri(CONNECT_RPC_PATH).body(())?;
    opening.extensions_mut().insert(handoff);
    assert!(service.oneshot(opening).await.is_err());
    assert!(!forwarded.load(Ordering::SeqCst));
    Ok(())
}

fn nonce(input: &HeaderValue) -> anyhow::Result<&str> {
    input
        .to_str()?
        .split_once(";nonce=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(nonce, _)| nonce)
        .ok_or_else(|| anyhow!("missing signed nonce"))
}
