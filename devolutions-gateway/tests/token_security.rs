#![allow(clippy::too_many_arguments)]
#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::net::IpAddr;

use anyhow::Context as _;
use devolutions_gateway::recording::ActiveRecordings;
use devolutions_gateway::token::{
    ApplicationProtocol, JrlTokenClaims, MAX_SUBKEY_TOKEN_VALIDITY_DURATION_SECS, Protocol, Subkey, TokenError,
    new_token_cache,
};
use devolutions_gateway_generators::*;
use parking_lot::Mutex;
use picky::jose::jwe;
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::CheckedJwtSig;
use picky::key::{PrivateKey, PublicKey};
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use rstest::{fixture, rstest};
use uuid::Uuid;

const PROVISIONER_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDkrPiL/5dmGIT5
/KuC3H/jIjeLoLoddsLhAlikO5JQQo3Zs71GwT4Wd2z8WLMe0lVZu/Jr2S28p0M8
F3Lnz4IgzjocQomFgucFWWQRyD03ZE2BHfEeelFsp+/4GZaM6lKZauYlIMtjR1vD
lflgvxNTr0iaii4JR9K3IKCunCRy1HQYPcZ9waNtlG5xXtW9Uf1tLWPJpP/3I5HL
M85JPBv4r286vpeUlfQIa/NB4g5w6KZ6MfEAIU4KeEQpeLAyyYvwUzPR2uQZ4y4I
4Nj84dWYB1cMTlSGugvSgOFKYit1nwLGeA7EevVYPbILRfSMBU/+avGNJJ8HCaaq
FIyY42W9AgMBAAECggEBAImsGXcvydaNrIFUvW1rkxML5qUJfwN+HJWa9ALsWoo3
h28p5ypR7S9ZdyP1wuErgHcl0C1d80tA6BmlhGhLZeyaPCIHbQQUa0GtL7IE+9X9
bSvu+tt+iMcB1FdqEFmGOXRkB2sS82Ax9e0qvZihcOFRBkUEK/MqapIV8qctGkSG
wIE6yn5LHRls/fJU8BJeeqJmYpuWljipwTkp9hQ7SdRYFLNjwjlz/b0hjmgFs5QZ
LUNMyTHdHtXQHNsf/GayRUAKf5wzN/jru+nK6lMob2Ehfx9/RAfgaDHzy5BNFMj0
i9+sAycgIW1HpTuDvSEs3qP26NeQ82GbJzATmdAKa4ECgYEA9Vti0YG+eXJI3vdS
uXInU0i1SY4aEG397OlGMwh0yQnp2KGruLZGkTvqxG/Adj1ObDyjFH9XUhMrd0za
Nk/VJFybWafljUPcrfyPAVLQLjsBfMg3Y34sTF6QjUnhg49X2jfvy9QpC5altCtA
46/KVAGREnQJ3wMjfGGIFP8BUZsCgYEA7phYE/cYyWg7a/o8eKOFGqs11ojSqG3y
0OE7kvW2ugUuy3ex+kr19Q/8pOWEc7M1UEV8gmc11xgB70EhIFt9Jq379H0X4ahS
+mgLiPzKAdNCRPpkxwwN9HxFDgGWoYcgMplhoAmg9lWSDuE1Exy8iu5inMWuF4MT
/jG+cLnUZ4cCgYAfMIXIUjDvaUrAJTp73noHSUfaWNkRW5oa4rCMzjdiUwNKCYs1
yN4BmldGr1oM7dApTDAC7AkiotM0sC1RGCblH2yUIha5NXY5G9Dl/yv9pHyU6zK3
UBO7hY3kmA611aP6VoACLi8ljPn1hEYUa4VR1n0llmCm29RH/HH7EUuOnwKBgExH
OCFp5eq+AAFNRvfqjysvgU7M/0wJmo9c8obRN1HRRlyWL7gtLuTh74toNSgoKus2
y8+E35mce0HaOJT3qtMq3FoVhAUIoz6a9NUevBZJS+5xfraEDBIViJ4ps9aANLL4
hlV7vpICWWeYaDdsAHsKK0yjhjzOEx45GQFA578RAoGBAOB42BG53tL0G9pPeJPt
S2LM6vQKeYx+gXTk6F335UTiiC8t0CgNNQUkW105P/SdpCTTKojAsOPMKOF7z4mL
lj/bWmNq7xu9uVOcBKrboVFGO/n6FXyWZxHPOTdjTkpe8kvvmSwl2iaTNllvSr46
Z/fDKMxHxeXla54kfV+HiGkH
-----END PRIVATE KEY-----"#;

const DELEGATION_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----"#;

const SUBKEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDoJu1ScaKFntQh
h9z+b3gaOxJmm2TvMh2KtoMw+ezfOIqPGyAmHAIuNqXUyBOApIjpTaGdXzBX4vuJ
IL7QBwQ7Y8OWxW/Up5PJItq0MGaVdwfSYro94FHQ0CUl+BGjo8v6Kxm4FOfxz9ts
bWEjxGzyUcKEfbBPjyZCuQGFLmiR0kDv184UVaUptsWeEPF3w+ZrModepgCsyjeH
PGY3c5LHnrH6VFQG8a6dIgMrJvXTQecb0ubg/2/qnFVceVnL66bOUD74RMOPz32B
HEIx3/rmLmR8xlwAA5CtWS3++0s0mYR8qv0wS+YdgEKu/DLSZzxt7liJIv5mMUyF
GlxvsHBzAgMBAAECggEBAMylZBeFLKt1s7JLPjjcspcM88+XtIZXO0uIUGXgKzsr
cJluZAy0LAfpDI5iQS7p2/cuBAXiX49Z/DqJrytaxBRGgahrK4Xeo5xvKTQmZofj
gfWoKl1ZXUYh9l1eLM6AGdPSIr3vT/gOL3OJiFQrV47VHBAHbGD149h1li19F5lS
fMARBaG4gN7BIYdo3af1go4hDLm5Dh7Ab6ANK1tNsYT1ol55xVVr3Sxgn/whpyzw
LzZO/egPW1o//GRxZgO3jvX0gid4iCzn0UNiYMbjyK2ikVM9nKrXuTBhrd8Nz+ST
Y9WrOQXrFk+Q+Uti8cGu7gvRG1nGcWLb2oZEk3ut+YECgYEA/0zmyqPNWLjL9qbN
tlLarkheW5Yl1UHYcGKFN1Ds4Doy2xwC3sv/RvSR/tBYLpRBl3JVPdxkIA9ymrlY
hodcXVqHNz0sMJ22dEan8fZ2VthN22nZlcGQLnUCZZbmreKVswVcGvUA6br6ZJnp
HS5mz3xp52lBKKRg3rUAifftkcMCgYEA6MnJVnNb4ukeR7kONhbFMPWGnLaycB7A
cGnf2LznT93Oo/9kY4/qHayB2m6d6fmuomiJiPCyMoOtE4H5jcgNq8Pr8ppYpqGy
qlnLIQZyxWNrqZLC342SnV4P/146FuuD6fUEVrtj0T+gOHWxD6EOaWLjpU+7N1yw
PAg4wxBUi5ECgYEA9tXffqUI8XMaoQt9cX6COGd3840kXyAep+pZarYvkEw0x2w5
yjfqRSxJy9icqcxl7ot4pyrjE6xb3gS99rQBNbFFcr8ObqLNuXZnAqaMnELeY/nf
ic9wG7q96oMP3adpnYDdIKMpktJZLdMxdClc9dcQfdFiUm07y5etQbgYVgkCgYAJ
F9jFh7wPIQwNwSzM8BbD0tNvS7OsrYbW3UvhK3/dnsxzm4ZQXU7H2fU4kxmYCijI
L00wDDbpwjsAiBM3dpkSHJUa5OyRlb9k6B0HLTlOfJO4DAOQt/cCLqpxTzz1qD1+
5hNFUAyWH+YiTnacJa5qb3J1AqhNgVFhBvEwrXKgAQKBgGGitzhzr5NOPA2NMLd3
4590JBN8bdmKsV9SCWEfRSRtHJI9xR1US8rZeXjfp8eWQmbBZWZR8rvx0IIBzx8g
Gz2sM9EZDQGifSwkQLinBEc4pj4Ftp+XLm9Vx0HhWrT+TNLLvxrVpFAScxsXCykN
02KdL+VAc/tazDW+zOcmLJVY
-----END PRIVATE KEY-----"#;

#[fixture]
fn jrl() -> Mutex<JrlTokenClaims> {
    Mutex::new(JrlTokenClaims::default())
}

#[fixture]
fn active_recordings() -> ActiveRecordings {
    let (rx, _) = devolutions_gateway::recording::recording_message_channel();
    std::sync::Arc::try_unwrap(rx.active_recordings).unwrap()
}

#[fixture]
fn provisioner_key() -> PrivateKey {
    PrivateKey::from_pem_str(PROVISIONER_KEY).unwrap()
}

#[fixture]
fn delegation_key() -> PrivateKey {
    PrivateKey::from_pem_str(DELEGATION_KEY).unwrap()
}

#[fixture]
fn subkey() -> PrivateKey {
    PrivateKey::from_pem_str(SUBKEY).unwrap()
}

#[fixture]
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[fixture]
fn source_ip() -> IpAddr {
    IpAddr::from([13u8, 12u8, 11u8, 10u8])
}

#[fixture]
fn source_ip_2() -> IpAddr {
    IpAddr::from([15u8, 12u8, 11u8, 10u8])
}

#[fixture]
fn this_gw_id() -> Uuid {
    Uuid::try_from("123e4567-e89b-12d3-a456-426614174000").unwrap()
}

#[fixture]
fn subkey_kid() -> &'static str {
    "<subkey-kid>"
}

#[derive(Debug, Clone)]
struct RevocableItem {
    claim_to_revoke: Option<(String, serde_json::Value)>,
    claims: serde_json::Value,
    token: String,
}

fn revocable_item<'a>(
    now: i64,
    delegation_key: &'a PublicKey,
    provisioner_key: &'a PrivateKey,
) -> impl Strategy<Value = RevocableItem> + 'a {
    any_claims(now)
        .prop_flat_map(move |claims| {
            let token = CheckedJwtSig::new_with_cty(JwsAlg::RS256, claims.content_type(), &claims)
                .encode(provisioner_key)
                .unwrap();

            let token = if claims.should_encrypt() {
                jwe::Jwe::new(jwe::JweAlg::RsaOaep256, jwe::JweEnc::Aes256Gcm, token.into_bytes())
                    .encode(delegation_key)
                    .unwrap()
            } else {
                token
            };

            let claims = serde_json::to_value(&claims).unwrap();
            let nb_claims = claims.as_object().unwrap().len();
            (Just(claims), option::of(0..nb_claims), Just(token))
        })
        .prop_map(|(claims, idx_to_revoke, token)| {
            let claim_to_revoke = idx_to_revoke
                .and_then(|idx| claims.as_object().unwrap().iter().nth(idx))
                .map(|(k, v)| (k.clone(), v.clone()));

            RevocableItem {
                claim_to_revoke,
                claims,
                token,
            }
        })
        .no_shrink()
}

/// Assert that a token containing revoked claims is refused
#[rstest]
fn revocation_list(
    active_recordings: ActiveRecordings,
    provisioner_key: PrivateKey,
    delegation_key: PrivateKey,
    source_ip: IpAddr,
    now: i64,
) {
    let provisioner_key_pub = provisioner_key.to_public_key().unwrap();
    let delegation_key_pub = delegation_key.to_public_key().unwrap();

    let test_impl = |items: Vec<RevocableItem>| -> anyhow::Result<()> {
        // Make sure all tokens are valid before any revocation

        let empty_jrl = Mutex::new(JrlTokenClaims::default());
        let token_cache = new_token_cache();

        for (idx, item) in items.iter().enumerate() {
            devolutions_gateway::token::TokenValidator::builder()
                .source_ip(source_ip)
                .provisioner_key(&provisioner_key_pub)
                .delegation_key(Some(&delegation_key))
                .token_cache(&token_cache)
                .revocation_list(&empty_jrl)
                .gw_id(None)
                .subkey(None)
                .active_recordings(&active_recordings)
                .disconnected_info(None)
                .build()
                .validate(&item.token)
                .with_context(|| format!("Item n°{idx} validation failed"))?;
        }

        // Revoke claims

        let updated_jrl = {
            let mut claims = JrlTokenClaims::default();

            for item in &items {
                let (k, v) = if let Some((k, v)) = &item.claim_to_revoke {
                    (k.clone(), v.clone())
                } else {
                    continue;
                };

                let bucket = claims.jrl.entry(k).or_insert_with(Vec::new);

                bucket.push(v);
            }

            claims
        };

        // Update item list and keep track of which token is revoked

        let items: Vec<_> = items
            .into_iter()
            .map(|item| {
                if item.claim_to_revoke.is_some() {
                    (item, true)
                } else {
                    let is_revoked = updated_jrl
                        .jrl
                        .iter()
                        .any(|(key, revoked_values)| matches!(item.claims.get(key), Some(token_value) if revoked_values.contains(token_value)));
                    (item, is_revoked)
                }
            })
            .collect();

        // Validate that only revoked tokens are rejected

        let updated_jrl = Mutex::new(updated_jrl);
        let token_cache = new_token_cache();

        for (idx, (item, is_revoked)) in items.into_iter().enumerate() {
            let res = devolutions_gateway::token::TokenValidator::builder()
                .source_ip(source_ip)
                .provisioner_key(&provisioner_key_pub)
                .delegation_key(Some(&delegation_key))
                .token_cache(&token_cache)
                .revocation_list(&updated_jrl)
                .gw_id(None)
                .subkey(None)
                .active_recordings(&active_recordings)
                .disconnected_info(None)
                .build()
                .validate(&item.token);

            if is_revoked {
                let e = res
                    .err()
                    .with_context(|| format!("Item n°{idx} validation should have failed, but it didn't"))?;
                assert!(matches!(e, TokenError::Revoked), "Unexpected error kind: {e:?}");
            } else {
                res.with_context(|| format!("Item n°{idx} validation failed, but it wasn't expected to"))?;
            }
        }

        Ok(())
    };

    proptest!(ProptestConfig::with_cases(16), |(items in vec(revocable_item(now, &delegation_key_pub, &provisioner_key), 1..5))| {
        test_impl(items).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
    });
}

/// Assert that tokens can't be reused without any constaint
#[rstest]
fn token_cache(
    jrl: Mutex<JrlTokenClaims>,
    active_recordings: ActiveRecordings,
    provisioner_key: PrivateKey,
    delegation_key: PrivateKey,
    source_ip: IpAddr,
    source_ip_2: IpAddr,
    now: i64,
) {
    let provisioner_key_pub = provisioner_key.to_public_key().unwrap();
    let delegation_key_pub = delegation_key.to_public_key().unwrap();

    let test_impl = |same_ip: bool, claims: TokenClaims| -> anyhow::Result<()> {
        let token =
            CheckedJwtSig::new_with_cty(JwsAlg::RS256, claims.content_type(), &claims).encode(&provisioner_key)?;

        let token = if claims.should_encrypt() {
            jwe::Jwe::new(jwe::JweAlg::RsaOaep256, jwe::JweEnc::Aes256Gcm, token.into_bytes())
                .encode(&delegation_key_pub)?
        } else {
            token
        };

        let token_cache = new_token_cache();

        devolutions_gateway::token::TokenValidator::builder()
            .source_ip(source_ip)
            .provisioner_key(&provisioner_key_pub)
            .delegation_key(Some(&delegation_key))
            .token_cache(&token_cache)
            .revocation_list(&jrl)
            .gw_id(None)
            .subkey(None)
            .active_recordings(&active_recordings)
            .disconnected_info(None)
            .build()
            .validate(&token)?;

        let ip_when_reusing = if same_ip { source_ip } else { source_ip_2 };

        let res = devolutions_gateway::token::TokenValidator::builder()
            .source_ip(ip_when_reusing)
            .provisioner_key(&provisioner_key_pub)
            .delegation_key(Some(&delegation_key))
            .token_cache(&token_cache)
            .revocation_list(&jrl)
            .gw_id(None)
            .subkey(None)
            .active_recordings(&active_recordings)
            .disconnected_info(None)
            .build()
            .validate(&token);

        let can_reuse = matches!(claims, TokenClaims::Kdc(_))
            || matches!(claims, TokenClaims::Bridge(_))
            || same_ip
                && matches!(
                    claims,
                    TokenClaims::Association(AssociationClaims {
                        jet_ap: ApplicationProtocol::Known(Protocol::Rdp),
                        ..
                    })
                );

        if can_reuse {
            // RDP association tokens can be re-used if source IP is identical
            res?;
        } else {
            let e = res.err().context("validation should have failed")?;
            assert!(
                matches!(e, TokenError::UnexpectedReplay { .. }),
                "Unexpected error kind: {e:?}"
            );
        }

        Ok(())
    };

    proptest!(ProptestConfig::with_cases(64), |(same_ip in any::<bool>(), claims in any_claims(now).no_shrink())| {
        test_impl(same_ip, claims).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
    });
}

/// Randomly choose between the provided ID and a newly generated one
fn jet_gw_id(this_gw_id: Uuid) -> impl Strategy<Value = Option<Uuid>> {
    (option::of(uuid_typed()), any::<bool>()).prop_map(
        move |(other_id, is_this_gw_id)| {
            if is_this_gw_id { Some(this_gw_id) } else { other_id }
        },
    )
}

/// Assert that a token is refused if it doesn't conform to the scope rules:
/// - Gateway ID if `jet_gw_id` claim is present
/// - Content Type if `kid` header parameter is present and a subkey is used
/// - The validity duration is small enough when a subkey is used
#[rstest]
fn with_scopes(
    jrl: Mutex<JrlTokenClaims>,
    active_recordings: ActiveRecordings,
    provisioner_key: PrivateKey,
    delegation_key: PrivateKey,
    subkey: PrivateKey,
    subkey_kid: &str,
    source_ip: IpAddr,
    this_gw_id: Uuid,
    now: i64,
) {
    let provisioner_key_pub = provisioner_key.to_public_key().unwrap();
    let delegation_key_pub = delegation_key.to_public_key().unwrap();
    let subkey_pub = subkey.to_public_key().unwrap();
    let subkey_metadata = Subkey {
        data: subkey_pub,
        kid: subkey_kid.into(),
    };

    let test_impl = |jet_gw_id: Option<Uuid>, use_subkey: bool, claims: TokenClaims| -> anyhow::Result<()> {
        let should_succeed = match jet_gw_id {
            None => true,
            Some(id) if id == this_gw_id => true,
            _ => false,
        };

        let should_succeed = should_succeed
            && match (use_subkey, &claims) {
                (false, _) => true,
                (
                    true,
                    TokenClaims::Jmux(JmuxClaims { nbf, exp, .. })
                    | TokenClaims::Association(AssociationClaims { nbf, exp, .. })
                    | TokenClaims::Kdc(KdcClaims { nbf, exp, .. }),
                ) => exp - nbf <= MAX_SUBKEY_TOKEN_VALIDITY_DURATION_SECS,
                (true, _) => false,
            };

        let should_encrypt = claims.should_encrypt();

        let content_type = claims.content_type();

        let mut claims = serde_json::to_value(claims).unwrap();

        if let Some(id) = jet_gw_id {
            claims["jet_gw_id"] = serde_json::Value::String(id.to_string());
        }

        let mut token = CheckedJwtSig::new_with_cty(JwsAlg::RS256, content_type, &claims);

        let token = if use_subkey {
            token.header.kid = Some(subkey_metadata.kid.clone());
            token.encode(&subkey)?
        } else {
            token.encode(&provisioner_key)?
        };

        let token = if should_encrypt {
            jwe::Jwe::new(jwe::JweAlg::RsaOaep256, jwe::JweEnc::Aes256Gcm, token.into_bytes())
                .encode(&delegation_key_pub)?
        } else {
            token
        };

        let token_cache = new_token_cache();

        let result = devolutions_gateway::token::TokenValidator::builder()
            .source_ip(source_ip)
            .provisioner_key(&provisioner_key_pub)
            .delegation_key(Some(&delegation_key))
            .token_cache(&token_cache)
            .revocation_list(&jrl)
            .gw_id(Some(this_gw_id))
            .subkey(Some(&subkey_metadata))
            .active_recordings(&active_recordings)
            .disconnected_info(None)
            .build()
            .validate(&token);

        if should_succeed {
            result.context("failure was unexpected")?;
        } else {
            result.err().context("failure was expected")?;
        }

        Ok(())
    };

    proptest!(
        ProptestConfig::with_cases(64),
        |(scope_dw_id in jet_gw_id(this_gw_id), use_subkey in any::<bool>(), claims in any_claims(now).no_shrink())| {
            test_impl(scope_dw_id, use_subkey, claims).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        }
    );
}

fn subkey_compatible_claims(now: i64) -> impl Strategy<Value = TokenClaims> {
    (15..MAX_SUBKEY_TOKEN_VALIDITY_DURATION_SECS).prop_flat_map(move |validity_duration| {
        prop_oneof![
            any_jmux_claims(now, validity_duration).prop_map(TokenClaims::Jmux),
            any_association_claims(now, validity_duration).prop_map(TokenClaims::Association),
            any_kdc_claims(now, validity_duration).prop_map(TokenClaims::Kdc),
        ]
    })
}

/// Randomly choose between the provided kid and a newly generated one
fn kid(this_kid: &str) -> impl Strategy<Value = String> + '_ {
    ("[a-zA-Z]{5,15}".no_shrink(), any::<bool>()).prop_map(
        |(other_kid, use_this_kid)| {
            if use_this_kid { this_kid.to_owned() } else { other_kid }
        },
    )
}

/// Assert that tokens using a subkey are allowed if properly configured
#[rstest]
fn with_subkey(
    jrl: Mutex<JrlTokenClaims>,
    active_recordings: ActiveRecordings,
    provisioner_key: PrivateKey,
    delegation_key: PrivateKey,
    subkey: PrivateKey,
    subkey_kid: &str,
    source_ip: IpAddr,
    this_gw_id: Uuid,
    now: i64,
) {
    let provisioner_key_pub = provisioner_key.to_public_key().unwrap();
    let delegation_key_pub = delegation_key.to_public_key().unwrap();
    let subkey_pub = subkey.to_public_key().unwrap();
    let subkey_metadata = Subkey {
        data: subkey_pub,
        kid: subkey_kid.into(),
    };

    let test_impl = |kid: String, claims: TokenClaims| -> anyhow::Result<()> {
        let should_succeed = kid == subkey_metadata.kid;

        let should_encrypt = claims.should_encrypt();

        let content_type = claims.content_type();

        let mut token = CheckedJwtSig::new_with_cty(JwsAlg::RS256, content_type, &claims);
        token.header.kid = Some(kid);
        let token = token.encode(&subkey)?;

        let token = if should_encrypt {
            jwe::Jwe::new(jwe::JweAlg::RsaOaep256, jwe::JweEnc::Aes256Gcm, token.into_bytes())
                .encode(&delegation_key_pub)?
        } else {
            token
        };

        let token_cache = new_token_cache();

        let result = devolutions_gateway::token::TokenValidator::builder()
            .source_ip(source_ip)
            .provisioner_key(&provisioner_key_pub)
            .delegation_key(Some(&delegation_key))
            .token_cache(&token_cache)
            .revocation_list(&jrl)
            .gw_id(Some(this_gw_id))
            .subkey(Some(&subkey_metadata))
            .active_recordings(&active_recordings)
            .disconnected_info(None)
            .build()
            .validate(&token);

        if should_succeed {
            result.context("failure was unexpected")?;
        } else {
            result.err().context("failure was expected")?;
        }

        Ok(())
    };

    proptest!(
        ProptestConfig::with_cases(16),
        |(kid in kid(&subkey_metadata.kid), claims in subkey_compatible_claims(now).no_shrink())| {
            test_impl(kid, claims).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        }
    );
}
