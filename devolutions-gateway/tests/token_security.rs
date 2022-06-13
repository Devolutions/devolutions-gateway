use anyhow::Context as _;
use devolutions_gateway::token::{new_token_cache, ApplicationProtocol, JrlTokenClaims, Protocol};
use devolutions_gateway_generators::*;
use parking_lot::Mutex;
use picky::jose::jwe;
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::CheckedJwtSig;
use picky::key::{PrivateKey, PublicKey};
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use std::net::IpAddr;

const KEY: &str = r#"-----BEGIN PRIVATE KEY-----
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

#[derive(Debug, Clone)]
struct RevocableItem {
    claim_to_revoke: Option<(String, serde_json::Value)>,
    claims: serde_json::Value,
    token: String,
}

fn revocable_item<'a>(
    now: i64,
    pub_key: &'a PublicKey,
    priv_key: &'a PrivateKey,
) -> impl Strategy<Value = RevocableItem> + 'a {
    any_association_claims(now)
        .prop_flat_map(move |claims| {
            let mut token = CheckedJwtSig::new(JwsAlg::RS256, &claims);
            token.header.cty = Some("ASSOCIATION".to_owned());
            let token = token.encode(&priv_key).unwrap();
            let token = if matches!(claims.jet_cm, ConnectionMode::Fwd { creds: Some(_), .. }) {
                jwe::Jwe::new(jwe::JweAlg::RsaOaep256, jwe::JweEnc::Aes256Gcm, token.into_bytes())
                    .encode(&pub_key)
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

#[test]
fn revocation_list() {
    let priv_key = PrivateKey::from_pem_str(KEY).unwrap();
    let pub_key = priv_key.to_public_key();
    let source_ip = IpAddr::from([13u8, 12u8, 11u8, 10u8]);
    let now = chrono::Utc::now().timestamp();

    let test_impl = |items: Vec<RevocableItem>| -> anyhow::Result<()> {
        // Make sure all tokens are valid before any revocation

        let empty_jrl = Mutex::new(JrlTokenClaims::default());
        let token_cache = new_token_cache();

        for (idx, item) in items.iter().enumerate() {
            devolutions_gateway::token::validate_token(
                &item.token,
                source_ip,
                &pub_key,
                Some(&priv_key),
                &token_cache,
                &empty_jrl,
            )
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
                        .any(|(key, revoked_values)| match item.claims.get(key) {
                            Some(token_value) if revoked_values.contains(token_value) => true,
                            _ => false,
                        });
                    (item, is_revoked)
                }
            })
            .collect();

        // Validate that only revoked tokens are refused

        let updated_jrl = Mutex::new(updated_jrl);
        let token_cache = new_token_cache();

        for (idx, (item, is_revoked)) in items.into_iter().enumerate() {
            let res = devolutions_gateway::token::validate_token(
                &item.token,
                source_ip,
                &pub_key,
                Some(&priv_key),
                &token_cache,
                &updated_jrl,
            );

            if is_revoked {
                let e = res
                    .err()
                    .with_context(|| format!("Item n°{idx} validation should have failed, but it didn't"))?;
                assert!(e.to_string().contains("Received a token containing a revoked value"));
            } else {
                res.with_context(|| format!("Item n°{idx} validation failed, but it wasn't expected to"))?;
            }
        }

        Ok(())
    };

    proptest!(ProptestConfig::with_cases(16), |(items in vec(revocable_item(now, &pub_key, &priv_key), 1..5))| {
        test_impl(items).map_err(|e| TestCaseError::fail(format!("{:#}", e)))?;
    });
}

#[test]
fn token_cache() {
    let jrl = Mutex::new(JrlTokenClaims::default());
    let priv_key = PrivateKey::from_pem_str(KEY).unwrap();
    let pub_key = priv_key.to_public_key();
    let source_ip = IpAddr::from([13u8, 12u8, 11u8, 10u8]);
    let source_ip_2 = IpAddr::from([15u8, 12u8, 11u8, 10u8]);
    let now = chrono::Utc::now().timestamp();

    let test_impl = |same_ip: bool, claims: AssociationClaims| -> anyhow::Result<()> {
        let mut token = CheckedJwtSig::new(JwsAlg::RS256, &claims);
        token.header.cty = Some("ASSOCIATION".to_owned());
        let token = token.encode(&priv_key)?;
        let token = if matches!(claims.jet_cm, ConnectionMode::Fwd { creds: Some(_), .. }) {
            jwe::Jwe::new(jwe::JweAlg::RsaOaep256, jwe::JweEnc::Aes256Gcm, token.into_bytes()).encode(&pub_key)?
        } else {
            token
        };

        let token_cache = new_token_cache();

        devolutions_gateway::token::validate_token(&token, source_ip, &pub_key, Some(&priv_key), &token_cache, &jrl)?;

        let ip_when_reusing = if same_ip { source_ip } else { source_ip_2 };

        let res = devolutions_gateway::token::validate_token(
            &token,
            ip_when_reusing,
            &pub_key,
            Some(&priv_key),
            &token_cache,
            &jrl,
        );

        if same_ip && matches!(claims.jet_ap, ApplicationProtocol::Known(Protocol::Rdp)) {
            // RDP association tokens can be re-used if source IP is identical
            res?;
        } else {
            let e = res.err().context("validation should have failed")?;
            assert!(e.to_string().contains("Received identical token twice"));
        }

        Ok(())
    };

    proptest!(ProptestConfig::with_cases(32), |(same_ip in any::<bool>(), claims in any_association_claims(now).no_shrink())| {
        test_impl(same_ip, claims).map_err(|e| TestCaseError::fail(format!("{:#}", e)))?;
    });
}
