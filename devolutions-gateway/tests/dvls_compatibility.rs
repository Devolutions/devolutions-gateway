use devolutions_gateway::token::{new_token_cache, CurrentJrl, JrlTokenClaims, TokenCache};
use devolutions_gateway_generators::*;
use parking_lot::Mutex;
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::CheckedJwtSig;
use picky::key::{PrivateKey, PublicKey};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};

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

/// This emulate a token validation on Gateway side using the provided claims
fn encode_decode_round_trip<C>(
    pub_key: &PublicKey,
    priv_key: &PrivateKey,
    claims: C,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> anyhow::Result<()>
where
    C: serde::ser::Serialize,
{
    // DVLS side
    let token = CheckedJwtSig::new(JwsAlg::RS256, claims).encode(priv_key)?;

    // Gateway side
    let source_ip = std::net::IpAddr::from([13u8, 12u8, 11u8, 10u8]);
    devolutions_gateway::token::validate_token(&token, source_ip, pub_key, None, token_cache, jrl)?;

    Ok(())
}

mod as_of_v2021_2_13_0 {
    use super::*;
    use chrono::{DateTime, Utc};
    use proptest::collection::vec;

    const TYPE_ASSOCIATION: &str = "association";
    const JET_CM: &str = "fwd";

    #[derive(Serialize, Debug)]
    struct DvlsAssociationClaims {
        #[serde(rename = "type")]
        ty: &'static str,
        jet_aid: String,
        jet_ap: String,
        jet_cm: &'static str,
        dst_hst: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        dst_alt: Vec<String>,
        nbf: i64,
        exp: i64,
    }

    prop_compose! {
        fn dvls_host()(host in "[a-z]{1,10}\\.[a-z]{1,5}(:[0-9]{3,4})?") -> String {
            host
        }
    }

    prop_compose! {
        fn dvls_application_protocol()(protocol in "(rdp|ssh)") -> String {
            protocol
        }
    }

    prop_compose! {
        fn dvls_alternate_hosts()(alternates in vec(dvls_host(), 0..4)) -> Vec<String> {
            alternates
        }
    }

    prop_compose! {
        fn dvls_association_claims(
            now: i64
        )(
            jet_aid in uuid_str(),
            jet_ap in dvls_application_protocol(),
            dst_hst in dvls_host(),
            dst_alt in dvls_alternate_hosts(),
        ) -> DvlsAssociationClaims {
            DvlsAssociationClaims {
                ty: TYPE_ASSOCIATION,
                jet_aid,
                jet_ap,
                jet_cm: JET_CM,
                dst_hst,
                dst_alt,
                nbf: now,
                exp: now + 1000,
            }
        }
    }

    /// Make sure current Gateway is able to validate association tokens provided by DVLS
    #[test]
    fn association_token_validation() {
        let token_cache = new_token_cache();
        let jrl = Mutex::new(JrlTokenClaims::default());
        let priv_key = PrivateKey::from_pem_str(KEY).unwrap();
        let pub_key = priv_key.to_public_key();
        let now = chrono::Utc::now().timestamp();
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_association_claims(now).no_shrink())| {
            encode_decode_round_trip(&pub_key, &priv_key, claims, &token_cache, &jrl).map_err(|e| TestCaseError::fail(format!("{:#}", e)))?;
        });
    }

    /// DVLS is roughly deserializing using this model (except everything is in C#)
    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct DvlsSessionInfo {
        association_id: String,
        application_protocol: String,
        recording_policy: bool,
        filtering_policy: bool,
        connection_mode: String,
        destination_host: String,
        start_timestamp: DateTime<Utc>,
    }

    /// Make sure current Gateway is serializing the session info structure in a way that is understood by DVLS
    ///
    /// NOTE: as of DVLS v2021.2.13.0, only forward sessions are created.
    #[test]
    fn session_info_serialization() {
        proptest!(|(
            info in session_info_fwd_only(),
        )| {
            let serialized = serde_json::to_string(&info)?;
            serde_json::from_str::<DvlsSessionInfo>(&serialized)?;
        })
    }
}

mod as_of_v2021_2_4 {
    use super::*;

    const TYPE_SCOPE: &str = "scope";

    #[derive(Debug, Serialize)]
    struct DvlsScopeClaims {
        #[serde(rename = "type")]
        ty: &'static str,
        scope: String,
        nbf: i64,
        exp: i64,
    }

    prop_compose! {
        fn dvls_access_scope()(scope in "(gateway\\.sessions\\.read|gateway\\.associations\\.read|gateway\\.diagnostics\\.read)") -> String {
            scope
        }
    }

    prop_compose! {
        fn dvls_scope_claims(now: i64)(
            scope in dvls_access_scope(),
        ) -> DvlsScopeClaims {
            DvlsScopeClaims {
                ty: TYPE_SCOPE,
                scope,
                nbf: now,
                exp: now + 1000,
            }
        }
    }

    /// Make sure current Gateway is able to validate scope tokens provided by DVLS
    #[test]
    fn scope_token_validation() {
        let token_cache = new_token_cache();
        let jrl = Mutex::new(JrlTokenClaims::default());
        let priv_key = PrivateKey::from_pem_str(KEY).unwrap();
        let pub_key = priv_key.to_public_key();
        let now = chrono::Utc::now().timestamp();
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_scope_claims(now).no_shrink())| {
            encode_decode_round_trip(&pub_key, &priv_key, claims, &token_cache, &jrl).map_err(|e| TestCaseError::fail(format!("{:#}", e)))?;
        });
    }
}

mod as_of_v2021_1_7_0 {
    use super::*;

    const JET_CM: &str = "fwd";
    const JET_AP: &str = "rdp";

    #[derive(Serialize, Debug)]
    struct DvlsAssociationClaims {
        jet_ap: &'static str,
        jet_cm: &'static str,
        dst_hst: String,
        nbf: i64,
        exp: i64,
    }

    prop_compose! {
        fn dvls_host()(host in "[a-z]{1,10}\\.[a-z]{1,5}:[0-9]{3,4}") -> String {
            host
        }
    }

    prop_compose! {
        fn dvls_association_claims(
            now: i64
        )(
            dst_hst in dvls_host(),
        ) -> DvlsAssociationClaims {
            DvlsAssociationClaims {
                jet_ap: JET_AP,
                jet_cm: JET_CM,
                dst_hst,
                nbf: now,
                exp: now + 1000,
            }
        }
    }

    /// Make sure current Gateway is able to validate association tokens provided by DVLS
    #[test]
    fn association_token_validation() {
        let token_cache = new_token_cache();
        let jrl = Mutex::new(JrlTokenClaims::default());
        let priv_key = PrivateKey::from_pem_str(KEY).unwrap();
        let pub_key = priv_key.to_public_key();
        let now = chrono::Utc::now().timestamp();
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_association_claims(now).no_shrink())| {
            encode_decode_round_trip(&pub_key, &priv_key, claims, &token_cache, &jrl).map_err(|e| TestCaseError::fail(format!("{:#}", e)))?;
        });
    }
}
