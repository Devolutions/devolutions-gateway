#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use devolutions_gateway::recording::ActiveRecordings;
use devolutions_gateway::token::{CurrentJrl, JrlTokenClaims, TokenCache};
use devolutions_gateway_generators::*;
use parking_lot::Mutex;
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::CheckedJwtSig;
use picky::key::{PrivateKey, PublicKey};
use proptest::prelude::*;
use rstest::{fixture, rstest};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
#[allow(clippy::too_many_arguments)] // not an API boundary, and local uses only
fn encode_decode_round_trip<C>(
    pub_key: &PublicKey,
    priv_key: &PrivateKey,
    claims: C,
    cty: Option<String>,
    gw_id: Option<Uuid>,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    active_recordings: &ActiveRecordings,
) -> anyhow::Result<()>
where
    C: Serialize,
{
    // DVLS side
    let mut token = CheckedJwtSig::new(JwsAlg::RS256, claims);
    if let Some(cty) = cty {
        token.header.cty = Some(cty);
    }
    let token = token.encode(priv_key)?;

    // Gateway side
    devolutions_gateway::token::TokenValidator::builder()
        .source_ip(std::net::IpAddr::from([13u8, 12u8, 11u8, 10u8]))
        .provisioner_key(pub_key)
        .delegation_key(None)
        .token_cache(token_cache)
        .revocation_list(jrl)
        .gw_id(gw_id)
        .subkey(None)
        .active_recordings(active_recordings)
        .disconnected_info(None)
        .build()
        .validate(&token)?;

    Ok(())
}

#[fixture]
fn token_cache() -> TokenCache {
    devolutions_gateway::token::new_token_cache()
}

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
fn priv_key() -> PrivateKey {
    PrivateKey::from_pem_str(KEY).unwrap()
}

#[fixture]
fn pub_key() -> PublicKey {
    priv_key().to_public_key().unwrap()
}

#[fixture]
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

mod as_of_v2025_2_6_0 {
    use super::*;

    #[rstest]
    #[case::jmux(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpNVVgifQ.eyJkc3RfYWRkbCI6WyJodHRwczovL2xvY2FsaG9zdDo0NDMiLCJodHRwOi8vd3d3LmxvY2FsaG9zdDo4ODAwIiwiaHR0cHM6Ly93d3cubG9jYWxob3N0OjQ0MyJdLCJkc3RfaHN0IjoiaHR0cDovL2xvY2FsaG9zdDo4ODAwIiwiZXhwIjoxNzUzNjU4NDgxLCJpYXQiOjE3NTM2NTgxODEsImpldF9haWQiOiIyYzNjOGI4ZC0wZThlLTQwMGItYWVmMy1mM2U4ZjFhN2EzOTQiLCJqZXRfYXAiOiJodHRwIiwiamV0X2d3X2lkIjoiZGU0ZDMyODUtMjUzOS00NjhkLThlMmEtMTc1OWVjMDQyYTM3IiwianRpIjoiYTk3NWI4OGMtOGU5My00N2JkLThkNDQtY2QwZGI2YzViNGNmIiwibmJmIjoxNzUzNjU4MTgxfQ.g9yKXuH-A_oRlPaS6xcKddnzQZZ4XTnSFd_pzN-pPzbLAuxOpNyzkhOfSUEkday0Uh3Z2TQ2KxAnkG7zjvO6dKecv4xUamiU8gItuzhgHTzQQBqNsiu-t4rHvG1Ad83cXDzcuGMXiYHAxq4zqPrUN2atzkzXlF6eoG3mNQw8kNGrTCWWyAZgU1_Sjwuyd-MRATNdZt0cy3Awj6dMPCdGR3_oBTnLhPyqIAzfh_56bpUVlayy8u3HBFZo5Wj8uX8dbgN0izna-idvR85rWKqyBLpZUgeEctrk4UnM6Cz9kwCIxtQI5jTmi-U7UIGfggcbmyRWkoWvxr2tnBIPxSZDkA"
    )]
    fn samples(#[case] sample: &str) {
        #[allow(deprecated)]
        devolutions_gateway::token::unsafe_debug::dangerous_validate_token(sample, None).unwrap();
    }
}

mod as_of_v2022_3_0_0 {
    use proptest::collection::vec;

    use super::*;

    const CTY_JMUX: &str = "JMUX";
    const CTY_ASSOCIATION: &str = "ASSOCIATION";
    const CTY_KDC: &str = "KDC";
    const CTY_JRL: &str = "JRL";
    const CTY_SCOPE: &str = "SCOPE";

    const TYPE_SCOPE: &str = "scope";
    const TYPE_ASSOCIATION: &str = "association";

    const JET_CM: &str = "fwd";

    #[derive(Debug, Serialize)]
    struct DvlsScopeClaims {
        #[serde(rename = "type")]
        ty: &'static str,
        jet_gw_id: Uuid,
        scope: DvlsAccessScope,
        nbf: i64,
        exp: i64,
        jti: Uuid,
    }

    #[derive(Clone, Debug, Serialize)]
    pub(crate) enum DvlsAccessScope {
        #[serde(rename = "gateway.sessions.read")]
        SessionsRead,
        #[serde(rename = "gateway.session.terminate")]
        SessionTerminate,
        #[serde(rename = "gateway.associations.read")]
        AssociationsRead,
        #[serde(rename = "gateway.diagnostics.read")]
        DiagnosticsRead,
        #[serde(rename = "gateway.jrl.read")]
        JrlRead,
        #[serde(rename = "gateway.config.write")]
        ConfigWrite,
    }

    fn dvls_access_scope() -> impl Strategy<Value = DvlsAccessScope> {
        prop_oneof![
            Just(DvlsAccessScope::SessionsRead),
            Just(DvlsAccessScope::SessionTerminate),
            Just(DvlsAccessScope::AssociationsRead),
            Just(DvlsAccessScope::DiagnosticsRead),
            Just(DvlsAccessScope::JrlRead),
            Just(DvlsAccessScope::ConfigWrite),
            Just(DvlsAccessScope::ConfigWrite),
        ]
    }

    fn dvls_scope_claims(now: i64) -> impl Strategy<Value = DvlsScopeClaims> {
        (dvls_access_scope(), uuid_typed(), uuid_typed()).prop_map(move |(scope, jet_gw_id, jti)| DvlsScopeClaims {
            ty: TYPE_SCOPE,
            jet_gw_id,
            scope,
            nbf: now,
            exp: now + 1000,
            jti,
        })
    }

    /// Make sure current Gateway is able to validate scope tokens provided by DVLS
    #[rstest]
    fn scope_token_validation(
        token_cache: TokenCache,
        jrl: Mutex<JrlTokenClaims>,
        active_recordings: ActiveRecordings,
        priv_key: PrivateKey,
        pub_key: PublicKey,
        now: i64,
    ) {
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_scope_claims(now).no_shrink())| {
            let jet_gw_id = claims.jet_gw_id;
            encode_decode_round_trip(
                &pub_key,
                &priv_key,
                claims,
                Some(CTY_SCOPE.to_owned()),
                Some(jet_gw_id),
                &token_cache,
                &jrl,
                &active_recordings,
            ).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        });
    }

    #[derive(Serialize, Debug)]
    struct DvlsAssociationClaims {
        #[serde(rename = "type")]
        ty: &'static str,
        jet_aid: Uuid,
        jet_ap: String,
        jet_cm: &'static str,
        jet_gw_id: Uuid,
        dst_hst: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        dst_alt: Vec<String>,
        nbf: i64,
        exp: i64,
        jti: Uuid,
    }

    fn dvls_host() -> impl Strategy<Value = String> {
        "[a-z]{1,10}\\.[a-z]{1,5}(:[0-9]{3,4})?"
    }

    fn dvls_application_protocol_assoc() -> impl Strategy<Value = String> {
        "(rdp|ssh|ssh-pwsh|sftp|scp|ard|vnc)"
    }

    fn dvls_alternate_hosts() -> impl Strategy<Value = Vec<String>> {
        vec(dvls_host(), 0..4)
    }

    prop_compose! {
        fn dvls_association_claims(
            now: i64
        )(
            jet_aid in uuid_typed(),
            jet_ap in dvls_application_protocol_assoc(),
            jet_gw_id in uuid_typed(),
            dst_hst in dvls_host(),
            dst_alt in dvls_alternate_hosts(),
            jti in uuid_typed(),
        ) -> DvlsAssociationClaims {
            DvlsAssociationClaims {
                ty: TYPE_ASSOCIATION,
                jet_aid,
                jet_ap,
                jet_cm: JET_CM,
                jet_gw_id,
                dst_hst,
                dst_alt,
                nbf: now,
                exp: now + 1000,
                jti,
            }
        }
    }

    /// Make sure current Gateway is able to validate association tokens provided by DVLS
    #[rstest]
    fn association_token_validation(
        token_cache: TokenCache,
        jrl: Mutex<JrlTokenClaims>,
        active_recordings: ActiveRecordings,
        priv_key: PrivateKey,
        pub_key: PublicKey,
        now: i64,
    ) {
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_association_claims(now).no_shrink())| {
            let jet_gw_id = claims.jet_gw_id;
            encode_decode_round_trip(
                &pub_key,
                &priv_key,
                claims,
                Some(CTY_ASSOCIATION.to_owned()),
                Some(jet_gw_id),
                &token_cache,
                &jrl,
                &active_recordings,
            ).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        });
    }

    #[derive(Serialize, Debug)]
    struct DvlsJmuxClaims {
        dst_hst: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        dst_addl: Vec<String>,
        jet_ap: String,
        jet_aid: Uuid,
        jet_gw_id: Uuid,
        nbf: i64,
        exp: i64,
        jti: Uuid,
    }

    fn dvls_application_protocol_jmux() -> impl Strategy<Value = String> {
        "(winrm-http-pwsh|winrm-https-pwsh|http|https)"
    }

    prop_compose! {
        fn dvls_jmux_claims(
            now: i64
        )(
            jet_aid in uuid_typed(),
            jet_ap in dvls_application_protocol_jmux(),
            jet_gw_id in uuid_typed(),
            dst_hst in dvls_host(),
            dst_addl in dvls_alternate_hosts(),
            jti in uuid_typed(),
        ) -> DvlsJmuxClaims {
            DvlsJmuxClaims {
                dst_hst,
                dst_addl,
                jet_ap,
                jet_aid,
                jet_gw_id,
                nbf: now,
                exp: now + 1000,
                jti,
            }
        }
    }

    /// Make sure current Gateway is able to validate JMUX tokens provided by DVLS
    #[rstest]
    fn jmux_token_validation(
        token_cache: TokenCache,
        jrl: Mutex<JrlTokenClaims>,
        active_recordings: ActiveRecordings,
        priv_key: PrivateKey,
        pub_key: PublicKey,
        now: i64,
    ) {
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_jmux_claims(now).no_shrink())| {
            let jet_gw_id = claims.jet_gw_id;
            encode_decode_round_trip(
                &pub_key,
                &priv_key,
                claims,
                Some(CTY_JMUX.to_owned()),
                Some(jet_gw_id),
                &token_cache,
                &jrl,
                &active_recordings,
            ).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        });
    }

    #[derive(Serialize, Debug)]
    struct DvlsKdcClaims {
        krb_kdc: String,
        krb_realm: String,
        jet_gw_id: Uuid,
        nbf: i64,
        exp: i64,
        jti: Uuid,
    }

    fn dvls_krb_realm() -> impl Strategy<Value = String> {
        "([a-z]{2,5}\\.){0,5}[a-z]{1,3}"
    }

    fn dvls_krb_kdc() -> impl Strategy<Value = String> {
        "(tcp://|udp://)?(?-u:(\\w{2,5}\\.){0,5}\\w{1,3})(:[0-9]{1,4})?"
    }

    prop_compose! {
        fn dvls_kdc_claims(
            now: i64
        )(
            krb_kdc in dvls_krb_kdc(),
            krb_realm in dvls_krb_realm(),
            jet_gw_id in uuid_typed(),
            jti in uuid_typed(),
        ) -> DvlsKdcClaims {
            DvlsKdcClaims {
                krb_kdc,
                krb_realm,
                jet_gw_id,
                nbf: now,
                exp: now + 1000,
                jti,
            }
        }
    }

    #[rstest]
    fn kdc_token_validation(
        token_cache: TokenCache,
        jrl: Mutex<JrlTokenClaims>,
        active_recordings: ActiveRecordings,
        priv_key: PrivateKey,
        pub_key: PublicKey,
        now: i64,
    ) {
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_kdc_claims(now).no_shrink())| {
            let jet_gw_id = claims.jet_gw_id;
            encode_decode_round_trip(
                &pub_key,
                &priv_key,
                claims,
                Some(CTY_KDC.to_owned()),
                Some(jet_gw_id),
                &token_cache,
                &jrl,
                &active_recordings,
            ).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        });
    }

    #[derive(Serialize, Debug)]
    struct DvlsJrlClaims {
        jrl: DvlsJrl,
        jet_gw_id: Uuid,
        iat: i64,
        jti: Uuid,
    }

    prop_compose! {
        fn dvls_jrl_claims(
            now: i64
        )(
            jrl in dvls_jrl(),
            jet_gw_id in uuid_typed(),
            jti in uuid_typed(),
        ) -> DvlsJrlClaims {
            DvlsJrlClaims {
                jrl,
                jet_gw_id,
                iat: now,
                jti,
            }
        }
    }

    #[derive(Serialize, Debug)]
    struct DvlsJrl {
        jti: Vec<String>,
    }

    fn dvls_jrl() -> impl Strategy<Value = DvlsJrl> {
        vec(uuid_str(), 0..3).prop_map(|jti| DvlsJrl { jti })
    }

    #[rstest]
    fn jrl_token_validation(
        token_cache: TokenCache,
        jrl: Mutex<JrlTokenClaims>,
        active_recordings: ActiveRecordings,
        priv_key: PrivateKey,
        pub_key: PublicKey,
        now: i64,
    ) {
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_jrl_claims(now).no_shrink())| {
            let jet_gw_id = claims.jet_gw_id;
            encode_decode_round_trip(
                &pub_key,
                &priv_key,
                claims,
                Some(CTY_JRL.to_owned()),
                Some(jet_gw_id),
                &token_cache,
                &jrl,
                &active_recordings,
            ).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        });
    }

    #[rstest]
    #[case::assoc_vnc(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0.eyJuYmYiOjE2NjYxMjk2NjQsImV4cCI6MTY2NjEyOTk2NCwiaWF0IjoxNjY2MTI5NjY0LCJ0eXBlIjoiYXNzb2NpYXRpb24iLCJqZXRfYXAiOiJ2bmMiLCJqZXRfY20iOiJmd2QiLCJkc3RfaHN0IjoiMTI3LjAuMC4xOjU5MDAiLCJqZXRfYWlkIjoiNDIzZmU3MGQtNDcxOS00YTU0LTg3NTItZTAwNDY0ZjE3NDhjIiwianRpIjoiZTE2NTk3ZWMtM2NmNi00Mzk0LTlhYTMtMDRkMzBjNDY1MTY0IiwiamV0X2d3X2lkIjoiYjhhMWEwNjQtMTk4NS00ZDc5LWIwYzQtOWFjMTFiM2U4NGUxIn0.whUS7l8xJ6zvjrZBD2Tu1zEI84oMRdFnwivhLkwIr9qDygpKmZsMZnSZSNv4BC3rs2Le3VjDiUEc-rWkwQJWba5WSE6LLZdufJUVJ-S0XzjVMsqP8zc6VQJLx2j86fnivedYQsfwCjK4w8zcj8Fy2dd4lyjWTq-sAKfSftMwJ2Ic_uchwdDnMZdUTmG2y6h6gCpAZSkValr-LUbj4tsj08CnWOkh1fBRmRwhMoE14dB9QQ76oPiY1CbtzqPvah8ogwd66iHctamn5UwpgvlUyzfle3EHaCVlw14Q6x1c8j4s74L_CAycI6Npk61X1vx1k6GNU2wGmo3m00tGcFH8eA"
    )]
    #[case::assoc_ssh(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0.eyJuYmYiOjE2NjYxMjk3NDQsImV4cCI6MTY2NjEzMDA0NCwiaWF0IjoxNjY2MTI5NzQ0LCJ0eXBlIjoiYXNzb2NpYXRpb24iLCJqZXRfYXAiOiJzc2giLCJqZXRfY20iOiJmd2QiLCJkc3RfaHN0IjoiMTAuMTAuMC4yOjIyIiwiamV0X2FpZCI6IjBjNzdlZDM2LTljODEtNGE2Mi1iZDViLTVmMzNiMjM5NmRkNCIsImp0aSI6ImUyYmU3Y2U5LTc3YTQtNGYzNi04YmFlLTM0N2UyYmY2Mjk5MCIsImpldF9nd19pZCI6ImI4YTFhMDY0LTE5ODUtNGQ3OS1iMGM0LTlhYzExYjNlODRlMSJ9.sbZtiJMamnslZScOwl1jeHcGwkYGk_L-un-mveimo3gikfFRJ-_coWd4tT9HIWpahGVzjRyuSWTUBgCSM6Ho6K4AtfFuoISYIRDW_mT-MqM3tUVV0Ro4nMId4hze8jh6e0swxxjP6Ln7vKs15FEEcxH82Tk42qWmFxBafqI229RQzTPFsVCOd_nRwDRZcf9WMrTvJw89A0i-DpAko7QqVyYnFQvPjX3I0ZhvDck6BvESf2LkW5iVNp1BbNtLOazQgEoGoSnHiTO-YglW_t2OyLHnZRJ82jT0hdlRXSEFsp4GTK11XAh_NqSTR3fiKuFkOUfT8zP5r7doiF1dpJ0_bA"
    )]
    #[case::jrl(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpSTCJ9.eyJqcmwiOnsianRpIjpbXX0sImp0aSI6IjliYTdmNmI2LWUwYzYtNDhkMC05MGU1LWFkMWUzMmIwZTFmNCIsImlhdCI6MTY2NjEyOTg0MCwiamV0X2d3X2lkIjoiYjhhMWEwNjQtMTk4NS00ZDc5LWIwYzQtOWFjMTFiM2U4NGUxIn0.v14JZ6eM2yk0iJ56ZOjPhkPFW-KklBxKbmohjZS_EfXr6Wmgfz-vQZ5xOxb9ZNRt545IH7135-1e5xw4tLmyj3VajeJ890viEVetdOzU4-bh4vPfQHcsN6Wf__eFPd_O4bNVIbFi_b1oNVNSRUd51jb5-5w_PVHzUgSMDNUZoW1OgIiHlzr45Z0MLPjlyfn2zbrqgIWE2LlYV3gIxOny4Z_LMNI8dqzrPSm8s7F6vNb7fq4m9RVVuoaZ8J327ZXq-SnRUGmFzFJlVtmGTm--51MAKEi_pmk8f9KwYCtw_2cA3rTHslO4mfyActVPbISvm4oECJYETVO-4btAsNdzmg"
    )]
    #[case::scope(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlNDT1BFIn0.eyJuYmYiOjE2NjYxMjk4OTQsImV4cCI6MTY2NjEzMDE5NCwiaWF0IjoxNjY2MTI5ODk0LCJ0eXBlIjoic2NvcGUiLCJzY29wZSI6ImdhdGV3YXkuZGlhZ25vc3RpY3MucmVhZCIsImp0aSI6ImY3NGQ0ZWViLTBjMGYtNDYzNi05OGZhLWYzNDQ5YzhlZTA4MyIsImpldF9nd19pZCI6ImI4YTFhMDY0LTE5ODUtNGQ3OS1iMGM0LTlhYzExYjNlODRlMSJ9.tsM8h5fnVMxszpkjHQdsVZFZInUtCcLyPdlFewiit_9rPLJV7H_vhqKKDWZbqzOAyO5r5cuR3guT9b8gqD5kEn8NOG58ItBh4MDWKwHB0n8GOUZ-ZeWBAqV-LkOYj--3nhW2vuqXifFbQJUIuDvY1_9VTFej-XR2N-zns8i2nbMJL1JjA-mF7sFbeCZE4Nc-d221bu0DHbchdDKDFMoBKXZ6PT301jjpnD_exRVY1MlZYPC2Xh3IcwDO0JXqOMjvi8feEpdgDX3khEjvN63O8cPF7Hw6RV3PULyBQcEreo-mntMFkCoHv1mOO4M56ssLx99nI4PfhRkLwZfBESYhuA"
    )]
    #[case::jmux(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpNVVgifQ.eyJuYmYiOjE2NjYxMjk3OTksImV4cCI6MTY2NjEzMDA5OSwiaWF0IjoxNjY2MTI5Nzk5LCJkc3RfaHN0IjoiaHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTo0NDMiLCJqZXRfYXAiOiJodHRwcyIsImpldF9haWQiOiJlNDA3ZGIyMy1lNWUyLTQwOTMtYTRlOC02OTVlMmQyMjc3YmIiLCJqdGkiOiJmMjJhYjcwNi0yM2UyLTQwZGUtOTU3NC1iNWZiYzczZTRkYmMiLCJqZXRfZ3dfaWQiOiJiOGExYTA2NC0xOTg1LTRkNzktYjBjNC05YWMxMWIzZTg0ZTEifQ.Onvt9g_pquwMGfbJUng0xF_7bfh6aj_-Q_32snHVpPQJvwVTsy6J9ftq4emhlpBbk7NRdZkLh2WNzLNZKcPGD0_lC1D5NKTqHbwoWUcRWfFvedacecvnGcNx6DXZRT3iyBF9EgqMVYiEI1KsuGDCd4scL76JeR9WIBI2Nt3TWS93GcxkGZX_5JsgyyJD0toy78YcrcWpq7SW58JqpH12FBXcUU_D_WWoHF1UvbHQg9oPvcBXuHRY5EviO_dYrsiQqVLTDtbvJL8v0G1jtGLLsVm6S4pTaPxVMnaqi7Rmxbz7ADRkAhrzFnBprHQhn7CW1zTe3lrZCvgV3YB7dJiWug"
    )]
    fn samples(#[case] sample: &str) {
        #[allow(deprecated)]
        devolutions_gateway::token::unsafe_debug::dangerous_validate_token(sample, None).unwrap();
    }
}

mod as_of_v2022_2_0_0 {
    use proptest::collection::vec;

    use super::*;

    const CTY_JMUX: &str = "JMUX";
    const CTY_ASSOCIATION: &str = "ASSOCIATION";
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
        jti: Uuid,
    }

    fn dvls_host() -> impl Strategy<Value = String> {
        "[a-z]{1,10}\\.[a-z]{1,5}(:[0-9]{3,4})?"
    }

    fn dvls_application_protocol_assoc() -> impl Strategy<Value = String> {
        "(rdp|ssh|ssh-pwsh|sftp|scp|ard|vnc)"
    }

    fn dvls_alternate_hosts() -> impl Strategy<Value = Vec<String>> {
        vec(dvls_host(), 0..4)
    }

    prop_compose! {
        fn dvls_association_claims(
            now: i64
        )(
            jet_aid in uuid_str(),
            jet_ap in dvls_application_protocol_assoc(),
            dst_hst in dvls_host(),
            dst_alt in dvls_alternate_hosts(),
            jti in uuid_typed(),
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
                jti,
            }
        }
    }

    /// Make sure current Gateway is able to validate association tokens provided by DVLS
    #[rstest]
    fn association_token_validation(
        token_cache: TokenCache,
        jrl: Mutex<JrlTokenClaims>,
        active_recordings: ActiveRecordings,
        priv_key: PrivateKey,
        pub_key: PublicKey,
        now: i64,
    ) {
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_association_claims(now).no_shrink())| {
            encode_decode_round_trip(
                &pub_key,
                &priv_key,
                claims,
                Some(CTY_ASSOCIATION.to_owned()),
                None,
                &token_cache,
                &jrl,
                &active_recordings,
            ).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        });
    }

    #[derive(Serialize, Debug)]
    struct DvlsJmuxClaims {
        dst_hst: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        dst_addl: Vec<String>,
        jet_ap: String,
        jet_aid: String,
        nbf: i64,
        exp: i64,
        jti: Uuid,
    }

    fn dvls_application_protocol_jmux() -> impl Strategy<Value = String> {
        "(winrm-http-pwsh|winrm-https-pwsh|http|https)"
    }

    prop_compose! {
        fn dvls_jmux_claims(
            now: i64
        )(
            jet_aid in uuid_str(),
            jet_ap in dvls_application_protocol_jmux(),
            dst_hst in dvls_host(),
            dst_addl in dvls_alternate_hosts(),
            jti in uuid_typed(),
        ) -> DvlsJmuxClaims {
            DvlsJmuxClaims {
                dst_hst,
                dst_addl,
                jet_ap,
                jet_aid,
                nbf: now,
                exp: now + 1000,
                jti,
            }
        }
    }

    /// Make sure current Gateway is able to validate JMUX tokens provided by DVLS
    #[rstest]
    fn jmux_token_validation(
        token_cache: TokenCache,
        jrl: Mutex<JrlTokenClaims>,
        active_recordings: ActiveRecordings,
        priv_key: PrivateKey,
        pub_key: PublicKey,
        now: i64,
    ) {
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_jmux_claims(now).no_shrink())| {
            encode_decode_round_trip(
                &pub_key,
                &priv_key,
                claims,
                Some(CTY_JMUX.to_owned()),
                None,
                &token_cache,
                &jrl,
                &active_recordings,
            ).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        });
    }

    #[rstest]
    #[case::assoc(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0.eyJuYmYiOjE2NTA0MDM2NzIsImV4cCI6MTY1MDQwMzk3MiwiaWF0IjoxNjUwNDAzNjcyLCJ0eXBlIjoiYXNzb2NpYXRpb24iLCJqZXRfYXAiOiJzc2giLCJqZXRfY20iOiJmd2QiLCJkc3RfaHN0IjoiMTI4LjEyOC4xMjguMTgyOjIyIiwiamV0X2FpZCI6ImQwMWMwOWQ0LTc2NjItNDdlZS1hNzBkLWJmNDlkMDVlZDI2ZSIsImp0aSI6IjQzZWEyN2Y3LTk3NGEtNDVjZC1iMjdiLWI4OGQ3N2QzMzc4NCJ9.QLW4cjLj8hAz3iX5mNKXZtUXA0MaEfbrCbt8to2Ptqqv2iJSArTtCqvXCTnqpwKPKsHx25-2E8xHHfrXVrqLOZcwag-jECLNDggpwtHgm6YM4wZ44Rzh15hWjHUPi1ZwGmuiDuZbVLfCXt6SGeHpGmHr9YkIBd4ay2hs_pJ02faPYT5rJBA8LT1z-rRK76VhOlsrf4mrD43xH_2v3ANchIukp-kZOMouJNb6iU6ZBCzREaEY7gtGZCtTb4qleEHSlJ6r-Tu-w_lqCyuxKo5uO3mAGyHk5QRS83xfx1NV8VaWO4X4UzcL66TnkR5LOoIbf_x2Tw5teBF5QkxUZ7Q_8Q"
    )]
    #[case::scope(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlNDT1BFIn0.eyJuYmYiOjE2NTA0MDM0ODEsImV4cCI6MTY1MDQwMzc4MSwiaWF0IjoxNjUwNDAzNDgxLCJzY29wZSI6ImdhdGV3YXkuZGlhZ25vc3RpY3MucmVhZCIsImp0aSI6Ijc4MTk2ODRkLTQ5ZjktNDExYy05ZGFiLTE2M2MwMjJiOTlhMCIsInR5cGUiOiJzY29wZSJ9.qxiHVjlvrbUdxyBApV1asWdYGE0VzF2FPiJtWYr0EjN7TJv3mWIZbpXGkQQoWoPs9qOBKOp6atrXXbhrfbxwIH32s07RI7W6_mOxRwIag1G7SRHXHLXZWH8Jw-t_my7BYS90-lr_hcLoirb6pDVhTFe70RoEL9rjl8jitWel8vC8rmbXIdzQGbcbA6Ed41mksCwEfvMCHIt8xnkmu7krFTbmN9kWwGgGnEryzX-tbq6H6DzQ26n9diliy6O24Zk5oKf8zZ6K5ACFEuL_xPnqr37Ttl7wmvt7bS3ugz6Lop5weXD9yB9GOxpai7yit0Ri-0qVNCt9rzQ-9od3_4Kj7Q"
    )]
    #[case::jmux(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpNVVgifQ.eyJuYmYiOjE2NTQ2MzAyODQsImV4cCI6MTY1NDYzMDU4NCwiaWF0IjoxNjU0NjMwMjg0LCJkc3RfaHN0IjoiaHR0cDovLzE5Mi4xNjguOC4xMjg6MTExMTEiLCJqZXRfYXAiOiJodHRwIiwiamV0X2FpZCI6ImJmMmQ5MmJhLTQ4OTktNGEzMi04ZWFjLTJlNzM3ZDA2ODg2ZiIsImp0aSI6IjhhNTk0OTQyLWRmODAtNDk0Mi05ZTBlLTVkYmIyNDI5NjA1ZiJ9.IayaQwjsHTHUbirO7VVXqgKyJI3jdQX5fcb2u_mSgV-oyJ6zKwh8h-LEhLMmp5dgoxorC4-dWPgHwnOjXWPvQDSragghyp2be9qW45va_r20gjUFOUVCV3lT9_XXVu6l46GlM6W3ZP_I67aEPbLHgL6-5qIxb-6SW_HkjWOGnc88Lcicv74ujgcyq0U4L_Mh1jLPaopDsGNhqtg4SHzbgayHU7yL7icgWWVDWz-MEWCZkwC1bk2IAJJCRd6YjlCNQhZpO5MRiD6omLLmtS-6npivKb94ao9J8R8mxrDQ9idgVXAgqY9uPHvKXAE2eDjt8xbsVbSss4yI8LGhoC-Rgg"
    )]
    fn samples(#[case] sample: &str) {
        #[allow(deprecated)]
        devolutions_gateway::token::unsafe_debug::dangerous_validate_token(sample, None).unwrap();
    }
}

mod as_of_v2021_2_13_0 {
    use proptest::collection::vec;
    use time::OffsetDateTime;

    use super::*;

    const TYPE_ASSOCIATION: &str = "association";
    const JET_CM: &str = "fwd";

    #[derive(Serialize, Debug)]
    struct DvlsAssociationClaims {
        #[serde(rename = "type")]
        ty: &'static str,
        jet_aid: Uuid,
        jet_ap: String,
        jet_cm: &'static str,
        dst_hst: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        dst_alt: Vec<String>,
        nbf: i64,
        exp: i64,
        jti: Uuid,
    }

    fn dvls_host() -> impl Strategy<Value = String> {
        "[a-z]{1,10}\\.[a-z]{1,5}(:[0-9]{3,4})?"
    }

    fn dvls_application_protocol() -> impl Strategy<Value = String> {
        "(rdp|ssh)"
    }

    fn dvls_alternate_hosts() -> impl Strategy<Value = Vec<String>> {
        vec(dvls_host(), 0..4)
    }

    prop_compose! {
        fn dvls_association_claims(
            now: i64
        )(
            jet_aid in uuid_typed(),
            jet_ap in dvls_application_protocol(),
            dst_hst in dvls_host(),
            dst_alt in dvls_alternate_hosts(),
            jti in uuid_typed(),
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
                jti,
            }
        }
    }

    /// Make sure current Gateway is able to validate association tokens provided by DVLS
    #[rstest]
    fn association_token_validation(
        token_cache: TokenCache,
        jrl: Mutex<JrlTokenClaims>,
        active_recordings: ActiveRecordings,
        priv_key: PrivateKey,
        pub_key: PublicKey,
        now: i64,
    ) {
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_association_claims(now).no_shrink())| {
            encode_decode_round_trip(
                &pub_key,
                &priv_key,
                claims,
                None,
                None,
                &token_cache,
                &jrl,
                &active_recordings,
            ).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
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
        #[serde(with = "time::serde::rfc3339")]
        start_timestamp: OffsetDateTime,
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
        jti: Uuid,
    }

    fn dvls_access_scope() -> impl Strategy<Value = String> {
        "(gateway\\.sessions\\.read|gateway\\.associations\\.read|gateway\\.diagnostics\\.read)"
    }

    prop_compose! {
        fn dvls_scope_claims(now: i64)(
            scope in dvls_access_scope(),
            jti in uuid_typed(),
        ) -> DvlsScopeClaims {
            DvlsScopeClaims {
                ty: TYPE_SCOPE,
                scope,
                nbf: now,
                exp: now + 1000,
                jti,
            }
        }
    }

    /// Make sure current Gateway is able to validate scope tokens provided by DVLS
    #[rstest]
    fn scope_token_validation(
        token_cache: TokenCache,
        jrl: Mutex<JrlTokenClaims>,
        active_recordings: ActiveRecordings,
        priv_key: PrivateKey,
        pub_key: PublicKey,
        now: i64,
    ) {
        proptest!(ProptestConfig::with_cases(32), |(claims in dvls_scope_claims(now).no_shrink())| {
            encode_decode_round_trip(
                &pub_key,
                &priv_key,
                claims,
                None,
                None,
                &token_cache,
                &jrl,
                &active_recordings,
            ).map_err(|e| TestCaseError::fail(format!("{e:#}")))?;
        });
    }
}
