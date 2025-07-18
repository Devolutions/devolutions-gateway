use devolutions_gateway::session::{ConnectionModeDetails, SessionInfo};
use devolutions_gateway::target_addr::TargetAddr;
use devolutions_gateway::token::{
    self, AccessScope, ApplicationProtocol, MAX_SUBKEY_TOKEN_VALIDITY_DURATION_SECS, Protocol, RecordingPolicy,
};
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use serde::Serialize;
use uuid::Uuid;

pub fn uuid_str() -> impl Strategy<Value = String> {
    "[[:digit:]]{8}-([[:digit:]]{4}-){3}[[:digit:]]{12}".no_shrink()
}

pub fn uuid_typed() -> impl Strategy<Value = Uuid> {
    uuid_str().prop_map(|id| Uuid::parse_str(&id).unwrap())
}

pub fn token_content_type() -> impl Strategy<Value = token::ContentType> {
    prop_oneof![
        Just(token::ContentType::Association),
        Just(token::ContentType::Scope),
        Just(token::ContentType::Bridge),
        Just(token::ContentType::Jmux),
        Just(token::ContentType::Kdc),
        Just(token::ContentType::Jrl),
    ]
    .no_shrink()
}

pub fn application_protocol() -> impl Strategy<Value = ApplicationProtocol> {
    prop_oneof![
        Just(ApplicationProtocol::Known(Protocol::Wayk)),
        Just(ApplicationProtocol::Known(Protocol::Rdp)),
        Just(ApplicationProtocol::Known(Protocol::Ard)),
        Just(ApplicationProtocol::Known(Protocol::Vnc)),
        Just(ApplicationProtocol::Known(Protocol::Ssh)),
        Just(ApplicationProtocol::Known(Protocol::SshPwsh)),
        Just(ApplicationProtocol::Known(Protocol::Sftp)),
        Just(ApplicationProtocol::Known(Protocol::Scp)),
        Just(ApplicationProtocol::Known(Protocol::WinrmHttpPwsh)),
        Just(ApplicationProtocol::Known(Protocol::WinrmHttpsPwsh)),
        Just(ApplicationProtocol::Known(Protocol::Http)),
        Just(ApplicationProtocol::Known(Protocol::Https)),
        Just(ApplicationProtocol::Known(Protocol::Ldap)),
        Just(ApplicationProtocol::Known(Protocol::Ldaps)),
        Just(ApplicationProtocol::unknown()),
    ]
    .no_shrink()
}

pub fn recording_policy() -> impl Strategy<Value = RecordingPolicy> {
    prop_oneof![
        Just(RecordingPolicy::None),
        Just(RecordingPolicy::Stream),
        Just(RecordingPolicy::Proxy),
    ]
    .no_shrink()
}

pub fn target_addr() -> impl Strategy<Value = TargetAddr> {
    "[a-z]{1,10}\\.[a-z]{1,5}:[0-9]{3,4}".prop_map(|addr| TargetAddr::parse(&addr, None).unwrap())
}

pub fn host() -> impl Strategy<Value = String> {
    "[a-z]{1,10}\\.[a-z]{1,5}(:[0-9]{3,4})?"
}

pub fn alternate_hosts() -> impl Strategy<Value = Vec<String>> {
    vec(host(), 0..4)
}

pub fn host_with_port() -> impl Strategy<Value = String> {
    "[a-z]{1,10}\\.[a-z]{1,5}:[0-9]{3,4}"
}

pub fn alternate_hosts_with_ports() -> impl Strategy<Value = Vec<String>> {
    vec(host_with_port(), 0..4)
}

pub fn access_scope() -> impl Strategy<Value = AccessScope> {
    prop_oneof![
        Just(AccessScope::SessionsRead),
        Just(AccessScope::AssociationsRead),
        Just(AccessScope::DiagnosticsRead),
        Just(AccessScope::JrlRead),
        Just(AccessScope::Wildcard),
    ]
}

#[derive(Debug, Serialize, Clone)]
pub struct CredsClaims {
    pub prx_usr: String,
    pub prx_pwd: String,
    pub dst_usr: String,
    pub dst_pwd: String,
}

pub fn creds_claims() -> impl Strategy<Value = CredsClaims> {
    (".*", ".*", ".*", ".*")
        .prop_map(|(prx_usr, prx_pwd, dst_usr, dst_pwd)| CredsClaims {
            prx_usr,
            prx_pwd,
            dst_usr,
            dst_pwd,
        })
        .no_shrink()
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "jet_cm")]
pub enum ConnectionMode {
    Rdv,
    Fwd {
        /// Destination Host
        dst_hst: String,
        /// Alternate Destination Hosts
        dst_alt: Vec<String>,
        #[serde(flatten)]
        creds: Option<CredsClaims>,
    },
}

pub fn jet_ap_and_jet_cm() -> impl Strategy<Value = (ApplicationProtocol, ConnectionMode)> {
    prop_oneof![
        (application_protocol(), Just(ConnectionMode::Rdv)),
        application_protocol().prop_flat_map(|jet_ap| {
            if jet_ap.known_default_port().is_some() {
                (
                    Just(jet_ap),
                    (host(), alternate_hosts(), option::of(creds_claims())).prop_map(|(dst_hst, dst_alt, creds)| {
                        ConnectionMode::Fwd {
                            dst_hst,
                            dst_alt,
                            creds,
                        }
                    }),
                )
                    .boxed()
            } else {
                (
                    Just(jet_ap),
                    (
                        host_with_port(),
                        alternate_hosts_with_ports(),
                        option::of(creds_claims()),
                    )
                        .prop_map(|(dst_hst, dst_alt, creds)| ConnectionMode::Fwd {
                            dst_hst,
                            dst_alt,
                            creds,
                        }),
                )
                    .boxed()
            }
        }),
    ]
    .no_shrink()
}

#[derive(Debug, Serialize, Clone)]
pub struct AssociationClaims {
    pub jet_aid: Uuid,
    pub jet_ap: ApplicationProtocol,
    #[serde(flatten)]
    pub jet_cm: ConnectionMode,
    pub jet_rec: RecordingPolicy,
    pub jet_flt: bool,
    pub nbf: i64,
    pub exp: i64,
    pub jti: Uuid,
}

impl AssociationClaims {
    pub fn should_encrypt(&self) -> bool {
        matches!(self.jet_cm, ConnectionMode::Fwd { creds: Some(_), .. })
    }
}

pub fn any_association_claims(now: i64, validity_duration: i64) -> impl Strategy<Value = AssociationClaims> {
    (
        uuid_typed(),
        jet_ap_and_jet_cm(),
        recording_policy(),
        any::<bool>(),
        uuid_typed(),
    )
        .prop_map(
            move |(jet_aid, (jet_ap, jet_cm), jet_rec, jet_flt, jti)| AssociationClaims {
                jet_aid,
                jet_ap,
                jet_cm,
                jet_rec,
                jet_flt,
                jti,
                nbf: now,
                exp: now + validity_duration,
            },
        )
}

pub fn session_info_fwd_only() -> impl Strategy<Value = SessionInfo> {
    (uuid_typed(), application_protocol(), target_addr()).prop_map(|(id, application_protocol, destination_host)| {
        SessionInfo::builder()
            .id(id)
            .application_protocol(application_protocol)
            .details(ConnectionModeDetails::Fwd { destination_host })
            .recording_policy(token::RecordingPolicy::None)
            .filtering_policy(false)
            .time_to_live(token::SessionTtl::Unlimited)
            .build()
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeClaims {
    pub scope: AccessScope,
    pub nbf: i64,
    pub exp: i64,
    pub jti: Uuid,
}

pub fn any_scope_claims(now: i64, validity_duration: i64) -> impl Strategy<Value = ScopeClaims> {
    (access_scope(), uuid_typed()).prop_map(move |(scope, jti)| ScopeClaims {
        scope,
        jti,
        nbf: now,
        exp: now + validity_duration,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct BridgeClaims {
    pub target_host: TargetAddr,
    pub jet_aid: Uuid,
    pub jet_ap: ApplicationProtocol,
    pub jet_rec: RecordingPolicy,
    pub nbf: i64,
    pub exp: i64,
    pub jti: Uuid,
}

pub fn any_bridge_claims(now: i64, validity_duration: i64) -> impl Strategy<Value = BridgeClaims> {
    (
        target_addr(),
        uuid_typed(),
        application_protocol(),
        recording_policy(),
        uuid_typed(),
    )
        .prop_map(move |(target_host, jet_aid, jet_ap, jet_rec, jti)| BridgeClaims {
            target_host,
            jet_aid,
            jet_ap,
            jet_rec,
            nbf: now,
            exp: now + validity_duration,
            jti,
        })
}

#[derive(Debug, Clone, Serialize)]
pub struct JmuxClaims {
    pub jet_aid: Uuid,
    pub jet_rec: RecordingPolicy,
    pub dst_hst: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dst_addl: Vec<String>,
    pub jet_ap: ApplicationProtocol,
    pub nbf: i64,
    pub exp: i64,
    pub jti: Uuid,
}

pub fn any_jmux_claims(now: i64, validity_duration: i64) -> impl Strategy<Value = JmuxClaims> {
    (
        uuid_typed(),
        recording_policy(),
        host(),
        alternate_hosts(),
        application_protocol(),
        uuid_typed(),
    )
        .prop_map(move |(jet_aid, jet_rec, dst_hst, dst_addl, jet_ap, jti)| JmuxClaims {
            jet_aid,
            jet_rec,
            dst_hst,
            dst_addl,
            jet_ap,
            jti,
            nbf: now,
            exp: now + validity_duration,
        })
}

#[derive(Debug, Clone, Serialize)]
pub struct KdcClaims {
    pub krb_realm: String,
    pub krb_kdc: String,
    pub nbf: i64,
    pub exp: i64,
    pub jti: Uuid,
}

pub fn any_kdc_claims(now: i64, validity_duration: i64) -> impl Strategy<Value = KdcClaims> {
    (
        "[a-z0-9_-]{5,25}",
        "(tcp|udp)://[a-z]{1,10}\\.[a-z]{1,5}(:[0-9]{3,4})?",
        uuid_typed(),
    )
        .prop_map(move |(krb_realm, krb_kdc, jti)| KdcClaims {
            krb_realm,
            krb_kdc,
            jti,
            nbf: now,
            exp: now + validity_duration,
        })
}

#[derive(Debug, Serialize, Clone)]
#[serde(untagged)]
pub enum TokenClaims {
    Association(AssociationClaims),
    Scope(ScopeClaims),
    Bridge(BridgeClaims),
    Jmux(JmuxClaims),
    Kdc(KdcClaims),
}

impl TokenClaims {
    pub fn content_type(&self) -> &'static str {
        match self {
            TokenClaims::Association(_) => "ASSOCIATION",
            TokenClaims::Scope(_) => "SCOPE",
            TokenClaims::Bridge(_) => "BRIDGE",
            TokenClaims::Jmux(_) => "JMUX",
            TokenClaims::Kdc(_) => "KDC",
        }
    }

    pub fn should_encrypt(&self) -> bool {
        match self {
            TokenClaims::Association(assoc) => assoc.should_encrypt(),
            _ => false,
        }
    }
}

pub fn any_claims_with_validity_duration(now: i64, validity_duration: i64) -> impl Strategy<Value = TokenClaims> {
    prop_oneof![
        any_scope_claims(now, validity_duration).prop_map(TokenClaims::Scope),
        any_bridge_claims(now, validity_duration).prop_map(TokenClaims::Bridge),
        any_kdc_claims(now, validity_duration).prop_map(TokenClaims::Kdc),
        any_jmux_claims(now, validity_duration).prop_map(TokenClaims::Jmux),
        any_association_claims(now, validity_duration).prop_map(TokenClaims::Association),
    ]
}

pub fn any_claims(now: i64) -> impl Strategy<Value = TokenClaims> {
    (15..(MAX_SUBKEY_TOKEN_VALIDITY_DURATION_SECS * 2))
        .prop_flat_map(move |validity_duration| any_claims_with_validity_duration(now, validity_duration))
}
