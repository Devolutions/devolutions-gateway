use crate::target_addr::TargetAddr;

/// How the Gateway's internal client should reach the target, provisioned alongside the credentials.
///
/// The KDC address is fully validated at construction — supported scheme, a host, and a parseable
/// URL — so the rest of the code can trust `krb_kdc` without re-checking it or failing late when a
/// session starts.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawTargetConnectionOptions")]
pub(crate) struct TargetConnectionOptions {
    krb_kdc: Option<TargetAddr>,
}

impl TargetConnectionOptions {
    pub(crate) fn new(krb_kdc: Option<TargetAddr>) -> Result<Self, InvalidKdcAddr> {
        if let Some(krb_kdc) = &krb_kdc {
            if !is_supported_krb_kdc_scheme(krb_kdc.scheme()) {
                return Err(InvalidKdcAddr::UnsupportedScheme(krb_kdc.scheme().to_owned()));
            }
            if krb_kdc.host().is_empty() {
                return Err(InvalidKdcAddr::MissingHost(krb_kdc.as_str().to_owned()));
            }
            // The target-side CredSSP leg turns this into a URL. Reject a value that won't parse here,
            // so provisioning fails fast instead of at session start.
            url::Url::try_from(krb_kdc).map_err(|_| InvalidKdcAddr::NotAUrl(krb_kdc.as_str().to_owned()))?;
        }
        Ok(Self { krb_kdc })
    }

    pub(crate) fn krb_kdc(&self) -> Option<&TargetAddr> {
        self.krb_kdc.as_ref()
    }
}

pub(crate) fn is_supported_krb_kdc_scheme(scheme: &str) -> bool {
    matches!(scheme, "tcp" | "udp")
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum InvalidKdcAddr {
    #[error("unsupported KDC protocol: {0}")]
    UnsupportedScheme(String),
    #[error("KDC address is missing a host: {0}")]
    MissingHost(String),
    #[error("KDC address is not a valid URL: {0}")]
    NotAUrl(String),
}

#[derive(Deserialize)]
struct RawTargetConnectionOptions {
    #[serde(default)]
    krb_kdc: Option<TargetAddr>,
}

impl TryFrom<RawTargetConnectionOptions> for TargetConnectionOptions {
    type Error = InvalidKdcAddr;

    fn try_from(raw: RawTargetConnectionOptions) -> Result<Self, Self::Error> {
        Self::new(raw.krb_kdc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_supported_kdc_protocols() {
        for krb_kdc in ["tcp://dc.example.com:88", "udp://dc.example.com:88"] {
            let options: TargetConnectionOptions = serde_json::from_value(serde_json::json!({
                "krb_kdc": krb_kdc,
            }))
            .expect("supported KDC protocol should deserialize");

            assert_eq!(
                options.krb_kdc().expect("KDC address should be present").as_str(),
                krb_kdc
            );
        }
    }

    #[test]
    fn rejects_unsupported_kdc_protocol() {
        let error = serde_json::from_value::<TargetConnectionOptions>(serde_json::json!({
            "krb_kdc": "https://dc.example.com:443",
        }))
        .expect_err("unsupported KDC protocol should be rejected");

        assert!(error.to_string().contains("unsupported KDC protocol: https"));
    }

    #[test]
    fn rejects_kdc_without_a_host() {
        assert!(
            serde_json::from_value::<TargetConnectionOptions>(serde_json::json!({
                "krb_kdc": "tcp://:88",
            }))
            .is_err(),
            "a host-less KDC address must be rejected at provisioning time"
        );
    }

    #[test]
    fn new_rejects_unsupported_scheme_for_in_crate_callers() {
        let krb_kdc = TargetAddr::parse("https://dc.example.com:443", Some(443)).expect("addr parses");
        assert!(TargetConnectionOptions::new(Some(krb_kdc)).is_err());
    }
}
