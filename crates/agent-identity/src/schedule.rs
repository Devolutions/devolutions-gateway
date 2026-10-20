//! Renewal and check-in schedules of a stored identity.

use std::time::{Duration, SystemTime};

use serde_json::Value;
use url::Url;

/// The `agent_channel_url` of a config, classified by [CONTRACT.md §5.2 "`POST enroll`"][contract].
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.md#52-post-enroll
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelUrl {
    Absent,
    Usable(Url),
    /// Present but not an absolute `https` URL without a query or fragment.
    Malformed,
}

/// Classifies the `agent_channel_url` of a config.
pub fn channel_url(config: &Value) -> ChannelUrl {
    match config.get("agent_channel_url") {
        None | Some(Value::Null) => ChannelUrl::Absent,
        Some(Value::String(url)) => match Url::parse(url) {
            Ok(url)
                if url.scheme() == "https" && url.has_host() && url.query().is_none() && url.fragment().is_none() =>
            {
                ChannelUrl::Usable(url)
            }
            _ => ChannelUrl::Malformed,
        },
        Some(_) => ChannelUrl::Malformed,
    }
}

/// Returns when a certificate valid from `not_before` to `not_after` is due for renewal.
///
/// `jitter` is a uniform sample from `[0, 1]` that scales the `[0, lifetime / 12]` jitter window.
pub fn renewal_time(
    not_before: SystemTime,
    not_after: SystemTime,
    renewal_after: Option<Duration>,
    jitter: f64,
) -> SystemTime {
    if let Some(renewal_after) = renewal_after {
        return not_before + renewal_after;
    }
    let lifetime = not_after.duration_since(not_before).unwrap_or_default();
    not_before + lifetime * 2 / 3 + (lifetime / 12).mul_f64(jitter.clamp(0.0, 1.0))
}

/// Returns a check-in interval varied by up to ±10% of `base`.
///
/// `jitter` is a uniform sample from `[0, 1]`; `0.5` returns `base` unchanged.
pub fn check_in_interval(base: Duration, jitter: f64) -> Duration {
    base - base / 10 + (base / 5).mul_f64(jitter.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use serde_json::json;

    use super::*;

    const DAY: Duration = Duration::from_secs(86_400);

    #[test]
    fn renewal_is_due_two_thirds_into_the_lifetime_plus_up_to_a_twelfth() {
        // `crates/agent-identity/INTENT.md` ("Schedules"): renew at `notBefore + 2/3 × lifetime` plus a jitter
        // drawn from `[0, lifetime / 12]`; a 90-day certificate renews between day 60 and day 67.5.
        let not_before = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let not_after = not_before + 90 * DAY;
        assert_eq!(renewal_time(not_before, not_after, None, 0.0), not_before + 60 * DAY);
        assert_eq!(
            renewal_time(not_before, not_after, None, 1.0),
            not_before + 60 * DAY + DAY * 15 / 2
        );
    }

    #[test]
    fn renewal_after_replaces_the_scheduled_time_without_jitter() {
        // `devolutions-agent/src/identity/INTENT.md` ("Configuration"): `renewal_after_secs` replaces the scheduled
        // renewal time with that many seconds after `notBefore`.
        let not_before = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let renewal_after = Some(Duration::from_secs(5));
        assert_eq!(
            renewal_time(not_before, not_before + 90 * DAY, renewal_after, 1.0),
            not_before + Duration::from_secs(5)
        );
    }

    #[test]
    fn only_an_absolute_https_channel_url_without_query_or_fragment_is_usable() {
        // `CONTRACT.md` §5.2: `agent_channel_url` must be an absolute `https` URL without a query or fragment, and any
        // other value is treated as absent with a warning; §1 accepts `null` for an absent optional field.
        let config = |url: Value| json!({"version": 1, "revision": 1, "agent_channel_url": url});
        assert_eq!(channel_url(&json!({"version": 1, "revision": 1})), ChannelUrl::Absent);
        assert_eq!(channel_url(&config(Value::Null)), ChannelUrl::Absent);
        assert_eq!(
            channel_url(&config(json!("https://host/dvls"))),
            ChannelUrl::Usable(Url::parse("https://host/dvls").expect("valid test URL"))
        );
        for malformed in [
            json!("http://host/dvls"),
            json!("https://host/dvls?x=1"),
            json!("https://host/dvls#part"),
            json!("/dvls"),
            json!(42),
        ] {
            assert_eq!(
                channel_url(&config(malformed.clone())),
                ChannelUrl::Malformed,
                "{malformed}"
            );
        }
    }

    #[test]
    fn check_in_interval_varies_by_ten_percent() {
        // `crates/agent-identity/INTENT.md` ("Schedules"): check-in runs every 24 h ±10%.
        let day = Duration::from_secs(86_400);
        assert_eq!(check_in_interval(day, 0.0), Duration::from_secs(77_760));
        assert_eq!(check_in_interval(day, 0.5), day);
        assert_eq!(check_in_interval(day, 1.0), Duration::from_secs(95_040));
    }
}
