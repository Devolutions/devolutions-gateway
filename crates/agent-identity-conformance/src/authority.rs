//! The authorities a run tests, what each offers, and which ones a test runs on.

use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context as _, ensure};

use crate::client::Target;

pub(crate) const DAY_SECS: u64 = 24 * 3600;

/// The shortest leaf lifetime that outlasts a test: 3/2 of [`crate::TEST_TIMEOUT`].
///
/// Every wait of a test ends within its timeout, and the agent renews a certificate `2/3 × lifetime` after its anchor ([agent intent], "Schedules").
/// A leaf issued during a test therefore neither comes due for renewal nor expires, which would close its stream ([contract], "Termination"), before the test ends.
/// This takes the anchor to be no earlier than the test's start: an authority that backdates `notBefore`, or whose clock runs behind the runner's, needs longer leaves.
///
/// [agent intent]: ../../agent-identity/INTENT.md#schedules
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#channel-termination
pub(crate) const LONG_LEAF_SECS: u64 = crate::TEST_TIMEOUT.as_secs() * 3 / 2;

static LONG_LEAVES_MISSING: LazyLock<String> =
    LazyLock::new(|| format!("requires leaves that outlast a test, of --leaf-lifetime-secs >= {LONG_LEAF_SECS}"));

/// What an authority offers the tests, as the runner's flags declare it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    /// The lifetime of the leaves the authority issues, which must match its setting.
    pub(crate) leaf_lifetime_secs: u64,
    /// Whether the runner assumes that the authority offers the agent channel, rather than probing for it.
    pub(crate) expect_channel: bool,
    /// Whether rotation and settings changes are safe on the authority.
    pub(crate) disposable: bool,
    /// The rotation window, or `None` to derive it from the leaf lifetime.
    pub(crate) rotation_window_secs: Option<u64>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            leaf_lifetime_secs: 90 * DAY_SECS,
            expect_channel: true,
            disposable: false,
            rotation_window_secs: None,
        }
    }
}

impl Profile {
    /// The rotation window: the explicit one, or else 60 seconds, capped at 75% of the leaf lifetime in whole seconds.
    ///
    /// DVLS refuses a rotation deadline after the rotation maximum, which is at most one leaf lifetime ahead ([DVLS intent], "Rotation").
    /// A leaf lifetime of one second leaves no whole second within that cap, so it requires an explicit window.
    ///
    /// [DVLS intent]: ../../../docs/agent-identity/INTENT.DVLS.md
    pub(crate) fn rotation_window_secs(&self) -> anyhow::Result<u64> {
        if let Some(window) = self.rotation_window_secs {
            return Ok(window);
        }
        let window = (self.leaf_lifetime_secs.saturating_mul(3) / 4).min(60);
        ensure!(
            window > 0,
            "--leaf-lifetime-secs must be at least 2 for a default rotation window, or pass --dvls-rotation-window-secs"
        );
        Ok(window)
    }
}

/// An authority under test.
#[derive(Clone)]
pub(crate) struct Authority {
    /// The flag that declares the authority, such as `--base-url` or `--authority 2`.
    pub(crate) name: String,
    pub(crate) target: Target,
    pub(crate) profile: Profile,
    /// Whether the authority offers the agent channel: assumed when the profile expects it, and probed otherwise.
    pub(crate) channel_available: bool,
    /// Whether the profile's leaf lifetime is the authority's certificate lifetime setting, which the runner reads only on a disposable DVLS target.
    pub(crate) lifetime_from_settings: bool,
    pub(crate) rotation_window_secs: u64,
}

impl Authority {
    pub(crate) fn leaf_lifetime(&self) -> Duration {
        Duration::from_secs(self.profile.leaf_lifetime_secs)
    }
}

/// An authority that `--authority` declares, as comma-separated `<key>=<value>` items.
pub(crate) struct AuthoritySpec {
    pub(crate) base_url: String,
    pub(crate) app_key: String,
    pub(crate) app_secret: String,
    pub(crate) authority_id: Option<String>,
    pub(crate) ca_path: Option<PathBuf>,
    pub(crate) profile: Profile,
}

impl AuthoritySpec {
    /// Parses `spec`, whose application secret is in the environment variable that its `app-secret-env` item names, as `variable` reads it.
    ///
    /// Errors name known keys and item positions, never values or unknown keys, since a misplaced value may be a secret.
    pub(crate) fn parse(spec: &str, variable: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut base_url = None;
        let mut app_key = None;
        let mut secret_variable = None;
        let mut authority_id = None;
        let mut ca_path = None;
        let mut profile = Profile::default();
        let mut seen = Vec::new();
        for (item, position) in spec.split(',').zip(1..) {
            let (key, value) = item
                .split_once('=')
                .with_context(|| format!("--authority item {position} is not <key>=<value>"))?;
            let positive = || -> anyhow::Result<u64> {
                value
                    .parse()
                    .ok()
                    .filter(|number| 0 < *number)
                    .with_context(|| format!("--authority {key} must be a positive integer"))
            };
            let switch = || {
                value
                    .parse::<bool>()
                    .with_context(|| format!("--authority {key} must be true or false"))
            };
            match key {
                "base-url" => base_url = Some(value.to_owned()),
                "app-key" => app_key = Some(value.to_owned()),
                "app-secret-env" => secret_variable = Some(value),
                "authority-id" => authority_id = Some(value.to_owned()),
                "extra-trusted-root" => ca_path = Some(PathBuf::from(value)),
                "leaf-lifetime-secs" => profile.leaf_lifetime_secs = positive()?,
                "expect-channel" => profile.expect_channel = switch()?,
                "disposable-dvls-target" => profile.disposable = switch()?,
                "dvls-rotation-window-secs" => profile.rotation_window_secs = Some(positive()?),
                _ => anyhow::bail!("--authority item {position} has an unknown key"),
            }
            ensure!(!seen.contains(&key), "--authority repeats {key}");
            seen.push(key);
        }
        let app_secret = variable(secret_variable.context("--authority requires app-secret-env")?)
            .filter(|secret| !secret.is_empty())
            .context("--authority app-secret-env names an unset or empty environment variable")?;
        Ok(Self {
            base_url: base_url.context("--authority requires base-url")?,
            app_key: app_key.context("--authority requires app-key")?,
            app_secret,
            authority_id,
            ca_path,
            profile,
        })
    }
}

/// A capability that a test needs from the authority it runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Need {
    /// The authority offers the agent channel.
    Channel,
    /// The authority offers no agent channel; the mock withdraws it with a fault.
    NoChannel,
    /// Rotation and settings changes are safe.
    Disposable,
    /// The authority issues leaves of at most 30 seconds; the mock does with a fault.
    ShortLeaves,
    /// The authority issues leaves of its certificate lifetime setting, which the profile's leaf lifetime matches, rather than a test lifetime in seconds.
    SettingsLifetime,
    /// The management API can change a config, so that an identity's stored revision becomes stale; the mock changes one with a control.
    ConfigChange,
    /// The authority's leaves outlast a test, by lasting at least [`LONG_LEAF_SECS`]; the mock's last its default 90 days, which each test's reset restores.
    LongLeaves,
}

impl Need {
    pub(crate) const ALL: [Self; 7] = [
        Self::Channel,
        Self::NoChannel,
        Self::Disposable,
        Self::ShortLeaves,
        Self::SettingsLifetime,
        Self::ConfigChange,
        Self::LongLeaves,
    ];

    pub(crate) const fn bit(self) -> u8 {
        1 << self as u8
    }

    fn met_by(self, authority: &Authority, mock: bool) -> bool {
        let profile = &authority.profile;
        match self {
            Self::Channel => authority.channel_available,
            Self::NoChannel => mock || !authority.channel_available,
            Self::Disposable => mock || profile.disposable,
            Self::ShortLeaves => mock || profile.leaf_lifetime_secs <= 30,
            Self::SettingsLifetime => mock || authority.lifetime_from_settings,
            // DVLS's management API changes a config only through the agent channel switch, which needs both.
            Self::ConfigChange => mock || profile.disposable && authority.channel_available,
            Self::LongLeaves => mock || LONG_LEAF_SECS <= profile.leaf_lifetime_secs,
        }
    }

    /// Why a test that has this need reports `SKIP` when no authority meets it.
    fn missing(self) -> &'static str {
        match self {
            Self::Channel => "config.agent_channel_url absent and --expect-channel=false",
            Self::NoChannel => "requires a naturally channelless DVLS target",
            Self::Disposable => "rotation and settings changes require --disposable-dvls-target",
            Self::ShortLeaves => "real-target stream expiry requires --leaf-lifetime-secs <= 30",
            Self::SettingsLifetime => {
                "requires a disposable DVLS target without a test leaf lifetime, whose --leaf-lifetime-secs is its certificate lifetime in days"
            }
            Self::ConfigChange => {
                "a stale Hello requires a disposable DVLS target that offers the agent channel, whose switch changes the config"
            }
            Self::LongLeaves => LONG_LEAVES_MISSING.as_str(),
        }
    }
}

const SECOND_MISSING: &str =
    "requires a second authority that meets the same needs (--second-base-url and --second-app-key, or --authority)";

/// The authorities a test runs on, by index: the first that meets every need, and, when the test needs two, the next one that does.
///
/// When too few do, the error is the test's `SKIP` reason: the first need that the first authority lacks, or else the missing second authority.
pub(crate) fn pick(
    authorities: &[Authority],
    needs: &[Need],
    second: bool,
    mock: bool,
) -> Result<(usize, Option<usize>), &'static str> {
    let meets = |authority: &Authority| needs.iter().all(|need| need.met_by(authority, mock));
    let mut candidates = authorities
        .iter()
        .enumerate()
        .filter(|(_, authority)| meets(authority))
        .map(|(index, _)| index);
    let Some(first) = candidates.next() else {
        let lacking = authorities
            .first()
            .and_then(|authority| needs.iter().find(|need| !need.met_by(authority, mock)));
        return Err(lacking.map_or(SECOND_MISSING, |need| need.missing()));
    };
    if !second {
        return Ok((first, None));
    }
    candidates.next().map(|next| (first, Some(next))).ok_or(SECOND_MISSING)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvls::AppCredential;

    fn authority(profile: Profile, channel_available: bool, lifetime_from_settings: bool) -> anyhow::Result<Authority> {
        Ok(Authority {
            name: "--authority".to_owned(),
            target: Target::new(
                "https://localhost/authority".to_owned(),
                AppCredential::new("key".to_owned(), "secret".to_owned()),
                None,
                None,
            )?,
            profile,
            channel_available,
            lifetime_from_settings,
            rotation_window_secs: profile.rotation_window_secs()?,
        })
    }

    /// A DVLS run with two authorities issuing 20-second test leaves with the channel, a third issuing one-day test leaves, and a fourth with neither test leaves nor the channel.
    fn dvls_run() -> anyhow::Result<Vec<Authority>> {
        let short = Profile {
            leaf_lifetime_secs: 20,
            disposable: true,
            ..Profile::default()
        };
        let day = Profile {
            leaf_lifetime_secs: DAY_SECS,
            ..short
        };
        let plain = Profile {
            expect_channel: false,
            disposable: true,
            ..Profile::default()
        };
        Ok(vec![
            authority(short, true, false)?,
            authority(short, true, false)?,
            authority(day, true, false)?,
            authority(plain, false, true)?,
        ])
    }

    /// A check runs on the first authority that offers what it needs, so a profile-dependent check reaches an extra authority instead of skipping.
    #[test]
    fn a_check_runs_on_the_first_authority_that_meets_its_needs() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
        let authorities = dvls_run()?;
        assert_eq!(pick(&authorities, &[], false, false), Ok((0, None)));
        assert_eq!(
            pick(&authorities, &[Need::Disposable, Need::SettingsLifetime], false, false),
            Ok((3, None))
        );
        assert_eq!(
            pick(
                &authorities[2..],
                &[Need::Disposable, Need::SettingsLifetime],
                false,
                false
            ),
            Ok((1, None))
        );
        assert_eq!(pick(&authorities, &[Need::NoChannel], false, false), Ok((3, None)));
        assert_eq!(
            pick(&authorities, &[Need::Channel, Need::ConfigChange], false, false),
            Ok((0, None))
        );
        assert_eq!(pick(&authorities, &[Need::Channel], true, false), Ok((0, Some(1))));
        // Twenty-second leaves expire within a test, while a day's outlast it.
        assert_eq!(
            pick(&authorities, &[Need::Channel, Need::LongLeaves], false, false),
            Ok((2, None))
        );
        Ok(())
    }

    /// A run that lacks a fixture reports `SKIP` with the capability it lacks, rather than a generic reason.
    #[test]
    fn a_check_skips_with_the_missing_capability_only_when_no_authority_meets_it() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
        let authorities = dvls_run()?;
        assert_eq!(
            pick(&authorities[..2], &[Need::NoChannel], false, false),
            Err(Need::NoChannel.missing())
        );
        assert_eq!(
            pick(
                &authorities[..3],
                &[Need::Disposable, Need::SettingsLifetime],
                false,
                false
            ),
            Err(Need::SettingsLifetime.missing())
        );
        assert_eq!(
            pick(&authorities[3..], &[Need::Channel, Need::ConfigChange], false, false),
            Err(Need::Channel.missing())
        );
        assert_eq!(pick(&authorities, &[Need::NoChannel], true, false), Err(SECOND_MISSING));
        assert_eq!(
            pick(&authorities[..2], &[Need::Channel, Need::LongLeaves], false, false),
            Err(Need::LongLeaves.missing())
        );
        Ok(())
    }

    /// The mock offers every fixture through its controls, so a mock run never skips for one, and runs on its first authority.
    #[test]
    fn the_mock_meets_every_need_but_an_absent_channel() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
        let mock = [authority(Profile::default(), true, false)?];
        for need in Need::ALL {
            assert_eq!(pick(&mock, &[need], false, true), Ok((0, None)), "{need:?}");
        }
        let channelless = [authority(Profile::default(), false, false)?];
        assert_eq!(
            pick(&channelless, &[Need::Channel], false, true),
            Err(Need::Channel.missing())
        );
        Ok(())
    }

    /// An authority's secret comes from the environment, which keeps it off the command line.
    #[test]
    fn an_authority_spec_reads_its_secret_from_the_variable_it_names() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
        let variable = |name: &str| (name == "C_SECRET").then(|| "synthetic-secret".to_owned());
        let spec = AuthoritySpec::parse(
            "base-url=https://localhost:15512,app-key=c-key,app-secret-env=C_SECRET,leaf-lifetime-secs=7776000,expect-channel=false,disposable-dvls-target=true",
            &variable,
        )?;
        assert_eq!(
            (spec.base_url.as_str(), spec.app_key.as_str(), spec.app_secret.as_str()),
            ("https://localhost:15512", "c-key", "synthetic-secret")
        );
        assert_eq!(
            spec.profile,
            Profile {
                leaf_lifetime_secs: 7_776_000,
                expect_channel: false,
                disposable: true,
                rotation_window_secs: None,
            }
        );
        Ok(())
    }

    /// A usage error lands in CI logs, so an `--authority` item that holds a secret in a form the runner does not take must not appear in it.
    #[test]
    fn authority_spec_errors_never_echo_a_value() {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
        let secret = "synthetic-credential";
        let variable = |_: &str| None;
        for spec in [
            format!("base-url=https://localhost,app-key=key,app-secret={secret}"),
            format!("base-url=https://localhost,app-key=key,{secret}"),
            format!("base-url=https://localhost,app-key=key,app-secret-env={secret}"),
            format!("base-url=https://localhost,app-key=key,app-secret-env=V,leaf-lifetime-secs={secret}"),
            format!("base-url=https://localhost,app-key=key,app-secret-env=V,expect-channel={secret}"),
        ] {
            let error = AuthoritySpec::parse(&spec, &variable)
                .err()
                .map(|error| format!("{error:#}"));
            assert!(
                error.as_ref().is_some_and(|error| !error.contains(secret)),
                "{spec} gave {error:?}"
            );
        }
    }
}
