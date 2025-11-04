use std::fmt;
use std::str::FromStr;

use serde::de::Deserialize;
use serde::ser::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("invalid date (`YYYY.MM.DD.R`) version")]
pub struct DateVersionError;

/// Parsed application version represented in the format `YYYY.MM.DD.R`
#[derive(Debug, Default, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub struct DateVersion {
    // NOTE: Field order is important for `PartialOrd` and `Ord` derives
    pub year: u32,
    pub month: u32,
    pub day: u32,
    pub revision: u32,
}

impl DateVersion {
    pub fn fmt_without_revision(&self) -> String {
        format!("{}.{}.{}", self.year, self.month, self.day)
    }
}

impl Serialize for DateVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DateVersion {
    fn deserialize<D>(deserializer: D) -> Result<DateVersion, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DateVersion::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for DateVersion {
    type Err = DateVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(4, '.');

        let mut next_part = || parts.next().and_then(|s| u32::from_str(s).ok()).ok_or(DateVersionError);

        let year = next_part()?;
        let month = next_part()?;
        let day = next_part()?;
        // Allow version without revision
        let revision = next_part().unwrap_or(0);

        if parts.next().is_some() {
            return Err(DateVersionError);
        }

        Ok(DateVersion {
            year,
            month,
            day,
            revision,
        })
    }
}

impl fmt::Display for DateVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.year, self.month, self.day, self.revision)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

    use super::*;

    #[test]
    fn date_version_roundtrip() {
        let version = DateVersion {
            year: 2022,
            month: 10,
            day: 1,
            revision: 2,
        };

        let version_str = version.to_string();
        assert_eq!(version_str, "2022.10.1.2");
        let parsed_version = DateVersion::from_str(&version_str).unwrap();

        assert_eq!(version, parsed_version);
    }

    // Regression test in case field order gets changed
    #[test]
    fn date_version_ordering() {
        const VERSIONS_ASCENDING_PAIRS: &[(&str, &str)] = &[
            // cases (>) for fields in order
            ("2022.10.1.2", "2022.10.1.1"),
            ("2022.10.2.1", "2022.10.1.1"),
            ("2022.11.1.1", "2022.10.1.1"),
            ("2023.10.1.1", "2022.10.1.1"),
        ];

        for (v1, v2) in VERSIONS_ASCENDING_PAIRS {
            let greater = DateVersion::from_str(v1).unwrap();
            let lesser = DateVersion::from_str(v2).unwrap();

            assert!(greater > lesser);
        }
    }
}
