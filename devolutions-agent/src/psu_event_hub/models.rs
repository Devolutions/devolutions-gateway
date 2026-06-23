use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WebsocketEventResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default)]
    pub job_outputs: Vec<JobOutput>,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub timeout: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminating_error: Option<String>,
}

impl WebsocketEventResponse {
    pub(super) fn pending() -> Self {
        Self {
            data: None,
            job_outputs: Vec::new(),
            complete: false,
            timeout: false,
            terminating_error: None,
        }
    }

    pub(super) fn terminating_error(message: impl Into<String>) -> Self {
        Self {
            data: None,
            job_outputs: Vec::new(),
            complete: true,
            timeout: false,
            terminating_error: Some(message.into()),
        }
    }

    pub(super) fn timeout(message: impl Into<String>) -> Self {
        Self {
            data: None,
            job_outputs: Vec::new(),
            complete: true,
            timeout: true,
            terminating_error: Some(message.into()),
        }
    }
}

impl Default for WebsocketEventResponse {
    fn default() -> Self {
        Self::pending()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JobOutput {
    #[serde(default)]
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(rename = "type")]
    pub output_type: JobOutputType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub job_id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum JobOutputType {
    Information = 0,
    Verbose = 1,
    Debug = 2,
    Warning = 3,
    Error = 4,
    Progress = 5,
}

impl JobOutputType {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Information),
            1 => Some(Self::Verbose),
            2 => Some(Self::Debug),
            3 => Some(Self::Warning),
            4 => Some(Self::Error),
            5 => Some(Self::Progress),
            _ => None,
        }
    }
}

impl Serialize for JobOutputType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for JobOutputType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = JobOutputType;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a PSU JobOutputType numeric value or name")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let value = u8::try_from(value).map_err(|_| E::custom("JobOutputType value is out of range"))?;
                JobOutputType::from_u8(value).ok_or_else(|| E::custom("unknown JobOutputType value"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "Information" => Ok(JobOutputType::Information),
                    "Verbose" => Ok(JobOutputType::Verbose),
                    "Debug" => Ok(JobOutputType::Debug),
                    "Warning" => Ok(JobOutputType::Warning),
                    "Error" => Ok(JobOutputType::Error),
                    "Progress" => Ok(JobOutputType::Progress),
                    _ => Err(E::custom("unknown JobOutputType name")),
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_output_type_serializes_as_psu_numeric_value() {
        let json = serde_json::to_string(&JobOutputType::Error).expect("serialize output type");
        assert_eq!(json, "4");
    }

    #[test]
    fn job_output_type_accepts_worker_names() {
        let output_type: JobOutputType = serde_json::from_str("\"Warning\"").expect("deserialize output type");
        assert_eq!(output_type, JobOutputType::Warning);
    }
}
