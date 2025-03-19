use core::fmt;

use serde::{de, ser};

#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum Credentials {
    #[serde(rename = "username-password")]
    UsernamePassword { username: String, password: Password },
}

#[derive(PartialEq, Eq, Clone, zeroize::Zeroize)]
pub struct Password(String);

impl Password {
    /// Do not copy the return value without wrapping into some "Zeroize"able structure
    pub fn get(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password").finish_non_exhaustive()
    }
}

impl<'de> de::Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;

        impl de::Visitor<'_> for V {
            type Value = Password;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Password(v))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Password(v.to_owned()))
            }
        }

        let password = deserializer.deserialize_string(V)?;

        Ok(password)
    }
}

impl ser::Serialize for Password {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}
