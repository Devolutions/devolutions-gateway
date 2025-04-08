use core::{error, fmt};
use std::{fs, io};

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::data_dir;

/// The application config.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) struct Config {
    /// The selected database backend.
    ///
    /// Only one can be active at a given time.
    pub(crate) db: DbBackend,
    pub(crate) postgres: Option<PgConfig>,
    pub(crate) libsql: Option<LibsqlConfig>,
}

impl Config {
    /// Creates a new config with the default values for a new setup.
    fn standard() -> Self {
        Self {
            db: DbBackend::default(),
            postgres: None,
            libsql: Some(LibsqlConfig {
                path: data_dir().join("pedm.sqlite"),
            }),
        }
    }

    /// Loads the config file from the specified path.
    pub(crate) fn load_from_path(path: &Utf8Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(s) => {
                info!("Loading config from {path}");
                let c: Self = toml::from_str(&s)?;
                c.validate()?;
                Ok(c)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                info!("Config not found at {path}. Initializing default config");
                let c = Config::standard();
                fs::write(path, toml::to_string(&c)?).map_err(|e| ConfigError::Io(e, path.into()))?;
                Ok(c)
            }
            Err(e) => Err(ConfigError::Io(e, path.into())),
        }
    }

    /// Loads the config file from the default path.
    pub(crate) fn load_from_default_path() -> Result<Self, ConfigError> {
        let path = data_dir().join("config.toml");
        Self::load_from_path(&path)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        match self.db {
            #[cfg(feature = "libsql")]
            DbBackend::Libsql if self.libsql.is_none() => Err(ConfigError::MissingSection(DbBackend::Libsql)),
            #[cfg(feature = "postgres")]
            DbBackend::Postgres if self.postgres.is_none() => Err(ConfigError::MissingSection(DbBackend::Postgres)),
            _ => Ok(()),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "lowercase")]
pub enum DbBackend {
    #[cfg_attr(feature = "libsql", default)]
    #[cfg(feature = "libsql")]
    Libsql,
    #[cfg_attr(all(feature = "postgres", not(feature = "libsql")), default)]
    #[cfg(feature = "postgres")]
    Postgres,
}

impl fmt::Display for DbBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "libsql")]
            Self::Libsql => write!(f, "libsql"),
            #[cfg(feature = "postgres")]
            Self::Postgres => write!(f, "postgres"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct LibsqlConfig {
    /// The path to the SQLite database file.
    pub(crate) path: Utf8PathBuf,
}

// TODO: SSL support
#[derive(Serialize, Deserialize)]
pub(crate) struct PgConfig {
    pub(crate) host: String,
    pub(crate) dbname: String,
    pub(crate) port: Option<u16>, // 5432 if omitted
    pub(crate) user: String,
    pub(crate) password: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error, Utf8PathBuf),
    TomlDe(toml::de::Error),
    TomlSer(toml::ser::Error),
    MissingSection(DbBackend),
}

impl error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(e, _) => Some(e),
            Self::TomlDe(e) => Some(e),
            Self::TomlSer(e) => Some(e),
            Self::MissingSection(_) => None,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e, path) => write!(f, "IO error while loading config at {path}: {e}"),
            Self::TomlDe(e) => e.fmt(f),
            Self::TomlSer(e) => e.fmt(f),
            Self::MissingSection(s) => write!(f, "{s} config section is missing"),
        }
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        Self::TomlDe(e)
    }
}
impl From<toml::ser::Error> for ConfigError {
    fn from(e: toml::ser::Error) -> Self {
        Self::TomlSer(e)
    }
}
