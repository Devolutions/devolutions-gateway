use core::{error, fmt};
use std::{fs, io};

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::data_dir;

/// Specifies the default pipe name.
///
/// This is a workaround for `serde(default)` not taking a raw string literal or escaped backslashes.
fn default_pipe_name() -> String {
    "\\\\.\\pipe\\DevolutionsPEDM".to_owned()
}

/// The application config.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    /// The selected database backend.
    ///
    /// Only one can be active at a given time.
    pub db: DbBackend,
    pub postgres: Option<PgConfig>,
    pub libsql: Option<LibsqlConfig>,
    /// Specify the pipe name, if desired.
    ///
    /// Backslashes must be escaped, like "\\\\.\\pipe\\foo".
    /// This field is intentionally omitted from the example configuration.
    #[serde(default = "default_pipe_name")]
    pub pipe_name: String,
}

impl Config {
    /// Creates a new config with the default values for a new setup.
    pub fn standard() -> Self {
        Self {
            db: DbBackend::default(),
            postgres: None,
            libsql: Some(LibsqlConfig {
                path: data_dir().join("pedm.sqlite"),
            }),
            pipe_name: default_pipe_name(),
        }
    }

    /// Loads the config file from the specified path.
    ///
    /// If the config file is not found, it will be written to disk at the specified path.
    pub fn load_from_path(path: &Utf8Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(s) => {
                info!("Loading config from {path}");
                let c: Self = serde_json::from_str(&s)?;
                c.validate()?;
                Ok(c)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                info!("Config not found at {path}. Initializing default config");
                let c = Config::standard();
                fs::write(path, serde_json::to_string(&c)?).map_err(|e| ConfigError::Io(e, path.into()))?;
                Ok(c)
            }
            Err(e) => Err(ConfigError::Io(e, path.into())),
        }
    }

    /// Loads the config file from the default path.
    pub fn load_from_default_path() -> Result<Self, ConfigError> {
        let path = data_dir().join("config.json");
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
#[serde(rename_all = "PascalCase")]
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
#[serde(rename_all = "PascalCase")]
pub struct LibsqlConfig {
    /// The path to the SQLite database file.
    pub path: Utf8PathBuf,
}

// TODO: SSL support
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PgConfig {
    pub host: String,
    pub dbname: String,
    pub port: Option<u16>, // 5432 if omitted
    pub user: String,
    pub password: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error, Utf8PathBuf),
    Json(serde_json::Error),
    MissingSection(DbBackend),
}

impl error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(e, _) => Some(e),
            Self::Json(e) => Some(e),
            Self::MissingSection(_) => None,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e, path) => write!(f, "IO error while loading config at {path}: {e}"),
            Self::Json(e) => e.fmt(f),
            Self::MissingSection(s) => write!(f, "{s} config section is missing"),
        }
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
