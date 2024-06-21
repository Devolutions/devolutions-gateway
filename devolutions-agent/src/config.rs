use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{bail, Context};
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_agent_shared::get_data_dir;
use serde::{Deserialize, Serialize};
use tap::prelude::*;

#[derive(Debug, Clone)]
pub struct Conf {
    pub log_file: Utf8PathBuf,
    pub verbosity_profile: dto::VerbosityProfile,
    pub updater: dto::UpdaterConf,
    pub debug: dto::DebugConf,
}

impl Conf {
    pub fn from_conf_file(conf_file: &dto::ConfFile) -> anyhow::Result<Self> {
        let data_dir = get_data_dir();

        let log_file = conf_file
            .log_file
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("agent"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        Ok(Conf {
            log_file,
            verbosity_profile: conf_file.verbosity_profile.unwrap_or_default(),
            updater: conf_file.updater.clone().unwrap_or_default(),
            debug: conf_file.debug.clone().unwrap_or_default(),
        })
    }
}

/// Configuration Handle, source of truth for current configuration state
#[derive(Clone)]
pub struct ConfHandle {
    inner: Arc<ConfHandleInner>,
}

struct ConfHandleInner {
    conf: parking_lot::RwLock<Arc<Conf>>,
    conf_file: parking_lot::RwLock<Arc<dto::ConfFile>>,
}

impl ConfHandle {
    /// Initializes configuration for this instance.
    ///
    /// It's best to call this only once to avoid inconsistencies.
    pub fn init() -> anyhow::Result<Self> {
        let conf_file = load_conf_file_or_generate_new()?;
        let conf = Conf::from_conf_file(&conf_file).context("invalid configuration file")?;

        Ok(Self {
            inner: Arc::new(ConfHandleInner {
                conf: parking_lot::RwLock::new(Arc::new(conf)),
                conf_file: parking_lot::RwLock::new(Arc::new(conf_file)),
            }),
        })
    }

    /// Returns current configuration state (do not hold it forever as it may become outdated)
    pub fn get_conf(&self) -> Arc<Conf> {
        self.inner.conf.read().clone()
    }

    /// Returns current configuration file state (do not hold it forever as it may become outdated)
    pub fn get_conf_file(&self) -> Arc<dto::ConfFile> {
        self.inner.conf_file.read().clone()
    }
}

fn save_config(conf: &dto::ConfFile) -> anyhow::Result<()> {
    let conf_file_path = get_conf_file_path();
    let json = serde_json::to_string_pretty(conf).context("failed JSON serialization of configuration")?;
    std::fs::write(&conf_file_path, json).with_context(|| format!("failed to write file at {conf_file_path}"))?;
    Ok(())
}

fn get_conf_file_path() -> Utf8PathBuf {
    get_data_dir().join("agent.json")
}

fn normalize_data_path(path: &Utf8Path, data_dir: &Utf8Path) -> Utf8PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        data_dir.join(path)
    }
}

fn load_conf_file(conf_path: &Utf8Path) -> anyhow::Result<Option<dto::ConfFile>> {
    match File::open(conf_path) {
        Ok(file) => BufReader::new(file)
            .pipe(serde_json::from_reader)
            .map(Some)
            .with_context(|| format!("invalid config file at {conf_path}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!(e).context(format!("couldn't open config file at {conf_path}"))),
    }
}

pub fn load_conf_file_or_generate_new() -> anyhow::Result<dto::ConfFile> {
    let conf_file_path = get_conf_file_path();

    let conf_file = match load_conf_file(&conf_file_path).context("failed to load configuration")? {
        Some(conf_file) => conf_file,
        None => {
            let defaults = dto::ConfFile::generate_new();
            println!("Write default configuration to disk…");
            save_config(&defaults).context("failed to save configuration")?;
            defaults
        }
    };

    Ok(conf_file)
}

pub mod dto {
    use super::*;

    pub const fn default_bool<const V: bool>() -> bool {
        V
    }

    #[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct UpdaterConf {
        /// Enable updater module (enabled by default)
        #[serde(default = "default_bool::<true>")]
        pub enabled: bool,
    }

    /// Source of truth for Agent configuration
    ///
    /// This struct represents the JSON file used for configuration as close as possible
    /// and is not trying to be too smart.
    ///
    /// Unstable options are subject to change
    #[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ConfFile {
        /// Verbosity profile
        #[serde(skip_serializing_if = "Option::is_none")]
        pub verbosity_profile: Option<VerbosityProfile>,

        /// (Unstable) Folder and prefix for log files
        #[serde(skip_serializing_if = "Option::is_none")]
        pub log_file: Option<Utf8PathBuf>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub updater: Option<UpdaterConf>,

        /// (Unstable) Unsafe debug options for developers
        #[serde(default, rename = "__debug__", skip_serializing_if = "Option::is_none")]
        pub debug: Option<DebugConf>,

        /// Other unofficial options.
        /// This field is useful so that we can deserialize
        /// and then losslessly serialize back all root keys of the config file.
        #[serde(flatten)]
        pub rest: serde_json::Map<String, serde_json::Value>,
    }

    impl ConfFile {
        pub fn generate_new() -> Self {
            Self {
                verbosity_profile: None,
                log_file: None,
                updater: None,
                debug: None,
                rest: serde_json::Map::new(),
            }
        }
    }

    /// Verbosity profile (pre-defined tracing directives)
    #[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize, Default)]
    pub enum VerbosityProfile {
        /// The default profile, mostly info records
        #[default]
        Default,
        /// Recommended profile for developers
        Debug,
        /// Show all traces
        All,
        /// Only show warnings and errors
        Quiet,
    }

    impl VerbosityProfile {
        pub fn to_log_filter(self) -> &'static str {
            match self {
                VerbosityProfile::Default => "info",
                VerbosityProfile::Debug => "info,devolutions_agent=debug",
                VerbosityProfile::All => "trace",
                VerbosityProfile::Quiet => "warn",
            }
        }
    }

    /// Unsafe debug options that should only ever be used at development stage
    ///
    /// These options might change or get removed without further notice.
    ///
    /// Note to developers: all options should be safe by default, never add an option
    /// that needs to be overridden manually in order to be safe.
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    pub struct DebugConf {
        /// Directives string in the same form as the RUST_LOG environment variable
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub log_directives: Option<String>,
        /// Skip MSI installation in updater module. Useful for debugging updater logic
        /// without actually changing the system.
        #[serde(default)]
        pub skip_msi_install: bool,
    }

    /// Manual Default trait implementation just to make sure default values are deliberates
    #[allow(clippy::derivable_impls)]
    impl Default for DebugConf {
        fn default() -> Self {
            Self {
                log_directives: None,
                skip_msi_install: false,
            }
        }
    }

    impl DebugConf {
        pub fn is_default(&self) -> bool {
            Self::default().eq(self)
        }
    }
}

pub fn handle_cli(command: &str) -> Result<(), anyhow::Error> {
    match command {
        "init" => {
            let _config = load_conf_file_or_generate_new()?;
        }
        _ => {
            bail!("unknown config command: {}", command);
        }
    }

    Ok(())
}
