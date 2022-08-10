use crate::listener::ListenerUrls;
use crate::token::Subkey;
use crate::utils::TargetAddr;
use anyhow::Context;
use camino::{Utf8Path, Utf8PathBuf};
use cfg_if::cfg_if;
use core::fmt;
use picky::key::{PrivateKey, PublicKey};
use picky::pem::Pem;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tap::prelude::*;
use tokio_rustls::rustls;
use url::Url;
use uuid::Uuid;

const CERTIFICATE_LABEL: &str = "CERTIFICATE";
const PRIVATE_KEY_LABELS: &[&str] = &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

cfg_if! {
    if #[cfg(target_os = "windows")] {
        const COMPANY_DIR: &str = "Devolutions";
        const PROGRAM_DIR: &str = "Gateway";
        const APPLICATION_DIR: &str = "Devolutions\\Gateway";
    } else if #[cfg(target_os = "macos")] {
        const COMPANY_DIR: &str = "Devolutions";
        const PROGRAM_DIR: &str = "Gateway";
        const APPLICATION_DIR: &str = "Devolutions Gateway";
    } else {
        const COMPANY_DIR: &str = "devolutions";
        const PROGRAM_DIR: &str = "gateway";
        const APPLICATION_DIR: &str = "devolutions-gateway";
    }
}

#[derive(Debug, Clone)]
pub struct TlsPublicKey(pub Vec<u8>);

#[derive(Clone)]
pub struct Tls {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub certificate: rustls::Certificate,
    pub private_key: rustls::PrivateKey,
    pub public_key: TlsPublicKey,
}

impl fmt::Debug for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("certificate", &self.certificate)
            .field("private_key", &self.private_key)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Tls {
    fn init(certificate: rustls::Certificate, private_key: rustls::PrivateKey) -> anyhow::Result<Self> {
        let public_key = {
            let cert = picky::x509::Cert::from_der(&certificate.0).context("Failed to parse TLS certificate")?;
            TlsPublicKey(cert.public_key().to_der().unwrap())
        };

        let rustls_config = crate::tls_sanity::build_rustls_config(certificate.clone(), private_key.clone())
            .context("Failed build TLS config")?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(rustls_config));

        Ok(Self {
            acceptor,
            certificate,
            private_key,
            public_key,
        })
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SogarPushRegistryInfo {
    pub registry_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub image_name: Option<String>,
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub enum SogarPermission {
    Push,
    Pull,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
pub struct SogarUser {
    pub password: Option<String>,
    pub username: Option<String>,
    pub permission: Option<SogarPermission>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SogarRegistryConfig {
    pub serve_as_registry: bool,
    pub local_registry_name: Option<String>,
    pub local_registry_image: Option<String>,
    pub keep_files: bool,
    pub keep_time: Option<u64>,
    pub push_files: bool,
    pub sogar_push_registry_info: SogarPushRegistryInfo,
}

#[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
pub enum DataEncoding {
    #[default]
    Multibase,
    Base64,
    Base64Pad,
    Base64Url,
    Base64UrlPad,
}

#[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
pub enum CertFormat {
    #[default]
    X509,
}

#[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
pub enum PrivKeyFormat {
    #[default]
    Pkcs8,
    Ec,
    Rsa,
}

#[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
pub enum PubKeyFormat {
    #[default]
    Spki,
    Rsa,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub id: Option<Uuid>,
    pub service_mode: bool,
    pub listeners: Vec<ListenerUrls>,
    pub hostname: String,
    pub capture_path: Option<Utf8PathBuf>,
    pub log_file: Utf8PathBuf,
    pub log_directive: Option<String>,
    pub tls: Option<Tls>,
    pub provisioner_public_key: PublicKey,
    pub sub_provisioner_public_key: Option<Subkey>,
    pub delegation_private_key: Option<PrivateKey>,
    pub plugins: Option<Vec<Utf8PathBuf>>,
    pub recording_path: Option<Utf8PathBuf>,
    pub sogar: dto::SogarConf,
    pub jrl_file: Utf8PathBuf,
    pub debug: dto::DebugConf,
}

impl Config {
    pub fn init() -> anyhow::Result<Self> {
        let service_mode = std::env::args().any(|arg| arg == "--service");
        let conf_file_path = get_conf_file_path();
        let conf_file = match load_conf_file(&conf_file_path).context("Failed to load configuration")? {
            Some(conf_file) => conf_file,
            None => {
                let defaults = dto::ConfFile::default();
                println!("Write default configuration to disk…");
                save_config(&defaults).context("Failed to save configuration")?;
                defaults
            }
        };
        Self::from_conf_file(&conf_file, service_mode).context("Invalid configuration file")
    }

    pub fn from_conf_file(conf_file: &dto::ConfFile, service_mode: bool) -> anyhow::Result<Self> {
        let has_http_listener = conf_file
            .listeners
            .iter()
            .any(|l| matches!(l.internal_url.scheme(), "http" | "https" | "ws" | "wss"));

        if !has_http_listener {
            anyhow::bail!("At least one HTTP-capable listener is required");
        }

        let requires_tls = conf_file
            .listeners
            .iter()
            .any(|l| matches!(l.internal_url.scheme(), "https" | "wss"));

        if requires_tls && conf_file.tls.is_none() {
            anyhow::bail!("TLS usage implied but TLS configuration is missing (certificate or/and private key)");
        }

        let hostname = conf_file
            .hostname
            .clone()
            .unwrap_or_else(|| default_hostname().unwrap_or_else(|| "localhost".to_owned()));

        let listeners: Vec<_> = conf_file
            .listeners
            .iter()
            .map(|l| dto::ListenerConf::to_listener_urls(l, &hostname))
            .collect();

        let data_dir = get_data_dir();

        let log_file = conf_file
            .log_file
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("gateway.log"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let jrl_file = conf_file
            .jrl_file
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("jrl.json"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let tls = conf_file
            .tls
            .as_ref()
            .map(|tls_conf| {
                let tls_certificate = tls_conf
                    .tls_certificate
                    .read_rustls_certificate()
                    .context("TLS certificate")?;
                let tls_private_key = tls_conf
                    .tls_private_key
                    .read_rustls_priv_key()
                    .context("TLS private key")?;
                Tls::init(tls_certificate, tls_private_key).context("failed to init TLS config")
            })
            .transpose()?;

        let provisioner_public_key = conf_file
            .provisioner_public_key
            .as_ref()
            .context("Provisioner public key is missing")?
            .read_pub_key()
            .context("Provisioner public key")?;

        let sub_provisioner_public_key = conf_file
            .sub_provisioner_public_key
            .as_ref()
            .map(|subkey| {
                let kid = subkey.id.clone();
                let key = subkey.inner.read_pub_key().context("Sub provisioner public key")?;
                Ok::<_, anyhow::Error>(Subkey { data: key, kid })
            })
            .transpose()?;

        let delegation_private_key = conf_file
            .delegation_private_key
            .as_ref()
            .map(|key| key.read_priv_key().context("Delegation private key"))
            .transpose()?;

        Ok(Config {
            id: conf_file.id,
            service_mode,
            listeners,
            hostname,
            capture_path: conf_file.capture_path.clone(),
            log_file,
            log_directive: conf_file.log_directive.clone(),
            tls,
            provisioner_public_key,
            sub_provisioner_public_key,
            delegation_private_key,
            plugins: conf_file.plugins.clone(),
            recording_path: conf_file.recording_path.clone(),
            sogar: conf_file.sogar.clone().unwrap_or_default(),
            jrl_file,
            debug: conf_file.debug.clone().unwrap_or_default(),
        })
    }
}

pub fn save_config(conf: &dto::ConfFile) -> anyhow::Result<()> {
    let conf_file_path = get_conf_file_path();
    let json = serde_json::to_string_pretty(conf).context("Failed JSON serialization of configuration")?;
    std::fs::write(&conf_file_path, &json).context("Failed to write to file")?;
    Ok(())
}

fn get_data_dir() -> Utf8PathBuf {
    if let Ok(config_path_env) = env::var("DGATEWAY_CONFIG_PATH") {
        Utf8PathBuf::from(config_path_env)
    } else {
        let mut config_path = Utf8PathBuf::new();

        if cfg!(target_os = "windows") {
            let program_data_env = env::var("ProgramData").expect("ProgramData env variable");
            config_path.push(program_data_env);
            config_path.push(COMPANY_DIR);
            config_path.push(PROGRAM_DIR);
        } else if cfg!(target_os = "macos") {
            config_path.push("/Library/Application Support");
            config_path.push(APPLICATION_DIR);
        } else {
            config_path.push("/etc");
            config_path.push(APPLICATION_DIR);
        }

        config_path
    }
}

fn get_conf_file_path() -> Utf8PathBuf {
    get_data_dir().join("gateway.json")
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
            .with_context(|| format!("Invalid config file at {conf_path}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!(e).context(format!("Couldn't open config file at {conf_path}"))),
    }
}

fn default_hostname() -> Option<String> {
    hostname::get().ok()?.into_string().ok()
}

pub mod dto {
    use super::*;

    /// Source of truth for Gateway configuration
    ///
    /// This struct represents the JSON file used for configuration as close as possible
    /// and is not trying to be too smart.
    ///
    /// Unstable options are subject to change
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ConfFile {
        //== Gateway Identity ==//
        /// This Gateway unique ID (e.g.: 123e4567-e89b-12d3-a456-426614174000)
        pub id: Option<Uuid>,
        /// This Gateway hostname (e.g.: my-relay.ngrok.io)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub hostname: Option<String>,

        //== Tokens related keys ==//
        /// Provisioner key to verify token with no restriction
        #[serde(flatten, with = "provisioner_public_key")]
        pub provisioner_public_key: Option<ConfFileOrData<PubKeyFormat>>,
        /// Sub provisioner key which can only be used when establishing a session
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sub_provisioner_public_key: Option<SubProvisionerKeyConf>,
        /// Delegation key used to decrypt sensitive data
        #[serde(flatten, with = "delegation_private_key", skip_serializing_if = "Option::is_none")]
        pub delegation_private_key: Option<ConfFileOrData<PrivKeyFormat>>,

        //== TLS config ==//
        #[serde(flatten)]
        pub tls: Option<TlsConf>,

        //== Listeners configuration ==//
        /// Listeners to launch at startup
        pub listeners: Vec<ListenerConf>,

        /// (Unstable) Folder and prefix for log files
        #[serde(skip_serializing_if = "Option::is_none")]
        pub log_file: Option<Utf8PathBuf>,
        /// (Unstable) Path to the JRL file
        #[serde(skip_serializing_if = "Option::is_none")]
        pub jrl_file: Option<Utf8PathBuf>,
        /// (Unstable) Directive string in the same form as the RUST_LOG environment variable
        #[serde(skip_serializing_if = "Option::is_none")]
        pub log_directive: Option<String>,

        //== Plugins ==//
        /// (Unstable) Plugin paths to load at startup
        #[serde(skip_serializing_if = "Option::is_none")]
        pub plugins: Option<Vec<Utf8PathBuf>>,
        /// (Unstable) Recording path to be provided to the recording plugin
        #[serde(skip_serializing_if = "Option::is_none")]
        pub recording_path: Option<Utf8PathBuf>,
        /// (Unstable) Folder where pcap recordings should be stored
        /// Providing this option will cause the PCAP interceptor to be attached to each stream.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub capture_path: Option<Utf8PathBuf>,

        //== Sogar (generic OCI registry) ==//
        /// (Unstable)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sogar: Option<SogarConf>,

        //== Unsafe debug options for developers ==//
        /// (Unstable)
        #[serde(default, rename = "__debug__", skip_serializing_if = "Option::is_none")]
        pub debug: Option<DebugConf>,
    }

    impl Default for ConfFile {
        fn default() -> Self {
            Self {
                id: None,
                hostname: None,
                provisioner_public_key: Some(ConfFileOrData::Path {
                    file: "provisioner.pub.key".into(),
                }),
                sub_provisioner_public_key: None,
                delegation_private_key: None,
                tls: Some(TlsConf {
                    tls_certificate: ConfFileOrData::Path {
                        file: "tls-certificate.pem".into(),
                    },
                    tls_private_key: ConfFileOrData::Path {
                        file: "tls-private.key".into(),
                    },
                }),
                listeners: vec![
                    ListenerConf {
                        internal_url: "tcp://*:8080".try_into().unwrap(),
                        external_url: "tcp://*:8080".try_into().unwrap(),
                    },
                    ListenerConf {
                        internal_url: "ws://*:7171".try_into().unwrap(),
                        external_url: "wss://*:7171".try_into().unwrap(),
                    },
                ],
                log_file: None,
                jrl_file: None,
                log_directive: None,
                plugins: None,
                recording_path: None,
                capture_path: None,
                sogar: None,
                debug: None,
            }
        }
    }

    serde_with::with_prefix!(provisioner_public_key "ProvisionerPublicKey");
    serde_with::with_prefix!(delegation_private_key "DelegationPrivateKey");

    /// Unsafe debug options that should only ever be used at development stage
    ///
    /// These options might change or get removed without further notice.
    ///
    /// Note to developers: all options should be safe by default, never add an option
    /// that needs to be overridden manually in order to be safe.
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    pub struct DebugConf {
        /// Dump received tokens using a `debug` statement
        #[serde(default)]
        pub dump_tokens: bool,

        /// Ignore token signature and accept as-is (any signer is accepted), expired tokens and token
        /// reuse is allowed, etc. Only restriction is to provide claims in the right format.
        #[serde(default)]
        pub disable_token_validation: bool,

        /// Ignore KDC address provided by KDC token, and use this one instead
        pub override_kdc: Option<TargetAddr>,
    }

    /// Manual Default trait implementation just to make sure default values are deliberates
    #[allow(clippy::derivable_impls)]
    impl Default for DebugConf {
        fn default() -> Self {
            Self {
                dump_tokens: false,
                disable_token_validation: false,
                override_kdc: None,
            }
        }
    }

    impl DebugConf {
        pub fn is_default(&self) -> bool {
            Self::default().eq(self)
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    pub struct SogarConf {
        pub registry_url: String,
        pub username: String,
        pub password: String,
        pub image_name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub user_list: Vec<SogarUser>,
        #[serde(default)]
        pub serve_as_registry: bool,
        pub registry_name: String,
        pub registry_image: String,
        #[serde(default)]
        pub push_files: bool,
        #[serde(default)]
        pub keep_files: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub keep_time: Option<u64>,
    }

    impl Default for SogarConf {
        fn default() -> Self {
            Self {
                registry_url: String::new(),
                username: String::new(),
                password: String::new(),
                image_name: "videos".to_owned(),
                user_list: Vec::new(),
                serve_as_registry: false,
                registry_name: "devolutions_registry".to_owned(),
                registry_image: "videos".to_owned(),
                push_files: false,
                keep_files: false,
                keep_time: None,
            }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ConfData<Format> {
        pub value: String,
        #[serde(default)]
        pub format: Format,
        #[serde(default)]
        pub encoding: DataEncoding,
    }

    impl<Format> ConfData<Format> {
        fn decode_value(&self) -> anyhow::Result<Vec<u8>> {
            match self.encoding {
                DataEncoding::Multibase => multibase::decode(&self.value).map(|o| o.1),
                DataEncoding::Base64 => multibase::Base::Base64.decode(&self.value),
                DataEncoding::Base64Pad => multibase::Base::Base64Pad.decode(&self.value),
                DataEncoding::Base64Url => multibase::Base::Base64Url.decode(&self.value),
                DataEncoding::Base64UrlPad => multibase::Base::Base64UrlPad.decode(&self.value),
            }
            .context("Invalid encoding for value")
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum ConfFileOrData<Format> {
        #[serde(rename_all = "PascalCase")]
        Path {
            file: Utf8PathBuf,
        },
        #[serde(rename_all = "PascalCase")]
        Inlined {
            #[serde(bound(deserialize = "ConfData<Format>: Deserialize<'de>"))]
            data: ConfData<Format>,
        },
        Flattened(#[serde(bound(deserialize = "ConfData<Format>: Deserialize<'de>"))] ConfData<Format>),
    }

    impl ConfFileOrData<CertFormat> {
        pub(super) fn read_rustls_certificate(&self) -> anyhow::Result<rustls::Certificate> {
            match self {
                Self::Path { file } => {
                    let path = normalize_data_path(file, &get_data_dir());
                    let pem: Pem = std::fs::read_to_string(&path)
                        .with_context(|| format!("Couldn't read file at {path}"))?
                        .pipe_deref(str::parse)
                        .context("Couldn't parse pem document")?;

                    if pem.label() != CERTIFICATE_LABEL {
                        anyhow::bail!("bad pem label (expected {})", CERTIFICATE_LABEL);
                    }

                    Ok(rustls::Certificate(pem.into_data().into_owned()))
                }
                Self::Inlined { data } | Self::Flattened(data) => {
                    let value = data.decode_value()?;

                    match data.format {
                        CertFormat::X509 => Ok(rustls::Certificate(value)),
                    }
                }
            }
        }
    }

    impl ConfFileOrData<PubKeyFormat> {
        pub(super) fn read_pub_key(&self) -> anyhow::Result<PublicKey> {
            match self {
                Self::Path { file } => {
                    let path = normalize_data_path(file, &get_data_dir());
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("Couldn't read file at {path}"))?
                        .pipe_deref(PublicKey::from_pem_str)
                        .context("Couldn't parse pem document")
                }
                Self::Inlined { data } | Self::Flattened(data) => {
                    let value = data.decode_value()?;

                    match data.format {
                        PubKeyFormat::Spki => PublicKey::from_der(&value).context("Bad SPKI"),
                        PubKeyFormat::Rsa => PublicKey::from_rsa_der(&value).context("Bad RSA value"),
                    }
                }
            }
        }
    }

    impl ConfFileOrData<PrivKeyFormat> {
        pub(super) fn read_rustls_priv_key(&self) -> anyhow::Result<rustls::PrivateKey> {
            let data = match self {
                Self::Path { file } => {
                    let path = normalize_data_path(file, &get_data_dir());
                    let pem: Pem = std::fs::read_to_string(&path)
                        .with_context(|| format!("Couldn't read file at {path}"))?
                        .pipe_deref(str::parse)
                        .context("Couldn't parse pem document")?;

                    if PRIVATE_KEY_LABELS.iter().all(|&label| pem.label() != label) {
                        anyhow::bail!("bad pem label (expected one of {:?})", PRIVATE_KEY_LABELS);
                    }

                    pem.into_data().into_owned()
                }
                Self::Inlined { data } | Self::Flattened(data) => data.decode_value()?,
            };

            Ok(rustls::PrivateKey(data))
        }

        pub(super) fn read_priv_key(&self) -> anyhow::Result<PrivateKey> {
            match self {
                Self::Path { file } => {
                    let path = normalize_data_path(file, &get_data_dir());
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("Couldn't read file at {path}"))?
                        .pipe_deref(PrivateKey::from_pem_str)
                        .context("Couldn't parse pem document")
                }
                Self::Inlined { data } | Self::Flattened(data) => {
                    let value = data.decode_value()?;

                    match data.format {
                        PrivKeyFormat::Pkcs8 => PrivateKey::from_pkcs8(&value).context("Bad PKCS8"),
                        PrivKeyFormat::Ec => PrivateKey::from_ec_der(&value).context("Bad EC value"),
                        PrivKeyFormat::Rsa => PrivateKey::from_rsa_der(&value).context("Bad RSA value"),
                    }
                }
            }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct SubProvisionerKeyConf {
        pub id: String,
        #[serde(flatten)]
        pub inner: ConfFileOrData<PubKeyFormat>,
    }

    serde_with::with_prefix!(certificate "Certificate");
    serde_with::with_prefix!(private_key "PrivateKey");
    serde_with::with_prefix!(tls_certificate "TlsCertificate");
    serde_with::with_prefix!(tls_private_key "TlsPrivateKey");

    /// TLS config    
    #[derive(PartialEq, Eq, Debug, Clone, Serialize)]
    pub struct TlsConf {
        /// Certificate to use for TLS
        #[serde(flatten, with = "tls_certificate")]
        pub tls_certificate: ConfFileOrData<CertFormat>,
        /// Private key to use for TLS
        #[serde(flatten, with = "tls_private_key")]
        pub tls_private_key: ConfFileOrData<PrivKeyFormat>,
    }

    impl<'de> Deserialize<'de> for TlsConf {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Error as _;

            #[derive(Deserialize)]
            pub struct Helper {
                #[serde(flatten, with = "tls_certificate")]
                pub tls_certificate: Option<ConfFileOrData<CertFormat>>,
                #[serde(flatten, with = "certificate")]
                pub certificate: Option<ConfFileOrData<CertFormat>>,
                #[serde(flatten, with = "tls_private_key")]
                pub tls_private_key: Option<ConfFileOrData<PrivKeyFormat>>,
                #[serde(flatten, with = "private_key")]
                pub private_key: Option<ConfFileOrData<PrivKeyFormat>>,
            }

            let conf = Helper::deserialize(deserializer)?;

            let certificate = match (conf.tls_certificate, conf.certificate) {
                (Some(certificate), _) => certificate,
                (None, Some(certificate)) => certificate,
                _ => return Err(D::Error::missing_field("TlsCertificateFile")),
            };

            let key = match (conf.tls_private_key, conf.private_key) {
                (Some(key), _) => key,
                (None, Some(key)) => key,
                _ => return Err(D::Error::missing_field("TlsPrivateKeyFile")),
            };

            Ok(Self {
                tls_certificate: certificate,
                tls_private_key: key,
            })
        }

        fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            // Default implementation just delegates to `deserialize` impl.
            *place = Deserialize::deserialize(deserializer)?;
            Ok(())
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ListenerConf {
        pub internal_url: Url,
        pub external_url: Url,
    }

    impl ListenerConf {
        pub(super) fn to_listener_urls(&self, hostname: &str) -> ListenerUrls {
            fn map_scheme(url: &Url) -> &str {
                match url.scheme() {
                    "http" => "ws",
                    "https" => "wss",
                    other => other,
                }
            }

            let mut internal_url = self.internal_url.clone();

            // Should not panic because initial scheme is valid, and the mapping closure can't return a bad scheme
            internal_url
                .set_scheme(map_scheme(&self.internal_url))
                .expect("valid scheme mapping");

            if internal_url.host_str() == Some("*") {
                let _ = internal_url.set_host(Some("0.0.0.0"));
            }

            let mut external_url = self.external_url.clone();

            // Should not panic because initial scheme is valid, and the mapping closure can't return a bad scheme
            external_url
                .set_scheme(map_scheme(&self.external_url))
                .expect("valid scheme mapping");

            if external_url.host_str() == Some("*") {
                let _ = external_url.set_host(Some(hostname));
            }

            ListenerUrls {
                internal_url,
                external_url,
            }
        }
    }
}
