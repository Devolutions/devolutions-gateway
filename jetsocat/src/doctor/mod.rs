mod common;
mod help;
mod macros;
#[cfg(feature = "native-tls")]
mod native_tls;
#[cfg(feature = "rustls")]
mod rustls;

use core::fmt;
use std::path::PathBuf;

use tinyjson::JsonValue;

#[derive(Default, Debug, Clone)]
pub struct Args {
    pub server_port: Option<u16>,
    pub subject_name: Option<String>,
    pub chain_path: Option<PathBuf>,
    pub allow_network: bool,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub name: String,
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub help: Option<String>,
    pub links: Vec<Link>,
}

#[derive(Debug, Clone)]
pub struct Link {
    pub name: String,
    pub href: String,
    pub description: String,
}

pub fn run(args: Args, callback: &mut dyn FnMut(Diagnostic) -> bool) {
    common::run(callback);

    #[cfg(feature = "rustls")]
    {
        rustls::run(&args, callback);
    }

    #[cfg(feature = "native-tls")]
    {
        native_tls::run(&args, callback);
    }
}

impl Diagnostic {
    pub fn into_json(self) -> JsonValue {
        use std::collections::HashMap;
        use tinyjson::JsonValue;

        let mut object = HashMap::new();

        object.insert("name".to_owned(), JsonValue::String(self.name));
        object.insert("success".to_owned(), JsonValue::Boolean(self.success));

        if let Some(output) = self.output {
            object.insert("output".to_owned(), JsonValue::String(output));
        }

        if let Some(error_message) = self.error {
            object.insert("error".to_owned(), JsonValue::String(error_message));
        }

        if let Some(help_message) = self.help {
            object.insert("help".to_owned(), JsonValue::String(help_message));
        }

        if !self.links.is_empty() {
            object.insert(
                "links".to_owned(),
                JsonValue::Array(self.links.into_iter().map(Link::into_json).collect()),
            );
        }

        JsonValue::Object(object)
    }

    pub fn json_display(&self) -> impl fmt::Display + '_ {
        return DiagnosticJsonDisplay(self);

        struct DiagnosticJsonDisplay<'a>(&'a Diagnostic);

        impl fmt::Display for DiagnosticJsonDisplay<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let s = self
                    .0
                    .clone()
                    .into_json()
                    .stringify()
                    .expect("we expect enough memory to write the JSON string");
                write!(f, "{s}")
            }
        }
    }

    pub fn human_display(&self) -> impl fmt::Display + '_ {
        return DiagnosticHumanDisplay(self);

        struct DiagnosticHumanDisplay<'a>(&'a Diagnostic);

        impl fmt::Display for DiagnosticHumanDisplay<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "=> {} ", self.0.name)?;

                if self.0.success {
                    write!(f, "OK ✅")?;
                } else {
                    write!(f, "FAILED ❌")?;
                }

                if let Some(output) = self.0.output.as_deref() {
                    write!(f, "\n\n### Output\n{output}")?;
                }

                if let Some(error_message) = self.0.error.as_deref() {
                    write!(f, "\n\n### Error\n{}", capitalize(error_message))?;
                }

                if let Some(help_message) = self.0.help.as_deref() {
                    write!(f, "\n\n### Help\n{help_message}")?;
                }

                if !self.0.links.is_empty() {
                    write!(f, "\n\n### Links")?;
                    for link in &self.0.links {
                        write!(f, "\n{} ({}): {}", link.name, link.description, link.href)?;
                    }
                }

                return Ok(());

                fn capitalize(s: &str) -> String {
                    let mut c = s.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => {
                            let mut s: String = f.to_uppercase().collect();
                            s.push_str(c.as_str());
                            s
                        }
                    }
                }
            }
        }
    }
}

impl Link {
    pub fn into_json(self) -> JsonValue {
        use std::collections::HashMap;
        use tinyjson::JsonValue;

        let mut object = HashMap::new();

        object.insert("name".to_owned(), JsonValue::String(self.name));
        object.insert("href".to_owned(), JsonValue::String(self.href));
        object.insert("description".to_owned(), JsonValue::String(self.description));

        JsonValue::Object(object)
    }
}

#[derive(Default)]
struct DiagnosticCtx {
    help: Option<String>,
    links: Vec<Link>,
}

impl DiagnosticCtx {
    fn attach_help(&mut self, message: impl Into<String>) {
        self.help = Some(message.into());
    }

    fn attach_link(&mut self, name: impl Into<String>, href: impl Into<String>, description: impl Into<String>) {
        self.links.push(Link {
            name: name.into(),
            href: href.into(),
            description: description.into(),
        })
    }
}

fn cert_to_pem(cert_der: &[u8]) -> Result<String, std::fmt::Error> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use std::fmt::Write as _;

    let body = STANDARD.encode(cert_der);

    let mut out = String::new();

    write!(out, "------BEGIN CERTIFICATE------")?;

    for (idx, char) in body.chars().enumerate() {
        if idx % 64 == 0 {
            write!(out, "\n{char}")?;
        } else {
            write!(out, "{char}")?;
        }
    }

    writeln!(out, "\n------END CERTIFICATE------")?;

    Ok(out)
}

struct DiagnosticTrace(std::sync::Mutex<Vec<u8>>);

impl DiagnosticTrace {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(std::sync::Mutex::new(Vec::new())))
    }

    fn finish(self: std::sync::Arc<Self>) -> String {
        let trace = std::sync::Arc::into_inner(self).expect("call finish when you are done logging");
        let inner = trace.0.into_inner().expect("poisoned");
        String::from_utf8(inner).expect("only write UTF-8")
    }
}

impl std::io::Write for &DiagnosticTrace {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("poisoned").write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn build_tracing_dispatcher(trace: std::sync::Arc<DiagnosticTrace>) -> tracing::Dispatch {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_env("JETSOCAT_LOG").unwrap_or_else(|_| EnvFilter::new("debug"));

    let subscriber = fmt::Subscriber::builder()
        .with_ansi(false)
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(trace)
        .finish();

    tracing::dispatcher::Dispatch::new(subscriber)
}
