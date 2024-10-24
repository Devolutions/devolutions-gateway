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
    common_checks::run(callback);

    #[cfg(feature = "rustls")]
    {
        rustls_checks::run(&args, callback);
    }

    #[cfg(feature = "native-tls")]
    {
        native_tls_checks::run(&args, callback);
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

macro_rules! diagnostic {
    ( $callback:ident, $name:ident ( $( $arg:expr ),* ) ) => {{
        use crate::doctor::{Diagnostic, DiagnosticCtx};

        let diagnostic_name = stringify!($name);

        let mut ctx = DiagnosticCtx::default();

        let result = $name ( &mut ctx, $( $arg ),* );

        let diagnostic = Diagnostic {
            name: diagnostic_name.to_owned(),
            success: result.is_ok(),
            output: (!ctx.out.is_empty()).then_some(ctx.out.trim_end().to_owned()),
            error: result.as_ref().err().map(|e| format!("{:?}", e)),
            help: ctx.help,
            links: ctx.links,
        };

        let success = (*$callback)(diagnostic);

        if !success {
            return;
        }
    }}
}

macro_rules! output {
    ( $dst:expr, $($arg:tt)* ) => {
        anyhow::Context::context(writeln!( $dst, $($arg)* ), "write output")
    };
}

#[derive(Default)]
struct DiagnosticCtx {
    out: String,
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

fn write_cert_as_pem(mut out: impl fmt::Write, cert_der: &[u8]) -> fmt::Result {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let body = STANDARD.encode(cert_der);

    write!(out, "------BEGIN CERTIFICATE------")?;

    for (idx, char) in body.chars().enumerate() {
        if idx % 64 == 0 {
            write!(out, "\n{char}")?;
        } else {
            write!(out, "{char}")?;
        }
    }

    writeln!(out, "\n------END CERTIFICATE------")?;

    Ok(())
}

mod common_checks {
    use std::fmt::Write as _;

    use crate::doctor::{Diagnostic, DiagnosticCtx};

    pub(super) fn run(callback: &mut dyn FnMut(Diagnostic) -> bool) {
        diagnostic!(callback, openssl_probe());
    }

    pub(crate) fn openssl_probe(ctx: &mut DiagnosticCtx) -> anyhow::Result<()> {
        let result = openssl_probe::probe();

        output!(ctx.out, "cert_file = {:?}", result.cert_file)?;
        output!(ctx.out, "cert_dir = {:?}", result.cert_dir)?;

        Ok(())
    }
}

#[cfg(feature = "rustls")]
mod rustls_checks {
    use anyhow::Context as _;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{pki_types, DigitallySignedStruct, Error, SignatureScheme};
    use std::fmt::Write as _;
    use std::ops::Deref;
    use std::path::Path;

    use crate::doctor::{help, write_cert_as_pem, Args, Diagnostic, DiagnosticCtx};

    pub(super) fn run(args: &Args, callback: &mut dyn FnMut(Diagnostic) -> bool) {
        let mut root_store = rustls::RootCertStore::empty();
        let mut server_certificates = Vec::new();

        diagnostic!(callback, rustls_load_native_certs(&mut root_store));

        if let Some(chain_path) = &args.chain_path {
            diagnostic!(callback, rustls_read_chain(&chain_path, &mut server_certificates));
        } else if let Some(subject_name) = args.subject_name.as_deref() {
            if args.allow_network {
                diagnostic!(
                    callback,
                    rustls_fetch_chain(subject_name, args.server_port, &mut server_certificates)
                );
            }
        }

        if !server_certificates.is_empty() {
            diagnostic!(
                callback,
                rustls_check_end_entity_cert(&server_certificates, args.subject_name.as_deref())
            );
            diagnostic!(callback, rustls_check_chain(&root_store, &server_certificates));
        }
    }

    fn rustls_load_native_certs(ctx: &mut DiagnosticCtx, root_store: &mut rustls::RootCertStore) -> anyhow::Result<()> {
        let result = rustls_native_certs::load_native_certs();

        for error in result.errors {
            output!(
                ctx.out,
                "-> Error when loading native certs: {:?}",
                anyhow::Error::new(error),
            )?;
        }

        for cert in result.certs {
            if let Err(e) = root_store.add(cert.clone()) {
                output!(ctx.out, "-> Invalid root certificate: {e}")?;
                write_cert_as_pem(&mut ctx.out, &cert).context("failed to write the certificate as PEM")?;
            }
        }

        Ok(())
    }

    fn rustls_fetch_chain(
        ctx: &mut DiagnosticCtx,
        subject_name: &str,
        port: Option<u16>,
        server_certificates: &mut Vec<pki_types::CertificateDer<'static>>,
    ) -> anyhow::Result<()> {
        use std::io::Write as _;
        use std::net::TcpStream;

        output!(ctx.out, "-> Connect to {subject_name}")?;

        let mut socket = TcpStream::connect((subject_name, port.unwrap_or(443)))
            .with_context(|| format!("failed to connect to {subject_name}..."))
            .inspect_err(|_| help::failed_to_connect_to_server(ctx, subject_name))?;

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoCertificateVerification))
            .with_no_client_auth();

        let config = std::sync::Arc::new(config);
        let subject_name = pki_types::ServerName::try_from(subject_name.to_owned()).context("invalid DNS name")?;
        let mut client = rustls::ClientConnection::new(config, subject_name).context("failed to create TLS client")?;

        output!(ctx.out, "-> Fetch server certificates")?;

        loop {
            if client.wants_read() {
                client.read_tls(&mut socket).context("read_tls failed")?;
                client.process_new_packets().context("process_new_packets failed")?;
            }

            if client.wants_write() {
                client.write_tls(&mut socket).context("write_tls failed")?;
            }

            socket.flush().context("flush failed")?;

            if let Some(peer_certificates) = client.peer_certificates() {
                for certificate in peer_certificates {
                    write_cert_as_pem(&mut ctx.out, certificate)
                        .context("failed to write the peer certificate as PEM")?;
                    server_certificates.push(certificate.clone().into_owned());
                }

                break;
            }
        }

        help::x509_io_link(ctx, server_certificates.iter().map(|cert| cert.deref()));

        Ok(())
    }

    fn rustls_read_chain(
        ctx: &mut DiagnosticCtx,
        chain_path: &Path,
        server_certificates: &mut Vec<pki_types::CertificateDer<'static>>,
    ) -> anyhow::Result<()> {
        output!(ctx.out, "-> Read file at {}", chain_path.display())?;

        let mut file = std::fs::File::open(chain_path)
            .map(std::io::BufReader::new)
            .context("read file from disk")?;

        for (idx, certificate) in rustls_pemfile::certs(&mut file).enumerate() {
            let certificate = certificate.with_context(|| format!("failed to read certificate number {idx}"))?;
            write_cert_as_pem(&mut ctx.out, &certificate)
                .with_context(|| format!("failed to write the certificate number {idx}"))?;
            server_certificates.push(certificate);
        }

        help::x509_io_link(ctx, server_certificates.iter().map(|cert| cert.deref()));

        Ok(())
    }

    fn rustls_check_end_entity_cert(
        ctx: &mut DiagnosticCtx,
        server_certificates: &[pki_types::CertificateDer<'static>],
        subject_name_to_verify: Option<&str>,
    ) -> anyhow::Result<()> {
        let end_entity_cert = server_certificates.first().cloned().context("empty chain")?;

        output!(ctx.out, "-> Decode end entity certificate")?;

        let end_entity_cert =
            rustls::server::ParsedCertificate::try_from(&end_entity_cert).context("parse end entity certificate")?;

        if let Some(subject_name_to_verify) = subject_name_to_verify {
            output!(ctx.out, "-> Verify validity for DNS name")?;

            let server_name = pki_types::ServerName::try_from(subject_name_to_verify).context("invalid DNS name")?;
            rustls::client::verify_server_name(&end_entity_cert, &server_name)
                .inspect_err(|_| help::cert_invalid_hostname(ctx, subject_name_to_verify))
                .context("verify DNS name")?;
        }

        Ok(())
    }

    fn rustls_check_chain(
        ctx: &mut DiagnosticCtx,
        root_store: &rustls::RootCertStore,
        server_certificates: &[pki_types::CertificateDer<'static>],
    ) -> anyhow::Result<()> {
        use rustls::client::verify_server_cert_signed_by_trust_anchor;

        let mut certs = server_certificates.iter().cloned();

        let end_entity_cert = certs.next().context("empty chain")?;

        output!(ctx.out, "-> Decode end entity certificate")?;

        let end_entity_cert =
            rustls::server::ParsedCertificate::try_from(&end_entity_cert).context("parse end entity certificate")?;

        output!(ctx.out, "-> Verify server certificate signed by trust anchor")?;

        let intermediates: Vec<_> = certs.collect();
        let now = pki_types::UnixTime::now();
        let ring_crypto_provider = rustls::crypto::ring::default_provider();

        verify_server_cert_signed_by_trust_anchor(
            &end_entity_cert,
            root_store,
            &intermediates,
            now,
            ring_crypto_provider.signature_verification_algorithms.all,
        )
        .inspect_err(|error| {
            if let Error::InvalidCertificate(cert_error) = error {
                match cert_error {
                    rustls::CertificateError::Expired => help::cert_is_expired(ctx),
                    rustls::CertificateError::NotValidYet => help::cert_is_not_yet_valid(ctx),
                    rustls::CertificateError::UnknownIssuer => help::cert_unknown_issuer(ctx),
                    rustls::CertificateError::InvalidPurpose => help::cert_invalid_purpose(ctx),
                    _ => (),
                }
            }
        })
        .context("failed to verify certification chain")?;

        Ok(())
    }

    #[derive(Debug)]
    struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _: &pki_types::CertificateDer<'_>,
            _: &[pki_types::CertificateDer<'_>],
            _: &pki_types::ServerName<'_>,
            _: &[u8],
            _: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

#[cfg(feature = "native-tls")]
mod native_tls_checks {
    use anyhow::Context as _;
    use std::fmt::Write as _;

    use crate::doctor::{help, write_cert_as_pem, Args, Diagnostic, DiagnosticCtx};

    pub(crate) fn run(args: &Args, callback: &mut dyn FnMut(Diagnostic) -> bool) {
        #[cfg(not(windows))]
        {
            openssl::run(args, callback);
        }

        match args.subject_name.as_deref() {
            Some(subject_name) if args.allow_network => {
                diagnostic!(callback, native_tls_connect(subject_name, args.server_port));
            }
            _ => {}
        }
    }

    fn native_tls_connect(ctx: &mut DiagnosticCtx, subject_name: &str, port: Option<u16>) -> anyhow::Result<()> {
        use native_tls::TlsConnector;
        use std::net::TcpStream;

        output!(ctx.out, "-> Connect to {subject_name}")?;

        let connector = TlsConnector::new().context("failed to build TLS connector")?;

        let socket = TcpStream::connect((subject_name, port.unwrap_or(443)))
            .inspect_err(|_| help::failed_to_connect_to_server(ctx, subject_name))
            .context("failed to connect to server...")?;

        output!(ctx.out, "-> Perform TLS handshake")?;

        let tls_stream = connector
            .connect(subject_name, socket)
            .inspect_err(|e| {
                let native_tls::HandshakeError::Failure(e) = e else {
                    unreachable!()
                };
                parse_tls_connect_error_string(ctx, e, subject_name)
            })
            .context("TLS connection failed")?;

        output!(
            ctx.out,
            "-> NOTE: We can't retrieve the certification chain using the API exposed by native-tls and schannel crates"
        )?;

        let peer_certificate = tls_stream
            .peer_certificate()
            .context("failed to retrieve peer certificate")?
            .context("no peer certificate attached to the TLS stream")?;
        let peer_certificate = peer_certificate.to_der().context("peer certificate der conversion")?;

        output!(ctx.out, "-> Peer certificate:")?;
        write_cert_as_pem(&mut ctx.out, &peer_certificate).context("failed to write the peer certificate as PEM")?;

        Ok(())
    }

    /// Parses Windows (schannel) error messages and convert them into a helpful diagnostic error
    #[cfg(target_os = "windows")]
    fn parse_tls_connect_error_string(ctx: &mut DiagnosticCtx, error: &native_tls::Error, hostname: &str) {
        let mut dyn_error: Option<&dyn std::error::Error> = Some(error);

        loop {
            let Some(source_error) = dyn_error.take() else {
                break;
            };

            if let Some(io_error) = source_error.downcast_ref::<std::io::Error>() {
                if let Some(code) = io_error.raw_os_error() {
                    if os_error_look_up(ctx, hostname, code) {
                        break;
                    }
                }
            }

            let formatted_error = source_error.to_string();

            if str_look_up(ctx, hostname, &formatted_error) {
                break;
            }

            dyn_error = source_error.source();
        }

        fn os_error_look_up(ctx: &mut DiagnosticCtx, hostname: &str, code: i32) -> bool {
            match code {
                -2146762481 => {
                    help::cert_invalid_hostname(ctx, hostname);
                    true
                }
                -2146762487 => {
                    help::cert_unknown_issuer(ctx);
                    true
                }
                -2146762495 => {
                    help::cert_is_expired(ctx);
                    true
                }
                _ => false,
            }
        }

        fn str_look_up(ctx: &mut DiagnosticCtx, hostname: &str, s: &str) -> bool {
            if s.contains("CN name does not match the passed value") {
                help::cert_invalid_hostname(ctx, hostname);
                true
            } else if s.contains("terminated in a root certificate which is not trusted by the trust provider") {
                help::cert_unknown_issuer(ctx);
                true
            } else if s.contains("not within its validity period when verifying against the current system clock") {
                help::cert_is_expired(ctx);
                true
            } else {
                false
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn parse_tls_connect_error_string(_ctx: &mut DiagnosticCtx, _error: &native_tls::Error, _hostname: &str) {}

    #[cfg(not(any(target_os = "windows", target_vendor = "apple")))]
    mod openssl {
        use anyhow::Context as _;
        use openssl::x509::X509;
        use std::fmt::Write as _;
        use std::path::Path;

        use crate::doctor::{help, write_cert_as_pem, Args, Diagnostic, DiagnosticCtx};

        pub(super) fn run(args: &Args, callback: &mut dyn FnMut(Diagnostic) -> bool) {
            let mut server_certificates = Vec::new();

            if let Some(chain_path) = &args.chain_path {
                diagnostic!(callback, openssl_read_chain(&chain_path, &mut server_certificates));
            } else if let Some(subject_name) = args.subject_name.as_deref() {
                if args.allow_network {
                    diagnostic!(
                        callback,
                        openssl_fetch_chain(subject_name, args.server_port, &mut server_certificates)
                    );
                }
            }

            if !server_certificates.is_empty() {
                if let Some(subject_name) = args.subject_name.as_deref() {
                    diagnostic!(
                        callback,
                        openssl_check_end_entity_cert(subject_name, &server_certificates)
                    );
                }

                diagnostic!(callback, openssl_check_chain(&server_certificates));
            }
        }

        fn openssl_fetch_chain(
            ctx: &mut DiagnosticCtx,
            subject_name: &str,
            port: Option<u16>,
            server_certificates: &mut Vec<X509>,
        ) -> anyhow::Result<()> {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
            use std::net::TcpStream;

            output!(ctx.out, "-> Connect to {subject_name}")?;

            let mut builder = SslConnector::builder(SslMethod::tls_client()).context("failed to create SSL builder")?;
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();

            let socket = TcpStream::connect((subject_name, port.unwrap_or(443)))
                .inspect_err(|_| help::failed_to_connect_to_server(ctx, subject_name))
                .context("failed to connect to server...")?;

            output!(ctx.out, "-> Fetch server certificates")?;

            let stream = connector
                .connect(subject_name, socket)
                .context("TLS connection failed")?;

            let ssl = stream.ssl();

            // On the client side, the chain includes the leaf certificate, but on the server side it does not. Fun!
            for certificate in ssl
                .peer_cert_chain()
                .context("peer certification chain missing from SSL context")?
            {
                let der = certificate.to_der().context("certificate.to_der()")?;
                write_cert_as_pem(&mut ctx.out, &der).context("failed to write the peer chain as PEM")?;
                server_certificates.push(certificate.to_owned());
            }

            help::x509_io_link(
                ctx,
                server_certificates
                    .iter()
                    .map(|cert| cert.to_der().expect("checked above")),
            );

            Ok(())
        }

        fn openssl_read_chain(
            ctx: &mut DiagnosticCtx,
            chain_path: &Path,
            server_certificates: &mut Vec<X509>,
        ) -> anyhow::Result<()> {
            output!(ctx.out, "-> Read file at {}", chain_path.display())?;

            let mut file = std::fs::File::open(chain_path)
                .map(std::io::BufReader::new)
                .context("read file from disk")?;

            for (idx, certificate) in rustls_pemfile::certs(&mut file).enumerate() {
                let certificate = certificate.with_context(|| format!("failed to read certificate number {idx}"))?;
                write_cert_as_pem(&mut ctx.out, &certificate)
                    .with_context(|| format!("failed to write certificate number {idx} as PEM"))?;
                let certificate = X509::from_der(&certificate).context("X509::from_der")?;
                server_certificates.push(certificate);
            }

            help::x509_io_link(
                ctx,
                server_certificates
                    .iter()
                    .map(|cert| cert.to_der().expect("checked above")),
            );

            Ok(())
        }

        fn openssl_check_end_entity_cert(
            ctx: &mut DiagnosticCtx,
            subject_name_to_verify: &str,
            server_certificates: &[X509],
        ) -> anyhow::Result<()> {
            let certificate = server_certificates
                .first()
                .context("end entity certificate is missing")?;

            output!(ctx.out, "-> Inspect the end entity certificate")?;

            let mut certificate_names = Vec::new();

            let certificate_subject_name = certificate.subject_name();

            for entry in certificate_subject_name.entries() {
                if entry.object().nid() == openssl::nid::Nid::COMMONNAME {
                    if let Ok(data) = entry.data().as_utf8() {
                        certificate_names.push(data.to_owned());
                    }
                }
            }

            if let Some(alt_names) = certificate.subject_alt_names() {
                for name in alt_names {
                    if let Some(dnsname) = name.dnsname() {
                        certificate_names.push(dnsname.to_owned());
                    }

                    if let Some(directory_name) = name.directory_name() {
                        for entry in directory_name.entries() {
                            if entry.object().nid() == openssl::nid::Nid::COMMONNAME {
                                if let Ok(data) = entry.data().as_utf8() {
                                    certificate_names.push(data.to_owned());
                                }
                            }
                        }
                    }
                }
            }

            for value in &certificate_names {
                output!(ctx.out, "-> Found name: {value}")?;
            }

            output!(ctx.out, "-> Verify validity for subject name {subject_name_to_verify}")?;

            let success = certificate_names
                .into_iter()
                .any(|certificate_name| wildcard_host_match(&certificate_name, subject_name_to_verify));

            if !success {
                help::cert_invalid_hostname(ctx, subject_name_to_verify);
                anyhow::bail!("the subject name '{subject_name_to_verify}' does not match any domain identified by the certificate");
            }

            return Ok(());

            fn wildcard_host_match(wildcard_host: &str, actual_host: &str) -> bool {
                let mut expected_it = wildcard_host.rsplit('.');
                let mut actual_it = actual_host.rsplit('.');
                loop {
                    match (expected_it.next(), actual_it.next()) {
                        (Some(expected), Some(actual)) if expected.eq_ignore_ascii_case(actual) => {}
                        (Some("*"), Some(_)) => {}
                        (None, None) => return true,
                        _ => return false,
                    }
                }
            }
        }

        fn openssl_check_chain(ctx: &mut DiagnosticCtx, server_certificates: &[X509]) -> anyhow::Result<()> {
            use openssl::ssl::{SslConnector, SslMethod};
            use openssl::stack::Stack;
            use openssl::x509::X509StoreContext;
            use openssl::x509::X509VerifyResult;

            output!(ctx.out, "-> Create SSL context")?;

            let connector = SslConnector::builder(SslMethod::tls_client())
                .context("failed to create SSL builder")?
                .build();

            let connection_configuration = connector.configure().context("failed to configure")?;

            // Use an arbitrary "foo" domain name because X509_verify_cert doesn’t verify it anyway.
            let ssl = connection_configuration.into_ssl("foo").context("into_ssl")?;

            let ssl_context = ssl.ssl_context();
            let store = ssl_context.cert_store();

            output!(ctx.out, "-> Verify chain")?;

            let mut store_context = X509StoreContext::new().context("failed to create X509 store context")?;

            let mut certs = server_certificates.iter();

            let leaf_certificate = certs.next().context("leaf certificate is missing")?;

            let mut chain = Stack::new().context("create chain stack")?;

            for intermediate_certificate in certs {
                chain
                    .push(intermediate_certificate.clone())
                    .context("failed to push extra intermediate certificate")?;
            }

            let result = store_context
                .init(store, leaf_certificate, &chain, |ctx| {
                    ctx.verify_cert()?;
                    Ok(ctx.error())
                })
                .context("verification failed")?;

            if result != X509VerifyResult::OK {
                match result.as_raw() {
                    10 => help::cert_is_expired(ctx),
                    18 => help_cert_is_self_signed(ctx),
                    19 => help::cert_unknown_issuer(ctx),
                    _ => (),
                }

                anyhow::bail!("chain verification failed: {}", result.error_string());
            }

            Ok(())
        }

        pub(crate) fn help_cert_is_self_signed(ctx: &mut DiagnosticCtx) {
            ctx.attach_help("The certificate is self-signed.
It is generally considered a bad practice to use self-signed certificates, because it goes against the purpose of public key infrastructures (PKIs).
To resolve this issue, you can:
- Trust the self-signed certificate on your system, if you know what you are doing.
- Obtain and use a certificate signed by a legitimate certification authority.");
        }
    }
}

mod help {
    use core::fmt;

    use crate::doctor::DiagnosticCtx;

    pub(crate) fn failed_to_connect_to_server(ctx: &mut DiagnosticCtx, hostname: &str) {
        ctx.attach_help(format!(
            "Connection could not be established with the server for the hostname '{hostname}'.
Please verify that:
- '{hostname}' is the correct hostname.
- The server is up and running.
- You correctly configured DNS records for '{hostname}'."
        ));
    }

    pub(crate) fn cert_invalid_hostname(ctx: &mut DiagnosticCtx, hostname: &str) {
        ctx.attach_help(format!(
            "The certificate is not valid for the subject name '{hostname}' (domain/DNS name).
To resolve this issue, you can:
- Update your DNS records to use a domain that is matched by the certificate, and use this name instead.
- Generate and install a new certificate that includes '{hostname}'.
Please note that asterisks '*' found in domain name fragments of wildcard certificates only match one level of subdomains.
For example: 'a.b.c' is matched by '*.b.c', but is not matched by '*.c' (the wildcard does not cover multiple levels)."
        ));

        ctx.attach_link(
            "Public key certificate",
            "https://en.wikipedia.org/wiki/Public_key_certificate",
            "more information on certificate structure, types such as Wildcard certificates, certificate authorities, and so on",
        );
    }

    pub(crate) fn cert_unknown_issuer(ctx: &mut DiagnosticCtx) {
        ctx.attach_help( "The issuer is not trusted by the trust provider (issuer is unknown).
Please ensure the following:
- The server is providing intermediate certificates along with the leaf certificate.
- If you are using a custom root CA managed by you or your organization, verify that the root certificate is installed and trusted on your system.
- For self-signed certificates, either trust the certificate on your system or obtain one signed by a recognized certificate authority.
If none of the above applies, you could be facing a Man-in-the-Middle (MITM) attack.".to_owned());

        ctx.attach_link(
            "Man-in-the-middle attack",
            "https://en.wikipedia.org/wiki/Man-in-the-middle_attack",
            "more information on MITM attacks",
        );
    }

    pub(crate) fn cert_is_expired(ctx: &mut DiagnosticCtx) {
        ctx.attach_help(
            "The certificate has expired.
To resolve this, you should:
- Renew the certificate through your certification authority.
- Install the new certificate on your server.
If you believe the certificate should still be valid, verify that your system clock is set to the correct time."
                .to_owned(),
        );
    }

    pub(crate) fn cert_is_not_yet_valid(ctx: &mut DiagnosticCtx) {
        ctx.attach_help(
            "The certificate is not yet valid.
Make sure your clock is set to the correct time."
                .to_owned(),
        )
    }

    pub(crate) fn cert_invalid_purpose(ctx: &mut DiagnosticCtx) {
        ctx.attach_help(
            "The certificate is not valid for server authentication.
You need to generate a separate certificate valid for server authentication."
                .to_owned(),
        )
    }

    pub(crate) fn x509_io_link<C>(ctx: &mut DiagnosticCtx, certs: C)
    where
        C: Iterator,
        C::Item: AsRef<[u8]>,
    {
        let mut href = String::new();
        write_x509_io_link(&mut href, certs)
            .expect("writing to a String will typially not cause any error (unless OOM)");

        ctx.attach_link(
            "x509.io Certificates Viewer",
            href,
            "view the extracted certification chain using x509.io certificates viewer in the browser",
        );

        fn write_x509_io_link<C>(mut out: impl fmt::Write, certs: C) -> fmt::Result
        where
            C: Iterator,
            C::Item: AsRef<[u8]>,
        {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine as _;

            write!(out, "https://x509.io/?cert=")?;

            let mut is_first = true;

            for cert_der in certs {
                if is_first {
                    is_first = false;
                } else {
                    write!(out, ",")?;
                }

                let cert_base64 = URL_SAFE_NO_PAD.encode(cert_der.as_ref());

                write!(out, "{cert_base64}")?;
            }

            Ok(())
        }
    }
}
