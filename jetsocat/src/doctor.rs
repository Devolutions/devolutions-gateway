use core::fmt;
use std::path::PathBuf;

use tinyjson::JsonValue;

macro_rules! diagnostic {
    ( $callback:ident, $name:ident ( $( $arg:expr ),* ) ) => {{
        let diagnostic_name = stringify!($name);

        let mut output = String::new();
        let result = $name ( &mut output, $( $arg ),* );

        let diagnostic = Diagnostic {
            name: diagnostic_name.to_owned(),
            success: result.is_ok(),
            output: (!output.is_empty()).then_some(output),
            error: result.err().map(|e| format!("{e:?}")),
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
                    write!(f, "\n\n### Error\n{error_message}")?;
                }

                Ok(())
            }
        }
    }
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
    use core::fmt;

    use super::Diagnostic;

    pub(super) fn run(callback: &mut dyn FnMut(Diagnostic) -> bool) {
        diagnostic!(callback, openssl_probe());
    }

    pub(crate) fn openssl_probe(mut out: impl fmt::Write) -> anyhow::Result<()> {
        let result = openssl_probe::probe();

        output!(out, "cert_file = {:?}", result.cert_file)?;
        output!(out, "cert_dir = {:?}", result.cert_dir)?;

        Ok(())
    }
}

#[cfg(feature = "rustls")]
mod rustls_checks {
    use anyhow::Context as _;
    use core::fmt;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{pki_types, DigitallySignedStruct, Error, SignatureScheme};
    use std::path::Path;

    use super::{write_cert_as_pem, Args, Diagnostic};

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

    fn rustls_load_native_certs(
        mut out: impl fmt::Write,
        root_store: &mut rustls::RootCertStore,
    ) -> anyhow::Result<()> {
        for cert in rustls_native_certs::load_native_certs().context("failed to load native certificates")? {
            if let Err(e) = root_store.add(cert.clone()) {
                output!(out, "-> Invalid root certificate: {e}")?;
                write_cert_as_pem(&mut out, &cert)?;
            }
        }

        Ok(())
    }

    fn rustls_fetch_chain(
        mut out: impl fmt::Write,
        subject_name: &str,
        port: Option<u16>,
        server_certificates: &mut Vec<pki_types::CertificateDer<'static>>,
    ) -> anyhow::Result<()> {
        use std::io::Write as _;
        use std::net::TcpStream;

        output!(out, "-> Connect to {subject_name}")?;

        let mut socket =
            TcpStream::connect((subject_name, port.unwrap_or(443))).context("failed to connect to server...")?;

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoCertificateVerification))
            .with_no_client_auth();

        let config = std::sync::Arc::new(config);
        let subject_name = pki_types::ServerName::try_from(subject_name.to_owned()).context("invalid DNS name")?;
        let mut client = rustls::ClientConnection::new(config, subject_name).context("failed to create TLS client")?;

        output!(out, "-> Fetch server certificates")?;

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
                    write_cert_as_pem(&mut out, certificate)?;
                    server_certificates.push(certificate.clone().into_owned());
                }

                break;
            }
        }

        Ok(())
    }

    fn rustls_read_chain(
        mut out: impl fmt::Write,
        chain_path: &Path,
        server_certificates: &mut Vec<pki_types::CertificateDer<'static>>,
    ) -> anyhow::Result<()> {
        output!(out, "-> Read file at {}", chain_path.display())?;

        let mut file = std::fs::File::open(chain_path)
            .map(std::io::BufReader::new)
            .context("read file from disk")?;

        for (idx, certificate) in rustls_pemfile::certs(&mut file).enumerate() {
            let certificate = certificate.with_context(|| format!("failed to read certificate number {idx}"))?;
            write_cert_as_pem(&mut out, &certificate)?;
            server_certificates.push(certificate);
        }

        Ok(())
    }

    fn rustls_check_end_entity_cert(
        mut out: impl fmt::Write,
        server_certificates: &[pki_types::CertificateDer<'static>],
        subject_name: Option<&str>,
    ) -> anyhow::Result<()> {
        let end_entity_cert = server_certificates.first().cloned().context("empty chain")?;

        output!(out, "-> Decode end entity certificate")?;

        let end_entity_cert =
            rustls::server::ParsedCertificate::try_from(&end_entity_cert).context("parse end entity certificate")?;

        if let Some(subject_name) = subject_name {
            output!(out, "-> Verify validity for DNS name")?;

            let subject_name = pki_types::ServerName::try_from(subject_name).context("invalid DNS name")?;
            rustls::client::verify_server_name(&end_entity_cert, &subject_name).context("verify DNS name")?;
        }

        Ok(())
    }

    fn rustls_check_chain(
        mut out: impl fmt::Write,
        root_store: &rustls::RootCertStore,
        server_certificates: &[pki_types::CertificateDer<'static>],
    ) -> anyhow::Result<()> {
        use rustls::client::verify_server_cert_signed_by_trust_anchor;

        let mut certs = server_certificates.iter().cloned();

        let end_entity_cert = certs.next().context("empty chain")?;

        output!(out, "-> Decode end entity certificate")?;

        let end_entity_cert =
            rustls::server::ParsedCertificate::try_from(&end_entity_cert).context("parse end entity certificate")?;

        output!(out, "-> Verify server certificate signed by trust anchor")?;

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
    use core::fmt;

    use crate::doctor::{write_cert_as_pem, Args, Diagnostic};

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

    fn native_tls_connect(mut out: impl fmt::Write, subject_name: &str, port: Option<u16>) -> anyhow::Result<()> {
        use native_tls::TlsConnector;
        use std::net::TcpStream;

        output!(out, "-> Connect to {subject_name}")?;

        let connector = TlsConnector::new().context("failed to build TLS connector")?;

        let socket =
            TcpStream::connect((subject_name, port.unwrap_or(443))).context("failed to connect to server...")?;

        output!(out, "-> Perform TLS handshake")?;

        let tls_stream = connector
            .connect(subject_name, socket)
            .context("TLS connection failed")?;

        output!(
            out,
            "-> NOTE: We can't retrieve the certification chain using the API exposed by native-tls and schannel crates"
        )?;

        let peer_certificate = tls_stream
            .peer_certificate()
            .context("failed to retrieve peer certificate")?
            .context("no peer certificate attached to the TLS stream")?;
        let peer_certificate = peer_certificate.to_der().context("peer certificate der conversion")?;

        output!(out, "-> Peer certificate:")?;
        write_cert_as_pem(&mut out, &peer_certificate)?;

        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_vendor = "apple")))]
    mod openssl {
        use anyhow::Context as _;
        use core::fmt;
        use openssl::x509::X509;
        use std::path::Path;

        use crate::doctor::{write_cert_as_pem, Args, Diagnostic};

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
            mut out: impl fmt::Write,
            subject_name: &str,
            port: Option<u16>,
            server_certificates: &mut Vec<X509>,
        ) -> anyhow::Result<()> {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
            use std::net::TcpStream;

            output!(out, "-> Connect to {subject_name}")?;

            let mut builder = SslConnector::builder(SslMethod::tls()).context("failed to create SSL builder")?;
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();

            let socket =
                TcpStream::connect((subject_name, port.unwrap_or(443))).context("failed to connect to server...")?;

            output!(out, "-> Fetch server certificates")?;

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
                write_cert_as_pem(&mut out, &der)?;
                server_certificates.push(certificate.to_owned());
            }

            Ok(())
        }

        fn openssl_read_chain(
            mut out: impl fmt::Write,
            chain_path: &Path,
            server_certificates: &mut Vec<X509>,
        ) -> anyhow::Result<()> {
            output!(out, "-> Read file at {}", chain_path.display())?;

            let mut file = std::fs::File::open(chain_path)
                .map(std::io::BufReader::new)
                .context("read file from disk")?;

            for (idx, certificate) in rustls_pemfile::certs(&mut file).enumerate() {
                let certificate = certificate.with_context(|| format!("failed to read certificate number {idx}"))?;
                write_cert_as_pem(&mut out, &certificate)?;
                let certificate = X509::from_der(&certificate).context("X509::from_der")?;
                server_certificates.push(certificate);
            }

            Ok(())
        }

        fn openssl_check_end_entity_cert(
            mut out: impl fmt::Write,
            subject_name_to_verify: &str,
            server_certificates: &[X509],
        ) -> anyhow::Result<()> {
            let certificate = server_certificates
                .first()
                .context("end entity certificate is missing")?;

            output!(out, "-> Inspect the end entity certificate")?;

            let mut certificate_names = Vec::new();

            let certificate_subject_name = certificate.subject_name();

            for entry in certificate_subject_name.entries() {
                let Ok(data) = entry.data().as_utf8() else { continue };
                certificate_names.push(data.to_owned());
            }

            if let Some(alt_names) = certificate.subject_alt_names() {
                for name in alt_names {
                    if let Some(dnsname) = name.dnsname() {
                        certificate_names.push(dnsname.to_owned());
                    }

                    if let Some(directory_name) = name.directory_name() {
                        for entry in directory_name.entries() {
                            let Ok(data) = entry.data().as_utf8() else { continue };
                            certificate_names.push(data.to_owned());
                        }
                    }
                }
            }

            for value in &certificate_names {
                output!(out, "-> Found name: {value}")?;
            }

            output!(out, "-> Verify validity for subject name {subject_name_to_verify}")?;

            let success = certificate_names
                .into_iter()
                .any(|certificate_name| wildcard_host_match(&certificate_name, subject_name_to_verify));

            if !success {
                anyhow::bail!("{subject_name_to_verify} doesn't match any domain identified by the certificate");
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

        fn openssl_check_chain(mut out: impl fmt::Write, server_certificates: &[X509]) -> anyhow::Result<()> {
            use openssl::ssl::{SslConnector, SslMethod};
            use openssl::stack::Stack;
            use openssl::x509::X509StoreContext;
            use openssl::x509::X509VerifyResult;

            output!(out, "-> Create SSL context")?;

            let connector = SslConnector::builder(SslMethod::tls_client())
                .context("failed to create SSL builder")?
                .build();

            let connection_configuration = connector.configure().context("failed to configure")?;

            // Use an arbitrary "foo" domain name because X509_verify_cert doesn’t verify it anyway.
            let ssl = connection_configuration.into_ssl("foo").context("into_ssl")?;

            let ssl_context = ssl.ssl_context();
            let store = ssl_context.cert_store();

            output!(out, "-> Verify chain")?;

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
                anyhow::bail!("chain verification failed: {}", result.error_string());
            }

            Ok(())
        }
    }
}
