use std::process::ExitCode;

fn main() -> Result<(), ExitCode> {
    let (Some(cert_path), Some(subject_name)) = (std::env::args().nth(1), std::env::args().nth(2)) else {
        let pkg_name = env!("CARGO_PKG_NAME");
        println!("Usage: {pkg_name} [CERT FILE] [SUBJECT NAME]");
        return Err(ExitCode::FAILURE);
    };

    let subject_name = webpki::DnsNameRef::try_from_ascii_str(&subject_name).ctx("invalid subject name")?;

    println!("=> Read file at {cert_path}");

    let cert_val = std::fs::read(cert_path).ctx("couldn’t read file")?;

    let cert_der = match pem::parse(&cert_val) {
        Ok(cert_pem) => {
            println!("=> Detected PEM format");

            let pem_tag = cert_pem.tag();

            if pem_tag != "CERTIFICATE" {
                println!("WARNING: unexpected PEM tag: {pem_tag}");
            }

            cert_pem.into_contents()
        }
        Err(pem::PemError::NotUtf8(_)) => {
            println!("=> Read as raw DER");
            cert_val
        }
        Err(e) => {
            println!("Error: failed to read as PEM: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    println!("=> Decode end entity certificate");

    let end_entity_cert = webpki::EndEntityCert::try_from(cert_der.as_slice()).ctx("end entity cert decoding")?;

    println!("=> Verify validity for DNS name");

    end_entity_cert
        .verify_is_valid_for_dns_name(subject_name)
        .ctx("verify is valid for DNS name")?;

    println!("=> Ok");

    Ok(())
}

trait ResultExt<T> {
    fn ctx(self, note: &'static str) -> Result<T, ExitCode>;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: core::fmt::Display,
{
    fn ctx(self, note: &'static str) -> Result<T, ExitCode> {
        self.map_err(|e| {
            println!("Error: {note}. {e}");
            ExitCode::FAILURE
        })
    }
}
