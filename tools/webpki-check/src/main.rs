use std::process::ExitCode;

fn main() -> Result<(), ExitCode> {
    let (Some(cert_path), Some(subject_name)) = (std::env::args().nth(1), std::env::args().nth(2)) else {
        let pkg_name = env!("CARGO_PKG_NAME");
        println!("Usage: {pkg_name} [CERT FILE] [SUBJECT NAME]");
        return Err(ExitCode::FAILURE);
    };

    let subject_name = match webpki::SubjectNameRef::try_from_ascii_str(&subject_name) {
        Ok(name) => name,
        Err(e) => {
            println!("Error: invalid subject name. {e:?}");
            return Err(ExitCode::FAILURE);
        }
    };

    println!("Read file at {cert_path}");

    let cert_val = match std::fs::read(cert_path) {
        Ok(contents) => contents,
        Err(e) => {
            println!("Error: couldn’t read file. {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    let cert_der = match pem::parse(&cert_val) {
        Ok(cert_pem) => {
            println!("Detected PEM format");

            let pem_tag = cert_pem.tag();

            if pem_tag != "CERTIFICATE" {
                println!("WARNING: unexpected PEM tag: {pem_tag}");
            }

            cert_pem.into_contents()
        }
        Err(pem::PemError::NotUtf8(_)) => {
            println!("Read as raw DER");
            cert_val
        }
        Err(e) => {
            println!("Failed to read as PEM: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    let end_entity_cert = match webpki::EndEntityCert::try_from(cert_der.as_slice()) {
        Ok(cert) => cert,
        Err(e) => {
            println!("Error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    match end_entity_cert.verify_is_valid_for_subject_name(subject_name) {
        Ok(()) => {
            println!("=> Ok");
            Ok(())
        }
        Err(e) => {
            println!("Error: {e}");
            Err(ExitCode::FAILURE)
        }
    }
}
