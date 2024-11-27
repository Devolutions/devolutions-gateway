use crate::doctor::macros::diagnostic;
use crate::doctor::{Diagnostic, DiagnosticCtx};

pub(super) fn run(callback: &mut dyn FnMut(Diagnostic) -> bool) {
    diagnostic!(callback, openssl_probe());
}

pub(crate) fn openssl_probe(_: &mut DiagnosticCtx) -> anyhow::Result<()> {
    let result = openssl_probe::probe();

    info!(cert_file = ?result.cert_file);
    info!(cert_dir = ?result.cert_dir);

    Ok(())
}
