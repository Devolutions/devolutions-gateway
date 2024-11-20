use std::fmt::Write as _;

use crate::doctor::macros::{diagnostic, output};
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
