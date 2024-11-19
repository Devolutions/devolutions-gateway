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

pub(crate) use diagnostic;

macro_rules! output {
    ( $dst:expr, $($arg:tt)* ) => {
        anyhow::Context::context(writeln!( $dst, $($arg)* ), "write output")
    };
}

pub(crate) use output;
