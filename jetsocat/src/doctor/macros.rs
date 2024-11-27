macro_rules! diagnostic {
    ( $callback:ident, $name:ident ( $( $arg:expr ),* ) ) => {{
        use crate::doctor::{Diagnostic, DiagnosticCtx};

        let diagnostic_name = stringify!($name);

        let trace = $crate::doctor::DiagnosticTrace::new();

        let mut ctx = DiagnosticCtx::default();

        let result = {
            let dispatcher = $crate::doctor::build_tracing_dispatcher(std::sync::Arc::clone(&trace));
            tracing::dispatcher::with_default(&dispatcher, || $name ( &mut ctx, $( $arg ),* ))
        };

        let output = trace.finish();

        let diagnostic = Diagnostic {
            name: diagnostic_name.to_owned(),
            success: result.is_ok(),
            output: (!output.is_empty()).then_some(output.trim_end().to_owned()),
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
