use std::sync::{Arc, Mutex};

use tracing::span;

#[derive(Clone, Debug)]
pub struct CovMarkSubscriber {
    records: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone, Debug)]
pub struct CovMarkHandle {
    records: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone, Debug)]
struct CovMarkVisitor {
    records: Arc<Mutex<Vec<String>>>,
}

pub fn init_cov_mark() -> (CovMarkHandle, tracing::subscriber::DefaultGuard) {
    let subscriber = CovMarkSubscriber::new();
    let cov_handle = subscriber.handle();
    let default_guard = tracing::subscriber::set_default(subscriber);
    (cov_handle, default_guard)
}

impl CovMarkSubscriber {
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn handle(&self) -> CovMarkHandle {
        CovMarkHandle {
            records: self.records.clone(),
        }
    }
}

impl Default for CovMarkSubscriber {
    fn default() -> Self {
        Self::new()
    }
}

impl tracing::Subscriber for CovMarkSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = CovMarkVisitor {
            records: self.records.clone(),
        };
        event.record(&mut visitor);
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

impl CovMarkHandle {
    #[track_caller]
    pub fn assert_mark(&self, covmark: &str) {
        let mut guard = self.records.lock().unwrap();
        let idx = guard
            .iter()
            .enumerate()
            .find_map(|(idx, mark)| (mark.as_str() == covmark).then_some(idx))
            .expect("coverage marker not emitted");
        guard.remove(idx);
    }
}

impl tracing::field::Visit for CovMarkVisitor {
    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "covmark" {
            self.records.lock().unwrap().push(value.to_owned());
        }
    }
}
