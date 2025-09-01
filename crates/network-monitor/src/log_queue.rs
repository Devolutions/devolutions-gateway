use std::collections::VecDeque;
use std::mem;
use std::sync::Mutex;

/// Thread-safe VecDeque which can be drained (consumed until empty) without blocking writers.
pub(crate) struct LogQueue<T> {
    entries: Mutex<VecDeque<T>>,
}

impl<T> LogQueue<T> {
    pub(crate) fn new() -> Self {
        LogQueue {
            entries: Mutex::new(VecDeque::new()),
        }
    }

    pub(crate) fn write(&self, data: T) {
        let mut entries = self.entries.lock().expect("poisoned");

        entries.push_back(data);
    }

    pub(crate) fn drain(&self) -> VecDeque<T> {
        let mut entries = self.entries.lock().expect("poisoned");

        mem::take(&mut entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_drain_returns_logged_value() {
        // Given
        let log: LogQueue<String> = LogQueue::new();
        log.write(String::from("hey"));

        // When
        let result = log.drain();

        // Then
        assert!(result.len() == 1 && result.front().unwrap() == "hey");
    }

    #[test]
    fn write_and_drain_clears_log() {
        // Given
        let log: LogQueue<String> = LogQueue::new();
        log.write(String::from("hey"));

        // When
        _ = log.drain();

        // Then
        let result = log.drain();
        assert!(result.len() == 0);
    }
}
