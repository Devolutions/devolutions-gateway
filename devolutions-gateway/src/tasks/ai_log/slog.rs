//! Writes AI actions as a Session Recording Log (`.slog`): one JSON object per line, in the shipped schema.

use std::collections::BTreeMap;
use std::time::Duration;

use devolutions_gateway_ai::session_actions::{Action, PROMPT_VERSION};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Entry<'a> {
    timestamp: String,
    seq: usize,
    event: &'static str,
    description: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    object: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt_version: Option<&'static str>,
}

impl<'a> Entry<'a> {
    fn new(seq: usize, timestamp: String, event: &'static str, description: &'a str) -> Self {
        Self {
            timestamp,
            seq,
            event,
            description,
            object: None,
            parameters: None,
            source: None,
            model: None,
            prompt_version: None,
        }
    }
}

/// Writes the log of a session entry by entry, so the actions never have to be all in memory.
pub(crate) struct SlogWriter<W> {
    out: W,
    start_time: i64,
    seq: usize,
}

impl<W: std::io::Write> SlogWriter<W> {
    /// Writes `session.start` for a session that started at `start_time` (unix seconds).
    pub(crate) fn start(out: W, start_time: i64, model: &str) -> anyhow::Result<Self> {
        let mut writer = Self {
            out,
            start_time,
            seq: 0,
        };

        let timestamp = timestamp(start_time, Duration::ZERO)?;
        writer.write(Entry {
            source: Some("ai"),
            model: Some(model),
            prompt_version: Some(PROMPT_VERSION),
            ..Entry::new(0, timestamp, "session.start", "Session started")
        })?;

        Ok(writer)
    }

    /// Actions must come in offset order.
    pub(crate) fn action(&mut self, action: &Action) -> anyhow::Result<()> {
        let timestamp = timestamp(self.start_time, action.offset)?;
        self.write(Entry {
            object: action.object.as_deref(),
            parameters: Some(&action.parameters).filter(|parameters| !parameters.is_empty()),
            ..Entry::new(self.seq, timestamp, "session.action", &action.description)
        })
    }

    /// Writes `session.end` for a session that lasted `duration` seconds.
    pub(crate) fn finish(mut self, duration: i64) -> anyhow::Result<W> {
        let end_offset = Duration::from_secs(u64::try_from(duration).unwrap_or(0));
        let timestamp = timestamp(self.start_time, end_offset)?;
        self.write(Entry::new(self.seq, timestamp, "session.end", "Session ended"))?;
        self.out.flush()?;
        Ok(self.out)
    }

    fn write(&mut self, entry: Entry<'_>) -> anyhow::Result<()> {
        serde_json::to_writer(&mut self.out, &entry)?;
        self.out.write_all(b"\n")?;
        self.seq += 1;
        Ok(())
    }
}

/// ISO 8601 UTC time with milliseconds, like the other `.slog` writers.
fn timestamp(start_time: i64, offset: Duration) -> anyhow::Result<String> {
    let time = time::OffsetDateTime::from_unix_timestamp(start_time)?
        .checked_add(time::Duration::try_from(offset)?)
        .ok_or_else(|| anyhow::anyhow!("timestamp out of range"))?;

    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        time.millisecond(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(start_time: i64, duration: i64, actions: &[Action]) -> String {
        let mut writer = SlogWriter::start(Vec::new(), start_time, "gpt-test").expect("started");
        for action in actions {
            writer.action(action).expect("written");
        }
        String::from_utf8(writer.finish(duration).expect("finished")).expect("UTF-8")
    }

    fn action(offset_ms: u64, description: &str, object: Option<&str>, parameters: &[(&str, &str)]) -> Action {
        Action {
            offset: Duration::from_millis(offset_ms),
            description: description.to_owned(),
            object: object.map(str::to_owned),
            parameters: parameters
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn writes_the_shipped_schema_with_ai_fields_on_session_start() {
        let actions = [
            action(1500, "Listed files", Some("/var/log"), &[("Command", "ls /var/log")]),
            action(62_250, "Closed the shell", None, &[]),
        ];

        let slog = write(1_787_255_035, 90, &actions);

        let session_start = format!(
            r#"{{"timestamp":"2026-08-20T19:43:55.000Z","seq":0,"event":"session.start","description":"Session started","source":"ai","model":"gpt-test","promptVersion":"{PROMPT_VERSION}"}}"#
        );

        let expected = [
            session_start.as_str(),
            r#"{"timestamp":"2026-08-20T19:43:56.500Z","seq":1,"event":"session.action","description":"Listed files","object":"/var/log","parameters":{"Command":"ls /var/log"}}"#,
            r#"{"timestamp":"2026-08-20T19:44:57.250Z","seq":2,"event":"session.action","description":"Closed the shell"}"#,
            r#"{"timestamp":"2026-08-20T19:45:25.000Z","seq":3,"event":"session.end","description":"Session ended"}"#,
        ];
        assert_eq!(slog, expected.map(|line| format!("{line}\n")).concat());
    }

    #[test]
    fn a_session_without_actions_still_starts_and_ends() {
        let slog = write(0, 5, &[]);

        let events: Vec<serde_json::Value> = slog
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON line"))
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event"], "session.start");
        assert_eq!(events[1]["event"], "session.end");
        assert_eq!(events[1]["seq"], 1);
        assert_eq!(events[1]["timestamp"], "1970-01-01T00:00:05.000Z");
    }
}
