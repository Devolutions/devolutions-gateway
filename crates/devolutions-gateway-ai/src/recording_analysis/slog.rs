//! Writes AI actions as a Session Recording Log (`.slog`): one JSON object per line, in the shipped schema.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

use crate::session_actions::Action;

/// One line of the AI `.slog`.
///
/// These types are the standard of what an AI log holds: each kind of event carries exactly its own fields.
#[derive(Serialize)]
struct Line<'a> {
    timestamp: String,
    seq: usize,
    #[serde(flatten)]
    event: Event<'a>,
    source: Source,
}

#[derive(Serialize)]
#[serde(tag = "event")]
enum Event<'a> {
    #[serde(rename = "session.start", rename_all = "camelCase")]
    Start {
        description: &'static str,
        model: &'a str,
        prompt_version: &'a str,
    },
    #[serde(rename = "session.action")]
    Action {
        description: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        object: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameters: Option<&'a BTreeMap<String, String>>,
    },
    #[serde(rename = "session.end")]
    End { description: &'static str },
}

#[derive(Serialize)]
enum Source {
    #[serde(rename = "ai")]
    Ai,
}

/// Writes the log of a session entry by entry, so the actions never have to be all in memory.
pub(super) struct SlogWriter<W> {
    out: W,
    start_time: i64,
    seq: usize,
}

impl<W: std::io::Write> SlogWriter<W> {
    /// Writes `session.start` for a session that started at `start_time` (unix seconds), naming the model and the
    /// versions of the prompts that found the actions.
    pub(super) fn start(out: W, start_time: i64, model: &str, prompt_version: &str) -> anyhow::Result<Self> {
        let mut writer = Self {
            out,
            start_time,
            seq: 0,
        };

        let timestamp = timestamp(start_time, Duration::ZERO)?;
        writer.write(
            timestamp,
            Event::Start {
                description: "Session started",
                model,
                prompt_version,
            },
        )?;

        Ok(writer)
    }

    /// Actions must come in offset order.
    pub(super) fn action(&mut self, action: &Action) -> anyhow::Result<()> {
        let timestamp = timestamp(self.start_time, action.offset)?;
        self.write(
            timestamp,
            Event::Action {
                description: &action.description,
                object: action.object.as_deref(),
                parameters: Some(&action.parameters).filter(|parameters| !parameters.is_empty()),
            },
        )
    }

    /// Writes `session.end` for a session that lasted `duration` seconds.
    pub(super) fn finish(mut self, duration: i64) -> anyhow::Result<W> {
        let end_offset = Duration::from_secs(u64::try_from(duration).unwrap_or(0));
        let timestamp = timestamp(self.start_time, end_offset)?;
        self.write(
            timestamp,
            Event::End {
                description: "Session ended",
            },
        )?;
        self.out.flush()?;
        Ok(self.out)
    }

    fn write(&mut self, timestamp: String, event: Event<'_>) -> anyhow::Result<()> {
        let line = Line {
            timestamp,
            seq: self.seq,
            event,
            source: Source::Ai,
        };
        serde_json::to_writer(&mut self.out, &line)?;
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
        let mut writer = SlogWriter::start(Vec::new(), start_time, "gpt-test", "session-actions-3").expect("started");
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

    // oracle: intent crates/devolutions-gateway-ai/INTENT.md §Analyze Recording
    // oracle: reference webapp/packages/session-recording-log/src/fixtures/sample-complete.slog
    #[test]
    fn writes_the_shipped_schema_with_the_source_on_every_line() {
        let actions = [
            action(1500, "Listed files", Some("/var/log"), &[("Command", "ls /var/log")]),
            action(62_250, "Closed the shell", None, &[]),
        ];

        let slog = write(1_787_255_035, 90, &actions);

        let expected = [
            r#"{"timestamp":"2026-08-20T19:43:55.000Z","seq":0,"event":"session.start","description":"Session started","source":"ai","model":"gpt-test","promptVersion":"session-actions-3"}"#,
            r#"{"timestamp":"2026-08-20T19:43:56.500Z","seq":1,"event":"session.action","description":"Listed files","object":"/var/log","parameters":{"Command":"ls /var/log"},"source":"ai"}"#,
            r#"{"timestamp":"2026-08-20T19:44:57.250Z","seq":2,"event":"session.action","description":"Closed the shell","source":"ai"}"#,
            r#"{"timestamp":"2026-08-20T19:45:25.000Z","seq":3,"event":"session.end","description":"Session ended","source":"ai"}"#,
        ];
        let lines = |text: &str| -> Vec<serde_json::Value> {
            text.lines()
                .map(|line| serde_json::from_str(line).expect("JSON line"))
                .collect()
        };
        assert_eq!(lines(&slog), lines(&expected.join("\n")));
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
        assert!(events.iter().all(|event| event["source"] == "ai"));
    }
}
