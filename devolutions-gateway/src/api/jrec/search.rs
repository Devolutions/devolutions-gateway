use std::collections::{HashMap, HashSet};
use std::{fmt, io};

use axum::Json;
use axum::extract::State;
use camino::{Utf8Path, Utf8PathBuf};
use serde::de::{self, MapAccess, Visitor};
use serde_json::Value;
use serde_json::value::RawValue;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use uuid::Uuid;

use super::is_safe_recording_file_name;
use crate::DgwState;
use crate::artifacts::JrecArtifacts;
use crate::extract::RecordingsSearchScope;
use crate::http::HttpError;
use crate::token::RecordingFileType;

/// Most hits returned by one search.
const MAX_HITS: usize = 1_000;

/// Most bytes of matching entries returned by one search.
const MAX_HIT_BYTES: usize = 16 * 1024 * 1024;

/// Most log bytes read by one search, so that searching every recording stays bounded.
const MAX_SCANNED_BYTES: u64 = 256 * 1024 * 1024;

// The log viewers read a `.slog` file through the log parser, which drops or truncates some entries.
// The search applies the same limits, so that it finds what the viewers show and nothing else.
// https://github.com/Devolutions/devolutions-gateway/blob/master/webapp/packages/session-recording-log/src/parser.ts

const MAX_LINE_BYTES: usize = 256 * 1024;
const MAX_SCANNED_LINES: usize = 20_000;
const MAX_PARSED_ENTRIES: usize = 10_000;
const MAX_RETAINED_BYTES: usize = 8 * 1024 * 1024;
/// Counted in UTF-16 code units, like JavaScript string lengths.
const MAX_STRING_LENGTH: usize = 4_096;
const MAX_PARAMETER_COUNT: usize = 200;
const MAX_OBJECT_DEPTH: usize = 8;
/// `Number.MAX_SAFE_INTEGER` in JavaScript.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Optional entry fields searched by the query, in addition to `timestamp` and `description`.
const SEARCHED_OPTIONAL_FIELDS: [&str; 4] = ["object", "actor", "host", "sessionType"];

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
pub(crate) struct RecordingSearchRequest {
    /// Text to search for.
    query: String,
    /// The recordings to search.
    recordings: RecordingSelection,
}

/// `"all"`, or a list of recording IDs.
///
/// A repeated ID is searched once, and an empty list searches nothing.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum RecordingSelection {
    All(AllRecordings),
    Listed(Vec<Uuid>),
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AllRecordings {
    All,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingSearchResponse {
    /// Matching entries, newest recording first when searching all recordings, otherwise in the requested order.
    hits: Vec<RecordingSearchHit>,
    /// The search stopped before reading every log, so more entries may match.
    limit_reached: bool,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingSearchHit {
    recording_id: Uuid,
    /// Name of the `.slog` file holding the entry, as listed in `recording.json`.
    file_name: String,
    /// The log entry exactly as recorded.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    entry: Box<RawValue>,
}

/// Searches the Session Recording Log (`.slog`) files of recordings stored on this instance
///
/// The query is a case-insensitive substring, matched against the same entry fields as the log viewers:
/// `timestamp`, `description`, `object`, `actor`, `host`, `sessionType`, and the parameter names and values.
/// Entries the log viewers do not show are not searched, and long strings are matched on the part the viewers show.
/// Recordings without a readable `recording.json` and IDs with no recording on this instance give no hits.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "SearchRecordings",
    tag = "Jrec",
    path = "/jet/jrec/search",
    request_body(content = RecordingSearchRequest, description = "JSON-encoded search request", content_type = "application/json"),
    responses(
        (status = 200, description = "Matching log entries", body = RecordingSearchResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("scope_token" = ["gateway.recordings.search"])),
))]
pub(crate) async fn search_recordings(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    _scope: RecordingsSearchScope,
    Json(request): Json<RecordingSearchRequest>,
) -> Result<Json<RecordingSearchResponse>, HttpError> {
    let text = SearchText::new(&request.query).ok_or_else(|| HttpError::bad_request().msg("empty search text"))?;

    let recording_root = conf_handle.get_conf().recording_path.clone();

    let recordings = match request.recordings {
        RecordingSelection::All(AllRecordings::All) => all_recording_logs_newest_first(&recording_root)
            .await
            .map_err(HttpError::internal().with_msg("failed recording listing").err())?,
        RecordingSelection::Listed(recording_ids) => {
            let mut seen = HashSet::new();
            let mut recordings = Vec::with_capacity(recording_ids.len());
            for recording_id in recording_ids
                .into_iter()
                .filter(|recording_id| seen.insert(*recording_id))
            {
                let recording_dir = recording_root.join(recording_id.to_string());
                recordings.extend(read_recording_logs(recording_dir, recording_id).await);
            }
            recordings
        }
    };

    let mut search = Search::new(text);

    for recording in recordings {
        for file_name in recording.file_names {
            let path = recording.dir.join(&file_name);

            match search.search_file(recording.recording_id, file_name, &path).await {
                Ok(()) => {}
                // A recording can be deleted while it is searched.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    debug!(%path, "Recording log listed in the manifest is missing");
                }
                Err(error) => warn!(%path, %error, "Failed to search a recording log"),
            }

            if search.limit_reached {
                return Ok(Json(search.into_response()));
            }
        }
    }

    Ok(Json(search.into_response()))
}

/// Search text in lowercase, the case entries are compared in.
struct SearchText(String);

impl SearchText {
    fn new(query: &str) -> Option<Self> {
        let text = query.trim().to_lowercase();
        (!text.is_empty()).then_some(Self(text))
    }

    fn is_in(&self, value: &str) -> bool {
        visible_text(value).to_lowercase().contains(&self.0)
    }
}

struct Search {
    text: SearchText,
    hits: Vec<RecordingSearchHit>,
    hit_bytes: usize,
    scanned_bytes: u64,
    limit_reached: bool,
}

impl Search {
    fn new(text: SearchText) -> Self {
        Self {
            text,
            hits: Vec::new(),
            hit_bytes: 0,
            scanned_bytes: 0,
            limit_reached: false,
        }
    }

    fn into_response(self) -> RecordingSearchResponse {
        RecordingSearchResponse {
            hits: self.hits,
            limit_reached: self.limit_reached,
        }
    }

    /// Adds the matching entries of one log, reading it the way the log parser does.
    async fn search_file(&mut self, recording_id: Uuid, file_name: String, path: &Utf8Path) -> io::Result<()> {
        let mut reader = BufReader::new(File::open(path).await?);
        let mut line = Vec::new();
        let mut scanned_lines = 0;
        let mut parsed_entries = 0;
        let mut retained_bytes = 0;

        while let Some(read) = read_line(&mut reader, &mut line).await? {
            // UNTESTED: the scanned-bytes budget stops the search and reports `limitReached`.
            // It keeps a search of every recording from reading an unbounded amount of logs.
            // When changing it, keep `limit_reached` set whenever logs are left unread.
            self.scanned_bytes += read.bytes;
            if MAX_SCANNED_BYTES < self.scanned_bytes {
                self.limit_reached = true;
                return Ok(());
            }

            scanned_lines += 1;
            if MAX_SCANNED_LINES < scanned_lines {
                break;
            }

            if !read.too_long && line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }

            if MAX_PARSED_ENTRIES <= parsed_entries {
                break;
            }

            if read.too_long {
                continue;
            }

            let is_match = match viewer_entry(&self.text, &line) {
                ViewerEntry::Hidden => continue,
                ViewerEntry::Match => true,
                ViewerEntry::NoMatch => false,
            };

            if MAX_RETAINED_BYTES < retained_bytes + line.len() {
                break;
            }
            retained_bytes += line.len();
            parsed_entries += 1;

            if is_match && !self.push(recording_id, &file_name, &line) {
                return Ok(());
            }
        }

        Ok(())
    }

    /// Returns `false` when the hit limits are reached.
    fn push(&mut self, recording_id: Uuid, file_name: &str, line: &[u8]) -> bool {
        // UNTESTED: the hit-bytes budget stops the search and reports `limitReached`.
        // It bounds the response size, which the hit count alone does not, because a line can be large.
        // When changing it, keep both the hit count and the hit bytes bounded.
        if self.hits.len() == MAX_HITS || MAX_HIT_BYTES < self.hit_bytes + line.len() {
            self.limit_reached = true;
            return false;
        }

        // The line was parsed as JSON already.
        let Ok(entry) = serde_json::from_slice::<Box<RawValue>>(line) else {
            return true;
        };

        self.hit_bytes += line.len();
        self.hits.push(RecordingSearchHit {
            recording_id,
            file_name: file_name.to_owned(),
            entry,
        });

        true
    }
}

/// How the log viewers see the entry on one line, given the search text.
#[derive(Debug, PartialEq, Eq)]
enum ViewerEntry {
    /// The viewers drop the entry.
    Hidden,
    /// The viewers show the entry, and the search text is in it.
    Match,
    /// The viewers show the entry, and the search text is not in it.
    NoMatch,
}

fn viewer_entry(text: &SearchText, line: &[u8]) -> ViewerEntry {
    return shown_entry_matches(text, line).map_or(ViewerEntry::Hidden, |is_match| match is_match {
        true => ViewerEntry::Match,
        false => ViewerEntry::NoMatch,
    });

    fn shown_entry_matches(text: &SearchText, line: &[u8]) -> Option<bool> {
        let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(line) else {
            return None;
        };

        if exceeds_max_object_depth(&fields) {
            return None;
        }

        let event = fields.get("event")?.as_str()?;
        if MAX_STRING_LENGTH < event.encode_utf16().count() {
            return None;
        }

        let timestamp = fields.get("timestamp")?.as_str()?;
        let description = fields.get("description")?.as_str()?;

        let seq = fields.get("seq")?.as_f64()?;
        if !(seq.fract() == 0.0 && (0.0..=MAX_SAFE_INTEGER).contains(&seq)) {
            return None;
        }

        let in_fields = [timestamp, description]
            .into_iter()
            .chain(
                SEARCHED_OPTIONAL_FIELDS
                    .iter()
                    .filter_map(|field| fields.get(*field)?.as_str()),
            )
            .any(|value| text.is_in(value));

        if in_fields {
            return Some(true);
        }

        if !fields.get("parameters").is_some_and(Value::is_object) {
            return Some(false);
        }

        // A `serde_json::Map` sorts its keys, and which parameters the viewers keep depends on their order.
        #[derive(Deserialize)]
        struct LineParameters {
            parameters: OrderedObject,
        }

        let Ok(LineParameters { parameters }) = serde_json::from_slice(line) else {
            return Some(false);
        };

        let mut kept_names = HashSet::new();

        let in_parameters = parameters
            .0
            .iter()
            .take(MAX_PARAMETER_COUNT)
            .filter_map(|(name, value)| Some((visible_text(name), value.as_str()?)))
            .filter(|(name, _)| kept_names.insert(*name))
            .any(|(name, value)| text.is_in(name) || text.is_in(value));

        Some(in_parameters)
    }
}

fn exceeds_max_object_depth(fields: &serde_json::Map<String, Value>) -> bool {
    let mut stack: Vec<(&Value, usize)> = fields.values().map(|value| (value, 2)).collect();

    while let Some((value, depth)) = stack.pop() {
        match value {
            Value::Array(_) | Value::Object(_) if MAX_OBJECT_DEPTH < depth => return true,
            Value::Array(items) => stack.extend(items.iter().map(|child| (child, depth + 1))),
            Value::Object(fields) => stack.extend(fields.values().map(|child| (child, depth + 1))),
            _ => {}
        }
    }

    false
}

/// The part of a string the log viewers keep: its first [`MAX_STRING_LENGTH`] UTF-16 code units.
fn visible_text(value: &str) -> &str {
    let mut code_units = 0;

    for (index, character) in value.char_indices() {
        code_units += character.len_utf16();

        if MAX_STRING_LENGTH < code_units {
            return &value[..index];
        }
    }

    value
}

/// A JSON object's entries in the order JavaScript enumerates them after `JSON.parse`.
///
/// Integer-like names come first in ascending order, then the other names in written order.
/// A repeated name keeps its first position and its last value.
struct OrderedObject(Vec<(String, Value)>);

impl<'de> serde::Deserialize<'de> for OrderedObject {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OrderedObjectVisitor;

        impl<'de> Visitor<'de> for OrderedObjectVisitor {
            type Value = OrderedObject;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut entries: Vec<(String, Value)> = Vec::new();
                let mut positions: HashMap<String, usize> = HashMap::new();

                while let Some((name, value)) = map.next_entry::<String, Value>()? {
                    match positions.get(&name) {
                        Some(&position) => entries[position].1 = value,
                        None => {
                            positions.insert(name.clone(), entries.len());
                            entries.push((name, value));
                        }
                    }
                }

                // A stable sort keeps the written order among the other names.
                entries.sort_by_key(|(name, _)| array_index(name).map_or((1, 0), |index| (0, index)));

                Ok(OrderedObject(entries))
            }
        }

        return deserializer.deserialize_map(OrderedObjectVisitor);

        /// The array index a property name stands for in JavaScript: a canonical decimal below `u32::MAX`.
        fn array_index(name: &str) -> Option<u32> {
            let index = name.parse::<u32>().ok()?;
            (index < u32::MAX && index.to_string() == name).then_some(index)
        }
    }
}

/// The `.slog` files of one recording.
struct RecordingLogs {
    recording_id: Uuid,
    dir: Utf8PathBuf,
    start_time: i64,
    file_names: Vec<String>,
}

/// Lists the recording logs and the log artifacts, such as the AI analysis, from `recording.json`.
async fn read_recording_logs(dir: Utf8PathBuf, recording_id: Uuid) -> Option<RecordingLogs> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Manifest {
        start_time: i64,
        files: Vec<ManifestFile>,
        #[serde(default)]
        artifacts: JrecArtifacts,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ManifestFile {
        file_name: String,
    }

    let path = dir.join("recording.json");

    // Every search reads every manifest again, so a failure here is not worth more than a debug event.
    let json = tokio::fs::read(&path)
        .await
        .inspect_err(|error| debug!(%path, %error, "Failed to read a recording manifest"))
        .ok()?;

    let manifest: Manifest = serde_json::from_slice(&json)
        .inspect_err(|error| debug!(%path, %error, "Invalid recording manifest"))
        .ok()?;

    let file_names = manifest
        .files
        .into_iter()
        .map(|file| file.file_name)
        .chain(manifest.artifacts.into_file_names())
        .filter(|file_name| {
            is_safe_recording_file_name(file_name)
                && Utf8Path::new(file_name)
                    .extension()
                    .and_then(RecordingFileType::from_extension)
                    == Some(RecordingFileType::SessionRecordingLog)
        })
        .collect();

    Some(RecordingLogs {
        recording_id,
        dir,
        start_time: manifest.start_time,
        file_names,
    })
}

/// Logs of every recording on this instance, newest first by manifest start time.
async fn all_recording_logs_newest_first(recording_root: &Utf8Path) -> anyhow::Result<Vec<RecordingLogs>> {
    let mut read_dir = match tokio::fs::read_dir(recording_root).await {
        Ok(read_dir) => read_dir,
        // No recording has been made yet.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut recordings = Vec::new();

    while let Some(entry) = read_dir.next_entry().await? {
        let Some(recording_id) = entry.file_name().to_str().and_then(|name| Uuid::parse_str(name).ok()) else {
            continue;
        };

        // A recording deleted while listing is skipped rather than failing the search.
        if !entry.file_type().await.is_ok_and(|file_type| file_type.is_dir()) {
            continue;
        }

        let Ok(dir) = Utf8PathBuf::try_from(entry.path()) else {
            continue;
        };

        recordings.extend(read_recording_logs(dir, recording_id).await);
    }

    recordings.sort_unstable_by(|a, b| b.start_time.cmp(&a.start_time));

    Ok(recordings)
}

struct LineRead {
    /// Bytes consumed, line break included.
    bytes: u64,
    /// The line is longer than [`MAX_LINE_BYTES`]; it is then read as empty.
    too_long: bool,
}

/// Reads the next line into `line`, without its line break, and returns `None` at the end of the file.
///
/// The reader never holds more than [`MAX_LINE_BYTES`] of one line in memory.
async fn read_line(reader: &mut BufReader<File>, line: &mut Vec<u8>) -> io::Result<Option<LineRead>> {
    line.clear();
    let mut read = LineRead {
        bytes: 0,
        too_long: false,
    };

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((read.bytes != 0).then_some(read));
        }

        let line_break = available.iter().position(|&byte| byte == b'\n');
        let chunk = &available[..line_break.unwrap_or(available.len())];

        if !read.too_long {
            if line.len() + chunk.len() <= MAX_LINE_BYTES {
                line.extend_from_slice(chunk);
            } else {
                read.too_long = true;
                line.clear();
            }
        }

        let consumed = line_break.map_or(available.len(), |index| index + 1);
        reader.consume(consumed);
        read.bytes += u64::try_from(consumed).expect("buffer length fits in u64");

        if line_break.is_some() {
            if line.last() == Some(&b'\r') {
                line.pop();
            }

            return Ok(Some(read));
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn search_text(query: &str) -> SearchText {
        SearchText::new(query).expect("non-empty query")
    }

    fn matches(query: &str, line: &str) -> ViewerEntry {
        viewer_entry(&search_text(query), line.as_bytes())
    }

    #[rstest]
    #[case::description("created user", ViewerEntry::Match)]
    #[case::object("desk ott", ViewerEntry::Match)]
    #[case::field_name("description", ViewerEntry::NoMatch)]
    #[case::event("session", ViewerEntry::NoMatch)]
    fn matches_field_values_ignoring_case(#[case] query: &str, #[case] expected: ViewerEntry) {
        let line = r#"{"timestamp":"t","seq":1,"event":"session.action","description":"Created User","object":"Help Desk Ottawa"}"#;

        assert_eq!(matches(query, line), expected);
    }

    #[rstest]
    #[case::no_seq(r#"{"timestamp":"t","event":"e","description":"hit"}"#)]
    #[case::negative_seq(r#"{"timestamp":"t","seq":-1,"event":"e","description":"hit"}"#)]
    #[case::unsafe_seq(r#"{"timestamp":"t","seq":9007199254740992,"event":"e","description":"hit"}"#)]
    #[case::fractional_seq(r#"{"timestamp":"t","seq":1.5,"event":"e","description":"hit"}"#)]
    #[case::number_timestamp(r#"{"timestamp":1,"seq":1,"event":"e","description":"hit"}"#)]
    #[case::no_event(r#"{"timestamp":"t","seq":1,"description":"hit"}"#)]
    #[case::no_description(r#"{"timestamp":"t","seq":1,"event":"e","object":"hit"}"#)]
    #[case::too_deep(r#"{"timestamp":"t","seq":1,"event":"e","description":"hit","x":[[[[[[[[1]]]]]]]]}"#)]
    #[case::not_an_object(r#"["hit"]"#)]
    fn skips_entries_the_viewers_drop(#[case] line: &str) {
        assert_eq!(matches("hit", line), ViewerEntry::Hidden);
    }

    #[test]
    fn keeps_an_entry_at_the_max_depth() {
        let line = r#"{"timestamp":"t","seq":1,"event":"e","description":"hit","x":[[[[[[[1]]]]]]]}"#;

        assert_eq!(matches("hit", line), ViewerEntry::Match);
    }

    #[test]
    fn matches_only_the_visible_part_of_long_strings() {
        let description = format!("{}tail", "a".repeat(MAX_STRING_LENGTH));
        let line = format!(r#"{{"timestamp":"t","seq":1,"event":"e","description":"{description}"}}"#);

        assert_eq!(matches("tail", &line), ViewerEntry::NoMatch);
        assert_eq!(matches("aaa", &line), ViewerEntry::Match);
    }

    #[rstest]
    #[case::name("new name", ViewerEntry::Match)]
    #[case::value("hull", ViewerEntry::Match)]
    #[case::non_string_value("count", ViewerEntry::NoMatch)]
    fn matches_string_parameters_only(#[case] query: &str, #[case] expected: ViewerEntry) {
        let line =
            r#"{"timestamp":"t","seq":1,"event":"e","description":"d","parameters":{"New name":"Hull","Count":2}}"#;

        assert_eq!(matches(query, line), expected);
    }

    #[test]
    fn matches_the_first_parameters_in_written_order() {
        let mut parameters: Vec<String> = (0..MAX_PARAMETER_COUNT).map(|i| format!(r#""z{i}":"v""#)).collect();
        parameters.push(r#""a-late":"late""#.to_owned());
        let line = format!(
            r#"{{"timestamp":"t","seq":1,"event":"e","description":"d","parameters":{{{}}}}}"#,
            parameters.join(",")
        );

        assert_eq!(matches("z199", &line), ViewerEntry::Match);
        assert_eq!(matches("late", &line), ViewerEntry::NoMatch);
    }

    #[test]
    fn keeps_the_first_parameter_whose_name_collides_after_truncation() {
        let name = "n".repeat(MAX_STRING_LENGTH);
        let line = format!(
            r#"{{"timestamp":"t","seq":1,"event":"e","description":"d","parameters":{{"{name}x":"first","{name}y":"second"}}}}"#
        );

        assert_eq!(matches("first", &line), ViewerEntry::Match);
        assert_eq!(matches("second", &line), ViewerEntry::NoMatch);
    }

    #[test]
    fn orders_parameters_like_javascript() {
        let line = r#"{"timestamp":"t","seq":1,"event":"e","description":"d","parameters":{"b":"1","10":"2","a":"3","2":"4","01":"5","b":"6"}}"#;

        #[derive(Deserialize)]
        struct LineParameters {
            parameters: OrderedObject,
        }

        let LineParameters { parameters } = serde_json::from_str(line).expect("parameters");
        let entries: Vec<_> = parameters
            .0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str().expect("string value")))
            .collect();

        assert_eq!(entries, [("2", "4"), ("10", "2"), ("b", "6"), ("a", "3"), ("01", "5")]);
    }

    #[rstest]
    #[case::all(r#""all""#, Some(None))]
    #[case::listed(
        r#"["00000000-0000-0000-0000-000000000002","00000000-0000-0000-0000-000000000001"]"#,
        Some(Some(vec![Uuid::from_u128(2), Uuid::from_u128(1)]))
    )]
    #[case::empty_list("[]", Some(Some(Vec::new())))]
    #[case::other_word(r#""some""#, None)]
    #[case::all_in_a_list(r#"["all"]"#, None)]
    fn parses_the_recording_selection(#[case] recordings: &str, #[case] expected: Option<Option<Vec<Uuid>>>) {
        let request = format!(r#"{{"query":"q","recordings":{recordings}}}"#);

        let actual = serde_json::from_str::<RecordingSearchRequest>(&request)
            .ok()
            .map(|request| match request.recordings {
                RecordingSelection::All(AllRecordings::All) => None,
                RecordingSelection::Listed(recording_ids) => Some(recording_ids),
            });

        assert_eq!(actual, expected);
    }

    async fn search_lines(content: &str) -> RecordingSearchResponse {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("recording-0.slog")).expect("UTF-8 path");
        std::fs::write(&path, content).expect("write log");

        let mut search = Search::new(search_text("hit"));
        search
            .search_file(Uuid::nil(), "recording-0.slog".to_owned(), &path)
            .await
            .expect("search log");

        search.into_response()
    }

    fn entry_line(seq: usize, description: &str) -> String {
        format!(r#"{{"timestamp":"t","seq":{seq},"event":"e","description":"{description}"}}"#)
    }

    #[tokio::test]
    async fn returns_entries_as_recorded() {
        let line = r#"{"timestamp":"t","seq":1,"event":"e","description":"hit","parameters":{"b":"1","a":"2"}}"#;

        let response = search_lines(&format!("{line}\r\n")).await;

        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].entry.get(), line);
    }

    #[tokio::test]
    async fn stops_at_the_hit_limit() {
        let content: String = (0..=MAX_HITS)
            .map(|seq| format!("{}\n", entry_line(seq, "hit")))
            .collect();

        let response = search_lines(&content).await;

        assert_eq!(response.hits.len(), MAX_HITS);
        assert!(response.limit_reached);
    }

    #[tokio::test]
    async fn skips_lines_longer_than_the_limit() {
        let long_line = entry_line(1, &format!("hit{}", "x".repeat(MAX_LINE_BYTES)));
        let content = format!(
            "{}\n{long_line}\n{}",
            entry_line(0, "hit first"),
            entry_line(2, "hit last")
        );

        let response = search_lines(&content).await;

        let seqs: Vec<_> = response
            .hits
            .iter()
            .map(|hit| serde_json::from_str::<Value>(hit.entry.get()).expect("JSON entry")["seq"].clone())
            .collect();
        assert_eq!(seqs, [serde_json::json!(0), serde_json::json!(2)]);
    }

    #[tokio::test]
    async fn stops_after_the_scanned_line_limit() {
        let mut content = "\n".repeat(MAX_SCANNED_LINES);
        content.push_str(&entry_line(0, "hit"));

        let response = search_lines(&content).await;

        assert!(response.hits.is_empty());
    }
}
