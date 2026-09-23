//! Search over the Session Recording Log (`.slog`) artifacts of recordings stored on this instance.
//!
//! Matching mirrors `searchSessionRecordingLogEntries` in `webapp/packages/session-recording-log`.
//! The query is a plain substring matched against the visible entry fields, ignoring case unless requested otherwise.
//! There is no fuzzy matching, tokenization, or regular expression support.
//! Keep both implementations in sync when changing the searchable fields or the matching rules.
//!
//! The search only knows the generic `.slog` entry fields, never a particular producer.
//! Hits carry the whole entry as recorded, so new producers and new fields need no change here.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

use anyhow::Context as _;
use axum::Json;
use axum::extract::State;
use camino::Utf8Path;
use hyper::StatusCode;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::is_safe_recording_file_name;
use crate::DgwState;
use crate::extract::RecordingsSearchScope;
use crate::http::{HttpError, HttpErrorBuilder};
use crate::token::RecordingFileType;

/// Maximum number of recordings a single request may list.
const MAX_RECORDING_IDS: usize = 1_000;

/// Hit limit applied when the request does not specify one.
const DEFAULT_HIT_LIMIT: usize = 100;

/// Upper bound for the requested hit limit.
const MAX_HIT_LIMIT: usize = 1_000;

/// Maximum query length, in characters.
///
/// The parser package truncates entry strings to 4,096 characters, so a longer query cannot match what viewers show.
const MAX_QUERY_LENGTH: usize = 4_096;

/// Maximum number of values in the event type filter.
const MAX_EVENT_TYPES: usize = 32;

/// Maximum size of a `recording.json` manifest.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Longer lines are skipped, like the parser package's `maxLineLengthBytes`.
const MAX_LINE_LENGTH_BYTES: usize = 256 * 1024;

/// Lines past this bound are not scanned, like the parser package's `maxScannedLines`.
const MAX_SCANNED_LINES_PER_FILE: usize = 20_000;

/// Bytes scanned across every file of one request.
const MAX_SCANNED_BYTES_PER_REQUEST: usize = 256 * 1024 * 1024;

/// Source bytes of the entries returned by one request, bounding the response size.
const MAX_HIT_BYTES_PER_REQUEST: usize = 16 * 1024 * 1024;

/// Session Recording Log search request
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingLogSearchRequest {
    /// Recordings to search, in the order results are returned
    ///
    /// When omitted, every recording stored on this instance is searched, newest first.
    /// An empty list searches nothing.
    recording_ids: Option<Vec<Uuid>>,
    /// Text to look for; an empty query matches every entry
    #[serde(default)]
    query: String,
    /// When not empty, only entries whose `event` is one of these values are considered
    #[serde(default)]
    event_types: Vec<String>,
    /// Only entries whose `timestamp` is at or after this instant are considered
    #[serde(default, with = "time::serde::rfc3339::option")]
    from: Option<OffsetDateTime>,
    /// Only entries whose `timestamp` is before this instant are considered
    #[serde(default, with = "time::serde::rfc3339::option")]
    to: Option<OffsetDateTime>,
    /// Match case exactly instead of ignoring case
    #[serde(default)]
    case_sensitive: bool,
    /// Maximum number of hits to return (default 100, capped at 1000)
    limit: Option<usize>,
}

/// Session Recording Log search result
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingLogSearchResponse {
    /// Matching entries, ordered by recording, then by manifest file order, then by line
    hits: Vec<RecordingLogSearchHit>,
    /// Listed recordings that are not stored on this instance or have no readable manifest
    not_found_recording_ids: Vec<Uuid>,
    /// The hit limit or the response size bound was reached, so more matches may exist
    limit_reached: bool,
    /// A scan bound was reached, so some entries were not searched
    scan_limit_reached: bool,
}

/// One Session Recording Log entry matching the search
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingLogSearchHit {
    /// Recording containing the entry
    recording_id: Uuid,
    /// Name of the `.slog` file containing the entry
    file_name: String,
    /// One-based line number of the entry in the file
    line_number: usize,
    /// The entry, as recorded
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    entry: Map<String, Value>,
    /// Fields matched by the query; empty when the query is empty
    matched_fields: Vec<RecordingLogSearchField>,
}

/// Session Recording Log entry field searched by the query
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum RecordingLogSearchField {
    #[serde(rename = "timestamp")]
    Timestamp,
    #[serde(rename = "description")]
    Description,
    #[serde(rename = "object")]
    Object,
    #[serde(rename = "actor")]
    Actor,
    #[serde(rename = "host")]
    Host,
    #[serde(rename = "sessionType")]
    SessionType,
    #[serde(rename = "parameter-key")]
    ParameterKey,
    #[serde(rename = "parameter-value")]
    ParameterValue,
}

/// Top-level string fields searched by the query, in the order they are reported.
const SEARCHED_STRING_FIELDS: [(&str, RecordingLogSearchField); 6] = [
    ("timestamp", RecordingLogSearchField::Timestamp),
    ("description", RecordingLogSearchField::Description),
    ("object", RecordingLogSearchField::Object),
    ("actor", RecordingLogSearchField::Actor),
    ("host", RecordingLogSearchField::Host),
    ("sessionType", RecordingLogSearchField::SessionType),
];

/// Searches the Session Recording Log (`.slog`) artifacts of recordings stored on this instance
///
/// The query is matched as a plain substring against the visible fields of each entry:
/// `timestamp`, `description`, `object`, `actor`, `host`, `sessionType`, and every parameter key and value.
/// Matching ignores case unless `caseSensitive` is set.
/// There is no fuzzy matching.
///
/// `from` and `to` filter on the entry `timestamp`; entries without a valid RFC 3339 timestamp are then excluded.
///
/// This route is unstable and only available when `__debug__.enable_unstable` is set.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "SearchRecordingLogs",
    tag = "Jrec",
    path = "/jet/jrec/search",
    request_body(content = RecordingLogSearchRequest, description = "JSON-encoded search request", content_type = "application/json"),
    responses(
        (status = 200, description = "Search results", body = RecordingLogSearchResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 413, description = "Too many recording IDs in one request"),
    ),
    security(("scope_token" = ["gateway.recordings.search"])),
))]
pub(crate) async fn search_recording_logs(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    _scope: RecordingsSearchScope,
    Json(request): Json<RecordingLogSearchRequest>,
) -> Result<Json<RecordingLogSearchResponse>, HttpError> {
    let options = SearchOptions::from_request(request)?;
    let recording_path = conf_handle.get_conf().recording_path.clone();

    let response = tokio::task::spawn_blocking(move || search(&recording_path, &options))
        .await
        .map_err(HttpError::internal().with_msg("recording log search failed").err())?
        .map_err(HttpError::internal().with_msg("recording log search failed").err())?;

    Ok(Json(response))
}

enum RecordingSelection {
    /// Every recording stored on this instance, newest first.
    All,
    /// INVARIANT: No duplicates, and at most `MAX_RECORDING_IDS` items.
    Listed(Vec<Uuid>),
}

struct SearchOptions {
    recordings: RecordingSelection,
    /// Trimmed query, lowercased unless `case_sensitive` is set.
    query: String,
    event_types: Vec<String>,
    /// INVARIANT: When both bounds are set, `from` is before `to`.
    from: Option<OffsetDateTime>,
    to: Option<OffsetDateTime>,
    case_sensitive: bool,
    /// INVARIANT: Between 1 and `MAX_HIT_LIMIT`.
    limit: usize,
}

impl SearchOptions {
    fn from_request(request: RecordingLogSearchRequest) -> Result<Self, HttpError> {
        let RecordingLogSearchRequest {
            recording_ids,
            query,
            event_types,
            from,
            to,
            case_sensitive,
            limit,
        } = request;

        let recordings = match recording_ids {
            None => RecordingSelection::All,
            Some(recording_ids) => {
                if recording_ids.len() > MAX_RECORDING_IDS {
                    return Err(HttpErrorBuilder::new(StatusCode::PAYLOAD_TOO_LARGE).msg("too many recording IDs"));
                }

                let mut seen = HashSet::new();
                RecordingSelection::Listed(recording_ids.into_iter().filter(|id| seen.insert(*id)).collect())
            }
        };

        let query = query.trim();

        if query.chars().count() > MAX_QUERY_LENGTH {
            return Err(HttpError::bad_request().msg("query is too long"));
        }

        if event_types.len() > MAX_EVENT_TYPES {
            return Err(HttpError::bad_request().msg("too many event types"));
        }

        if let (Some(from), Some(to)) = (from, to)
            && from >= to
        {
            return Err(HttpError::bad_request().msg("time range start must be before its end"));
        }

        let query = if case_sensitive {
            query.to_owned()
        } else {
            query.to_lowercase()
        };

        Ok(Self {
            recordings,
            query,
            event_types,
            from,
            to,
            case_sensitive,
            limit: limit.unwrap_or(DEFAULT_HIT_LIMIT).clamp(1, MAX_HIT_LIMIT),
        })
    }

    fn matches(&self, value: &str) -> bool {
        if self.case_sensitive {
            value.contains(self.query.as_str())
        } else {
            value.to_lowercase().contains(self.query.as_str())
        }
    }

    fn is_within_time_range(&self, entry: &Map<String, Value>) -> bool {
        if self.from.is_none() && self.to.is_none() {
            return true;
        }

        let Some(timestamp) = entry
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(|timestamp| OffsetDateTime::parse(timestamp, &Rfc3339).ok())
        else {
            return false;
        };

        self.from.is_none_or(|from| timestamp >= from) && self.to.is_none_or(|to| timestamp < to)
    }
}

struct RecordingTarget {
    recording_id: Uuid,
    start_time: i64,
    /// Safe `.slog` file names listed in the manifest, in manifest order.
    log_file_names: Vec<String>,
}

#[derive(Default)]
struct ScanState {
    hits: Vec<RecordingLogSearchHit>,
    hit_bytes: usize,
    scanned_bytes: usize,
    limit_reached: bool,
    scan_limit_reached: bool,
    budget_exhausted: bool,
}

fn search(recording_root: &Utf8Path, options: &SearchOptions) -> anyhow::Result<RecordingLogSearchResponse> {
    let mut not_found_recording_ids = Vec::new();

    // Resolve every recording before scanning, so `notFoundRecordingIds` is complete even when a limit stops the scan.
    let targets = match &options.recordings {
        RecordingSelection::All => {
            let mut targets: Vec<RecordingTarget> = list_recording_ids(recording_root)?
                .into_iter()
                .filter_map(|recording_id| read_recording_target(recording_root, recording_id))
                .filter(|target| !target.log_file_names.is_empty())
                .collect();

            targets.sort_by(|a, b| {
                b.start_time
                    .cmp(&a.start_time)
                    .then_with(|| a.recording_id.cmp(&b.recording_id))
            });

            targets
        }
        RecordingSelection::Listed(recording_ids) => {
            let mut targets = Vec::with_capacity(recording_ids.len());

            for &recording_id in recording_ids {
                match read_recording_target(recording_root, recording_id) {
                    Some(target) => targets.push(target),
                    None => not_found_recording_ids.push(recording_id),
                }
            }

            targets
        }
    };

    let mut state = ScanState::default();

    'recordings: for target in targets {
        let recording_dir = recording_root.join(target.recording_id.to_string());

        for file_name in target.log_file_names {
            let path = recording_dir.join(&file_name);

            if let Err(error) = search_file(&path, target.recording_id, &file_name, options, &mut state) {
                debug!(%path, error = format!("{error:#}"), "Failed to search recording log file");
            }

            if state.limit_reached || state.budget_exhausted {
                break 'recordings;
            }
        }
    }

    Ok(RecordingLogSearchResponse {
        hits: state.hits,
        not_found_recording_ids,
        limit_reached: state.limit_reached,
        scan_limit_reached: state.scan_limit_reached,
    })
}

fn list_recording_ids(recording_root: &Utf8Path) -> anyhow::Result<Vec<Uuid>> {
    if !recording_root.exists() {
        // The recording directory is created lazily, so a missing directory means there is no recording yet.
        return Ok(Vec::new());
    }

    let read_dir = std::fs::read_dir(recording_root).context("failed to read recording directory")?;

    let recording_ids = read_dir
        .filter_map(|entry| {
            let entry = entry.ok()?;

            if !entry.file_type().ok()?.is_dir() {
                return None;
            }

            Uuid::parse_str(entry.file_name().to_str()?).ok()
        })
        .collect();

    Ok(recording_ids)
}

/// Returns `None` when the recording has no readable manifest.
fn read_recording_target(recording_root: &Utf8Path, recording_id: Uuid) -> Option<RecordingTarget> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Manifest {
        #[serde(default)]
        start_time: i64,
        files: Vec<ManifestFile>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ManifestFile {
        file_name: String,
    }

    let manifest_path = recording_root.join(recording_id.to_string()).join("recording.json");

    let metadata = std::fs::metadata(&manifest_path).ok()?;

    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return None;
    }

    let manifest_bytes = std::fs::read(&manifest_path).ok()?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).ok()?;

    let log_file_names = manifest
        .files
        .into_iter()
        .map(|file| file.file_name)
        .filter(|file_name| is_safe_recording_file_name(file_name) && is_log_file_name(file_name))
        .collect();

    Some(RecordingTarget {
        recording_id,
        start_time: manifest.start_time,
        log_file_names,
    })
}

fn is_log_file_name(file_name: &str) -> bool {
    Utf8Path::new(file_name)
        .extension()
        .and_then(RecordingFileType::from_extension)
        == Some(RecordingFileType::SessionRecordingLog)
}

fn search_file(
    path: &Utf8Path,
    recording_id: Uuid,
    file_name: &str,
    options: &SearchOptions,
    state: &mut ScanState,
) -> io::Result<()> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut line = Vec::new();
    let mut line_number = 0;

    loop {
        if line_number >= MAX_SCANNED_LINES_PER_FILE {
            if has_more_data(&mut reader)? {
                state.scan_limit_reached = true;
            }

            return Ok(());
        }

        if state.scanned_bytes >= MAX_SCANNED_BYTES_PER_REQUEST {
            if has_more_data(&mut reader)? {
                state.scan_limit_reached = true;
                state.budget_exhausted = true;
            }

            return Ok(());
        }

        let (status, consumed) = read_bounded_line(&mut reader, &mut line)?;

        if status == LineStatus::EndOfFile {
            return Ok(());
        }

        state.scanned_bytes = state.scanned_bytes.saturating_add(consumed);
        line_number += 1;

        if status == LineStatus::TooLong {
            continue;
        }

        let Some((entry, matched_fields)) = match_entry(&line, options) else {
            continue;
        };

        state.hits.push(RecordingLogSearchHit {
            recording_id,
            file_name: file_name.to_owned(),
            line_number,
            entry,
            matched_fields,
        });
        state.hit_bytes = state.hit_bytes.saturating_add(line.len());

        if state.hits.len() >= options.limit || state.hit_bytes >= MAX_HIT_BYTES_PER_REQUEST {
            state.limit_reached = true;
            return Ok(());
        }
    }
}

fn has_more_data(reader: &mut impl BufRead) -> io::Result<bool> {
    Ok(!reader.fill_buf()?.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineStatus {
    EndOfFile,
    Complete,
    TooLong,
}

/// Reads the next line into `line`, without its line feed.
///
/// Only the first `MAX_LINE_LENGTH_BYTES` bytes are buffered; a longer line is consumed and reported as too long.
/// Returns the line status and the number of bytes consumed from the reader.
fn read_bounded_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<(LineStatus, usize)> {
    line.clear();

    let mut consumed = 0;
    let mut too_long = false;

    loop {
        let available = reader.fill_buf()?;

        if available.is_empty() {
            let status = if consumed == 0 {
                LineStatus::EndOfFile
            } else if too_long {
                LineStatus::TooLong
            } else {
                LineStatus::Complete
            };

            return Ok((status, consumed));
        }

        let newline_position = available.iter().position(|&byte| byte == b'\n');
        let chunk = &available[..newline_position.unwrap_or(available.len())];

        if !too_long {
            if line.len() + chunk.len() > MAX_LINE_LENGTH_BYTES {
                too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(chunk);
            }
        }

        let used = chunk.len() + usize::from(newline_position.is_some());
        reader.consume(used);
        consumed += used;

        if newline_position.is_some() {
            let status = if too_long {
                LineStatus::TooLong
            } else {
                LineStatus::Complete
            };

            return Ok((status, consumed));
        }
    }
}

/// Returns the entry and its matched fields when the line is a JSON object matching the search.
fn match_entry(line: &[u8], options: &SearchOptions) -> Option<(Map<String, Value>, Vec<RecordingLogSearchField>)> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);

    if line.iter().all(u8::is_ascii_whitespace) {
        return None;
    }

    let Ok(Value::Object(entry)) = serde_json::from_slice::<Value>(line) else {
        return None;
    };

    if !options.event_types.is_empty() {
        let event = entry.get("event").and_then(Value::as_str)?;

        if !options.event_types.iter().any(|event_type| event_type == event) {
            return None;
        }
    }

    if !options.is_within_time_range(&entry) {
        return None;
    }

    let mut matched_fields = Vec::new();

    if !options.query.is_empty() {
        for (key, field) in SEARCHED_STRING_FIELDS {
            if let Some(value) = entry.get(key).and_then(Value::as_str)
                && options.matches(value)
            {
                matched_fields.push(field);
            }
        }

        if let Some(Value::Object(parameters)) = entry.get("parameters") {
            let key_matched = parameters.keys().any(|key| options.matches(key));
            let value_matched = parameters
                .values()
                .filter_map(Value::as_str)
                .any(|value| options.matches(value));

            if key_matched {
                matched_fields.push(RecordingLogSearchField::ParameterKey);
            }

            if value_matched {
                matched_fields.push(RecordingLogSearchField::ParameterValue);
            }
        }

        if matched_fields.is_empty() {
            return None;
        }
    }

    Some((entry, matched_fields))
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;

    use super::*;

    const SAMPLE_LOG: &str = concat!(
        r#"{"timestamp":"2026-07-15T21:17:49.777Z","seq":0,"actor":"Administrator","host":"IT-HELP-DC","sessionType":"ADConsole","event":"session.start","description":"Session started"}"#,
        "\n",
        r#"{"timestamp":"2026-07-15T21:19:14.351Z","seq":1,"event":"session.action","description":"Renamed Object","object":"Help Desk Ottawa","parameters":{"New name":"Help Desk Ottawa/Hull","Members added":"Sarah O'Connor, Bob Smith"}}"#,
        "\n",
        r#"{"timestamp":"2026-07-15T21:20:00.000Z","seq":2,"event":"session.action","description":"Created User","object":"Bob Smith"}"#,
        "\n",
    );

    struct Fixture {
        _dir: tempfile::TempDir,
        root: Utf8PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("create temp dir");
            let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("UTF-8 temp dir");
            Self { _dir: dir, root }
        }

        /// Writes the files, and a manifest listing them in the given order.
        fn add_recording(&self, start_time: i64, files: &[(&str, &str)]) -> Uuid {
            let id = Uuid::new_v4();
            let dir = self.root.join(id.to_string());
            std::fs::create_dir(&dir).expect("create recording dir");

            let manifest_files: Vec<Value> = files
                .iter()
                .map(|(file_name, _)| {
                    serde_json::json!({ "fileName": file_name, "startTime": start_time, "duration": 1 })
                })
                .collect();

            for (file_name, contents) in files {
                if is_safe_recording_file_name(file_name) {
                    std::fs::write(dir.join(file_name), contents).expect("write recording file");
                }
            }

            let manifest = serde_json::json!({
                "sessionId": id,
                "startTime": start_time,
                "duration": 1,
                "files": manifest_files,
            });
            std::fs::write(dir.join("recording.json"), manifest.to_string()).expect("write manifest");

            id
        }
    }

    fn request(recording_ids: Option<Vec<Uuid>>, query: &str) -> RecordingLogSearchRequest {
        RecordingLogSearchRequest {
            recording_ids,
            query: query.to_owned(),
            event_types: Vec::new(),
            from: None,
            to: None,
            case_sensitive: false,
            limit: None,
        }
    }

    fn options(request: RecordingLogSearchRequest) -> SearchOptions {
        match SearchOptions::from_request(request) {
            Ok(options) => options,
            Err(_) => panic!("expected a valid request"),
        }
    }

    fn run(root: &Utf8Path, request: RecordingLogSearchRequest) -> RecordingLogSearchResponse {
        search(root, &options(request)).expect("search")
    }

    fn instant(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &Rfc3339).expect("valid RFC 3339 instant")
    }

    #[test]
    fn matches_parameter_value_ignoring_case() {
        let fixture = Fixture::new();
        let id = fixture.add_recording(0, &[("recording-0.slog", SAMPLE_LOG)]);

        let response = run(&fixture.root, request(Some(vec![id]), "o'connor"));

        assert_eq!(response.hits.len(), 1);
        let hit = &response.hits[0];
        assert_eq!(hit.recording_id, id);
        assert_eq!(hit.file_name, "recording-0.slog");
        assert_eq!(hit.line_number, 2);
        assert_eq!(hit.entry["seq"], 1);
        assert_eq!(hit.matched_fields, [RecordingLogSearchField::ParameterValue]);
        assert!(!response.limit_reached);
        assert!(!response.scan_limit_reached);
    }

    #[test]
    fn case_sensitive_query_requires_exact_case() {
        let fixture = Fixture::new();
        let id = fixture.add_recording(0, &[("recording-0.slog", SAMPLE_LOG)]);

        let mut lowercase = request(Some(vec![id]), "o'connor");
        lowercase.case_sensitive = true;
        assert!(run(&fixture.root, lowercase).hits.is_empty());

        let mut exact = request(Some(vec![id]), "O'Connor");
        exact.case_sensitive = true;
        assert_eq!(run(&fixture.root, exact).hits.len(), 1);
    }

    #[test]
    fn reports_every_matched_field_in_order() {
        let fixture = Fixture::new();
        let id = fixture.add_recording(0, &[("recording-0.slog", SAMPLE_LOG)]);

        let response = run(&fixture.root, request(Some(vec![id]), "help desk"));

        assert_eq!(response.hits.len(), 1);
        assert_eq!(
            response.hits[0].matched_fields,
            [RecordingLogSearchField::Object, RecordingLogSearchField::ParameterValue]
        );

        let response = run(&fixture.root, request(Some(vec![id]), "members"));
        assert_eq!(response.hits[0].matched_fields, [RecordingLogSearchField::ParameterKey]);
    }

    #[test]
    fn empty_query_returns_every_entry_of_the_requested_event_types() {
        let fixture = Fixture::new();
        let id = fixture.add_recording(0, &[("recording-0.slog", SAMPLE_LOG)]);

        let mut request = request(Some(vec![id]), "   ");
        request.event_types = vec!["session.action".to_owned()];
        let response = run(&fixture.root, request);

        let lines: Vec<usize> = response.hits.iter().map(|hit| hit.line_number).collect();
        assert_eq!(lines, [2, 3]);
        assert!(response.hits.iter().all(|hit| hit.matched_fields.is_empty()));
    }

    #[test]
    fn time_range_includes_its_start_and_excludes_its_end() {
        let fixture = Fixture::new();
        let contents = format!(
            "{SAMPLE_LOG}{}\n",
            r#"{"event":"session.action","description":"No timestamp"}"#
        );
        let id = fixture.add_recording(0, &[("recording-0.slog", &contents)]);

        let mut request = request(Some(vec![id]), "");
        request.from = Some(instant("2026-07-15T21:19:14.351Z"));
        request.to = Some(instant("2026-07-15T21:20:00Z"));
        let response = run(&fixture.root, request);

        let lines: Vec<usize> = response.hits.iter().map(|hit| hit.line_number).collect();
        assert_eq!(lines, [2]);
    }

    #[test]
    fn time_range_compares_instants_across_offsets() {
        let fixture = Fixture::new();
        let id = fixture.add_recording(0, &[("recording-0.slog", SAMPLE_LOG)]);

        let mut request = request(Some(vec![id]), "");
        request.from = Some(instant("2026-07-15T17:19:00-04:00"));
        let response = run(&fixture.root, request);

        let lines: Vec<usize> = response.hits.iter().map(|hit| hit.line_number).collect();
        assert_eq!(lines, [2, 3]);
    }

    #[test]
    fn skips_malformed_and_oversized_lines() {
        let fixture = Fixture::new();
        let oversized = format!(r#"{{"description":"Bob {}"}}"#, "x".repeat(MAX_LINE_LENGTH_BYTES));
        let contents = format!(
            "not json\n[\"Bob\"]\n{oversized}\n\n{}\r\n",
            r#"{"event":"session.action","description":"Deleted User","object":"Bob Smith"}"#
        );
        let id = fixture.add_recording(0, &[("recording-0.slog", &contents)]);

        let response = run(&fixture.root, request(Some(vec![id]), "bob"));

        let lines: Vec<usize> = response.hits.iter().map(|hit| hit.line_number).collect();
        assert_eq!(lines, [5]);
    }

    #[test]
    fn searches_log_files_in_manifest_order_and_ignores_other_files() {
        let fixture = Fixture::new();
        let id = fixture.add_recording(
            0,
            &[
                ("recording-0.webm", "Bob Smith"),
                (
                    "recording-1.slog",
                    r#"{"event":"session.action","description":"Bob in clip 1"}"#,
                ),
                ("recording-2.cast", "Bob Smith"),
                (
                    "recording-3.slog",
                    r#"{"event":"session.action","description":"Bob in clip 3"}"#,
                ),
            ],
        );

        let response = run(&fixture.root, request(Some(vec![id]), "bob"));

        let files: Vec<&str> = response.hits.iter().map(|hit| hit.file_name.as_str()).collect();
        assert_eq!(files, ["recording-1.slog", "recording-3.slog"]);
    }

    #[test]
    fn ignores_unsafe_manifest_file_names() {
        let fixture = Fixture::new();
        std::fs::write(
            fixture.root.join("escape.slog"),
            r#"{"event":"session.action","description":"Bob"}"#,
        )
        .expect("write file outside the recording");
        let id = fixture.add_recording(0, &[("../escape.slog", "")]);

        let response = run(&fixture.root, request(Some(vec![id]), "bob"));

        assert!(response.hits.is_empty());
        assert!(response.not_found_recording_ids.is_empty());
    }

    #[test]
    fn reports_listed_recordings_without_a_readable_manifest() {
        let fixture = Fixture::new();
        let found = fixture.add_recording(0, &[("recording-0.slog", SAMPLE_LOG)]);
        let missing = Uuid::new_v4();
        let without_manifest = Uuid::new_v4();
        std::fs::create_dir(fixture.root.join(without_manifest.to_string())).expect("create recording dir");

        let response = run(
            &fixture.root,
            request(Some(vec![missing, found, without_manifest, found]), "bob"),
        );

        assert_eq!(response.not_found_recording_ids, [missing, without_manifest]);
        assert_eq!(response.hits.len(), 2);
    }

    #[test]
    fn empty_recording_list_searches_nothing() {
        let fixture = Fixture::new();
        fixture.add_recording(0, &[("recording-0.slog", SAMPLE_LOG)]);

        let response = run(&fixture.root, request(Some(Vec::new()), "bob"));

        assert!(response.hits.is_empty());
        assert!(response.not_found_recording_ids.is_empty());
    }

    #[test]
    fn omitted_recording_list_searches_every_recording_newest_first() {
        let fixture = Fixture::new();
        let older = fixture.add_recording(100, &[("recording-0.slog", SAMPLE_LOG)]);
        let newer = fixture.add_recording(200, &[("recording-0.slog", SAMPLE_LOG)]);
        fixture.add_recording(300, &[("recording-0.webm", "Bob Smith")]);
        std::fs::create_dir(fixture.root.join("not-a-recording")).expect("create unrelated dir");
        std::fs::write(fixture.root.join(Uuid::new_v4().to_string()), "Bob").expect("write unrelated file");

        let mut request = request(None, "bob");
        request.event_types = vec!["session.action".to_owned()];
        let response = run(&fixture.root, request);

        let recordings: Vec<Uuid> = response.hits.iter().map(|hit| hit.recording_id).collect();
        assert_eq!(recordings, [newer, newer, older, older]);
        assert!(response.not_found_recording_ids.is_empty());
    }

    #[test]
    fn omitted_recording_list_tolerates_a_missing_recording_directory() {
        let fixture = Fixture::new();

        let response = run(&fixture.root.join("missing"), request(None, "bob"));

        assert!(response.hits.is_empty());
    }

    #[test]
    fn stops_at_the_hit_limit() {
        let fixture = Fixture::new();
        let first = fixture.add_recording(0, &[("recording-0.slog", SAMPLE_LOG)]);
        let second = fixture.add_recording(0, &[("recording-0.slog", SAMPLE_LOG)]);
        let missing = Uuid::new_v4();

        let mut request = request(Some(vec![first, second, missing]), "bob");
        request.limit = Some(1);
        let response = run(&fixture.root, request);

        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].recording_id, first);
        assert!(response.limit_reached);
        assert_eq!(response.not_found_recording_ids, [missing]);
    }

    #[test]
    fn stops_when_the_returned_entries_reach_the_response_size_bound() {
        let fixture = Fixture::new();
        let description = format!("Bob {}", "x".repeat(200 * 1024));
        let line = serde_json::json!({ "event": "session.action", "description": description }).to_string();
        let contents = format!("{line}\n").repeat(MAX_HIT_BYTES_PER_REQUEST / line.len() + 2);
        let id = fixture.add_recording(0, &[("recording-0.slog", &contents)]);

        let response = run(&fixture.root, request(Some(vec![id]), "bob"));

        assert_eq!(response.hits.len(), MAX_HIT_BYTES_PER_REQUEST.div_ceil(line.len()));
        assert!(response.limit_reached);
    }

    #[test]
    fn reports_when_a_file_exceeds_the_scanned_line_bound() {
        let fixture = Fixture::new();
        let line = r#"{"event":"session.action","description":"Unrelated"}"#;
        let mut contents = format!("{line}\n").repeat(MAX_SCANNED_LINES_PER_FILE);
        contents.push_str(r#"{"event":"session.action","description":"Bob"}"#);
        let id = fixture.add_recording(0, &[("recording-0.slog", &contents)]);

        let response = run(&fixture.root, request(Some(vec![id]), "bob"));

        assert!(response.hits.is_empty());
        assert!(response.scan_limit_reached);
    }

    #[test]
    fn rejects_invalid_requests() {
        let too_many_ids = (0..=MAX_RECORDING_IDS).map(|_| Uuid::new_v4()).collect();
        assert!(SearchOptions::from_request(request(Some(too_many_ids), "bob")).is_err());

        let too_long_query = "x".repeat(MAX_QUERY_LENGTH + 1);
        assert!(SearchOptions::from_request(request(None, &too_long_query)).is_err());

        let mut too_many_event_types = request(None, "bob");
        too_many_event_types.event_types = vec!["session.action".to_owned(); MAX_EVENT_TYPES + 1];
        assert!(SearchOptions::from_request(too_many_event_types).is_err());

        let mut empty_time_range = request(None, "bob");
        empty_time_range.from = Some(instant("2026-07-15T21:20:00Z"));
        empty_time_range.to = Some(instant("2026-07-15T21:20:00Z"));
        assert!(SearchOptions::from_request(empty_time_range).is_err());
    }

    #[test]
    fn normalizes_the_request() {
        let id = Uuid::new_v4();
        let mut request = request(Some(vec![id, id]), "  O'Connor  ");
        request.limit = Some(MAX_HIT_LIMIT + 1);

        let options = options(request);

        let RecordingSelection::Listed(recording_ids) = &options.recordings else {
            panic!("expected listed recordings");
        };
        assert_eq!(recording_ids, &[id]);
        assert_eq!(options.query, "o'connor");
        assert_eq!(options.limit, MAX_HIT_LIMIT);
    }
}
