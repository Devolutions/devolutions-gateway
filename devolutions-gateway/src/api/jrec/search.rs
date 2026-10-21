use std::collections::HashSet;
use std::io;

use axum::Json;
use axum::extract::State;
use camino::{Utf8Path, Utf8PathBuf};
use time::OffsetDateTime;
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

/// Log bytes one search reads before it stops, so that searching every recording takes a bounded time.
///
/// A search reads past it by about [`MAX_LINE_BYTES`] at most, to finish reading the start of a line.
const MAX_SCANNED_BYTES: u64 = 16 * 1024 * 1024;

/// Bytes of a line that are matched and returned; the rest of a longer line is skipped.
const MAX_LINE_BYTES: usize = 256 * 1024;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingSearchRequest {
    /// Text to search for.
    query: String,
    /// The recordings to search.
    recordings: RecordingSelection,
    /// Only search the recordings that started in this range.
    #[serde(default)]
    start_time: Option<StartTimeRange>,
}

/// `"all"`, or a list of recording IDs.
///
/// A repeated ID is searched once, and an empty list searches nothing.
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum RecordingSelection {
    All(AllRecordings),
    Listed(Vec<Uuid>),
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AllRecordings {
    All,
}

// The derived schema puts `"all"` in its own enum schema, which version 7.9.0 of the C# client generator turns into
// a `oneOf` constructor that does not compile.
#[cfg(feature = "openapi")]
impl<'__s> utoipa::ToSchema<'__s> for RecordingSelection {
    fn schema() -> (&'__s str, utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>) {
        use utoipa::openapi::schema::{
            ArrayBuilder, KnownFormat, ObjectBuilder, OneOfBuilder, SchemaFormat, SchemaType,
        };

        let all = ObjectBuilder::new()
            .schema_type(SchemaType::String)
            .enum_values(Some(["all"]));

        let listed = ArrayBuilder::new().items(
            ObjectBuilder::new()
                .schema_type(SchemaType::String)
                .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uuid))),
        );

        let schema = OneOfBuilder::new()
            .item(all)
            .item(listed)
            .description(Some(
                "`\"all\"`, or a list of recording IDs.\n\nA repeated ID is searched once, and an empty list searches nothing.",
            ));

        ("RecordingSelection", schema.into())
    }
}

/// A range of recording start times, as written in `recording.json`, that includes `from` and excludes `to`.
///
/// A missing end leaves that side of the range open.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
pub(crate) struct StartTimeRange {
    /// Earliest start time searched.
    #[serde(default, with = "time::serde::rfc3339::option")]
    from: Option<OffsetDateTime>,
    /// Recordings that start at this time or later are not searched.
    #[serde(default, with = "time::serde::rfc3339::option")]
    to: Option<OffsetDateTime>,
}

impl StartTimeRange {
    /// Whether a recording that started at `start_time`, in Unix seconds, is in the range.
    fn contains(&self, start_time: i64) -> bool {
        let start_time = i128::from(start_time) * 1_000_000_000;

        self.from.is_none_or(|from| from.unix_timestamp_nanos() <= start_time)
            && self.to.is_none_or(|to| start_time < to.unix_timestamp_nanos())
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingSearchResponse {
    /// Matching lines, newest recording first when searching all recordings, otherwise in the requested order.
    hits: Vec<RecordingSearchHit>,
    /// The search stopped before reading every log, so more lines may match.
    limit_reached: bool,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingSearchHit {
    recording_id: Uuid,
    /// Name of the `.slog` artifact holding the line, as listed in `recording.json`.
    file_name: String,
    /// Number of the line in the file, counting from 1.
    line_number: u64,
    /// Byte offset of the line in the file.
    offset: u64,
    /// The line's text without its line break; bytes that are not UTF-8 read as U+FFFD.
    line: String,
    /// The line is longer than 256 KiB, so `line` holds only its start, and the file holds the rest.
    truncated: bool,
}

/// Searches the `.slog` artifacts, such as AI analysis logs, of recordings stored on this instance
///
/// The query is a case-insensitive substring, matched against the raw text of each line.
/// Gateway does not interpret the logs, so any part of a line can match, field names included.
/// Only the files listed under `artifacts` in `recording.json` with the `slog` type are searched,
/// and a line longer than 256 KiB is matched on its first 256 KiB only.
/// Recordings without a readable `recording.json` and IDs with no recording on this instance give no hits.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "SearchRecordings",
    tag = "Jrec",
    path = "/jet/jrec/search",
    request_body(content = RecordingSearchRequest, description = "JSON-encoded search request", content_type = "application/json"),
    responses(
        (status = 200, description = "Matching log lines", body = RecordingSearchResponse),
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

    let mut recordings = match request.recordings {
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

    if let Some(start_time) = &request.start_time {
        recordings.retain(|recording| start_time.contains(recording.start_time));
    }

    let mut search = Search::new(text);

    for recording in recordings {
        for file_name in &recording.file_names {
            let path = recording.dir.join(file_name);

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

/// Search text in lowercase, the case lines are compared in.
struct SearchText(String);

impl SearchText {
    fn new(query: &str) -> Option<Self> {
        let text = query.trim().to_lowercase();
        (!text.is_empty()).then_some(Self(text))
    }

    fn is_in(&self, line: &str) -> bool {
        line.to_lowercase().contains(&self.0)
    }
}

struct Search {
    text: SearchText,
    hits: Vec<RecordingSearchHit>,
    scanned_bytes: u64,
    limit_reached: bool,
}

impl Search {
    fn new(text: SearchText) -> Self {
        Self {
            text,
            hits: Vec::new(),
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

    /// Adds the lines of one log that hold the search text.
    async fn search_file(&mut self, recording_id: Uuid, file_name: &str, path: &Utf8Path) -> io::Result<()> {
        let mut reader = BufReader::new(File::open(path).await?);
        let mut line = Vec::new();
        let mut line_number = 0;
        let mut offset = 0;

        loop {
            if MAX_SCANNED_BYTES <= self.scanned_bytes {
                self.limit_reached = true;
                return Ok(());
            }

            let Some(read) = read_line(&mut reader, &mut line).await? else {
                return Ok(());
            };
            self.scanned_bytes += read.bytes;
            line_number += 1;
            let line_offset = offset;
            offset += read.bytes;

            let text = String::from_utf8_lossy(&line);
            if self.text.is_in(&text) {
                if MAX_HITS <= self.hits.len() {
                    self.limit_reached = true;
                    return Ok(());
                }

                self.hits.push(RecordingSearchHit {
                    recording_id,
                    file_name: file_name.to_owned(),
                    line_number,
                    offset: line_offset,
                    line: text.into_owned(),
                    truncated: read.truncated,
                });
            }

            if read.rest_unread {
                let budget = MAX_SCANNED_BYTES.saturating_sub(self.scanned_bytes);
                let skipped = skip_rest_of_line(&mut reader, budget).await?;
                self.scanned_bytes += skipped.bytes;
                offset += skipped.bytes;

                if !skipped.finished {
                    self.limit_reached = true;
                    return Ok(());
                }
            }
        }
    }
}

/// The `.slog` artifacts of one recording.
struct RecordingLogs {
    recording_id: Uuid,
    dir: Utf8PathBuf,
    start_time: i64,
    file_names: Vec<String>,
}

/// Lists the `.slog` artifacts of a recording, such as its AI analysis, from `recording.json`.
async fn read_recording_logs(dir: Utf8PathBuf, recording_id: Uuid) -> Option<RecordingLogs> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Manifest {
        start_time: i64,
        #[serde(default)]
        artifacts: JrecArtifacts,
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
        .artifacts
        .into_file_names()
        .into_iter()
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

/// Logs of every recording on this instance, newest first by manifest start time, then by recording ID.
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

    // Ordering by ID too keeps the order of recordings that start together the same on every request.
    recordings.sort_unstable_by(|a, b| (b.start_time, b.recording_id).cmp(&(a.start_time, a.recording_id)));

    Ok(recordings)
}

struct LineRead {
    /// Bytes consumed, line break included.
    bytes: u64,
    /// The line is longer than [`MAX_LINE_BYTES`], so `line` holds only its start.
    truncated: bool,
    /// The rest of a truncated line, up to its line break, is still to be read.
    rest_unread: bool,
}

/// Reads the next line into `line`, without its line break, and returns `None` at the end of the file.
///
/// A line longer than [`MAX_LINE_BYTES`] is cut to its start, at a character boundary.
///
/// INVARIANT: on return, `line` holds at most [`MAX_LINE_BYTES`] bytes.
async fn read_line(reader: &mut BufReader<File>, line: &mut Vec<u8>) -> io::Result<Option<LineRead>> {
    // Room for a line of exactly `MAX_LINE_BYTES` and its `\r\n`, so that it is not taken for a longer one.
    const MAX_BUFFERED_BYTES: usize = MAX_LINE_BYTES + 2;

    line.clear();
    let mut bytes = 0;
    let mut ended = false;

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if bytes == 0 {
                return Ok(None);
            }

            ended = true;
            break;
        }

        let room = MAX_BUFFERED_BYTES - line.len();
        let window = &available[..available.len().min(room)];
        let line_break = window.iter().position(|&byte| byte == b'\n');
        line.extend_from_slice(&window[..line_break.unwrap_or(window.len())]);

        let consumed = line_break.map_or(window.len(), |index| index + 1);
        reader.consume(consumed);
        bytes += u64::try_from(consumed).expect("buffer length fits in u64");

        if line_break.is_some() {
            ended = true;
            break;
        }

        if line.len() == MAX_BUFFERED_BYTES {
            break;
        }
    }

    if ended && line.last() == Some(&b'\r') {
        line.pop();
    }

    let truncated = MAX_LINE_BYTES < line.len();
    if truncated {
        line.truncate(MAX_LINE_BYTES);
        line.truncate(len_without_cut_character(line));
    }

    Ok(Some(LineRead {
        bytes,
        truncated,
        rest_unread: !ended,
    }))
}

/// Length of `line` without a UTF-8 character that is cut at its end.
fn len_without_cut_character(line: &[u8]) -> usize {
    match std::str::from_utf8(line) {
        Err(error) if error.error_len().is_none() => error.valid_up_to(),
        _ => line.len(),
    }
}

struct Skipped {
    /// Bytes consumed, line break included.
    bytes: u64,
    /// The line break or the end of the file was reached.
    finished: bool,
}

/// Consumes the rest of a line up to its line break, reading at most `budget` bytes,
/// so that a log without line breaks cannot make one search read all of it.
async fn skip_rest_of_line(reader: &mut BufReader<File>, budget: u64) -> io::Result<Skipped> {
    let mut bytes = 0;

    while bytes < budget {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(Skipped { bytes, finished: true });
        }

        let room = usize::try_from(budget - bytes).unwrap_or(usize::MAX);
        let window = &available[..available.len().min(room)];
        let line_break = window.iter().position(|&byte| byte == b'\n');

        let consumed = line_break.map_or(window.len(), |index| index + 1);
        reader.consume(consumed);
        bytes += u64::try_from(consumed).expect("buffer length fits in u64");

        if line_break.is_some() {
            return Ok(Skipped { bytes, finished: true });
        }
    }

    Ok(Skipped { bytes, finished: false })
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    async fn search_log(query: &str, content: &[u8]) -> Search {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("ai-analysis-0.slog")).expect("UTF-8 path");
        std::fs::write(&path, content).expect("write log");

        let mut search = Search::new(SearchText::new(query).expect("non-empty query"));
        search
            .search_file(Uuid::nil(), "ai-analysis-0.slog", &path)
            .await
            .expect("search log");

        search
    }

    fn hit_lines(search: &Search) -> Vec<(u64, &str)> {
        search
            .hits
            .iter()
            .map(|hit| (hit.line_number, hit.line.as_str()))
            .collect()
    }

    #[rstest]
    #[case::value_in_another_case("created USER")]
    #[case::field_name("description")]
    #[case::event_name("session.action")]
    #[tokio::test]
    async fn matches_any_part_of_the_raw_line(#[case] query: &str) {
        let line = r#"{"seq":1,"event":"session.action","description":"Created User"}"#;

        let search = search_log(query, line.as_bytes()).await;

        assert_eq!(hit_lines(&search), [(1, line)]);
    }

    #[tokio::test]
    async fn returns_a_line_that_is_not_json() {
        let search = search_log("sess", br#"{"seq":12,"event":"sess"#).await;

        assert_eq!(hit_lines(&search), [(1, r#"{"seq":12,"event":"sess"#)]);
    }

    #[tokio::test]
    async fn gives_the_line_number_and_byte_offset_of_each_hit() {
        let search = search_log("hit", b"first\r\nsecond hit\r\nthird\r\nfourth hit\n").await;

        let positions: Vec<_> = search
            .hits
            .iter()
            .map(|hit| (hit.line_number, hit.offset, hit.line.as_str()))
            .collect();
        assert_eq!(positions, [(2, 7, "second hit"), (4, 26, "fourth hit")]);
    }

    #[tokio::test]
    async fn keeps_a_line_at_the_limit_ending_with_crlf_whole() {
        let line = format!("hit{}", "x".repeat(MAX_LINE_BYTES - 3));

        let search = search_log("hit", format!("{line}\r\n").as_bytes()).await;

        assert_eq!(search.hits.len(), 1);
        assert_eq!(search.hits[0].line, line);
        assert!(!search.hits[0].truncated);
    }

    #[tokio::test]
    async fn cuts_a_longer_line_and_keeps_reading_after_it() {
        let content = format!("hit{}\nhit again\n", "x".repeat(MAX_LINE_BYTES));

        let search = search_log("hit", content.as_bytes()).await;

        assert_eq!(search.hits.len(), 2);
        assert_eq!(search.hits[0].line.len(), MAX_LINE_BYTES);
        assert!(search.hits[0].truncated);
        assert_eq!(hit_lines(&search)[1], (2, "hit again"));
    }

    #[tokio::test]
    async fn does_not_match_past_the_first_256_kib_of_a_line() {
        let content = format!("{}hit\n", "x".repeat(MAX_LINE_BYTES));

        let search = search_log("hit", content.as_bytes()).await;

        assert!(search.hits.is_empty());
    }

    #[tokio::test]
    async fn cuts_a_long_line_on_a_character_boundary() {
        // "€" is 3 bytes, so the limit falls 1 byte into a character.
        let content = format!("hit{}", "€".repeat(MAX_LINE_BYTES / 3));

        let search = search_log("hit", content.as_bytes()).await;

        assert_eq!(search.hits[0].line.len(), MAX_LINE_BYTES - 1);
        assert!(!search.hits[0].line.contains('\u{FFFD}'));
    }

    #[tokio::test]
    async fn stops_at_the_hit_limit() {
        let content = "hit\n".repeat(MAX_HITS + 1);

        let search = search_log("hit", content.as_bytes()).await;

        assert_eq!(search.hits.len(), MAX_HITS);
        assert!(search.limit_reached);
    }

    #[tokio::test]
    async fn stops_inside_a_line_without_breaks_at_the_read_budget() {
        let budget = usize::try_from(MAX_SCANNED_BYTES).expect("budget fits in usize");
        let mut content = b"hit\n".to_vec();
        content.resize(content.len() + budget + 1024 * 1024, b'x');
        content.extend_from_slice(b"\nhit\n");

        let search = search_log("hit", &content).await;

        assert_eq!(hit_lines(&search), [(1, "hit")]);
        assert!(search.limit_reached);
        assert!(search.scanned_bytes <= MAX_SCANNED_BYTES);
    }

    const SECOND: i128 = 1_000_000_000;

    fn at(unix_nanos: i128) -> Option<OffsetDateTime> {
        Some(OffsetDateTime::from_unix_timestamp_nanos(unix_nanos).expect("valid time"))
    }

    #[rstest]
    #[case::from_is_included(at(100 * SECOND), None, true)]
    #[case::from_a_fraction_later(at(100 * SECOND + SECOND / 2), None, false)]
    #[case::to_is_excluded(None, at(100 * SECOND), false)]
    #[case::to_a_fraction_later(None, at(100 * SECOND + 1), true)]
    #[case::open(None, None, true)]
    fn keeps_start_times_from_from_up_to_to(
        #[case] from: Option<OffsetDateTime>,
        #[case] to: Option<OffsetDateTime>,
        #[case] contains: bool,
    ) {
        assert_eq!(StartTimeRange { from, to }.contains(100), contains);
    }

    fn parse_request(fields: &str) -> serde_json::Result<RecordingSearchRequest> {
        serde_json::from_str(&format!(r#"{{"query":"q",{fields}}}"#))
    }

    #[test]
    fn parses_start_times_with_fractions_and_offsets() {
        let request = parse_request(
            r#""recordings":"all","startTime":{"from":"2026-10-10T00:00:00.000Z","to":"2026-10-10T02:00:00+02:00"}"#,
        )
        .expect("valid request");

        let start_time = request.start_time.expect("start time range");
        assert!(start_time.from.is_some());
        assert_eq!(start_time.from, start_time.to);
    }

    #[test]
    fn parses_all_recordings() {
        let request = parse_request(r#""recordings":"all""#).expect("valid request");

        assert!(matches!(
            request.recordings,
            RecordingSelection::All(AllRecordings::All)
        ));
    }

    #[rstest]
    #[case::ids(
        r#"["00000000-0000-0000-0000-000000000002","00000000-0000-0000-0000-000000000001"]"#,
        vec![Uuid::from_u128(2), Uuid::from_u128(1)]
    )]
    #[case::empty("[]", Vec::new())]
    fn parses_listed_recordings(#[case] recordings: &str, #[case] expected: Vec<Uuid>) {
        let request = parse_request(&format!(r#""recordings":{recordings}"#)).expect("valid request");

        let RecordingSelection::Listed(recording_ids) = request.recordings else {
            panic!("expected a list of recording IDs");
        };
        assert_eq!(recording_ids, expected);
    }

    #[rstest]
    #[case::other_word(r#""some""#)]
    #[case::all_in_a_list(r#"["all"]"#)]
    fn rejects_other_recording_selections(#[case] recordings: &str) {
        assert!(parse_request(&format!(r#""recordings":{recordings}"#)).is_err());
    }
}
