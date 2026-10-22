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

/// What to search for, and in which recordings.
///
/// Unknown fields are rejected, so that an option added later is never silently ignored by a Gateway that predates it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecordingSearchRequest {
    /// Text to search for, ignoring case; leading and trailing spaces are part of it, and an empty text matches every
    /// line.
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
#[serde(deny_unknown_fields)]
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

/// The lines that match the search text.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingSearchResponse {
    /// Matching lines, newest recording first when searching all recordings, otherwise in the requested order.
    hits: Vec<RecordingSearchHit>,
    /// The search stopped before reading every log, so more lines may match.
    limit_reached: bool,
}

/// A line that matches the search text.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordingSearchHit {
    /// The recording whose artifact holds the line.
    recording_id: Uuid,
    /// Name of the `.slog` artifact holding the line, as listed in `recording.json`.
    file_name: String,
    /// Number of the line in the file, counting from 1.
    #[cfg_attr(feature = "openapi", schema(minimum = 1))]
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
/// The query is a case-insensitive substring, and an empty query matches every line.
/// In a line holding a JSON object, it is matched against the string values of the object at any depth, as they read
/// once unescaped, so field names, numbers, booleans and null never match.
/// Any other line, such as one still being written, is matched as raw text.
/// A line longer than 256 KiB is matched on its first 256 KiB only, by the same rule, so a cut JSON object is usually
/// matched as raw text.
/// Only the files listed under `artifacts` in `recording.json` with the `slog` type are searched.
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
    let text = SearchText::new(&request.query);

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
                    trace!(%path, "Recording log listed in the manifest is missing");
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

/// The query, lowercased the same way as the text it is compared with.
///
/// It also keeps the buffers that matching a line fills, so that once they have grown, a line is matched without
/// allocating.
struct SearchText {
    query: String,
    /// The arrays and objects open where the scan of a JSON line has reached.
    open: Vec<Container>,
    /// The text being compared with the query, lowercased.
    lowercase: String,
}

impl SearchText {
    fn new(query: &str) -> Self {
        let mut lowercase_query = String::new();
        push_lowercase_for_matching(query, &mut lowercase_query);

        Self {
            query: lowercase_query,
            open: Vec::new(),
            lowercase: String::new(),
        }
    }

    /// Whether `line` matches the search text.
    ///
    /// In a JSON object, only the string values count, once unescaped, so that a field name never matches and
    /// `DOMAIN\user` matches the `"DOMAIN\\user"` a JSON writer stores.
    /// Any other line is compared as raw text, so that a line of plain text that happens to parse as JSON, such as
    /// `2026`, still matches.
    fn is_in(&mut self, line: &[u8]) -> bool {
        // An empty query matches every line, as in rg, even one with no string value to compare.
        if self.query.is_empty() {
            return true;
        }

        match self.scan_object(line) {
            Some(found) => found,
            None => self.is_in_text(&String::from_utf8_lossy(line)),
        }
    }

    /// Reads `line` as one JSON object and tells whether one of its string values holds the query, or returns `None`
    /// when the line is anything else.
    ///
    /// The open arrays and objects are kept in a list rather than followed by recursion, so that an object nested
    /// however deep is still matched by its values.
    fn scan_object(&mut self, line: &[u8]) -> Option<bool> {
        let mut json = JsonCursor { bytes: line, at: 0 };
        let mut found = false;
        self.open.clear();

        json.skip_whitespace();
        if json.rest().first() != Some(&b'{') {
            return None;
        }

        loop {
            json.skip_whitespace();
            match json.take_byte()? {
                b'{' => {
                    json.skip_whitespace();
                    if !json.eat(b'}') {
                        self.open.push(Container::Object);
                        json.field_name()?;
                        continue;
                    }
                }
                b'[' => {
                    json.skip_whitespace();
                    if !json.eat(b']') {
                        self.open.push(Container::Array);
                        continue;
                    }
                }
                b'"' if found => json.string(None)?,
                b'"' => {
                    self.lowercase.clear();
                    json.string(Some(&mut self.lowercase))?;
                    found = self.lowercase.contains(&self.query);
                }
                b't' => json.rest_of_word(b"true")?,
                b'f' => json.rest_of_word(b"false")?,
                b'n' => json.rest_of_word(b"null")?,
                first @ (b'-' | b'0'..=b'9') => json.number(first)?,
                _ => return None,
            }

            loop {
                json.skip_whitespace();
                let Some(&container) = self.open.last() else {
                    return json.rest().is_empty().then_some(found);
                };

                match (json.take_byte()?, container) {
                    (b',', Container::Object) => {
                        json.field_name()?;
                        break;
                    }
                    (b',', Container::Array) => break,
                    (b'}', Container::Object) | (b']', Container::Array) => {
                        self.open.pop();
                    }
                    _ => return None,
                }
            }
        }
    }

    fn is_in_text(&mut self, text: &str) -> bool {
        self.lowercase.clear();
        push_lowercase_for_matching(text, &mut self.lowercase);
        self.lowercase.contains(&self.query)
    }
}

/// Appends `text` lowercased to `lowercase`, with every sigma in its middle form.
///
/// Greek ends a word with "ς" rather than "σ", so without this, a query that stops at a sigma would not match the same
/// letters inside a longer word.
fn push_lowercase_for_matching(text: &str, lowercase: &mut String) {
    // Logs are mostly ASCII, which lowercases far faster byte by byte than character by character.
    if text.is_ascii() {
        let start = lowercase.len();
        lowercase.push_str(text);
        lowercase[start..].make_ascii_lowercase();
        return;
    }

    for character in text.chars().flat_map(char::to_lowercase) {
        lowercase.push(if character == 'ς' { 'σ' } else { character });
    }
}

#[derive(Clone, Copy)]
enum Container {
    Object,
    Array,
}

/// A position in a line read as JSON.
struct JsonCursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> JsonCursor<'a> {
    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }

    fn take_byte(&mut self) -> Option<u8> {
        let byte = *self.rest().first()?;
        self.at += 1;
        Some(byte)
    }

    fn eat(&mut self, byte: u8) -> bool {
        let is_next = self.rest().first() == Some(&byte);
        if is_next {
            self.at += 1;
        }
        is_next
    }

    fn skip_whitespace(&mut self) {
        let whitespace = self
            .rest()
            .iter()
            .take_while(|&&byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
            .count();
        self.at += whitespace;
    }

    /// Skips digits, and tells whether there was any.
    fn digits(&mut self) -> bool {
        let digits = self.rest().iter().take_while(|byte| byte.is_ascii_digit()).count();
        self.at += digits;
        0 < digits
    }

    /// Reads the rest of `word`, whose first letter was just read.
    fn rest_of_word(&mut self, word: &[u8]) -> Option<()> {
        let letters = &word[1..];
        if !self.rest().starts_with(letters) {
            return None;
        }
        self.at += letters.len();
        Some(())
    }

    /// Reads the rest of a number whose first character, `first`, was just read.
    fn number(&mut self, first: u8) -> Option<()> {
        let first_digit = if first == b'-' { self.take_byte()? } else { first };
        match first_digit {
            b'0' => {}
            b'1'..=b'9' => {
                self.digits();
            }
            _ => return None,
        }

        if self.eat(b'.') && !self.digits() {
            return None;
        }

        if self.eat(b'e') || self.eat(b'E') {
            if !self.eat(b'+') {
                self.eat(b'-');
            }
            if !self.digits() {
                return None;
            }
        }

        Some(())
    }

    /// Reads a field name and the colon after it.
    fn field_name(&mut self) -> Option<()> {
        self.skip_whitespace();
        if !self.eat(b'"') {
            return None;
        }
        self.string(None)?;
        self.skip_whitespace();
        self.eat(b':').then_some(())
    }

    /// Reads the rest of a string, and appends its text, unescaped and lowercased, to `text` when given one.
    fn string(&mut self, mut text: Option<&mut String>) -> Option<()> {
        loop {
            let run = self
                .rest()
                .iter()
                .position(|&byte| byte == b'"' || byte == b'\\' || byte < 0x20)?;
            let unescaped = std::str::from_utf8(&self.rest()[..run]).ok()?;
            self.at += run;
            if let Some(text) = text.as_deref_mut() {
                push_lowercase_for_matching(unescaped, text);
            }

            match self.take_byte()? {
                b'"' => return Some(()),
                b'\\' => {
                    let character = self.escaped_character()?;
                    if let Some(text) = text.as_deref_mut() {
                        push_lowercase_for_matching(character.encode_utf8(&mut [0; 4]), text);
                    }
                }
                _ => return None,
            }
        }
    }

    /// Reads the rest of an escape, after its backslash.
    fn escaped_character(&mut self) -> Option<char> {
        let character = match self.take_byte()? {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let unit = self.hex_unit()?;
                // A character past U+FFFF is escaped as two UTF-16 units.
                let low_unit = if (0xD800..0xDC00).contains(&unit) {
                    if !(self.eat(b'\\') && self.eat(b'u')) {
                        return None;
                    }
                    Some(self.hex_unit()?)
                } else {
                    None
                };
                let utf16 = std::iter::once(unit).chain(low_unit);
                char::decode_utf16(utf16).next()?.ok()?
            }
            _ => return None,
        };
        Some(character)
    }

    /// Reads the four hexadecimal digits of a `\u` escape.
    fn hex_unit(&mut self) -> Option<u16> {
        let digits = self.rest().get(..4)?;
        // `from_str_radix` also takes a leading `+`.
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        self.at += 4;
        u16::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
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

    /// Adds the lines of one log that match the search text.
    async fn search_file(&mut self, recording_id: Uuid, file_name: &str, path: &Utf8Path) -> io::Result<()> {
        let mut reader = BufReader::new(File::open(path).await?);
        let mut line = Vec::new();
        let mut line_number = 0;
        let mut offset = 0;

        loop {
            if MAX_SCANNED_BYTES <= self.scanned_bytes {
                self.limit_reached = !reader.fill_buf().await?.is_empty();
                return Ok(());
            }

            let Some(read) = read_line(&mut reader, &mut line).await? else {
                return Ok(());
            };
            self.scanned_bytes += read.bytes;
            line_number += 1;
            let line_offset = offset;
            offset += read.bytes;

            if self.text.is_in(&line) {
                if MAX_HITS <= self.hits.len() {
                    self.limit_reached = true;
                    return Ok(());
                }

                self.hits.push(RecordingSearchHit {
                    recording_id,
                    file_name: file_name.to_owned(),
                    line_number,
                    offset: line_offset,
                    line: String::from_utf8_lossy(&line).into_owned(),
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

    // Every search reads every manifest again, so a failure here repeats on each search.
    let json = tokio::fs::read(&path)
        .await
        .inspect_err(|error| trace!(%path, %error, "Failed to read a recording manifest"))
        .ok()?;

    let manifest: Manifest = serde_json::from_slice(&json)
        .inspect_err(|error| trace!(%path, %error, "Invalid recording manifest"))
        .ok()?;

    // A log listed twice would be searched twice.
    let mut seen = HashSet::new();
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
                && seen.insert(file_name.clone())
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
        // Gateway names a recording folder by the hyphenated ID, and a copy under another spelling of the same ID
        // would be searched as the same recording twice.
        let Some(recording_id) = entry.file_name().to_str().and_then(|name| {
            Uuid::parse_str(name)
                .ok()
                .filter(|recording_id| recording_id.to_string() == name)
        }) else {
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

        let cut_character = line.utf8_chunks().last().map_or(0, |chunk| {
            let invalid = chunk.invalid();
            let is_incomplete = std::str::from_utf8(invalid).is_err_and(|error| error.error_len().is_none());
            if is_incomplete { invalid.len() } else { 0 }
        });
        line.truncate(line.len() - cut_character);
    }

    Ok(Some(LineRead {
        bytes,
        truncated,
        rest_unread: !ended,
    }))
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

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(Skipped { bytes, finished: true });
        }

        if budget <= bytes {
            return Ok(Skipped { bytes, finished: false });
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
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    async fn search_log(query: &str, content: &[u8]) -> Search {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("ai-analysis-0.slog")).expect("UTF-8 path");
        std::fs::write(&path, content).expect("write log");

        let mut search = Search::new(SearchText::new(query));
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

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    #[rstest]
    #[case::value_in_another_case("created USER")]
    #[case::event_name("session.action")]
    #[case::nested_value("ottawa/hull")]
    #[case::value_in_an_array("audit trail")]
    #[tokio::test]
    async fn matches_the_string_values_of_a_json_line(#[case] query: &str) {
        let line = r#"{"seq":1,"event":"session.action","description":"Created User","parameters":{"New name":"Help Desk Ottawa/Hull"},"tags":["Audit trail"]}"#;

        let search = search_log(query, line.as_bytes()).await;

        assert_eq!(hit_lines(&search), [(1, line)]);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    #[rstest]
    #[case::field_name("description")]
    #[case::nested_field_name("new name")]
    #[case::number("12")]
    #[case::boolean("true")]
    #[case::null("null")]
    #[tokio::test]
    async fn does_not_match_the_field_names_or_other_values_of_a_json_line(#[case] query: &str) {
        let line =
            r#"{"seq":12,"done":true,"actor":null,"description":"Created User","parameters":{"New name":"Bob"}}"#;

        let search = search_log(query, line.as_bytes()).await;

        assert!(search.hits.is_empty());
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    // oracle: spec RFC 8259 §7
    #[rstest]
    #[case::backslash(r"IT-HELP\Administrator", r#"{"description":"Reset IT-HELP\\Administrator"}"#)]
    #[case::quote(r#""net user""#, r#"{"description":"Ran \"net user\""}"#)]
    #[case::unicode_escape("créé", r#"{"description":"Utilisateur cr\u00e9\u00e9"}"#)]
    #[tokio::test]
    async fn matches_the_text_of_a_json_string_once_unescaped(#[case] query: &str, #[case] line: &str) {
        let search = search_log(query, line.as_bytes()).await;

        assert_eq!(hit_lines(&search), [(1, line)]);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    #[tokio::test]
    async fn matches_a_string_value_nested_at_any_depth_but_not_its_field_name() {
        let depth = 100_000;
        let (open, close) = ("[".repeat(depth), "]".repeat(depth));
        let line = format!(r#"{{"description":{open}"DOMAIN\\user"{close}}}"#);

        let value = search_log(r"DOMAIN\user", line.as_bytes()).await;
        let field_name = search_log("description", line.as_bytes()).await;

        assert_eq!(value.hits.len(), 1);
        assert!(field_name.hits.is_empty());
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    #[tokio::test]
    async fn matches_a_json_object_followed_by_more_text_as_raw_text() {
        let line = br#"{"description":"DOMAIN\\user"} and more"#;

        let field_name = search_log("description", line).await;
        let value = search_log(r"DOMAIN\user", line).await;

        assert_eq!(field_name.hits.len(), 1);
        assert!(value.hits.is_empty());
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    // oracle: reference rg
    #[tokio::test]
    async fn matches_every_line_with_an_empty_query() {
        let search = search_log("", b"{\"seq\":1}\n\nplain\n").await;

        assert_eq!(hit_lines(&search), [(1, r#"{"seq":1}"#), (2, ""), (3, "plain")]);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    #[tokio::test]
    async fn matches_a_line_of_plain_text_that_parses_as_a_json_number() {
        let search = search_log("2026", b"2026").await;

        assert_eq!(hit_lines(&search), [(1, "2026")]);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Hits
    #[tokio::test]
    async fn matches_a_cut_line_that_no_longer_parses_as_raw_text() {
        let line = format!(r#"{{"description":"{}"}}"#, "x".repeat(MAX_LINE_BYTES));

        let search = search_log("description", line.as_bytes()).await;

        assert_eq!(search.hits.len(), 1);
        assert!(search.hits[0].truncated);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Hits
    #[tokio::test]
    async fn matches_a_cut_line_by_its_string_values_when_what_was_read_parses() {
        let mut line = br#"{"description":"DOMAIN\\user"}"#.to_vec();
        line.resize(MAX_LINE_BYTES + 1, b' ');

        let search = search_log(r"DOMAIN\user", &line).await;

        assert_eq!(search.hits.len(), 1);
        assert!(search.hits[0].truncated);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    #[rstest]
    #[case::query_ending_in_a_capital_sigma("ΧΡΗΣ", "ΧΡΗΣΤΗΣ")]
    #[case::line_ending_in_a_capital_sigma("σ", "ΟΣ")]
    #[tokio::test]
    async fn matches_a_sigma_wherever_it_falls_in_a_word(#[case] query: &str, #[case] line: &str) {
        let search = search_log(query, line.as_bytes()).await;

        assert_eq!(hit_lines(&search), [(1, line)]);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    #[tokio::test]
    async fn keeps_the_spaces_of_the_query() {
        let search = search_log("user ", br#"{"name":"username"}"#).await;

        assert!(search.hits.is_empty());
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Hits
    #[tokio::test]
    async fn returns_a_line_that_is_not_json() {
        let search = search_log("sess", br#"{"seq":12,"event":"sess"#).await;

        assert_eq!(hit_lines(&search), [(1, r#"{"seq":12,"event":"sess"#)]);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Hits
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

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Hits
    // oracle: reference webapp/packages/session-recording-log/src/parser.ts
    #[tokio::test]
    async fn keeps_a_line_at_the_limit_ending_with_crlf_whole() {
        let line = format!("hit{}", "x".repeat(MAX_LINE_BYTES - 3));

        let search = search_log("hit", format!("{line}\r\n").as_bytes()).await;

        assert_eq!(search.hits.len(), 1);
        assert_eq!(search.hits[0].line, line);
        assert!(!search.hits[0].truncated);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Hits
    #[tokio::test]
    async fn cuts_a_longer_line_and_keeps_reading_after_it() {
        let content = format!("hit{}\nhit again\n", "x".repeat(MAX_LINE_BYTES));

        let search = search_log("hit", content.as_bytes()).await;

        assert_eq!(search.hits.len(), 2);
        assert_eq!(search.hits[0].line.len(), MAX_LINE_BYTES);
        assert!(search.hits[0].truncated);
        assert_eq!(hit_lines(&search)[1], (2, "hit again"));
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Hits
    #[tokio::test]
    async fn does_not_match_past_the_first_256_kib_of_a_line() {
        let content = format!("{}hit\n", "x".repeat(MAX_LINE_BYTES));

        let search = search_log("hit", content.as_bytes()).await;

        assert!(search.hits.is_empty());
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Hits
    #[rstest]
    #[case::valid_text(b"hit".as_slice())]
    #[case::after_an_invalid_byte(b"\xFFhi".as_slice())]
    #[tokio::test]
    async fn cuts_a_long_line_on_a_character_boundary(#[case] start: &[u8]) {
        // Both starts are 3 bytes and "€" is 3 bytes, so the limit falls 1 byte into a character.
        let mut content = start.to_vec();
        content.extend_from_slice("€".repeat(MAX_LINE_BYTES / 3).as_bytes());

        let search = search_log("hi", &content).await;

        assert!(search.hits[0].truncated);
        assert!(search.hits[0].line.ends_with('€'));
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Hits
    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Limits
    #[test]
    fn limits_match_the_intent() {
        assert_eq!(MAX_LINE_BYTES, 256 * 1024);
        assert_eq!(MAX_HITS, 1_000);
        assert_eq!(MAX_SCANNED_BYTES, 16 * 1024 * 1024);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Limits
    #[tokio::test]
    async fn stops_at_the_hit_limit() {
        let content = "hit\n".repeat(MAX_HITS + 1);

        let search = search_log("hit", content.as_bytes()).await;

        assert_eq!(search.hits.len(), MAX_HITS);
        assert!(search.limit_reached);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Limits
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

    // oracle: mutant limitReached set when the read budget runs out exactly where the log ends
    #[rstest]
    #[case::with_a_final_line_break(b"\n".as_slice())]
    #[case::without_one(b"".as_slice())]
    #[tokio::test]
    async fn reaches_no_limit_when_the_read_budget_ends_with_the_log(#[case] end: &[u8]) {
        let budget = usize::try_from(MAX_SCANNED_BYTES).expect("budget fits in usize");
        let mut content = b"hit\n".to_vec();
        content.resize(budget - end.len(), b'x');
        content.extend_from_slice(end);

        let search = search_log("hit", &content).await;

        assert_eq!(hit_lines(&search), [(1, "hit")]);
        assert!(!search.limit_reached);
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    #[tokio::test]
    async fn lists_a_log_once_when_the_manifest_repeats_it() {
        let root = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            root.path().join("recording.json"),
            r#"{"startTime":100,"artifacts":{"ai-analysis":[{"fileName":"ai-analysis-0.slog"},{"fileName":"ai-analysis-0.slog"}]}}"#,
        )
        .expect("write manifest");
        let dir = Utf8PathBuf::from_path_buf(root.path().to_owned()).expect("UTF-8 path");

        let recording = read_recording_logs(dir, Uuid::nil()).await.expect("readable manifest");

        assert_eq!(recording.file_names, ["ai-analysis-0.slog"]);
    }

    /// Lists the recordings of a root holding a folder per name, each with a manifest that starts at the same time.
    async fn list_recording_folders(names: impl IntoIterator<Item = String>) -> Vec<Uuid> {
        let root = tempfile::tempdir().expect("temp dir");
        for name in names {
            let dir = root.path().join(name);
            std::fs::create_dir(&dir).expect("create recording folder");
            std::fs::write(dir.join("recording.json"), r#"{"startTime":100}"#).expect("write manifest");
        }
        let root = Utf8Path::from_path(root.path()).expect("UTF-8 path");

        let recordings = all_recording_logs_newest_first(root).await.expect("list recordings");

        recordings.iter().map(|recording| recording.recording_id).collect()
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
    #[tokio::test]
    async fn lists_recordings_that_start_together_highest_id_first() {
        let ids = list_recording_folders((1..=3).map(|id| Uuid::from_u128(id).to_string())).await;

        assert_eq!(ids, [3, 2, 1].map(Uuid::from_u128));
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §What is searched
    #[tokio::test]
    async fn lists_only_folders_named_by_the_hyphenated_id() {
        let id = Uuid::from_u128(1);

        let ids = list_recording_folders([id.to_string(), id.simple().to_string(), id.braced().to_string()]).await;

        assert_eq!(ids, [id]);
    }

    const SECOND: i128 = 1_000_000_000;

    fn at(unix_nanos: i128) -> Option<OffsetDateTime> {
        Some(OffsetDateTime::from_unix_timestamp_nanos(unix_nanos).expect("valid time"))
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
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

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
    // oracle: spec RFC 3339 §5.6
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

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
    #[test]
    fn parses_all_recordings() {
        let request = parse_request(r#""recordings":"all""#).expect("valid request");

        assert!(matches!(
            request.recordings,
            RecordingSelection::All(AllRecordings::All)
        ));
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
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

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
    #[rstest]
    #[case::other_word(r#""some""#)]
    #[case::all_in_a_list(r#"["all"]"#)]
    fn rejects_other_recording_selections(#[case] recordings: &str) {
        assert!(parse_request(&format!(r#""recordings":{recordings}"#)).is_err());
    }

    // oracle: intent devolutions-gateway/src/api/jrec/search.intent.md §Request
    #[rstest]
    #[case::in_the_request(r#""recordings":"all","mode":"regex""#)]
    #[case::in_the_start_time(r#""recordings":"all","startTime":{"until":"2026-10-10T00:00:00Z"}"#)]
    fn rejects_unknown_fields(#[case] fields: &str) {
        assert!(parse_request(fields).is_err());
    }
}
