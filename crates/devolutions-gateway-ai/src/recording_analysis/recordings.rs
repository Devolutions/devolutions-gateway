//! The recordings of a session, sorted by kind when they are accepted.
//!
//! A session is recorded either as a terminal or as a video, never both, and the types hold that: [`Recordings`] is
//! all terminal or all video, and each file is accepted only with the extension of its kind.

use camino::Utf8Path;

/// A file listed in a session manifest, `recording.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingFile {
    /// Name of the file, in the folder of the manifest.
    pub file_name: String,
    /// Start of the recording, in Unix seconds.
    pub start_time: i64,
}

/// The recordings of one session: all terminal, or all video.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recordings {
    Terminal(Vec<TerminalRecording>),
    Video(Vec<VideoRecording>),
}

/// Why the files of a session manifest are not one kind of recording.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordingsError {
    #[error("session has no terminal or video recording")]
    NoRecording,
    #[error("session mixes terminal and video recordings")]
    Mixed,
}

impl Recordings {
    /// Sorts the files of a session manifest by kind; files that are not recordings, such as session logs, are
    /// skipped.
    pub fn from_files(files: impl IntoIterator<Item = RecordingFile>) -> Result<Self, RecordingsError> {
        let mut terminal = Vec::new();
        let mut video = Vec::new();

        for file in files {
            match Kind::of(&file.file_name) {
                Some(Kind::Terminal(format)) => terminal.push(TerminalRecording {
                    file_name: file.file_name,
                    start_time: file.start_time,
                    format,
                }),
                Some(Kind::Video) => video.push(VideoRecording {
                    file_name: file.file_name,
                    start_time: file.start_time,
                }),
                None => {}
            }
        }

        match (terminal.is_empty(), video.is_empty()) {
            (false, true) => Ok(Self::Terminal(terminal)),
            (true, false) => Ok(Self::Video(video)),
            (true, true) => Err(RecordingsError::NoRecording),
            (false, false) => Err(RecordingsError::Mixed),
        }
    }

    /// Version of the prompt that describes this kind of recording.
    pub(super) fn prompt_version(&self) -> &'static str {
        match self {
            Self::Terminal(_) => crate::session_actions::PROMPT_VERSION,
            Self::Video(_) => crate::screen_actions::PROMPT_VERSION,
        }
    }

    /// Total size of the recording files in `dir`; a file that cannot be read counts as empty.
    pub(super) fn total_bytes(&self, dir: &Utf8Path) -> u64 {
        let size = |file_name: &str| std::fs::metadata(dir.join(file_name)).map_or(0, |metadata| metadata.len());

        match self {
            Self::Terminal(recordings) => recordings.iter().map(|recording| size(recording.file_name())).sum(),
            Self::Video(recordings) => recordings.iter().map(|recording| size(recording.file_name())).sum(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Terminal(recordings) => recordings.is_empty(),
            Self::Video(recordings) => recordings.is_empty(),
        }
    }
}

/// A file that is not a recording of the expected kind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{file_name} is not a {expected} recording")]
pub struct WrongRecordingKind {
    pub file_name: String,
    pub expected: &'static str,
}

/// Format of a terminal recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalFormat {
    /// Asciicast v2 or v3, `.cast`.
    Asciicast,
    /// Terminal Playback Recording, `.trp`.
    Trp,
}

/// A terminal recording, `.cast` or `.trp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalRecording {
    file_name: String,
    start_time: i64,
    format: TerminalFormat,
}

impl TerminalRecording {
    /// Accepts `file_name` only with the `.cast` or `.trp` extension.
    pub fn new(file_name: impl Into<String>, start_time: i64) -> Result<Self, WrongRecordingKind> {
        let file_name = file_name.into();

        match Kind::of(&file_name) {
            Some(Kind::Terminal(format)) => Ok(Self {
                file_name,
                start_time,
                format,
            }),
            _ => Err(WrongRecordingKind {
                file_name,
                expected: "terminal",
            }),
        }
    }

    /// Name of the file, in the folder of the manifest.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Start of the recording, in Unix seconds.
    pub fn start_time(&self) -> i64 {
        self.start_time
    }

    pub fn format(&self) -> TerminalFormat {
        self.format
    }
}

/// A video recording, `.webm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoRecording {
    file_name: String,
    start_time: i64,
}

impl VideoRecording {
    /// Accepts `file_name` only with the `.webm` extension.
    pub fn new(file_name: impl Into<String>, start_time: i64) -> Result<Self, WrongRecordingKind> {
        let file_name = file_name.into();

        match Kind::of(&file_name) {
            Some(Kind::Video) => Ok(Self { file_name, start_time }),
            _ => Err(WrongRecordingKind {
                file_name,
                expected: "video",
            }),
        }
    }

    /// Name of the file, in the folder of the manifest.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Start of the recording, in Unix seconds.
    pub fn start_time(&self) -> i64 {
        self.start_time
    }
}

enum Kind {
    Terminal(TerminalFormat),
    Video,
}

impl Kind {
    fn of(file_name: &str) -> Option<Self> {
        match Utf8Path::new(file_name).extension()? {
            "cast" => Some(Self::Terminal(TerminalFormat::Asciicast)),
            "trp" => Some(Self::Terminal(TerminalFormat::Trp)),
            "webm" => Some(Self::Video),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(file_name: &str) -> RecordingFile {
        RecordingFile {
            file_name: file_name.to_owned(),
            start_time: 1,
        }
    }

    #[test]
    fn files_are_sorted_by_kind_and_other_files_skipped() {
        let terminal = Recordings::from_files([file("recording-0.cast"), file("log.slog"), file("recording-1.trp")]);
        let Ok(Recordings::Terminal(terminal)) = terminal else {
            panic!("terminal session: {terminal:?}");
        };
        assert_eq!(
            terminal.iter().map(TerminalRecording::format).collect::<Vec<_>>(),
            [TerminalFormat::Asciicast, TerminalFormat::Trp]
        );

        let video = Recordings::from_files([file("recording-0.webm"), file("recording-1.webm")]);
        assert!(
            matches!(video, Ok(Recordings::Video(ref video)) if video.len() == 2),
            "{video:?}"
        );
    }

    #[test]
    fn a_session_with_both_kinds_or_none_is_refused() {
        assert_eq!(
            Recordings::from_files([file("recording-0.cast"), file("recording-1.webm")]),
            Err(RecordingsError::Mixed)
        );
        assert_eq!(
            Recordings::from_files([file("log.slog"), file("notes.txt")]),
            Err(RecordingsError::NoRecording)
        );
        assert_eq!(Recordings::from_files([]), Err(RecordingsError::NoRecording));
    }

    #[test]
    fn a_recording_is_accepted_only_with_the_extension_of_its_kind() {
        assert!(TerminalRecording::new("recording-0.cast", 1).is_ok());
        assert!(TerminalRecording::new("recording-0.trp", 1).is_ok());
        assert!(VideoRecording::new("recording-0.webm", 1).is_ok());

        for name in ["recording-0.webm", "log.slog", "recording-0", "recording-0.CAST"] {
            assert!(TerminalRecording::new(name, 1).is_err(), "{name}");
        }
        for name in ["recording-0.cast", "recording-0.trp", "recording-0.mp4"] {
            assert!(VideoRecording::new(name, 1).is_err(), "{name}");
        }
    }
}
