//! Console encoding transcoding for IO redirection.
//!
//! When IO redirection is enabled, the child process writes its stdout/stderr using
//! the console's OEM codepage (e.g., `cmd.exe`, `powershell.exe`, `pwsh.exe`). This module
//! provides transcoding between the process's native encoding and UTF-8, which is
//! the encoding used on the wire (NowProto).

use std::borrow::Cow;

use tracing::warn;
use windows::Win32::Globalization::{
    MB_ERR_INVALID_CHARS, MultiByteToWideChar, WC_NO_BEST_FIT_CHARS, WideCharToMultiByte,
};

/// The encoding used for IO data streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataEncoding {
    /// Raw passthrough. No transcoding is performed.
    Raw,
    /// A Windows codepage that requires transcoding to/from UTF-8.
    Codepage(u32),
}

const CP_UTF8: u32 = 65001;

impl DataEncoding {
    /// Determine the OEM codepage encoding for the current system.
    ///
    /// Console applications (`cmd.exe`, `powershell.exe` 5.x, `pwsh.exe`) use the OEM
    /// codepage for piped/redirected output.
    pub fn from_oem_codepage() -> Self {
        // SAFETY: FFI call without outstanding preconditions.
        let cp = unsafe { windows::Win32::Globalization::GetOEMCP() };
        if cp == CP_UTF8 { Self::Raw } else { Self::Codepage(cp) }
    }

    /// Returns true if no transcoding is needed.
    pub fn is_raw(self) -> bool {
        matches!(self, Self::Raw)
    }

    /// Convert a UTF-8 string to bytes in this encoding.
    ///
    /// Returns borrowed bytes when no transcoding is needed (raw passthrough).
    pub fn encode_str<'a>(self, text: &'a str) -> Cow<'a, [u8]> {
        match self {
            Self::Raw => Cow::Borrowed(text.as_bytes()),
            Self::Codepage(cp) => Cow::Owned(convert_from_utf8(cp, text)),
        }
    }
}

/// Stateful decoder that transcodes from a Windows codepage to UTF-8.
///
/// Handles partial multi-byte characters that may be split across read chunks
/// (relevant for DBCS codepages like Shift-JIS, GBK, etc.).
pub struct OutputDecoder {
    encoding: DataEncoding,
    /// Leftover bytes from the previous chunk that form an incomplete multi-byte character.
    leftover: Vec<u8>,
}

impl OutputDecoder {
    pub fn new(encoding: DataEncoding) -> Self {
        Self {
            encoding,
            leftover: Vec::new(),
        }
    }

    /// Decode a chunk of bytes from the process encoding to UTF-8.
    ///
    /// Returns borrowed data when no transcoding is needed (raw passthrough).
    /// Any incomplete trailing multi-byte character is buffered internally and
    /// will be completed by the next call.
    pub fn decode<'a>(&mut self, data: &'a [u8]) -> Cow<'a, [u8]> {
        if self.encoding.is_raw() {
            return Cow::Borrowed(data);
        }

        let codepage = match self.encoding {
            DataEncoding::Codepage(cp) => cp,
            DataEncoding::Raw => unreachable!(),
        };

        // Prepend any leftover bytes from the previous chunk.
        let input = if self.leftover.is_empty() {
            Cow::Borrowed(data)
        } else {
            let mut combined = std::mem::take(&mut self.leftover);
            combined.extend_from_slice(data);
            Cow::Owned(combined)
        };

        if input.is_empty() {
            return Cow::Owned(Vec::new());
        }

        // Try to convert the entire buffer. If the last bytes form an incomplete
        // multi-byte character, we'll detect that and retry without those trailing bytes.
        match convert_to_utf8(codepage, &input) {
            Ok(utf8_bytes) => Cow::Owned(utf8_bytes),
            Err(_) => {
                // The conversion failed, likely due to an incomplete multi-byte sequence
                // at the end. Try progressively shorter slices to find the boundary.
                // For DBCS, at most 1 lead byte can be dangling.
                let max_trim = input.len().min(4);
                for trim in 1..=max_trim {
                    let end = input.len() - trim;
                    if end == 0 {
                        // Everything is leftover (very short input).
                        self.leftover = input.into_owned();
                        return Cow::Owned(Vec::new());
                    }
                    if let Ok(utf8_bytes) = convert_to_utf8(codepage, &input[..end]) {
                        self.leftover = input[end..].to_vec();
                        return Cow::Owned(utf8_bytes);
                    }
                }

                // If nothing works, the data is genuinely malformed.
                warn!(
                    codepage,
                    "Failed to decode process output; data may contain invalid characters"
                );
                self.leftover.clear();
                Cow::Owned(convert_to_utf8_lossy(codepage, &input))
            }
        }
    }

    /// Flush any remaining leftover bytes (call at EOF).
    ///
    /// If there are incomplete bytes remaining, they are converted lossily.
    pub fn flush(&mut self) -> Vec<u8> {
        if self.leftover.is_empty() || self.encoding.is_raw() {
            return Vec::new();
        }

        let codepage = match self.encoding {
            DataEncoding::Codepage(cp) => cp,
            DataEncoding::Raw => unreachable!(),
        };

        let leftover = std::mem::take(&mut self.leftover);
        convert_to_utf8_lossy(codepage, &leftover)
    }
}

/// Stateful encoder that transcodes from UTF-8 to a Windows codepage.
///
/// Handles partial UTF-8 sequences that may be split across write chunks.
pub struct InputEncoder {
    encoding: DataEncoding,
    /// Leftover bytes from the previous chunk that form an incomplete UTF-8 sequence.
    leftover: Vec<u8>,
}

impl InputEncoder {
    pub fn new(encoding: DataEncoding) -> Self {
        Self {
            encoding,
            leftover: Vec::new(),
        }
    }

    /// Encode a chunk of UTF-8 bytes to the process encoding.
    ///
    /// Returns borrowed data when no transcoding is needed (raw passthrough).
    /// Any incomplete trailing UTF-8 sequence is buffered internally and will
    /// be completed by the next call.
    pub fn encode<'a>(&mut self, data: &'a [u8]) -> Cow<'a, [u8]> {
        if self.encoding.is_raw() {
            return Cow::Borrowed(data);
        }

        let codepage = match self.encoding {
            DataEncoding::Codepage(cp) => cp,
            DataEncoding::Raw => unreachable!(),
        };

        // Prepend any leftover bytes from the previous chunk.
        let input = if self.leftover.is_empty() {
            Cow::Borrowed(data)
        } else {
            let mut combined = std::mem::take(&mut self.leftover);
            combined.extend_from_slice(data);
            Cow::Owned(combined)
        };

        if input.is_empty() {
            return Cow::Owned(Vec::new());
        }

        // Find the longest valid UTF-8 prefix.
        let valid_end = find_valid_utf8_end(&input);

        if valid_end == 0 {
            // All bytes are part of an incomplete sequence.
            self.leftover = input.into_owned();
            return Cow::Owned(Vec::new());
        }

        // Save any trailing incomplete UTF-8 bytes.
        if valid_end < input.len() {
            self.leftover = input[valid_end..].to_vec();
        }

        let utf8_str = match std::str::from_utf8(&input[..valid_end]) {
            Ok(s) => s,
            Err(_) => {
                // Should not happen since we validated above, but handle gracefully.
                warn!("Unexpected invalid UTF-8 in stdin data");
                self.leftover.clear();
                return Cow::Borrowed(data);
            }
        };

        Cow::Owned(convert_from_utf8(codepage, utf8_str))
    }

    /// Flush any remaining leftover bytes (call when stdin is closed).
    pub fn flush(&mut self) -> Vec<u8> {
        if self.leftover.is_empty() || self.encoding.is_raw() {
            return Vec::new();
        }

        let codepage = match self.encoding {
            DataEncoding::Codepage(cp) => cp,
            DataEncoding::Raw => unreachable!(),
        };

        let leftover = std::mem::take(&mut self.leftover);

        // Try to interpret as UTF-8 with replacement.
        let utf8_str = String::from_utf8_lossy(&leftover);
        convert_from_utf8(codepage, &utf8_str)
    }
}

/// Find the end index of the longest valid UTF-8 prefix in `data`.
///
/// Returns the byte index up to which the data is valid UTF-8.
/// Any trailing incomplete multi-byte sequence is excluded.
fn find_valid_utf8_end(data: &[u8]) -> usize {
    match std::str::from_utf8(data) {
        Ok(_) => data.len(),
        Err(e) => {
            // `valid_up_to()` gives us the position of the first invalid byte.
            // If the error is due to an incomplete sequence at the end (not an
            // invalid byte), `error_len()` returns None.
            if e.error_len().is_none() {
                // Incomplete sequence at end - return up to the valid portion.
                e.valid_up_to()
            } else {
                // Genuinely invalid byte. Include up to that point.
                // The caller will handle the leftover which includes the bad byte.
                e.valid_up_to()
            }
        }
    }
}

/// Convert bytes from a Windows codepage to UTF-8 using Win32 API.
///
/// Returns `Err` if the input contains an incomplete multi-byte character.
fn convert_to_utf8(codepage: u32, data: &[u8]) -> Result<Vec<u8>, ()> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // First pass: get required buffer size for UTF-16 conversion.
    // Using MB_ERR_INVALID_CHARS to detect incomplete sequences.
    // SAFETY: `data` is a valid byte slice.
    let wide_len = unsafe { MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, data, None) };

    if wide_len <= 0 {
        return Err(());
    }

    #[expect(clippy::cast_sign_loss, reason = "wide_len is verified positive above")]
    let wide_len = wide_len as usize;

    // Second pass: perform the actual conversion.
    let mut wide_buf = vec![0u16; wide_len];

    // SAFETY: `wide_buf` is properly sized and `data` is valid.
    let written = unsafe { MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, data, Some(&mut wide_buf)) };

    if written <= 0 {
        return Err(());
    }

    #[expect(clippy::cast_sign_loss, reason = "written is verified positive above")]
    wide_buf.truncate(written as usize);

    // Convert UTF-16 to UTF-8.
    Ok(String::from_utf16_lossy(&wide_buf).into_bytes())
}

/// Convert bytes from a Windows codepage to UTF-8, replacing invalid characters.
fn convert_to_utf8_lossy(codepage: u32, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    // First pass: get required buffer size (without MB_ERR_INVALID_CHARS for lossy conversion).
    // SAFETY: `data` is a valid byte slice.
    let wide_len = unsafe { MultiByteToWideChar(codepage, Default::default(), data, None) };

    if wide_len <= 0 {
        return data.to_vec();
    }

    #[expect(clippy::cast_sign_loss, reason = "wide_len is verified positive above")]
    let wide_len = wide_len as usize;

    let mut wide_buf = vec![0u16; wide_len];

    // SAFETY: `wide_buf` is properly sized and `data` is valid.
    let written = unsafe { MultiByteToWideChar(codepage, Default::default(), data, Some(&mut wide_buf)) };

    if written <= 0 {
        return data.to_vec();
    }

    #[expect(clippy::cast_sign_loss, reason = "written is verified positive above")]
    wide_buf.truncate(written as usize);

    String::from_utf16_lossy(&wide_buf).into_bytes()
}

/// Convert a UTF-8 string to a Windows codepage.
fn convert_from_utf8(codepage: u32, text: &str) -> Vec<u8> {
    if text.is_empty() {
        return Vec::new();
    }

    // First convert UTF-8 to UTF-16.
    let wide: Vec<u16> = text.encode_utf16().collect();

    // Get required buffer size.
    // SAFETY: `wide` is a valid UTF-16 slice.
    let mb_len = unsafe { WideCharToMultiByte(codepage, WC_NO_BEST_FIT_CHARS, &wide, None, None, None) };

    if mb_len <= 0 {
        return text.as_bytes().to_vec();
    }

    #[expect(clippy::cast_sign_loss, reason = "mb_len is verified positive above")]
    let mb_len = mb_len as usize;

    let mut mb_buf = vec![0u8; mb_len];

    // SAFETY: `mb_buf` is properly sized, `wide` is valid UTF-16.
    let written = unsafe { WideCharToMultiByte(codepage, WC_NO_BEST_FIT_CHARS, &wide, Some(&mut mb_buf), None, None) };

    if written <= 0 {
        return text.as_bytes().to_vec();
    }

    #[expect(clippy::cast_sign_loss, reason = "written is verified positive above")]
    mb_buf.truncate(written as usize);
    mb_buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_passthrough_decode() {
        let mut decoder = OutputDecoder::new(DataEncoding::Raw);
        let input = b"Hello, world!";
        let result = decoder.decode(input);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(&*result, input);
    }

    #[test]
    fn raw_passthrough_encode() {
        let mut encoder = InputEncoder::new(DataEncoding::Raw);
        let input = b"Hello, world!";
        let result = encoder.encode(input);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(&*result, input);
    }

    #[test]
    fn ascii_subset_works_for_any_codepage() {
        // ASCII characters (0x00-0x7F) are the same in all codepages.
        let encoding = DataEncoding::Codepage(437);
        let mut decoder = OutputDecoder::new(encoding);
        let input = b"Hello, world!\r\n";
        let output = decoder.decode(input);
        assert_eq!(&*output, input.as_slice());
    }

    #[test]
    fn encoder_ascii_subset_works_for_any_codepage() {
        let encoding = DataEncoding::Codepage(437);
        let mut encoder = InputEncoder::new(encoding);
        let input = b"Hello, world!\r\n";
        let output = encoder.encode(input);
        assert_eq!(&*output, input.as_slice());
    }

    #[test]
    fn split_utf8_input_handled() {
        let mut encoder = InputEncoder::new(DataEncoding::Codepage(437));

        // é in UTF-8 is [0xC3, 0xA9]. Split across two chunks.
        let chunk1 = &[0xC3u8];
        let chunk2 = &[0xA9u8];

        let out1 = encoder.encode(chunk1);
        // First chunk should produce nothing (incomplete UTF-8 sequence).
        assert!(out1.is_empty());

        let out2 = encoder.encode(chunk2);
        // Second chunk should produce the encoded character.
        assert!(!out2.is_empty());
    }

    #[test]
    fn find_valid_utf8_end_complete() {
        let data = "Hello".as_bytes();
        assert_eq!(find_valid_utf8_end(data), 5);
    }

    #[test]
    fn find_valid_utf8_end_incomplete() {
        // "é" is [0xC3, 0xA9]. If we only have the lead byte:
        let data = &[b'H', b'i', 0xC3];
        assert_eq!(find_valid_utf8_end(data), 2);
    }
}
