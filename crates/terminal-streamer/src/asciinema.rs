#[derive(Debug)]
pub(crate) struct AsciinemaHeader {
    pub(crate) version: u16,
    pub(crate) row: u16,
    pub(crate) col: u16,
}

impl Default for AsciinemaHeader {
    fn default() -> Self {
        Self {
            version: 2,
            row: 24,
            col: 80,
        }
    }
}

#[derive(Debug)]
pub(crate) enum AsciinemaEvent {
    TerminalOutput { payload: String, time: f64 },
    UserInput { payload: String, time: f64 },
    Resize { width: u16, height: u16, time: f64 },
}

impl AsciinemaHeader {
    pub(crate) fn to_json(&self) -> String {
        format!(
            r#"{{"version": {}, "row": {}, "col": {}}}"#,
            self.version, self.row, self.col
        )
    }
}

impl AsciinemaEvent {
    pub(crate) fn to_json(&self) -> String {
        match self {
            AsciinemaEvent::TerminalOutput { payload, time } => {
                let escaped_payload = Self::sanitize_payload(payload);
                format!(r#"[{},"o","{}"]"#, time, escaped_payload)
            }
            AsciinemaEvent::UserInput { payload, time } => {
                let escaped_payload = Self::sanitize_payload(payload);
                format!(r#"[{},"i","{}"]"#, time, escaped_payload)
            }
            AsciinemaEvent::Resize { width, height, time } => {
                format!(r#"[{},"r","{}x{}"]"#, time, width, height)
            }
        }
    }

    /// Sanitizes a string payload for JSON output by escaping ASCII control characters.
    /// 
    /// This function converts ASCII control characters (0x00-0x1F, 0x7F) into their Unicode
    /// escape sequence representation (e.g., '\u001b' for ESC), while leaving other characters unchanged.
    /// This ensures the resulting string is valid JSON and control characters are preserved in a readable format.
    /// 
    /// # Arguments
    /// * `payload` - The string to sanitize
    /// 
    /// # Returns
    /// A new string with all control characters escaped
    fn sanitize_payload(payload: &str) -> String {
        payload
            .chars()
            .fold(String::with_capacity(payload.len()), |mut acc, c| {
                if c.is_ascii_control() {
                    acc.push_str(&format!("\\u{:04x}", c as u32));
                } else {
                    acc.push(c);
                }
                acc
            })
    }
}
