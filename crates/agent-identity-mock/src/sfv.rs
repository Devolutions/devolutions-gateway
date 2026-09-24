//! Strict RFC 8941 structured-fields subset parser.
//!
//! Only what the CONTRACT.md §6 profile needs: dictionaries whose member values are
//! inner lists of strings with parameters (`Signature-Input`) or byte sequences
//! (`Signature`). Anything unparsable is rejected; the caller maps that to
//! `signature_invalid`.

/// A bare item value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemValue {
    Str(String),
    Int(i64),
    Bytes(Vec<u8>),
}

/// A `;key[=value]` parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub key: String,
    /// `None` is a bare parameter (boolean true in RFC 8941).
    pub value: Option<ItemValue>,
}

/// An item with its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    pub value: ItemValue,
    pub params: Vec<Param>,
}

/// An `( item item ... );params` inner list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerList {
    pub items: Vec<ListItem>,
    pub params: Vec<Param>,
}

/// A dictionary member value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberValue {
    Item(ListItem),
    InnerList(InnerList),
}

/// Parses an RFC 8941 dictionary, strictly. Returns `None` on any syntax error.
pub fn parse_dictionary(input: &str) -> Option<Vec<(String, MemberValue)>> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ows();
    let mut members = Vec::new();
    while p.peek().is_some() {
        let key = p.parse_key()?;
        p.expect(b'=')?;
        let value = if p.peek() == Some(b'(') {
            MemberValue::InnerList(p.parse_inner_list()?)
        } else {
            MemberValue::Item(p.parse_list_item()?)
        };
        members.push((key, value));
        p.skip_ows();
        if p.peek().is_none() {
            break;
        }
        p.expect(b',')?;
        p.skip_ows();
        // Trailing comma is not allowed.
        p.peek()?;
    }
    Some(members)
}

/// Serializes an inner list in canonical form: `("a" "b");k=v` with parameters in
/// received order.
pub fn serialize_inner_list(list: &InnerList) -> String {
    let mut out = String::from("(");
    for (i, item) in list.items.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&serialize_item(item));
    }
    out.push(')');
    out.push_str(&serialize_params(&list.params));
    out
}

fn serialize_item(item: &ListItem) -> String {
    let mut out = serialize_item_value(&item.value);
    out.push_str(&serialize_params(&item.params));
    out
}

fn serialize_params(params: &[Param]) -> String {
    let mut out = String::new();
    for param in params {
        out.push(';');
        out.push_str(&param.key);
        if let Some(value) = &param.value {
            out.push('=');
            out.push_str(&serialize_item_value(value));
        }
    }
    out
}

fn serialize_item_value(value: &ItemValue) -> String {
    match value {
        ItemValue::Str(s) => serialize_string(s),
        ItemValue::Int(i) => i.to_string(),
        ItemValue::Bytes(b) => {
            use base64::Engine as _;
            format!(":{}:", base64::engine::general_purpose::STANDARD.encode(b))
        }
    }
}

fn serialize_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn expect(&mut self, b: u8) -> Option<()> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }

    fn parse_key(&mut self) -> Option<String> {
        let start = self.pos;
        match self.peek()? {
            b'a'..=b'z' | b'*' => self.pos += 1,
            _ => return None,
        }
        while matches!(self.peek(), Some(b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')) {
            self.pos += 1;
        }
        core::str::from_utf8(&self.bytes[start..self.pos])
            .ok()
            .map(ToOwned::to_owned)
    }

    fn parse_params(&mut self) -> Option<Vec<Param>> {
        let mut params = Vec::new();
        while self.peek() == Some(b';') {
            self.pos += 1;
            self.skip_sp();
            let key = self.parse_key()?;
            let value = if self.peek() == Some(b'=') {
                self.pos += 1;
                Some(self.parse_item_value()?)
            } else {
                None
            };
            params.push(Param { key, value });
        }
        Some(params)
    }

    fn parse_list_item(&mut self) -> Option<ListItem> {
        let value = self.parse_item_value()?;
        let params = self.parse_params()?;
        Some(ListItem { value, params })
    }

    fn parse_inner_list(&mut self) -> Option<InnerList> {
        self.expect(b'(')?;
        let mut items = Vec::new();
        loop {
            let start = self.pos;
            while self.peek() == Some(b' ') {
                self.pos += 1;
            }
            match self.peek()? {
                b')' => {
                    self.pos += 1;
                    break;
                }
                _ if items.is_empty() || self.pos > start => items.push(self.parse_list_item()?),
                _ => return None,
            }
        }
        let params = self.parse_params()?;
        Some(InnerList { items, params })
    }

    fn parse_item_value(&mut self) -> Option<ItemValue> {
        match self.peek()? {
            b'"' => self.parse_string().map(ItemValue::Str),
            b':' => self.parse_byte_sequence().map(ItemValue::Bytes),
            b'-' | b'0'..=b'9' => self.parse_integer().map(ItemValue::Int),
            _ => None,
        }
    }

    fn parse_string(&mut self) -> Option<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.bump()? {
                b'"' => return Some(out),
                b'\\' => match self.bump()? {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    _ => return None,
                },
                // VCHAR and SP only; reject anything else (strict).
                0x20..=0x21 | 0x23..=0x7e => out.push(char::from(self.bytes[self.pos - 1])),
                _ => return None,
            }
        }
    }

    fn parse_byte_sequence(&mut self) -> Option<Vec<u8>> {
        use base64::Engine as _;
        self.expect(b':')?;
        let start = self.pos;
        while matches!(
            self.peek(),
            Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=')
        ) {
            self.pos += 1;
        }
        self.expect(b':')?;
        let raw = core::str::from_utf8(&self.bytes[start..self.pos - 1]).ok()?;
        base64::engine::general_purpose::STANDARD.decode(raw).ok()
    }

    fn parse_integer(&mut self) -> Option<i64> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let digits = self.pos - digits_start;
        // RFC 8941 integers are at most 15 digits.
        if digits == 0 || digits > 15 {
            return None;
        }
        core::str::from_utf8(&self.bytes[start..self.pos]).ok()?.parse().ok()
    }
}
