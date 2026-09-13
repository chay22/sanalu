use super::category::ThreatCategory;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizedUri<'a> {
    Clean(Cow<'a, str>),
    ImmediateMalicious(ThreatCategory),
}

const MALICIOUS_PATTERNS: &[&str] = &[
    "%00", "\0", "%0d%0a", "%0D%0A", "%0d", "%0D", "%0a", "%0A", "\r", "\n",
];

#[inline]
fn contains_malicious(s: &str) -> bool {
    MALICIOUS_PATTERNS.iter().any(|pat| s.contains(pat))
}

#[inline]
fn push_slash(out: &mut Vec<u8>) {
    if out.last() != Some(&b'/') {
        out.push(b'/');
    }
}

#[inline]
fn try_decode_escape(b1: u8, b2: u8) -> Option<u8> {
    if b1 == b'2' && (b2 == b'f' || b2 == b'F') {
        Some(b'/')
    } else if b1 == b'2' && (b2 == b'e' || b2 == b'E') {
        Some(b'.')
    } else if b1 == b'5' && (b2 == b'c' || b2 == b'C') {
        Some(b'/')
    } else {
        None
    }
}

fn decode_and_collapse(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() {
            if let Some(decoded) = try_decode_escape(bytes[i + 1], bytes[i + 2]) {
                if decoded == b'/' {
                    push_slash(&mut out);
                } else {
                    out.push(decoded);
                }
                i += 3;
                continue;
            }
        }
        if b == b'\\' || b == b'/' {
            push_slash(&mut out);
            i += 1;
            continue;
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

pub fn normalize_request_uri<'a>(raw: &'a str) -> NormalizedUri<'a> {
    if contains_malicious(raw) {
        return NormalizedUri::ImmediateMalicious(ThreatCategory::Common);
    }

    if !raw.contains('%') && !raw.contains('\\') && !raw.contains("//") {
        return NormalizedUri::Clean(Cow::Borrowed(raw));
    }

    let decoded = decode_and_collapse(raw);
    if contains_malicious(&decoded) {
        return NormalizedUri::ImmediateMalicious(ThreatCategory::Common);
    }

    NormalizedUri::Clean(Cow::Owned(decoded))
}
