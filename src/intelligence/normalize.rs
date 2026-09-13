use super::category::ThreatCategory;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizedUri<'a> {
    Clean(Cow<'a, str>),
    ImmediateMalicious(ThreatCategory),
}

#[inline]
fn contains_malicious(s: &str) -> bool {
    s.contains("%00")
        || s.contains('\0')
        || s.contains("%0d%0a")
        || s.contains("%0D%0A")
        || s.contains("%0d")
        || s.contains("%0D")
        || s.contains("%0a")
        || s.contains("%0A")
        || s.contains('\r')
        || s.contains('\n')
}

#[inline]
fn push_slash(out: &mut Vec<u8>) {
    if out.last() != Some(&b'/') {
        out.push(b'/');
    }
}

fn decode_and_collapse(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() {
            let b1 = bytes[i + 1];
            let b2 = bytes[i + 2];
            if b1 == b'2' && (b2 == b'f' || b2 == b'F') {
                push_slash(&mut out);
                i += 3;
                continue;
            }
            if b1 == b'2' && (b2 == b'e' || b2 == b'E') {
                out.push(b'.');
                i += 3;
                continue;
            }
            if b1 == b'5' && (b2 == b'c' || b2 == b'C') {
                push_slash(&mut out);
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
