pub fn check_unquoted_ip_hint(content: &str) -> Option<&'static str> {
    let mut in_array = false;
    let mut in_quote = false;
    let mut quote_char = '"';
    let mut token = String::new();

    for ch in content.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_quote = true;
                quote_char = ch;
                token.clear();
            }
            '[' => {
                in_array = true;
                token.clear();
            }
            ']' => {
                in_array = false;
                if is_unquoted_ip_like(&token) {
                    return Some(
                        "Hint: IP addresses in TOML arrays must be enclosed in quotes, e.g. whitelist = [\"1.2.3.4\", \"2001:db8::1\"]",
                    );
                }
                token.clear();
            }
            ',' | '\n' if in_array => {
                if is_unquoted_ip_like(&token) {
                    return Some(
                        "Hint: IP addresses in TOML arrays must be enclosed in quotes, e.g. whitelist = [\"1.2.3.4\", \"2001:db8::1\"]",
                    );
                }
                token.clear();
            }
            _ if in_array => {
                token.push(ch);
            }
            _ => {}
        }
    }
    None
}

fn is_unquoted_ip_like(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return false;
    }
    let (ip_part, _) = t.split_once('/').unwrap_or((t, ""));
    let dots = ip_part.bytes().filter(|&b| b == b'.').count();
    if dots == 3 && ip_part.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return true;
    }
    if ip_part.contains(':') && ip_part.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
        return true;
    }
    false
}
