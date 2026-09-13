use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NginxLogEntry<'a> {
    pub client_ip: IpAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub referer: &'a str,
    pub user_agent: &'a str,
    pub host: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledLogFormat {
    Delimited(Vec<FormatSegment>),
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatSegment {
    Variable(LogVariable),
    Literal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogVariable {
    RemoteAddr,
    CfConnectingIp,
    XForwardedFor,
    TimeLocal,
    Request,
    RequestMethod,
    RequestUri,
    Status,
    BodyBytesSent,
    HttpReferer,
    HttpUserAgent,
    Host,
    Ignored(String),
}

impl CompiledLogFormat {
    pub fn compile(format_body: &str) -> Self {
        let trimmed = format_body.trim();
        let stripped = if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2
        {
            trimmed.get(1..trimmed.len() - 1).unwrap_or("").trim()
        } else {
            trimmed
        };
        if stripped.starts_with('{') && stripped.ends_with('}') {
            return Self::Json;
        }
        let segments = parse_format_segments(stripped);
        Self::Delimited(segments)
    }

    pub fn parse_line<'a>(&self, line: &'a str) -> Option<NginxLogEntry<'a>> {
        match self {
            Self::Delimited(segments) => parse_delimited_line(segments, line),
            Self::Json => parse_json_log_line(line),
        }
    }
}

fn parse_format_segments(body: &str) -> Vec<FormatSegment> {
    let mut segments = Vec::new();
    let mut current_lit = String::new();
    let mut chars = body.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch == '$' {
            chars.next();
            if chars.peek() == Some(&'$') {
                chars.next();
                current_lit.push('$');
                continue;
            }
            if !current_lit.is_empty() {
                segments.push(FormatSegment::Literal(std::mem::take(&mut current_lit)));
            }
            let var_name = extract_var_name(&mut chars);
            if var_name.is_empty() {
                current_lit.push('$');
            } else {
                segments.push(FormatSegment::Variable(map_variable_name(&var_name)));
            }
        } else {
            chars.next();
            current_lit.push(ch);
        }
    }

    if !current_lit.is_empty() {
        segments.push(FormatSegment::Literal(current_lit));
    }

    segments
}

fn extract_var_name(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    let mut var_name = String::new();
    if chars.peek() == Some(&'{') {
        chars.next();
        while let Some(&vch) = chars.peek() {
            chars.next();
            if vch == '}' {
                break;
            }
            var_name.push(vch);
        }
    } else {
        while let Some(&vch) = chars.peek() {
            if vch.is_ascii_alphanumeric() || vch == '_' {
                chars.next();
                var_name.push(vch);
            } else {
                break;
            }
        }
    }
    var_name
}

fn map_variable_name(name: &str) -> LogVariable {
    if let Some(var) = map_network_variable(name) {
        return var;
    }
    if let Some(var) = map_http_variable(name) {
        return var;
    }
    LogVariable::Ignored(name.to_string())
}

fn map_network_variable(name: &str) -> Option<LogVariable> {
    match name {
        "remote_addr" => Some(LogVariable::RemoteAddr),
        "http_cf_connecting_ip" => Some(LogVariable::CfConnectingIp),
        "http_x_forwarded_for" => Some(LogVariable::XForwardedFor),
        "time_local" => Some(LogVariable::TimeLocal),
        _ => None,
    }
}

fn map_http_variable(name: &str) -> Option<LogVariable> {
    match name {
        "request" => Some(LogVariable::Request),
        "request_method" => Some(LogVariable::RequestMethod),
        "request_uri" | "uri" => Some(LogVariable::RequestUri),
        "status" => Some(LogVariable::Status),
        "body_bytes_sent" | "bytes_sent" => Some(LogVariable::BodyBytesSent),
        "http_referer" => Some(LogVariable::HttpReferer),
        "http_user_agent" => Some(LogVariable::HttpUserAgent),
        "host" | "http_host" => Some(LogVariable::Host),
        _ => None,
    }
}

#[derive(Default)]
struct ParsedFields<'a> {
    cf_ip: Option<&'a str>,
    xff: Option<&'a str>,
    remote_addr: Option<&'a str>,
    method: Option<&'a str>,
    path: Option<&'a str>,
    request: Option<&'a str>,
    status: Option<u16>,
    referer: &'a str,
    user_agent: &'a str,
    host: Option<&'a str>,
}

fn assign_variable_field<'a>(var: &LogVariable, slice: &'a str, fields: &mut ParsedFields<'a>) {
    if assign_ip_or_request_field(var, slice, fields) {
        return;
    }
    assign_meta_field(var, slice, fields);
}

fn assign_ip_or_request_field<'a>(
    var: &LogVariable,
    slice: &'a str,
    fields: &mut ParsedFields<'a>,
) -> bool {
    match var {
        LogVariable::CfConnectingIp => {
            fields.cf_ip = Some(slice.trim());
            true
        }
        LogVariable::XForwardedFor => {
            fields.xff = Some(slice.trim());
            true
        }
        LogVariable::RemoteAddr => {
            fields.remote_addr = Some(slice.trim());
            true
        }
        LogVariable::RequestMethod => {
            fields.method = Some(slice.trim());
            true
        }
        LogVariable::RequestUri => {
            fields.path = Some(slice.trim());
            true
        }
        LogVariable::Request => {
            fields.request = Some(slice.trim());
            true
        }
        _ => false,
    }
}

fn assign_meta_field<'a>(var: &LogVariable, slice: &'a str, fields: &mut ParsedFields<'a>) {
    match var {
        LogVariable::Status => fields.status = slice.trim().parse::<u16>().ok(),
        LogVariable::HttpReferer => fields.referer = slice,
        LogVariable::HttpUserAgent => fields.user_agent = slice,
        LogVariable::Host => {
            let h = slice.trim();
            fields.host = if h.is_empty() || h == "-" {
                None
            } else {
                Some(h)
            };
        }
        _ => {}
    }
}

fn parse_delimited_line<'a>(
    segments: &[FormatSegment],
    line: &'a str,
) -> Option<NginxLogEntry<'a>> {
    let clean_line = line.trim_end_matches(['\r', '\n']);
    if clean_line.trim().is_empty() {
        return None;
    }

    let mut fields = ParsedFields::default();
    let mut cursor = 0;
    let mut pending_var: Option<&LogVariable> = None;

    for seg in segments {
        match seg {
            FormatSegment::Literal(lit) => {
                if let Some(var) = pending_var.take() {
                    let rest = clean_line.get(cursor..)?;
                    let offset = rest.find(lit.as_str())?;
                    let val_slice = rest.get(..offset)?;
                    assign_variable_field(var, val_slice, &mut fields);
                    cursor += offset + lit.len();
                } else {
                    let rest = clean_line.get(cursor..)?;
                    if !rest.starts_with(lit.as_str()) {
                        return None;
                    }
                    cursor += lit.len();
                }
            }
            FormatSegment::Variable(var) => {
                if let Some(prev_var) = pending_var.take() {
                    let rest = clean_line.get(cursor..)?;
                    let offset = rest.find(' ').unwrap_or(rest.len());
                    assign_variable_field(prev_var, rest.get(..offset).unwrap_or(""), &mut fields);
                    cursor += offset;
                }
                pending_var = Some(var);
            }
        }
    }

    if let Some(var) = pending_var.take() {
        let val_slice = clean_line.get(cursor..)?;
        assign_variable_field(var, val_slice, &mut fields);
    }

    let client_ip = resolve_client_ip(fields.cf_ip, fields.xff, fields.remote_addr)?;
    let (method, path) = extract_request_parts(fields.method, fields.path, fields.request);

    Some(NginxLogEntry {
        client_ip,
        method,
        path,
        status: fields.status.unwrap_or(200),
        referer: fields.referer,
        user_agent: fields.user_agent,
        host: fields.host,
    })
}

fn extract_request_parts<'a>(
    method_opt: Option<&'a str>,
    path_opt: Option<&'a str>,
    request_opt: Option<&'a str>,
) -> (&'a str, &'a str) {
    let (mut m, mut p) = ("GET", "/");
    if let Some(req) = request_opt {
        let mut parts = req.split_whitespace();
        if let Some(method) = parts.next() {
            m = method;
        }
        if let Some(path) = parts.next() {
            p = path;
        }
    }
    if let Some(method) = method_opt {
        m = method.trim();
    }
    if let Some(path) = path_opt {
        p = path.trim();
    }
    (m, p)
}

fn resolve_client_ip(cf: Option<&str>, xff: Option<&str>, remote: Option<&str>) -> Option<IpAddr> {
    if let Some(cf_str) = cf {
        if let Some(ip) = parse_first_comma_ip(cf_str) {
            return Some(ip);
        }
    }
    if let Some(xff_str) = xff {
        if let Some(ip) = parse_xff_ip(xff_str, remote) {
            return Some(ip);
        }
    } else if let Some(rem_str) = remote {
        if let Ok(ip) = rem_str.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

fn parse_first_comma_ip(s: &str) -> Option<IpAddr> {
    let clean = s.split(',').next().unwrap_or("").trim();
    clean.parse::<IpAddr>().ok()
}

fn parse_xff_ip(xff_str: &str, remote: Option<&str>) -> Option<IpAddr> {
    let mut first_valid = None;
    for part in xff_str.split(',') {
        let clean = part.trim();
        if let Ok(ip) = clean.parse::<IpAddr>() {
            if !crate::is_loopback_or_private(ip) {
                return Some(ip);
            }
            if first_valid.is_none() {
                first_valid = Some(ip);
            }
        }
    }
    if let Some(rem_str) = remote {
        if let Ok(ip) = rem_str.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }
    first_valid
}

#[derive(serde::Deserialize)]
struct JsonLogRecord<'a> {
    client: Option<&'a str>,
    client_ip: Option<&'a str>,
    remote_addr: Option<&'a str>,
    ip: Option<&'a str>,
    http_cf_connecting_ip: Option<&'a str>,
    http_x_forwarded_for: Option<&'a str>,
    method: Option<&'a str>,
    request_method: Option<&'a str>,
    uri: Option<&'a str>,
    path: Option<&'a str>,
    request_uri: Option<&'a str>,
    request: Option<&'a str>,
    status: Option<serde_json::Value>,
    referer: Option<&'a str>,
    http_referer: Option<&'a str>,
    ua: Option<&'a str>,
    user_agent: Option<&'a str>,
    http_user_agent: Option<&'a str>,
    host: Option<&'a str>,
    http_host: Option<&'a str>,
}

fn parse_json_log_line<'a>(line: &'a str) -> Option<NginxLogEntry<'a>> {
    let trimmed = line.trim();
    if !trimmed.starts_with('{') {
        return None;
    }

    let rec: JsonLogRecord<'a> = serde_json::from_str(trimmed).ok()?;

    let cf = rec.http_cf_connecting_ip;
    let xff = rec.http_x_forwarded_for;
    let remote = rec.client.or(rec.client_ip).or(rec.remote_addr).or(rec.ip);

    let client_ip = resolve_client_ip(cf, xff, remote)?;

    let (method, path) = extract_request_parts(
        rec.method.or(rec.request_method),
        rec.uri.or(rec.path).or(rec.request_uri),
        rec.request,
    );

    let status = match rec.status {
        Some(serde_json::Value::Number(n)) => n.as_u64().map(|v| v as u16).unwrap_or(200),
        Some(serde_json::Value::String(s)) => s.parse::<u16>().unwrap_or(200),
        _ => 200,
    };

    let referer = rec.referer.or(rec.http_referer).unwrap_or("");
    let user_agent = rec
        .ua
        .or(rec.user_agent)
        .or(rec.http_user_agent)
        .unwrap_or("");
    let host = rec.host.or(rec.http_host).and_then(|h| {
        let t = h.trim();
        if t.is_empty() || t == "-" {
            None
        } else {
            Some(t)
        }
    });

    Some(NginxLogEntry {
        client_ip,
        method,
        path,
        status,
        referer,
        user_agent,
        host,
    })
}

pub fn parse_nginx_combined_line<'a>(line: &'a str) -> Option<NginxLogEntry<'a>> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let ip_end = trimmed.find(' ')?;
    let ip_str = trimmed.get(..ip_end)?;
    let client_ip: IpAddr = ip_str.parse().ok()?;

    let req_start = trimmed.find('"')? + 1;
    let req_end = req_start + trimmed.get(req_start..)?.find('"')?;
    let request_str = trimmed.get(req_start..req_end)?;

    let mut req_parts = request_str.split_whitespace();
    let method = req_parts.next().unwrap_or("GET");
    let path = req_parts.next().unwrap_or("/");

    let after_req = trimmed.get(req_end + 1..)?.trim_start();
    let mut tokens = after_req.split_whitespace();
    let status_str = tokens.next()?;
    let status: u16 = status_str.parse().ok()?;

    let ref_start = after_req.find('"')? + 1;
    let ref_end = ref_start + after_req.get(ref_start..)?.find('"')?;
    let referer = after_req.get(ref_start..ref_end)?;

    let after_ref = after_req.get(ref_end + 1..)?;
    let ua_start = after_ref.find('"')? + 1;
    let ua_end = ua_start + after_ref.get(ua_start..)?.find('"')?;
    let user_agent = after_ref.get(ua_start..ua_end)?;

    Some(NginxLogEntry {
        client_ip,
        method,
        path,
        status,
        referer,
        user_agent,
        host: None,
    })
}

pub fn parse_nginx_json_line(line: &str) -> Option<(IpAddr, String, String, u16, String, String)> {
    let trimmed = line.trim();
    if !trimmed.starts_with('{') {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let obj = parsed.as_object()?;

    let ip_str = obj
        .get("client")
        .or_else(|| obj.get("client_ip"))
        .or_else(|| obj.get("remote_addr"))
        .or_else(|| obj.get("ip"))
        .or_else(|| obj.get("http_cf_connecting_ip"))
        .or_else(|| obj.get("http_x_forwarded_for"))
        .and_then(|v| v.as_str())?;

    let client_ip: IpAddr = ip_str.split(',').next()?.trim().parse().ok()?;

    let method = obj
        .get("method")
        .or_else(|| obj.get("request_method"))
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_string();

    let uri = obj
        .get("uri")
        .or_else(|| obj.get("path"))
        .or_else(|| obj.get("request_uri"))
        .or_else(|| obj.get("request"))
        .and_then(|v| v.as_str())
        .unwrap_or("/")
        .to_string();

    let status = obj
        .get("status")
        .and_then(|v| {
            if let Some(n) = v.as_u64() {
                Some(n as u16)
            } else if let Some(s) = v.as_str() {
                s.parse::<u16>().ok()
            } else {
                None
            }
        })
        .unwrap_or(200);

    let referer = obj
        .get("referer")
        .or_else(|| obj.get("http_referer"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let ua = obj
        .get("ua")
        .or_else(|| obj.get("user_agent"))
        .or_else(|| obj.get("http_user_agent"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some((client_ip, method, uri, status, referer, ua))
}

pub fn parse_nginx_error_line(line: &str) -> Option<(IpAddr, String)> {
    let client_idx = line.find(", client: ")?;
    let after_client = line.get(client_idx + ", client: ".len()..)?;
    let end_ip = after_client
        .find(',')
        .or_else(|| after_client.find(' '))
        .unwrap_or(after_client.len());
    let ip_str = after_client.get(..end_ip)?.trim();
    let client_ip: IpAddr = ip_str.parse().ok()?;

    let error_marker = "[error]";
    let start_reason = if let Some(err_idx) = line.find(error_marker) {
        if let Some(after_err) = line.get(err_idx + error_marker.len()..) {
            if let Some(colon_idx) = after_err.find(": ") {
                err_idx + error_marker.len() + colon_idx + 2
            } else {
                err_idx + error_marker.len()
            }
        } else {
            0
        }
    } else {
        0
    };

    let reason_slice = if start_reason < client_idx {
        line.get(start_reason..client_idx).unwrap_or("")
    } else {
        line.get(..client_idx).unwrap_or("")
    };

    let clean_reason = if let Some(pos) = reason_slice.find('*') {
        if let Some(rest) = reason_slice.get(pos..) {
            if let Some(space_pos) = rest.find(' ') {
                reason_slice
                    .get(pos + space_pos + 1..)
                    .unwrap_or(reason_slice)
            } else {
                reason_slice
            }
        } else {
            reason_slice
        }
    } else {
        reason_slice
    };

    Some((client_ip, clean_reason.trim().to_string()))
}
