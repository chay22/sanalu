use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NginxLogEntry<'a> {
    pub client_ip: IpAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub referer: &'a str,
    pub user_agent: &'a str,
}

pub fn parse_nginx_combined_line<'a>(line: &'a str) -> Option<NginxLogEntry<'a>> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let ip_end = trimmed.find(' ')?;
    let ip_str = &trimmed[..ip_end];
    let client_ip: IpAddr = ip_str.parse().ok()?;

    let req_start = trimmed.find('"')? + 1;
    let req_end = req_start + trimmed[req_start..].find('"')?;
    let request_str = &trimmed[req_start..req_end];

    let mut req_parts = request_str.split_whitespace();
    let method = req_parts.next().unwrap_or("GET");
    let path = req_parts.next().unwrap_or("/");

    let after_req = trimmed[req_end + 1..].trim_start();
    let mut tokens = after_req.split_whitespace();
    let status_str = tokens.next()?;
    let status: u16 = status_str.parse().ok()?;

    let ref_start = after_req.find('"')? + 1;
    let ref_end = ref_start + after_req[ref_start..].find('"')?;
    let referer = &after_req[ref_start..ref_end];

    let after_ref = &after_req[ref_end + 1..];
    let ua_start = after_ref.find('"')? + 1;
    let ua_end = ua_start + after_ref[ua_start..].find('"')?;
    let user_agent = &after_ref[ua_start..ua_end];

    Some(NginxLogEntry {
        client_ip,
        method,
        path,
        status,
        referer,
        user_agent,
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
    let after_client = &line[client_idx + ", client: ".len()..];
    let end_ip = after_client
        .find(',')
        .or_else(|| after_client.find(' '))
        .unwrap_or(after_client.len());
    let ip_str = &after_client[..end_ip].trim();
    let client_ip: IpAddr = ip_str.parse().ok()?;

    let error_marker = "[error]";
    let start_reason = if let Some(err_idx) = line.find(error_marker) {
        let after_err = &line[err_idx + error_marker.len()..];
        if let Some(colon_idx) = after_err.find(": ") {
            err_idx + error_marker.len() + colon_idx + 2
        } else {
            err_idx + error_marker.len()
        }
    } else {
        0
    };

    let reason_slice = if start_reason < client_idx {
        &line[start_reason..client_idx]
    } else {
        &line[..client_idx]
    };

    let clean_reason = if let Some(pos) = reason_slice.find('*') {
        if let Some(space_pos) = reason_slice[pos..].find(' ') {
            &reason_slice[pos + space_pos + 1..]
        } else {
            reason_slice
        }
    } else {
        reason_slice
    };

    Some((client_ip, clean_reason.trim().to_string()))
}
