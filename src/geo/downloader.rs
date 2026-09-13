use super::lookup::IpLookupDb;
use crate::error::SanaluError;
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn format_http_date(time: SystemTime) -> String {
    let dur = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut secs = dur.as_secs();
    let sec = secs % 60;
    secs /= 60;
    let min = secs % 60;
    secs /= 60;
    let hour = secs % 24;
    let mut days = secs / 24;

    let day_names = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let day_name = day_names[(days % 7) as usize];

    let mut year = 1970u64;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let mut month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if is_leap {
        month_days[1] = 29;
    }

    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let mut month_idx = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month_idx = i;
            break;
        }
        days -= md;
    }
    let day_of_month = days + 1;

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        day_name, day_of_month, month_names[month_idx], year, hour, min, sec
    )
}

async fn fetch_decompressed_bytes_conditional(
    url: &str,
    if_modified_since: Option<&str>,
) -> Result<Option<Vec<u8>>, SanaluError> {
    if url == "mock" || url.starts_with("mock://") {
        let mock_tsv = b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n103.10.10.0\t103.10.10.255\t23700\tID\tINDOSAT\n";
        return Ok(Some(mock_tsv.to_vec()));
    }
    if let Some(file_path) = url.strip_prefix("file://") {
        let raw = std::fs::read(file_path)?;
        if url.ends_with(".gz") {
            let mut decoder = GzDecoder::new(&raw[..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| SanaluError::Geo(e.to_string()))?;
            return Ok(Some(decompressed));
        }
        return Ok(Some(raw));
    }
    let client = reqwest::Client::builder()
        .user_agent("sanalu-updater/0.1")
        .build()
        .map_err(|e| SanaluError::Geo(e.to_string()))?;

    let mut request = client.get(url);
    if let Some(ims) = if_modified_since {
        request = request.header(reqwest::header::IF_MODIFIED_SINCE, ims);
    }

    let resp = request
        .send()
        .await
        .map_err(|e| SanaluError::Geo(e.to_string()))?;

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }

    if !resp.status().is_success() {
        return Err(SanaluError::Geo(format!(
            "Failed to download IP database: status {}",
            resp.status()
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| SanaluError::Geo(e.to_string()))?;
    if url.ends_with(".gz") || (bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b) {
        let mut decoder = GzDecoder::new(&bytes[..]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| SanaluError::Geo(e.to_string()))?;
        Ok(Some(decompressed))
    } else {
        Ok(Some(bytes.to_vec()))
    }
}

async fn fetch_decompressed_bytes(url: &str) -> Result<Vec<u8>, SanaluError> {
    let result = fetch_decompressed_bytes_conditional(url, None).await?;
    result.ok_or_else(|| SanaluError::Geo("Unexpected empty response".to_string()))
}

pub async fn download_ip2asn_db(url: &str) -> Result<IpLookupDb, SanaluError> {
    let decompressed = fetch_decompressed_bytes(url).await?;
    IpLookupDb::from_tsv_reader(&decompressed[..])
}

pub async fn download_if_stale_or_missing(
    url: &str,
    dest_path: &Path,
    max_age_secs: u64,
) -> Result<Option<usize>, SanaluError> {
    let mut if_modified_since = None;
    if dest_path.exists() {
        let metadata = std::fs::metadata(dest_path)?;
        let modified = metadata.modified()?;
        let is_fresh = match SystemTime::now().duration_since(modified) {
            Ok(elapsed) => elapsed.as_secs() < max_age_secs,
            Err(_) => true,
        };
        if is_fresh {
            return Ok(None);
        }
        if_modified_since = Some(format_http_date(modified));
    }

    let decompressed =
        match fetch_decompressed_bytes_conditional(url, if_modified_since.as_deref()).await? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

    save_db_to_file(&decompressed, dest_path)?;
    let db = IpLookupDb::from_file(dest_path)?;
    Ok(Some(db.len()))
}

pub async fn download_and_save_ip2asn_db(
    url: &str,
    dest_path: &Path,
) -> Result<usize, SanaluError> {
    let decompressed = fetch_decompressed_bytes(url).await?;
    save_db_to_file(&decompressed, dest_path)?;
    let db = IpLookupDb::from_file(dest_path)?;
    Ok(db.len())
}

pub fn save_db_to_file(db_tsv_content: &[u8], path: &Path) -> Result<(), SanaluError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, db_tsv_content)?;
    Ok(())
}
