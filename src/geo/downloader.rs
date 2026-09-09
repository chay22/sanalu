use super::lookup::IpLookupDb;
use crate::error::SanaluError;
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::Path;

pub async fn download_ip2asn_db(url: &str) -> Result<IpLookupDb, SanaluError> {
    let client = reqwest::Client::builder()
        .user_agent("sanalu-updater/0.1")
        .build()
        .map_err(|e| SanaluError::Geo(e.to_string()))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| SanaluError::Geo(e.to_string()))?;

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
    if url.ends_with(".gz") {
        let mut decoder = GzDecoder::new(&bytes[..]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| SanaluError::Geo(e.to_string()))?;
        IpLookupDb::from_tsv_reader(&decompressed[..])
    } else {
        IpLookupDb::from_tsv_reader(&bytes[..])
    }
}

pub fn save_db_to_file(db_tsv_content: &[u8], path: &Path) -> Result<(), SanaluError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, db_tsv_content)?;
    Ok(())
}
