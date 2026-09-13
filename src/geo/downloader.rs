use super::lookup::IpLookupDb;
use crate::error::SanaluError;
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::Path;

async fn fetch_decompressed_bytes(url: &str) -> Result<Vec<u8>, SanaluError> {
    if url == "mock" || url.starts_with("mock://") {
        let mock_tsv = b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n103.10.10.0\t103.10.10.255\t23700\tID\tINDOSAT\n";
        return Ok(mock_tsv.to_vec());
    }
    if let Some(file_path) = url.strip_prefix("file://") {
        let raw = std::fs::read(file_path)?;
        if url.ends_with(".gz") {
            let mut decoder = GzDecoder::new(&raw[..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| SanaluError::Geo(e.to_string()))?;
            return Ok(decompressed);
        }
        return Ok(raw);
    }
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
        Ok(decompressed)
    } else {
        Ok(bytes.to_vec())
    }
}

pub async fn download_ip2asn_db(url: &str) -> Result<IpLookupDb, SanaluError> {
    let decompressed = fetch_decompressed_bytes(url).await?;
    IpLookupDb::from_tsv_reader(&decompressed[..])
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
