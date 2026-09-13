use crate::error::SanaluError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub size: u64,
}

pub fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let trimmed = v.trim();
    let stripped = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    let base = stripped.split(['-', '+']).next()?;
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse::<u64>().ok()?;
    let minor = parts[1].parse::<u64>().ok()?;
    let patch = parts[2].parse::<u64>().ok()?;
    Some((major, minor, patch))
}

pub fn is_newer_version(current: &str, candidate: &str) -> bool {
    match (parse_semver(current), parse_semver(candidate)) {
        (Some(curr), Some(cand)) => cand > curr,
        _ => false,
    }
}

pub fn find_matching_asset<'a>(
    assets: &'a [ReleaseAsset],
    target_arch: &str,
    prefers_deb: bool,
) -> Option<&'a ReleaseAsset> {
    let deb_arch = match target_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };

    if prefers_deb {
        let deb = assets
            .iter()
            .find(|a| a.name.ends_with(".deb") && a.name.contains(deb_arch));
        if deb.is_some() {
            return deb;
        }
    }

    assets.iter().find(|a| {
        a.name.ends_with(".tar.gz") && (a.name.contains(target_arch) || a.name.contains(deb_arch))
    })
}

pub async fn fetch_latest_release(repo: &str) -> Result<ReleaseInfo, SanaluError> {
    let client = reqwest::Client::builder().build()?;
    let url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let resp = client
        .get(&url)
        .header(
            "User-Agent",
            format!("sanalu/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(SanaluError::Update(format!(
            "Failed to fetch latest release: HTTP {}",
            resp.status()
        )));
    }

    let info: ReleaseInfo = resp.json().await?;
    Ok(info)
}
