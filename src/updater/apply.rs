use crate::discovery::is_root;
use crate::error::SanaluError;
use crate::updater::release::{
    fetch_latest_release_with_base_url, find_matching_asset, is_newer_version,
};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

pub async fn download_asset_to_file(url: &str, dest_path: &Path) -> Result<(), SanaluError> {
    let client = reqwest::Client::builder().build()?;
    let resp = client
        .get(url)
        .header(
            "User-Agent",
            format!("sanalu/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(SanaluError::Update(format!(
            "Download failed with HTTP {}",
            resp.status()
        )));
    }

    let bytes = resp.bytes().await?;
    let mut file = File::create(dest_path)?;
    file.write_all(&bytes)?;
    Ok(())
}

pub fn apply_deb_package(deb_path: &Path) -> Result<(), SanaluError> {
    let output = Command::new("dpkg").arg("-i").arg(deb_path).output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(SanaluError::Update(format!("dpkg install failed: {}", err)));
    }

    Ok(())
}

pub fn apply_binary_archive(archive_path: &Path, target_bin: &Path) -> Result<(), SanaluError> {
    let temp_dir = std::env::temp_dir().join(format!("sanalu-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir)?;
    let output = Command::new("tar")
        .args(["-xzf"])
        .arg(archive_path)
        .args(["-C"])
        .arg(&temp_dir)
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(SanaluError::Update(format!(
            "tar extraction failed: {}",
            err
        )));
    }

    let extracted_bin = temp_dir.join("sanalu");
    if !extracted_bin.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(SanaluError::Update(
            "Extracted archive does not contain 'sanalu' binary".into(),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(&extracted_bin, perms);
    }

    let target_parent = target_bin.parent().unwrap_or_else(|| Path::new("/usr/bin"));
    let temp_target = target_parent.join(".sanalu.update.tmp");
    std::fs::copy(&extracted_bin, &temp_target)?;
    std::fs::rename(&temp_target, target_bin)?;
    let _ = std::fs::remove_dir_all(&temp_dir);

    let _ = Command::new("systemctl")
        .args(["restart", "sanalu"])
        .output();

    Ok(())
}

pub async fn execute_update_with_base_url<W: Write>(
    out: &mut W,
    check: bool,
    yes: bool,
    base_url: &str,
    repo: &str,
) -> Result<(), SanaluError> {
    let release = fetch_latest_release_with_base_url(base_url, repo).await?;
    let current_ver = env!("CARGO_PKG_VERSION");
    let has_update = is_newer_version(current_ver, &release.tag_name);

    if check {
        let _ = writeln!(out, "Current version: {}", current_ver);
        let _ = writeln!(out, "Latest version:  {}", release.tag_name);
        if has_update {
            let _ = writeln!(
                out,
                "Update available! Run 'sudo sanalu update' to upgrade."
            );
        } else {
            let _ = writeln!(out, "sanalu is up to date.");
        }
        return Ok(());
    }

    if !has_update {
        let _ = writeln!(
            out,
            "sanalu is already up to date (version {}).",
            current_ver
        );
        return Ok(());
    }

    if !is_root() {
        return Err(SanaluError::Config(
            "Update requires root privileges. Please run with 'sudo sanalu update'.".into(),
        ));
    }

    if !yes {
        let _ = write!(
            out,
            "Update sanalu from {} to {}? [y/N]: ",
            current_ver, release.tag_name
        );
        let _ = out.flush();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            let _ = writeln!(out, "Update cancelled.");
            return Ok(());
        }
    }

    let arch = std::env::consts::ARCH;
    let has_dpkg = Command::new("dpkg").arg("--version").output().is_ok();
    let asset = find_matching_asset(&release.assets, arch, has_dpkg).ok_or_else(|| {
        SanaluError::Update("No compatible release asset found for this system.".into())
    })?;

    let temp_dir = std::env::temp_dir().join(format!("sanalu-update-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir)?;
    let temp_file = temp_dir.join(&asset.name);

    let _ = writeln!(out, "Downloading {}...", asset.name);
    let download_res = download_asset_to_file(&asset.browser_download_url, &temp_file).await;
    if let Err(e) = download_res {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(e);
    }

    let install_res = if asset.name.ends_with(".deb") {
        let _ = writeln!(out, "Installing Debian package via dpkg...");
        apply_deb_package(&temp_file)
    } else if asset.name.ends_with(".tar.gz") {
        let _ = writeln!(out, "Installing updated binary...");
        let target_bin =
            std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/usr/bin/sanalu"));
        apply_binary_archive(&temp_file, &target_bin)
    } else {
        Err(SanaluError::Update(
            "Unsupported asset package format".into(),
        ))
    };

    let _ = std::fs::remove_dir_all(&temp_dir);
    install_res?;

    let _ = writeln!(
        out,
        "[x] Successfully upgraded sanalu to {}!",
        release.tag_name
    );
    Ok(())
}

pub async fn execute_update<W: Write>(
    out: &mut W,
    check: bool,
    yes: bool,
) -> Result<(), SanaluError> {
    execute_update_with_base_url(out, check, yes, "https://api.github.com", "chay22/sanalu").await
}
