use crate::discovery::{detect_completion_paths, is_root};
use crate::error::SanaluError;
use std::path::Path;

pub fn bootstrap_files(config_path: &Path, db_path: &Path) -> Result<(), SanaluError> {
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
    }

    if !config_path.exists() {
        if let Some(parent) = config_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let template = include_str!("../../dist/sanalu.toml");
        std::fs::write(config_path, template)?;
    }

    if is_root() {
        let paths = detect_completion_paths();
        if !paths.bash_paths.is_empty() {
            let mut buf = Vec::new();
            super::query::generate_completions(clap_complete::Shell::Bash, &mut buf);
            for p in &paths.bash_paths {
                let _ = std::fs::write(p, &buf);
            }
        }
        if !paths.zsh_paths.is_empty() {
            let mut buf = Vec::new();
            super::query::generate_completions(clap_complete::Shell::Zsh, &mut buf);
            for p in &paths.zsh_paths {
                let _ = std::fs::write(p, &buf);
            }
        }
        if !paths.fish_paths.is_empty() {
            let mut buf = Vec::new();
            super::query::generate_completions(clap_complete::Shell::Fish, &mut buf);
            for p in &paths.fish_paths {
                let _ = std::fs::write(p, &buf);
            }
        }
    }

    let systemd_dir = Path::new("/etc/systemd/system");
    if systemd_dir.exists() && is_root() {
        let service_file = systemd_dir.join("sanalu.service");
        let lib_service_file = Path::new("/lib/systemd/system/sanalu.service");
        if !service_file.exists() && !lib_service_file.exists() {
            let unit = include_str!("../../dist/systemd/sanalu.service");
            let _ = std::fs::write(&service_file, unit);
            let _ = std::process::Command::new("systemctl")
                .arg("daemon-reload")
                .output();
        }
    }

    Ok(())
}
