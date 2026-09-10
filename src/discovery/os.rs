use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsInfo {
    pub id: String,
    pub id_like: Vec<String>,
    pub name: String,
    pub version_id: String,
}

impl OsInfo {
    pub fn detect() -> Self {
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            Self::parse(&content)
        } else if let Ok(content) = std::fs::read_to_string("/usr/lib/os-release") {
            Self::parse(&content)
        } else {
            Self {
                id: "linux".into(),
                id_like: Vec::new(),
                name: "Linux".into(),
                version_id: String::new(),
            }
        }
    }

    pub fn parse(content: &str) -> Self {
        let mut id = String::new();
        let mut id_like = Vec::new();
        let mut name = String::new();
        let mut version_id = String::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let val = v.trim().trim_matches('"').trim_matches('\'');
                match k.trim() {
                    "ID" => id = val.to_lowercase(),
                    "ID_LIKE" => {
                        id_like = val.split_whitespace().map(|s| s.to_lowercase()).collect();
                    }
                    "NAME" => name = val.to_string(),
                    "VERSION_ID" => version_id = val.to_string(),
                    _ => {}
                }
            }
        }

        Self {
            id,
            id_like,
            name,
            version_id,
        }
    }

    pub fn is_systemd_present() -> bool {
        Path::new("/run/systemd/system").exists()
    }

    pub fn is_nftables_present() -> bool {
        Path::new("/usr/sbin/nft").exists()
            || Path::new("/sbin/nft").exists()
            || Path::new("/usr/bin/nft").exists()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionPaths {
    pub bash_paths: Vec<PathBuf>,
    pub zsh_paths: Vec<PathBuf>,
    pub fish_paths: Vec<PathBuf>,
}

pub fn detect_completion_paths() -> CompletionPaths {
    let mut bash_paths = Vec::new();
    let mut zsh_paths = Vec::new();
    let mut fish_paths = Vec::new();

    let candidate_bash_dirs = [
        "/etc/profile.d",
        "/etc/bash_completion.d",
        "/usr/share/bash-completion/completions",
    ];
    for dir_str in candidate_bash_dirs {
        let dir = Path::new(dir_str);
        if dir.exists() {
            if dir_str == "/etc/profile.d" {
                bash_paths.push(dir.join("sanalu.sh"));
            } else {
                bash_paths.push(dir.join("sanalu"));
            }
        }
    }

    let candidate_zsh_dirs = [
        "/usr/share/zsh/vendor-completions",
        "/usr/share/zsh/site-functions",
        "/usr/local/share/zsh/site-functions",
    ];
    for dir_str in candidate_zsh_dirs {
        let dir = Path::new(dir_str);
        if dir.exists() {
            zsh_paths.push(dir.join("_sanalu"));
        }
    }

    let candidate_fish_dirs = [
        "/usr/share/fish/vendor_completions.d",
        "/etc/fish/completions",
    ];
    for dir_str in candidate_fish_dirs {
        let dir = Path::new(dir_str);
        if dir.exists() {
            fish_paths.push(dir.join("sanalu.fish"));
        }
    }

    CompletionPaths {
        bash_paths,
        zsh_paths,
        fish_paths,
    }
}

pub fn is_root() -> bool {
    if let Ok(output) = std::process::Command::new("id").arg("-u").output() {
        let s = String::from_utf8_lossy(&output.stdout);
        s.trim() == "0"
    } else {
        false
    }
}
