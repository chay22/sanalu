use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshLogSource {
    JournaldService(String),
    File(PathBuf),
}

pub fn detect_ssh_source() -> SshLogSource {
    if Path::new("/run/systemd/journal/socket").exists()
        || Path::new("/run/systemd/system").exists()
    {
        return SshLogSource::JournaldService("ssh".into());
    }
    if Path::new("/var/log/auth.log").exists() {
        return SshLogSource::File(PathBuf::from("/var/log/auth.log"));
    }
    if Path::new("/var/log/secure").exists() {
        return SshLogSource::File(PathBuf::from("/var/log/secure"));
    }
    SshLogSource::File(PathBuf::from("/var/log/auth.log"))
}
