use crate::discovery::SshLogSource;
use crate::firewall::{FirewallBackend, NftablesBackend};
use crate::geo::IpLookupDb;
use crate::intelligence::{PipelineAction, ThreatPipeline};
use crate::parser::SshStatefulParser;
use crate::storage::{RedbStore, StoredBanRecord};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(unix)]
fn file_ino(metadata: &std::fs::Metadata) -> u64 {
    metadata.ino()
}

#[cfg(not(unix))]
fn file_ino(_metadata: &std::fs::Metadata) -> u64 {
    0
}

fn fallback_auth_log() -> PathBuf {
    if Path::new("/var/log/auth.log").exists() {
        PathBuf::from("/var/log/auth.log")
    } else if Path::new("/var/log/secure").exists() {
        PathBuf::from("/var/log/secure")
    } else {
        PathBuf::from("/var/log/auth.log")
    }
}

fn check_file_rotation(
    path: &Path,
    reader: &mut BufReader<File>,
    current_ino: &mut u64,
    current_offset: &mut u64,
) {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };

    let new_ino = file_ino(&metadata);
    if new_ino != *current_ino {
        if let Ok(mut new_file) = File::open(path) {
            let _ = new_file.seek(SeekFrom::Start(0));
            *reader = BufReader::new(new_file);
            *current_ino = new_ino;
            *current_offset = 0;
        }
    } else if metadata.len() < *current_offset {
        if let Ok(mut new_file) = File::open(path) {
            let _ = new_file.seek(SeekFrom::Start(0));
            *reader = BufReader::new(new_file);
            *current_offset = 0;
        } else {
            let _ = reader.seek(SeekFrom::Start(0));
            *current_offset = 0;
        }
    }
}

async fn process_ssh_line(
    line: &str,
    parser: &mut SshStatefulParser,
    pipe: &ThreatPipeline,
    fw: &NftablesBackend,
    st: &RedbStore,
    cf: Option<&mpsc::Sender<()>>,
) {
    let trimmed = line.trim();
    let event = parser.process_line(trimmed);
    let action = pipe.evaluate_ssh_event(&event);
    if let PipelineAction::Ban { reason, permanent } = action {
        let ip = match event {
            crate::parser::SshEvent::ScannerProbe { ip, .. } => ip,
            crate::parser::SshEvent::AuthFailure { ip, .. } => ip,
            crate::parser::SshEvent::Ignore => return,
        };
        let timeout = if permanent { None } else { Some(3600) };
        let _ = fw.ban_ip(ip, timeout);

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let record = StoredBanRecord {
            target: ip.to_string(),
            ip: Some(ip),
            tier_level: 0,
            banned_at_secs: now_secs,
            expires_at_secs: timeout.map(|s| now_secs + s),
            reason: reason.clone(),
        };
        let _ = st.save_ban(&record);

        if let Some(tx) = cf {
            let _ = tx.send(()).await;
        }
        println!("[BAN] {} - {}", ip, reason);
    }
}

async fn tail_ssh_file(
    path: PathBuf,
    pipe: Arc<ThreatPipeline>,
    fw: Arc<NftablesBackend>,
    st: Arc<RedbStore>,
    cf: Option<mpsc::Sender<()>>,
    mut parser: SshStatefulParser,
) {
    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut current_offset = file.seek(SeekFrom::End(0)).unwrap_or(0);
    let mut current_ino = file.metadata().map(|m| file_ino(&m)).unwrap_or(0);
    let mut reader = BufReader::new(file);

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                check_file_rotation(&path, &mut reader, &mut current_ino, &mut current_offset);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(_) => {
                current_offset += line.len() as u64;
                process_ssh_line(&line, &mut parser, &pipe, &fw, &st, cf.as_ref()).await;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

async fn tail_ssh_journald(
    service: &str,
    pipe: Arc<ThreatPipeline>,
    fw: Arc<NftablesBackend>,
    st: Arc<RedbStore>,
    cf: Option<mpsc::Sender<()>>,
    mut parser: SshStatefulParser,
) {
    let child_res = tokio::process::Command::new("journalctl")
        .args(["-u", service, "-f", "-n", "0", "-o", "cat"])
        .stdout(std::process::Stdio::piped())
        .spawn();

    let mut child = match child_res {
        Ok(child) => child,
        Err(_) => {
            let fallback_path = fallback_auth_log();
            tail_ssh_file(fallback_path, pipe, fw, st, cf, parser).await;
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let fallback_path = fallback_auth_log();
            tail_ssh_file(fallback_path, pipe, fw, st, cf, parser).await;
            return;
        }
    };

    let mut reader = tokio::io::BufReader::new(stdout).lines();
    while let Ok(Some(line)) = reader.next_line().await {
        process_ssh_line(&line, &mut parser, &pipe, &fw, &st, cf.as_ref()).await;
    }
}

pub fn spawn_ssh_watcher(
    source: SshLogSource,
    pipe: Arc<ThreatPipeline>,
    fw: Arc<NftablesBackend>,
    st: Arc<RedbStore>,
    cf: Option<mpsc::Sender<()>>,
    _geo: Arc<IpLookupDb>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let parser = SshStatefulParser::new();
        match source {
            SshLogSource::JournaldService(service) => {
                tail_ssh_journald(&service, pipe, fw, st, cf, parser).await;
            }
            SshLogSource::File(path) => {
                tail_ssh_file(path, pipe, fw, st, cf, parser).await;
            }
        }
    })
}
