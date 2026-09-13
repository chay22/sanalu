use crate::firewall::{FirewallBackend, NftablesBackend};
use crate::geo::IpLookupDb;
use crate::intelligence::{PipelineAction, ThreatPipeline};
use crate::parser::CompiledLogFormat;
use crate::storage::{RedbStore, StoredBanRecord};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

async fn process_log_line(
    line: &str,
    format: &CompiledLogFormat,
    pipe: &ThreatPipeline,
    fw: &NftablesBackend,
    st: &RedbStore,
    cf: Option<&mpsc::Sender<()>>,
    geo: &IpLookupDb,
) {
    let trimmed = line.trim();
    if let Some(entry) = format.parse_line(trimmed) {
        let asn_info = geo.lookup(entry.client_ip);
        let action = pipe.evaluate_request(
            entry.client_ip,
            asn_info.as_ref(),
            entry.user_agent,
            entry.method,
            entry.path,
            entry.status,
            entry.referer,
        );
        if let PipelineAction::Ban { reason, permanent } = action {
            let timeout = if permanent { None } else { Some(3600) };
            let _ = fw.ban_ip(entry.client_ip, timeout);

            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let record = StoredBanRecord {
                target: entry.client_ip.to_string(),
                ip: Some(entry.client_ip),
                tier_level: 0,
                banned_at_secs: now_secs,
                expires_at_secs: timeout.map(|s| now_secs + s),
                reason: reason.clone(),
            };
            let _ = st.save_ban(&record);

            if let Some(tx) = cf {
                let _ = tx.send(()).await;
            }
            println!("[BAN] {} - {}", entry.client_ip, reason);
        }
    }
}

pub fn spawn_nginx_watcher(
    path: PathBuf,
    format: CompiledLogFormat,
    pipe: Arc<ThreatPipeline>,
    fw: Arc<NftablesBackend>,
    st: Arc<RedbStore>,
    cf: Option<mpsc::Sender<()>>,
    geo: Arc<IpLookupDb>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
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
                    process_log_line(&line, &format, &pipe, &fw, &st, cf.as_ref(), &geo).await;
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    })
}
