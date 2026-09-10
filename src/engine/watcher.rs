use crate::firewall::{FirewallBackend, NftablesBackend};
use crate::geo::IpLookupDb;
use crate::intelligence::{PipelineAction, ThreatPipeline};
use crate::parser::parse_nginx_combined_line;
use crate::storage::{RedbStore, StoredBanRecord};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub fn spawn_nginx_watcher(
    path: PathBuf,
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
        let _ = file.seek(SeekFrom::End(0));
        let mut reader = BufReader::new(file);

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    if let Some(entry) = parse_nginx_combined_line(trimmed) {
                        let asn_info = geo.lookup(entry.client_ip);
                        let action = pipe.evaluate(
                            entry.client_ip,
                            asn_info.as_ref(),
                            entry.user_agent,
                            entry.method,
                            entry.path,
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

                            if let Some(ref tx) = cf {
                                let _ = tx.send(()).await;
                            }
                            println!("[BAN] {} - {}", entry.client_ip, reason);
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    })
}
