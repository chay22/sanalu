use super::handlers;
use super::protocol::{IpcRequest, IpcResponse};
use crate::config::AppConfig;
use crate::error::SanaluError;
use crate::firewall::NftablesBackend;
use crate::storage::RedbStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

pub struct IpcServer {
    socket_path: PathBuf,
    store: Arc<RedbStore>,
    firewall: Arc<NftablesBackend>,
    cf_tx: Option<mpsc::Sender<()>>,
    config: Arc<AppConfig>,
}

impl IpcServer {
    pub fn new(
        socket_path: PathBuf,
        store: Arc<RedbStore>,
        firewall: Arc<NftablesBackend>,
        cf_tx: Option<mpsc::Sender<()>>,
        config: Arc<AppConfig>,
    ) -> Self {
        Self {
            socket_path,
            store,
            firewall,
            cf_tx,
            config,
        }
    }

    pub async fn run(&self) -> Result<(), SanaluError> {
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        if let Some(parent) = self.socket_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
                set_socket_dir_permissions(parent);
            }
        }

        let listener = UnixListener::bind(&self.socket_path).map_err(SanaluError::Io)?;
        set_socket_permissions(&self.socket_path);

        while let Ok((stream, _)) = listener.accept().await {
            let store = self.store.clone();
            let firewall = self.firewall.clone();
            let cf_tx = self.cf_tx.clone();
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_client(stream, store, firewall, cf_tx, config).await;
            });
        }
        Ok(())
    }
}

fn set_socket_dir_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn set_socket_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

async fn handle_client(
    mut stream: UnixStream,
    store: Arc<RedbStore>,
    firewall: Arc<NftablesBackend>,
    cf_tx: Option<mpsc::Sender<()>>,
    config: Arc<AppConfig>,
) -> Result<(), SanaluError> {
    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    let read_bytes = buf_reader
        .read_line(&mut line)
        .await
        .map_err(SanaluError::Io)?;
    if read_bytes == 0 {
        return Ok(());
    }

    let req: IpcRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = IpcResponse::err(format!("Invalid request format: {e}"));
            let mut payload = serde_json::to_vec(&resp).unwrap_or_default();
            payload.push(b'\n');
            let _ = writer.write_all(&payload).await;
            return Ok(());
        }
    };

    let resp = handlers::dispatch_request(req, &store, &firewall, cf_tx.as_ref(), &config).await;
    let mut payload = serde_json::to_vec(&resp).unwrap_or_default();
    payload.push(b'\n');
    let _ = writer.write_all(&payload).await;
    let _ = writer.flush().await;
    Ok(())
}
