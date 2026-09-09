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

    pub async fn run(self) -> Result<(), SanaluError> {
        prepare_socket_path(&self.socket_path)?;
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

fn prepare_socket_path(path: &Path) -> Result<(), SanaluError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(SanaluError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
            }
        }
    }
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
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

    let resp = dispatch_request(req, &store, &firewall, cf_tx.as_ref(), &config).await;
    let mut payload = serde_json::to_vec(&resp).unwrap_or_default();
    payload.push(b'\n');
    let _ = writer.write_all(&payload).await;
    let _ = writer.flush().await;
    Ok(())
}

async fn dispatch_request(
    req: IpcRequest,
    store: &RedbStore,
    firewall: &NftablesBackend,
    cf_tx: Option<&mpsc::Sender<()>>,
    config: &AppConfig,
) -> IpcResponse {
    let mut buf = Vec::new();
    match req {
        IpcRequest::Status => {
            match handlers::format_status(&mut buf, store, &config.general.db_path) {
                Ok(()) => IpcResponse::ok(String::from_utf8_lossy(&buf).to_string()),
                Err(e) => IpcResponse::err(e.to_string()),
            }
        }
        IpcRequest::Check { target } => match handlers::format_check(&mut buf, store, &target) {
            Ok(()) => IpcResponse::ok(String::from_utf8_lossy(&buf).to_string()),
            Err(e) => IpcResponse::err(e.to_string()),
        },
        IpcRequest::Ban { target, reason } => {
            match handlers::execute_ban(&mut buf, store, firewall, &target, reason) {
                Ok(()) => {
                    if let Some(tx) = cf_tx {
                        let _ = tx.send(()).await;
                    }
                    IpcResponse::ok(String::from_utf8_lossy(&buf).to_string())
                }
                Err(e) => IpcResponse::err(e.to_string()),
            }
        }
        IpcRequest::Unban { target } => {
            match handlers::execute_unban(&mut buf, store, firewall, &target) {
                Ok(()) => {
                    if let Some(tx) = cf_tx {
                        let _ = tx.send(()).await;
                    }
                    IpcResponse::ok(String::from_utf8_lossy(&buf).to_string())
                }
                Err(e) => IpcResponse::err(e.to_string()),
            }
        }
        IpcRequest::BanList { all, plain, filter } => {
            match handlers::format_ban_list(&mut buf, store, all, plain, filter) {
                Ok(()) => IpcResponse::ok(String::from_utf8_lossy(&buf).to_string()),
                Err(e) => IpcResponse::err(e.to_string()),
            }
        }
        IpcRequest::Whitelist { action } => {
            match handlers::execute_whitelist(&mut buf, store, action) {
                Ok(()) => IpcResponse::ok(String::from_utf8_lossy(&buf).to_string()),
                Err(e) => IpcResponse::err(e.to_string()),
            }
        }
        IpcRequest::Category { action } => {
            match handlers::execute_category(&mut buf, store, action) {
                Ok(()) => IpcResponse::ok(String::from_utf8_lossy(&buf).to_string()),
                Err(e) => IpcResponse::err(e.to_string()),
            }
        }
        IpcRequest::Asn { action } => match handlers::execute_asn(&mut buf, store, action) {
            Ok(()) => IpcResponse::ok(String::from_utf8_lossy(&buf).to_string()),
            Err(e) => IpcResponse::err(e.to_string()),
        },
        IpcRequest::Region { action } => match handlers::execute_region(&mut buf, store, action) {
            Ok(()) => IpcResponse::ok(String::from_utf8_lossy(&buf).to_string()),
            Err(e) => IpcResponse::err(e.to_string()),
        },
        IpcRequest::Cloudflare { action } => {
            match handlers::execute_cloudflare(&mut buf, store, config, action).await {
                Ok(()) => IpcResponse::ok(String::from_utf8_lossy(&buf).to_string()),
                Err(e) => IpcResponse::err(e.to_string()),
            }
        }
    }
}
