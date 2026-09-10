use super::handlers;
use super::protocol::{AsnCommands, IpcRequest, IpcResponse, RegionCommands};
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

fn to_response(res: Result<(), SanaluError>, buf: &[u8]) -> IpcResponse {
    match res {
        Ok(()) => IpcResponse::ok(String::from_utf8_lossy(buf).to_string()),
        Err(e) => IpcResponse::err(e.to_string()),
    }
}

async fn dispatch_ban(
    buf: &mut Vec<u8>,
    store: &RedbStore,
    firewall: &NftablesBackend,
    cf_tx: Option<&mpsc::Sender<()>>,
    target: &str,
    reason: Option<String>,
) -> IpcResponse {
    let res = handlers::execute_ban(buf, store, firewall, target, reason);
    if res.is_ok() {
        if let Some(tx) = cf_tx {
            let _ = tx.send(()).await;
        }
    }
    to_response(res, buf)
}

async fn dispatch_unban(
    buf: &mut Vec<u8>,
    store: &RedbStore,
    firewall: &NftablesBackend,
    cf_tx: Option<&mpsc::Sender<()>>,
    target: &str,
) -> IpcResponse {
    let res = handlers::execute_unban(buf, store, firewall, target);
    if res.is_ok() {
        if let Some(tx) = cf_tx {
            let _ = tx.send(()).await;
        }
    }
    to_response(res, buf)
}

async fn dispatch_policy(
    req: IpcRequest,
    buf: &mut Vec<u8>,
    store: &RedbStore,
    cf_tx: Option<&mpsc::Sender<()>>,
) -> IpcResponse {
    let notify_cf = matches!(
        req,
        IpcRequest::Asn {
            action: AsnCommands::Block { .. } | AsnCommands::Unblock { .. }
        } | IpcRequest::Region {
            action: RegionCommands::Allow { .. } | RegionCommands::Disallow { .. }
        }
    );
    let res = match req {
        IpcRequest::Whitelist { action } => handlers::execute_whitelist(buf, store, action),
        IpcRequest::Category { action } => handlers::execute_category(buf, store, action),
        IpcRequest::Asn { action } => handlers::execute_asn(buf, store, action),
        IpcRequest::Region { action } => handlers::execute_region(buf, store, action),
        _ => return IpcResponse::err("Invalid policy command".to_string()),
    };
    if res.is_ok() && notify_cf {
        if let Some(tx) = cf_tx {
            let _ = tx.send(()).await;
        }
    }
    to_response(res, buf)
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
        IpcRequest::Status => to_response(
            handlers::format_status(&mut buf, store, &config.general.db_path, Some(config)),
            &buf,
        ),
        IpcRequest::Check { target } => {
            to_response(handlers::format_check(&mut buf, store, &target), &buf)
        }
        IpcRequest::Ban { target, reason } => {
            dispatch_ban(&mut buf, store, firewall, cf_tx, &target, reason).await
        }
        IpcRequest::Unban { target } => {
            dispatch_unban(&mut buf, store, firewall, cf_tx, &target).await
        }
        IpcRequest::BanList { all, plain, filter } => to_response(
            handlers::format_ban_list(&mut buf, store, all, plain, filter),
            &buf,
        ),
        IpcRequest::Cloudflare { action } => to_response(
            handlers::execute_cloudflare(&mut buf, store, config, action).await,
            &buf,
        ),
        policy_req => dispatch_policy(policy_req, &mut buf, store, cf_tx).await,
    }
}
