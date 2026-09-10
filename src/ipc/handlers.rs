use super::protocol::{AsnCommands, IpcRequest, IpcResponse, RegionCommands};
use crate::config::AppConfig;
use crate::error::SanaluError;
use crate::firewall::NftablesBackend;
use crate::storage::RedbStore;
use tokio::sync::mpsc;

pub use super::actions::{
    execute_asn, execute_ban, execute_category, execute_region, execute_unban, execute_whitelist,
};
pub use super::cloudflare::execute_cloudflare;
pub use super::format::{
    format_ban_list, format_check, format_datetime, format_duration, format_status,
};

pub fn to_response(res: Result<(), SanaluError>, buf: &[u8]) -> IpcResponse {
    match res {
        Ok(()) => IpcResponse::ok(String::from_utf8_lossy(buf).to_string()),
        Err(e) => IpcResponse::err(e.to_string()),
    }
}

pub async fn dispatch_ban(
    buf: &mut Vec<u8>,
    store: &RedbStore,
    firewall: &NftablesBackend,
    cf_tx: Option<&mpsc::Sender<()>>,
    target: &str,
    reason: Option<String>,
) -> IpcResponse {
    let res = execute_ban(buf, store, firewall, target, reason);
    if res.is_ok() {
        if let Some(tx) = cf_tx {
            let _ = tx.send(()).await;
        }
    }
    to_response(res, buf)
}

pub async fn dispatch_unban(
    buf: &mut Vec<u8>,
    store: &RedbStore,
    firewall: &NftablesBackend,
    cf_tx: Option<&mpsc::Sender<()>>,
    target: &str,
) -> IpcResponse {
    let res = execute_unban(buf, store, firewall, target);
    if res.is_ok() {
        if let Some(tx) = cf_tx {
            let _ = tx.send(()).await;
        }
    }
    to_response(res, buf)
}

pub async fn dispatch_policy(
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
        IpcRequest::Whitelist { action } => execute_whitelist(buf, store, action),
        IpcRequest::Category { action } => execute_category(buf, store, action),
        IpcRequest::Asn { action } => execute_asn(buf, store, action),
        IpcRequest::Region { action } => execute_region(buf, store, action),
        _ => return IpcResponse::err("Invalid policy command".to_string()),
    };
    if res.is_ok() && notify_cf {
        if let Some(tx) = cf_tx {
            let _ = tx.send(()).await;
        }
    }
    to_response(res, buf)
}

pub async fn dispatch_request(
    req: IpcRequest,
    store: &RedbStore,
    firewall: &NftablesBackend,
    cf_tx: Option<&mpsc::Sender<()>>,
    config: &AppConfig,
) -> IpcResponse {
    let mut buf = Vec::new();
    match req {
        IpcRequest::Status => to_response(
            format_status(&mut buf, store, &config.general.db_path, Some(config)),
            &buf,
        ),
        IpcRequest::Check { target } => to_response(format_check(&mut buf, store, &target), &buf),
        IpcRequest::Ban { target, reason } => {
            dispatch_ban(&mut buf, store, firewall, cf_tx, &target, reason).await
        }
        IpcRequest::Unban { target } => {
            dispatch_unban(&mut buf, store, firewall, cf_tx, &target).await
        }
        IpcRequest::BanList { all, plain, filter } => {
            to_response(format_ban_list(&mut buf, store, all, plain, filter), &buf)
        }
        IpcRequest::Cloudflare { action } => to_response(
            execute_cloudflare(&mut buf, store, config, action).await,
            &buf,
        ),
        policy_req => dispatch_policy(policy_req, &mut buf, store, cf_tx).await,
    }
}
