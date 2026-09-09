use sanalu::cli::{AsnCommands, CategoryCommands, RegionCommands, WhitelistCommands};
use sanalu::config::AppConfig;
use sanalu::firewall::NftablesBackend;
use sanalu::ipc::client::{is_offline_error, try_send_request};
use sanalu::ipc::protocol::{IpcRequest, IpcResponse};
use sanalu::ipc::server::IpcServer;
use sanalu::storage::RedbStore;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_ipc_roundtrip_all_commands() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let socket_path = temp_dir.path().join("test.sock");

    let store = Arc::new(RedbStore::open(&db_path).unwrap());
    let firewall = Arc::new(NftablesBackend::auto_detect(true));
    let mut config = AppConfig::default();
    config.general.db_path = db_path.clone();
    config.general.socket_path = socket_path.clone();
    let config = Arc::new(config);

    let server = IpcServer::new(
        socket_path.clone(),
        store.clone(),
        firewall.clone(),
        None,
        config.clone(),
    );
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let status_resp = try_send_request(&socket_path, &IpcRequest::Status)
        .await
        .unwrap();
    assert!(status_resp.success);
    assert!(status_resp.output.contains("=== Sanalu Status ==="));

    let ban_resp = try_send_request(
        &socket_path,
        &IpcRequest::Ban {
            target: "203.0.113.50".into(),
            reason: Some("ipc_unit_test".into()),
        },
    )
    .await
    .unwrap();
    assert!(ban_resp.success);
    assert!(ban_resp.output.contains("Banned 203.0.113.50 successfully"));

    let check_resp = try_send_request(
        &socket_path,
        &IpcRequest::Check {
            target: "203.0.113.50".into(),
        },
    )
    .await
    .unwrap();
    assert!(check_resp.success);
    assert!(check_resp.output.contains("BANNED [Direct Ban]"));

    let list_resp = try_send_request(
        &socket_path,
        &IpcRequest::BanList {
            all: true,
            plain: true,
            filter: None,
        },
    )
    .await
    .unwrap();
    assert!(list_resp.success);
    assert!(list_resp.output.contains("203.0.113.50"));

    let loopback_ban_resp = try_send_request(
        &socket_path,
        &IpcRequest::Ban {
            target: "127.0.0.1".into(),
            reason: None,
        },
    )
    .await
    .unwrap();
    assert!(loopback_ban_resp.success);
    assert!(
        loopback_ban_resp
            .output
            .contains("Cannot ban loopback or private network IP")
    );

    let unban_resp = try_send_request(
        &socket_path,
        &IpcRequest::Unban {
            target: "203.0.113.50".into(),
        },
    )
    .await
    .unwrap();
    assert!(unban_resp.success);
    assert!(
        unban_resp
            .output
            .contains("Unbanned 203.0.113.50 successfully")
    );

    let check_after_unban = try_send_request(
        &socket_path,
        &IpcRequest::Check {
            target: "203.0.113.50".into(),
        },
    )
    .await
    .unwrap();
    assert!(check_after_unban.output.contains("CLEAN"));

    let wl_resp = try_send_request(
        &socket_path,
        &IpcRequest::Whitelist {
            action: WhitelistCommands::Add {
                entry: "198.51.100.1".into(),
            },
        },
    )
    .await
    .unwrap();
    assert!(wl_resp.success);
    assert!(wl_resp.output.contains("Added 198.51.100.1 to whitelist"));

    let cat_resp = try_send_request(
        &socket_path,
        &IpcRequest::Category {
            action: CategoryCommands::Block {
                name: "ai_crawler".into(),
            },
        },
    )
    .await
    .unwrap();
    assert!(cat_resp.success);
    assert!(
        cat_resp
            .output
            .contains("Category 'ai_crawler' is now blocked")
    );

    let asn_resp = try_send_request(
        &socket_path,
        &IpcRequest::Asn {
            action: AsnCommands::Block { asn: 64496 },
        },
    )
    .await
    .unwrap();
    assert!(asn_resp.success);
    assert!(asn_resp.output.contains("ASN 64496 is now blocked"));

    let reg_resp = try_send_request(
        &socket_path,
        &IpcRequest::Region {
            action: RegionCommands::Allow { code: "ID".into() },
        },
    )
    .await
    .unwrap();
    assert!(reg_resp.success);
    assert!(reg_resp.output.contains("Region 'ID' is now allowed"));

    server_handle.abort();
}

#[tokio::test]
async fn test_ipc_offline_error_detection() {
    let non_existent = std::path::PathBuf::from("/tmp/non_existent_sanalu_test_socket.sock");
    let res = try_send_request(&non_existent, &IpcRequest::Status).await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(is_offline_error(&err));
}

#[test]
fn test_ipc_protocol_serde() {
    let req = IpcRequest::Ban {
        target: "10.0.0.1".into(),
        reason: Some("test".into()),
    };
    let json = serde_json::to_string(&req).unwrap();
    let decoded: IpcRequest = serde_json::from_str(&json).unwrap();
    match decoded {
        IpcRequest::Ban { target, reason } => {
            assert_eq!(target, "10.0.0.1");
            assert_eq!(reason.as_deref(), Some("test"));
        }
        _ => panic!("Expected Ban request"),
    }

    let resp = IpcResponse::ok("all good".into());
    let resp_json = serde_json::to_string(&resp).unwrap();
    let decoded_resp: IpcResponse = serde_json::from_str(&resp_json).unwrap();
    assert!(decoded_resp.success);
    assert_eq!(decoded_resp.output, "all good");
    assert!(decoded_resp.error.is_none());
}
