use crate::error::SanaluError;
use crate::ipc::protocol::{IpcRequest, IpcResponse};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub fn is_offline_error(err: &SanaluError) -> bool {
    match err {
        SanaluError::Io(io_err) => matches!(
            io_err.kind(),
            std::io::ErrorKind::NotFound
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::PermissionDenied
        ),
        _ => false,
    }
}

pub async fn try_send_request(
    socket_path: &Path,
    req: &IpcRequest,
) -> Result<IpcResponse, SanaluError> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(SanaluError::Io)?;
    let req_json =
        serde_json::to_string(req).map_err(|e| SanaluError::Config(e.to_string()))?;
    stream
        .write_all(req_json.as_bytes())
        .await
        .map_err(SanaluError::Io)?;
    stream.write_all(b"\n").await.map_err(SanaluError::Io)?;
    stream.flush().await.map_err(SanaluError::Io)?;

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .await
        .map_err(SanaluError::Io)?;
    let resp: IpcResponse =
        serde_json::from_str(&resp_line).map_err(|e| SanaluError::Config(e.to_string()))?;
    Ok(resp)
}
