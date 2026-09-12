//! Authenticated, response-bounded HTTP transport for local wallet and node RPC.

use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::{JsonRpcTransport, RpcCall, RpcTransportError};

const MAX_COOKIE_BYTES: u64 = 1_024;
const MAX_HEADER_BYTES: usize = 32 * 1_024;
const MAX_REQUEST_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_ENVELOPE_OVERHEAD: usize = 64 * 1_024;

/// Invalid static configuration for a local authenticated RPC endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LoopbackTransportError {
    /// RPC must never leave the host trust boundary.
    #[error("RPC endpoint must be a nonzero loopback TCP address")]
    NonLoopbackEndpoint,
    /// The authentication cookie is not a protected ordinary file.
    #[error("RPC cookie file is not protected")]
    UnsafeCookieFile,
}

/// A minimal JSON-RPC HTTP/1.1 client restricted to a loopback endpoint.
///
/// Authentication is reloaded from a protected cookie file for every call, so
/// node cookie rotation does not require embedding credentials in configuration,
/// process arguments, or environment variables.
pub struct LoopbackHttpTransport {
    endpoint: SocketAddr,
    cookie_file: PathBuf,
    next_request_id: AtomicU64,
}

impl LoopbackHttpTransport {
    /// Creates a transport after checking the endpoint and cookie-file boundary.
    pub fn new(
        endpoint: SocketAddr,
        cookie_file: impl Into<PathBuf>,
    ) -> Result<Self, LoopbackTransportError> {
        let cookie_file = cookie_file.into();
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err(LoopbackTransportError::NonLoopbackEndpoint);
        }
        validate_cookie_file(&cookie_file)?;
        Ok(Self {
            endpoint,
            cookie_file,
            next_request_id: AtomicU64::new(1),
        })
    }

    fn allocate_request_id(&self) -> Result<u64, RpcTransportError> {
        self.next_request_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| RpcTransportError::unavailable())
    }

    fn execute(&self, call: RpcCall) -> Result<Value, RpcTransportError> {
        validate_cookie_file(&self.cookie_file).map_err(|_| RpcTransportError::unavailable())?;
        let mut cookie = read_cookie(&self.cookie_file)?;
        let request_id = self.allocate_request_id()?;
        let mut body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": call.method(),
            "params": call.params(),
        }))
        .map_err(|_| RpcTransportError::unavailable())?;
        if body.len() > MAX_REQUEST_BYTES {
            body.zeroize();
            cookie.zeroize();
            return Err(RpcTransportError::response_too_large());
        }

        let mut authorization = BASE64.encode(&cookie);
        cookie.zeroize();
        let header = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            self.endpoint,
            authorization,
            body.len(),
        );
        authorization.zeroize();
        let mut request = header.into_bytes();
        request.extend_from_slice(&body);
        body.zeroize();

        let result = self.exchange(&request, request_id, &call);
        request.zeroize();
        result
    }

    fn exchange(
        &self,
        request: &[u8],
        request_id: u64,
        call: &RpcCall,
    ) -> Result<Value, RpcTransportError> {
        let mut stream =
            TcpStream::connect_timeout(&self.endpoint, call.timeout()).map_err(map_io_error)?;
        stream
            .set_read_timeout(Some(call.timeout()))
            .map_err(map_io_error)?;
        stream
            .set_write_timeout(Some(call.timeout()))
            .map_err(map_io_error)?;
        stream.write_all(request).map_err(map_io_error)?;
        stream.flush().map_err(map_io_error)?;

        let body_limit = call
            .max_response_bytes()
            .checked_add(MAX_ENVELOPE_OVERHEAD)
            .ok_or_else(RpcTransportError::response_too_large)?;
        let (status, content_length, mut body) = read_response_head(&mut stream, body_limit)?;
        if content_length > body_limit || body.len() > content_length {
            body.zeroize();
            return Err(RpcTransportError::response_too_large());
        }
        let missing = content_length - body.len();
        if missing != 0 {
            let start = body.len();
            body.resize(content_length, 0);
            if let Err(error) = stream.read_exact(&mut body[start..]) {
                body.zeroize();
                return Err(map_io_error(error));
            }
        }

        let parsed: JsonRpcResponse = match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(_) => {
                body.zeroize();
                return Err(RpcTransportError::unavailable());
            }
        };
        body.zeroize();
        if parsed
            .jsonrpc
            .as_deref()
            .is_some_and(|version| version != "2.0")
            || parsed.id.as_u64() != Some(request_id)
        {
            return Err(RpcTransportError::unavailable());
        }

        match (status, parsed.result, parsed.error) {
            (200, Some(result), None) => {
                let result_size = serde_json::to_vec(&result)
                    .map_err(|_| RpcTransportError::unavailable())?
                    .len();
                if result_size > call.max_response_bytes() {
                    Err(RpcTransportError::response_too_large())
                } else {
                    Ok(result)
                }
            }
            (200 | 500, None, Some(error)) => {
                Err(RpcTransportError::server(error.code, error.message))
            }
            _ => Err(RpcTransportError::unavailable()),
        }
    }
}

impl fmt::Debug for LoopbackHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackHttpTransport")
            .field("endpoint", &self.endpoint)
            .field("cookie_file", &"[PROTECTED]")
            .finish_non_exhaustive()
    }
}

impl JsonRpcTransport for LoopbackHttpTransport {
    fn call(&self, call: RpcCall) -> Result<Value, RpcTransportError> {
        self.execute(call)
    }
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    jsonrpc: Option<String>,
    id: Value,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

fn validate_cookie_file(path: &Path) -> Result<(), LoopbackTransportError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| LoopbackTransportError::UnsafeCookieFile)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(LoopbackTransportError::UnsafeCookieFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(LoopbackTransportError::UnsafeCookieFile);
        }
        let parent = path
            .parent()
            .ok_or(LoopbackTransportError::UnsafeCookieFile)?;
        let parent_metadata = std::fs::symlink_metadata(parent)
            .map_err(|_| LoopbackTransportError::UnsafeCookieFile)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(LoopbackTransportError::UnsafeCookieFile);
        }
    }
    Ok(())
}

fn read_cookie(path: &Path) -> Result<Vec<u8>, RpcTransportError> {
    let file = File::open(path).map_err(|_| RpcTransportError::unavailable())?;
    let mut cookie = Vec::new();
    file.take(MAX_COOKIE_BYTES + 1)
        .read_to_end(&mut cookie)
        .map_err(|_| RpcTransportError::unavailable())?;
    while cookie.last().is_some_and(u8::is_ascii_whitespace) {
        cookie.pop();
    }
    if cookie.len() < 3
        || cookie.len() as u64 > MAX_COOKIE_BYTES
        || cookie.contains(&b'\r')
        || cookie.contains(&b'\n')
        || !cookie.contains(&b':')
    {
        cookie.zeroize();
        return Err(RpcTransportError::unavailable());
    }
    Ok(cookie)
}

fn read_response_head(
    stream: &mut TcpStream,
    body_limit: usize,
) -> Result<(u16, usize, Vec<u8>), RpcTransportError> {
    let mut received = Vec::with_capacity(4 * 1_024);
    let header_end = loop {
        if let Some(position) = find_bytes(&received, b"\r\n\r\n") {
            break position + 4;
        }
        if received.len() >= MAX_HEADER_BYTES {
            return Err(RpcTransportError::response_too_large());
        }
        let mut chunk = [0u8; 4 * 1_024];
        let read = stream.read(&mut chunk).map_err(map_io_error)?;
        if read == 0 {
            return Err(RpcTransportError::unavailable());
        }
        let allowed = MAX_HEADER_BYTES
            .checked_add(body_limit)
            .ok_or_else(RpcTransportError::response_too_large)?;
        if received.len().saturating_add(read) > allowed {
            return Err(RpcTransportError::response_too_large());
        }
        received.extend_from_slice(&chunk[..read]);
    };

    if header_end > MAX_HEADER_BYTES {
        received.zeroize();
        return Err(RpcTransportError::response_too_large());
    }
    let header = std::str::from_utf8(&received[..header_end])
        .map_err(|_| RpcTransportError::unavailable())?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| {
            line.strip_prefix("HTTP/1.1 ")
                .or_else(|| line.strip_prefix("HTTP/1.0 "))
        })
        .and_then(|line| line.split_ascii_whitespace().next())
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(RpcTransportError::unavailable)?;
    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            received.zeroize();
            return Err(RpcTransportError::unavailable());
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            received.zeroize();
            return Err(RpcTransportError::unavailable());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                received.zeroize();
                return Err(RpcTransportError::unavailable());
            }
            content_length = value.trim().parse::<usize>().ok();
            if content_length.is_none() {
                received.zeroize();
                return Err(RpcTransportError::unavailable());
            }
        }
    }
    let content_length = content_length.ok_or_else(RpcTransportError::unavailable)?;
    let mut body = received.split_off(header_end);
    received.zeroize();
    Ok((status, content_length, std::mem::take(&mut body)))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn map_io_error(error: io::Error) -> RpcTransportError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        RpcTransportError::timeout()
    } else {
        RpcTransportError::unavailable()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{fs, net::TcpListener, thread, time::Duration};

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    fn cookie() -> (TempDir, PathBuf) {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("rpc.cookie");
        fs::write(&path, b"rpc-user:rpc-password\n").expect("cookie written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("directory protected");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("cookie protected");
        }
        (directory, path)
    }

    fn rpc_call(transport: &LoopbackHttpTransport) -> Result<Value, RpcTransportError> {
        transport.call(RpcCall::new(
            "getwalletstatus",
            json!([]),
            Duration::from_secs(2),
            1_024,
        ))
    }

    fn serve_once(response: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("local address");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepted");
            let mut request = [0u8; 8 * 1_024];
            let read = stream.read(&mut request).expect("request read");
            let text = std::str::from_utf8(&request[..read]).expect("request UTF-8");
            assert!(text.starts_with("POST / HTTP/1.1\r\n"));
            assert!(text.contains("Authorization: Basic "));
            assert!(!text.contains("rpc-password"));
            stream.write_all(&response).expect("response written");
        });
        address
    }

    fn response(status: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[test]
    fn performs_authenticated_bounded_call() {
        let (_directory, path) = cookie();
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{"locked":false}}"#;
        let transport = LoopbackHttpTransport::new(serve_once(response("200 OK", body)), path)
            .expect("transport");
        assert_eq!(rpc_call(&transport), Ok(json!({ "locked": false })));
    }

    #[test]
    fn maps_server_error_without_exposing_text() {
        let (_directory, path) = cookie();
        let body =
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-26,"message":"already in mempool"}}"#;
        let transport = LoopbackHttpTransport::new(serve_once(response("500 Error", body)), path)
            .expect("transport");
        let error = rpc_call(&transport).expect_err("server error");
        assert_eq!(error.to_string(), "bounded JSON-RPC transport failed");
        assert!(!format!("{error:?}").contains("mempool"));
    }

    #[test]
    fn rejects_crossed_response_identity() {
        let (_directory, path) = cookie();
        let body = br#"{"jsonrpc":"2.0","id":2,"result":{"locked":false}}"#;
        let transport = LoopbackHttpTransport::new(serve_once(response("200 OK", body)), path)
            .expect("transport");
        assert_eq!(rpc_call(&transport), Err(RpcTransportError::unavailable()));
    }

    #[test]
    fn rejects_result_larger_than_call_budget() {
        let (_directory, path) = cookie();
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{}\"}}",
            "x".repeat(2_000)
        );
        let transport =
            LoopbackHttpTransport::new(serve_once(response("200 OK", body.as_bytes())), path)
                .expect("transport");
        assert_eq!(
            rpc_call(&transport),
            Err(RpcTransportError::response_too_large())
        );
    }

    #[test]
    fn rejects_non_loopback_and_unsafe_cookie() {
        let (_directory, path) = cookie();
        assert!(matches!(
            LoopbackHttpTransport::new("192.0.2.1:8232".parse().expect("address"), &path),
            Err(LoopbackTransportError::NonLoopbackEndpoint)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .expect("permission changed");
            assert!(matches!(
                LoopbackHttpTransport::new("127.0.0.1:8232".parse().expect("address"), &path,),
                Err(LoopbackTransportError::UnsafeCookieFile)
            ));
        }
    }
}
