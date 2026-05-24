//! mitm/mod.rs — HTTPS MITM proxy with full TLS interception.
//!
//! Flow:
//!   1. Client sends:  CONNECT api.freefireth.garena.com:443 HTTP/1.1
//!   2. We reply:      HTTP/1.1 200 Connection Established
//!   3. Client starts TLS handshake → we terminate it with a per-host cert
//!      signed by our mitmproxy CA (trusted by BlueStacks via C# installer)
//!   4. We connect to the real server with our own TLS client
//!   5. Bidirectional relay with full HTTP body intercept

pub mod http_intercept;
pub mod stream_patch;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::config::PROXY_PORT;
use crate::tls_intercept::CertAuthority;
use crate::uid_check::Db;
use self::http_intercept::{
    get_proto_template,
    handle_get_login_data,
    handle_major_login_request,
    handle_major_login_response,
};
use self::stream_patch::patch_tcp_message;

// ═══════════════════════════════════════════════════════════════
//  PROXY LISTENER
// ═══════════════════════════════════════════════════════════════

pub async fn run_proxy(db: Db, http_client: reqwest::Client) {
    let addr: SocketAddr = format!("0.0.0.0:{PROXY_PORT}").parse().unwrap();
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("[PROXY] Failed to bind {addr}: {e}");
            return;
        }
    };

    // Load proto template once
    let template = match get_proto_template() {
        Ok(t) => Arc::new(t),
        Err(e) => {
            error!("[PROXY] Failed to load MOBILE_PROTO template: {e}");
            return;
        }
    };

    // Load CA (mitmproxy-ca.pem) — required for TLS MITM
    let ca = match CertAuthority::load() {
        Ok(c) => c,
        Err(e) => {
            error!("[PROXY] {e}");
            error!("[PROXY] Copy mitmproxy-ca.pem next to xenitronix.exe and restart.");
            return;
        }
    };

    info!("[PROXY] Listening on {addr} (HTTPS MITM proxy)");
    info!("[PROXY] TLS interception active — all HTTPS intercepted");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("[PROXY] Accept error: {e}");
                continue;
            }
        };

        let db = db.clone();
        let http_client = http_client.clone();
        let template = template.clone();
        let ca = ca.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, db, http_client, template, ca).await {
                let msg = e.to_string();
                if !msg.contains("Connection reset")
                    && !msg.contains("Broken pipe")
                    && !msg.contains("os error")
                {
                    warn!("[PROXY] {peer}: {e}");
                }
            }
        });
    }
}

// ═══════════════════════════════════════════════════════════════
//  PER-CONNECTION HANDLER
// ═══════════════════════════════════════════════════════════════

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    db: Db,
    http_client: reqwest::Client,
    template: Arc<crate::protobuf::ProtoFields>,
    ca: Arc<CertAuthority>,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let db2 = db.clone();
    let http2 = http_client.clone();
    let tpl2 = template.clone();
    let ca2 = ca.clone();
    let peer_ip = peer.ip().to_string();

    let conn = hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let db = db2.clone();
                let http_client = http2.clone();
                let template = tpl2.clone();
                let ca = ca2.clone();
                let peer_ip = peer_ip.clone();
                async move {
                    handle_request(req, db, http_client, template, ca, peer_ip).await
                }
            }),
        )
        .with_upgrades();

    conn.await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  REQUEST DISPATCHER
// ═══════════════════════════════════════════════════════════════

async fn handle_request(
    req: Request<Incoming>,
    db: Db,
    http_client: reqwest::Client,
    template: Arc<crate::protobuf::ProtoFields>,
    ca: Arc<CertAuthority>,
    client_ip: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        let authority = req.uri().authority().cloned();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let host = authority.map(|a| a.to_string()).unwrap_or_default();
                    if let Err(e) = tls_tunnel(
                        TokioIo::new(upgraded),
                        &host,
                        db,
                        http_client,
                        template,
                        ca,
                        &client_ip,
                    )
                    .await
                    {
                        let msg = e.to_string();
                        if !msg.contains("os error") && !msg.contains("closed") {
                            warn!("[PROXY] TLS tunnel {host}: {e}");
                        }
                    }
                }
                Err(e) => warn!("[PROXY] Upgrade error: {e}"),
            }
        });
        // Send 200 Connection Established BEFORE the upgrade
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap())
    } else {
        // Plain HTTP (non-CONNECT) — intercept POST bodies directly
        let path = req.uri().path().to_lowercase();
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();
        let body_bytes = req.collect().await.map(|b| b.to_bytes()).unwrap_or_default();

        if method == Method::POST {
            if path.contains("majorlogin") {
                let (new_body, _uid) =
                    match handle_major_login_request(&body_bytes, &template) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("[PROXY] MajorLogin req patch failed: {e}");
                            (body_bytes.to_vec(), String::new())
                        }
                    };
                if let Ok(resp) = forward_and_intercept_major_login(
                    &uri.to_string(),
                    &headers,
                    &new_body,
                    &db,
                    &http_client,
                    &client_ip,
                )
                .await
                {
                    return Ok(resp);
                }
            } else if path.contains("getlogindata") {
                let new_body = match handle_get_login_data(&body_bytes, &template) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("[PROXY] GetLoginData patch failed: {e}");
                        body_bytes.to_vec()
                    }
                };
                if let Ok(resp) =
                    forward_plain(&uri.to_string(), &headers, &new_body, &http_client).await
                {
                    return Ok(resp);
                }
            }
        }

        Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Bad Gateway")))
            .unwrap())
    }
}

// ═══════════════════════════════════════════════════════════════
//  TLS MITM TUNNEL
// ═══════════════════════════════════════════════════════════════

async fn tls_tunnel<I>(
    mut client_io: I,
    host: &str,
    db: Db,
    http_client: reqwest::Client,
    template: Arc<crate::protobuf::ProtoFields>,
    ca: Arc<CertAuthority>,
    client_ip: &str,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // ── Step 1: Terminate TLS from client using per-host cert ──
    let acceptor = ca.get_acceptor(host)?;
    let tls_client = acceptor.accept(&mut client_io).await?;
    let mut tls_client = tokio::io::BufStream::new(tls_client);

    // ── Step 2: Connect to real upstream ──
    let hostname_only = host.split(':').next().unwrap_or(host);
    let port: u16 = host
        .split(':')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);

    let upstream_tcp = TcpStream::connect((hostname_only, port)).await?;
    let connector = ca.make_connector();
    let server_name = ServerName::try_from(hostname_only.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid server name: {hostname_only}"))?;
    let mut tls_server = tokio::io::BufStream::new(
        connector.connect(server_name, upstream_tcp).await?,
    );

    // ── Step 3: Bidirectional relay with full HTTP body intercept ──
    let mut client_buf = vec![0u8; 65536];
    let mut server_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            // Client → Server (outbound)
            n = tls_client.read(&mut client_buf) => {
                let n = n?;
                if n == 0 { break; }
                let mut data = client_buf[..n].to_vec();

                if let Some(path) = extract_http_path(&data) {
                    let path_lower = path.to_lowercase();
                    if path_lower.contains("majorlogin") || path_lower.contains("getlogindata") {
                        data = intercept_http_request_in_tunnel(&data, &template, &path_lower)
                            .await
                            .unwrap_or(data);
                    } else {
                        // Generic TCP stream patch (outbound)
                        patch_tcp_message(&mut data, true);
                    }
                } else {
                    patch_tcp_message(&mut data, true);
                }

                tls_server.write_all(&data).await?;
                tls_server.flush().await?;
            }

            // Server → Client (inbound)
            n = tls_server.read(&mut server_buf) => {
                let n = n?;
                if n == 0 { break; }
                let mut data = server_buf[..n].to_vec();

                if is_http_response(&data) {
                    if let Some(body) = extract_http_response_body(&data) {
                        match handle_major_login_response(&body, &db, client_ip, &http_client).await {
                            Ok(decision) => {
                                if decision.blocked {
                                    if let Some(block_msg) = decision.block_message {
                                        let resp = build_http_response(400, &block_msg);
                                        tls_client.write_all(&resp).await?;
                                        tls_client.flush().await?;
                                        continue;
                                    }
                                }
                                data = rebuild_http_response(&data, &decision.body);
                            }
                            Err(e) => {
                                warn!("[TLS] MajorLogin response intercept error: {e}");
                            }
                        }
                    } else {
                        // Non-MajorLogin inbound TCP → only F25
                        patch_tcp_message(&mut data, false);
                    }
                } else {
                    patch_tcp_message(&mut data, false);
                }

                tls_client.write_all(&data).await?;
                tls_client.flush().await?;
            }
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  HTTP HELPERS
// ═══════════════════════════════════════════════════════════════

fn extract_http_path(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(&data[..data.len().min(512)]).ok()?;
    let first_line = text.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

fn is_http_response(data: &[u8]) -> bool {
    data.starts_with(b"HTTP/")
}

fn extract_http_response_body(data: &[u8]) -> Option<Vec<u8>> {
    let separator = b"\r\n\r\n";
    data.windows(4)
        .position(|w| w == separator)
        .map(|pos| data[pos + 4..].to_vec())
}

fn rebuild_http_response(original: &[u8], new_body: &[u8]) -> Vec<u8> {
    let separator = b"\r\n\r\n";
    if let Some(pos) = original.windows(4).position(|w| w == separator) {
        let headers_str = String::from_utf8_lossy(&original[..pos]);
        let new_headers = if let Some(cl_start) = headers_str.to_lowercase().find("content-length:") {
            let before = &headers_str[..cl_start];
            let after_start = &headers_str[cl_start..];
            let line_end = after_start.find('\n').unwrap_or(after_start.len());
            format!("{before}Content-Length: {}{}", new_body.len(), &after_start[line_end..])
        } else {
            format!("{headers_str}\r\nContent-Length: {}", new_body.len())
        };
        let mut result = new_headers.into_bytes();
        result.extend_from_slice(separator);
        result.extend_from_slice(new_body);
        result
    } else {
        original.to_vec()
    }
}

fn build_http_response(status: u16, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Unknown",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
        body.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(body);
    out
}

async fn intercept_http_request_in_tunnel(
    data: &[u8],
    template: &crate::protobuf::ProtoFields,
    path: &str,
) -> Result<Vec<u8>> {
    let separator = b"\r\n\r\n";
    let sep_pos = data
        .windows(4)
        .position(|w| w == separator)
        .ok_or_else(|| anyhow::anyhow!("No HTTP separator"))?;

    let headers_raw = &data[..sep_pos];
    let body = &data[sep_pos + 4..];

    let new_body = if path.contains("majorlogin") {
        let (nb, _uid) = handle_major_login_request(body, template)?;
        nb
    } else {
        handle_get_login_data(body, template)?
    };

    let headers_str = String::from_utf8_lossy(headers_raw);
    let new_headers = if let Some(cl_start) = headers_str.to_lowercase().find("content-length:") {
        let before = &headers_str[..cl_start];
        let after_start = &headers_str[cl_start..];
        let line_end = after_start.find('\n').unwrap_or(after_start.len());
        format!("{before}Content-Length: {}{}", new_body.len(), &after_start[line_end..])
    } else {
        format!("{headers_str}\r\nContent-Length: {}", new_body.len())
    };

    let mut result = new_headers.into_bytes();
    result.extend_from_slice(separator);
    result.extend_from_slice(&new_body);
    Ok(result)
}

async fn forward_plain(
    url: &str,
    _headers: &hyper::HeaderMap,
    body: &[u8],
    client: &reqwest::Client,
) -> Result<Response<Full<Bytes>>> {
    let resp = client
        .post(url)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("forward_plain: {e}"))?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
    let resp_bytes = resp.bytes().await.unwrap_or_default();
    Ok(Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(resp_bytes.to_vec())))
        .unwrap())
}

async fn forward_and_intercept_major_login(
    url: &str,
    _headers: &hyper::HeaderMap,
    body: &[u8],
    db: &Db,
    client: &reqwest::Client,
    client_ip: &str,
) -> Result<Response<Full<Bytes>>> {
    let resp = client
        .post(url)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("forward: {e}"))?;
    let status_code = resp.status().as_u16();
    let resp_bytes = resp.bytes().await.unwrap_or_default();

    let decision = handle_major_login_response(&resp_bytes, db, client_ip, client)
        .await
        .unwrap_or_else(|_| http_intercept::LoginDecision {
            body: resp_bytes.to_vec(),
            blocked: false,
            uid: String::new(),
            block_message: None,
        });

    if decision.blocked {
        let block_body = decision.block_message.unwrap_or_default();
        return Ok(Response::builder()
            .status(400)
            .body(Full::new(Bytes::from(block_body)))
            .unwrap());
    }

    Ok(Response::builder()
        .status(status_code)
        .body(Full::new(Bytes::from(decision.body)))
        .unwrap())
}
