//! Hyper-based forward proxy implementation.
//!
//! This module implements the HTTP/HTTPS forward proxy server using hyper.
//! It handles:
//! - HTTP CONNECT tunneling for HTTPS (bidirectional TCP tunnel)
//! - Regular HTTP request forwarding
//! - Host-to-IP mappings for DNS bypass
//! - Optional upstream proxy forwarding

use crate::config::AppConfig;
use crate::resolver::{HostResolver, ResolveResult};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// The proxy server state.
#[derive(Clone)]
pub struct ProxyServer {
    config: Arc<RwLock<AppConfig>>,
    resolver: HostResolver,
}

impl ProxyServer {
    /// Creates a new proxy server.
    pub fn new(config: Arc<RwLock<AppConfig>>) -> Self {
        let resolver = HostResolver::new(config.clone());
        Self { config, resolver }
    }

    /// Runs the proxy server.
    pub async fn run(&self) -> anyhow::Result<()> {
        let listen_addr = {
            let cfg = self.config.read().unwrap();
            cfg.server.listen.clone()
        };

        let addr: SocketAddr = listen_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;

        info!(address = %addr, "Proxy server listening");

        loop {
            let (stream, client_addr) = listener.accept().await?;
            
            let config = self.config.clone();
            let resolver = self.resolver.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                
                let service = service_fn(move |req| {
                    let config = config.clone();
                    let resolver = resolver.clone();
                    async move {
                        handle_request(req, client_addr, config, resolver).await
                    }
                });

                if let Err(e) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    // Filter out common benign errors
                    let err_str = e.to_string();
                    if !err_str.contains("connection closed") 
                        && !err_str.contains("broken pipe")
                        && !err_str.contains("reset by peer") 
                    {
                        debug!(client = %client_addr, error = %e, "Connection error");
                    }
                }
            });
        }
    }

    /// Refreshes the resolver cache (called on config reload).
    pub fn refresh(&self) {
        self.resolver.refresh_cache();
    }
}

/// Handle an incoming HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    config: Arc<RwLock<AppConfig>>,
    resolver: HostResolver,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    debug!(
        client = %client_addr,
        method = %method,
        uri = %uri,
        "Request received"
    );

    if method == Method::CONNECT {
        // HTTPS CONNECT tunnel
        handle_connect(req, client_addr, config, resolver).await
    } else {
        // Regular HTTP proxy
        handle_http(req, client_addr, config, resolver).await
    }
}

/// Handle CONNECT requests (HTTPS tunneling).
async fn handle_connect(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    _config: Arc<RwLock<AppConfig>>,
    resolver: HostResolver,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let uri = req.uri().clone();
    
    // Parse host:port from CONNECT request
    let (host, port) = match parse_connect_target(&uri) {
        Some((h, p)) => (h, p),
        None => {
            warn!(client = %client_addr, uri = %uri, "Invalid CONNECT target");
            return Ok(error_response(StatusCode::BAD_REQUEST, "Invalid CONNECT target"));
        }
    };

    // Resolve the destination
    let resolve_result = resolver.resolve(&host, port, true);

    let target_addr = match &resolve_result {
        ResolveResult::Direct { ip, port, original_host } => {
            info!(
                client = %client_addr,
                host = %original_host,
                ip = %ip,
                port = port,
                "CONNECT tunnel to mapped IP"
            );
            format!("{}:{}", ip, port)
        }
        ResolveResult::Dns { hostname, port } => {
            debug!(
                client = %client_addr,
                host = %hostname,
                port = port,
                "CONNECT tunnel via DNS"
            );
            format!("{}:{}", hostname, port)
        }
        ResolveResult::Proxy { proxy_url, original_host, original_port, .. } => {
            // For upstream proxy, we connect to the proxy and send CONNECT
            info!(
                client = %client_addr,
                host = %original_host,
                port = original_port,
                proxy = %proxy_url,
                "CONNECT tunnel via upstream proxy"
            );
            
            return handle_connect_via_proxy(
                req,
                client_addr,
                proxy_url.clone(),
                original_host.clone(),
                *original_port,
            ).await;
        }
    };

    // Spawn the tunnel task after returning 200 Connection Established
    tokio::task::spawn(async move {
        // This is handled by hyper's upgrade mechanism
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let upgraded = TokioIo::new(upgraded);
                
                // Connect to target
                match TcpStream::connect(&target_addr).await {
                    Ok(target_stream) => {
                        if let Err(e) = tunnel(upgraded, target_stream).await {
                            debug!(
                                client = %client_addr,
                                target = %target_addr,
                                error = %e,
                                "Tunnel error"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            client = %client_addr,
                            target = %target_addr,
                            error = %e,
                            "Failed to connect to target"
                        );
                    }
                }
            }
            Err(e) => {
                error!(client = %client_addr, error = %e, "Upgrade failed");
            }
        }
    });

    // Return 200 Connection Established
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Proxy-Agent", "host-proxy")
        .body(empty_body())
        .unwrap())
}

/// Handle CONNECT via upstream proxy.
async fn handle_connect_via_proxy(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    proxy_url: String,
    target_host: String,
    target_port: u16,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Parse proxy URL
    let proxy_uri: Uri = match proxy_url.parse() {
        Ok(u) => u,
        Err(e) => {
            error!(error = %e, "Invalid proxy URL");
            return Ok(error_response(StatusCode::BAD_GATEWAY, "Invalid proxy configuration"));
        }
    };

    let proxy_host = proxy_uri.host().unwrap_or("localhost");
    let proxy_port = proxy_uri.port_u16().unwrap_or(3128);
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let client_stream = TokioIo::new(upgraded);
                
                // Connect to proxy
                match TcpStream::connect(&proxy_addr).await {
                    Ok(mut proxy_stream) => {
                        // Send CONNECT to upstream proxy
                        let connect_req = format!(
                            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                            target_host, target_port, target_host, target_port
                        );
                        
                        if let Err(e) = proxy_stream.write_all(connect_req.as_bytes()).await {
                            error!(error = %e, "Failed to send CONNECT to upstream proxy");
                            return;
                        }

                        // Read proxy response (we expect 200)
                        let mut buf = [0u8; 1024];
                        match tokio::io::AsyncReadExt::read(&mut proxy_stream, &mut buf).await {
                            Ok(n) if n > 0 => {
                                let response = String::from_utf8_lossy(&buf[..n]);
                                if !response.contains("200") {
                                    error!(response = %response, "Upstream proxy rejected CONNECT");
                                    return;
                                }
                            }
                            Ok(_) => {
                                error!("Upstream proxy closed connection");
                                return;
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to read from upstream proxy");
                                return;
                            }
                        }

                        // Now tunnel between client and proxy
                        if let Err(e) = tunnel(client_stream, proxy_stream).await {
                            debug!(error = %e, "Proxy tunnel error");
                        }
                    }
                    Err(e) => {
                        error!(
                            proxy = %proxy_addr,
                            error = %e,
                            "Failed to connect to upstream proxy"
                        );
                    }
                }
            }
            Err(e) => {
                error!(client = %client_addr, error = %e, "Upgrade failed");
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Proxy-Agent", "host-proxy")
        .body(empty_body())
        .unwrap())
}

/// Handle regular HTTP requests.
async fn handle_http(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    config: Arc<RwLock<AppConfig>>,
    resolver: HostResolver,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Extract host from request
    let host = req.uri().host()
        .or_else(|| req.headers().get("host").and_then(|h| h.to_str().ok()).map(|h| {
            // Remove port from host header if present
            h.split(':').next().unwrap_or(h)
        }))
        .unwrap_or("")
        .to_string();

    let port = req.uri().port_u16().unwrap_or(80);
    let is_https = req.uri().scheme_str() == Some("https");

    if host.is_empty() {
        return Ok(error_response(StatusCode::BAD_REQUEST, "Missing host"));
    }

    // Resolve the destination
    let resolve_result = resolver.resolve(&host, port, false);

    match resolve_result {
        ResolveResult::Direct { ip, port, original_host } => {
            debug!(
                client = %client_addr,
                host = %original_host,
                ip = %ip,
                port = port,
                "HTTP request to mapped IP"
            );
            forward_http_request(req, format!("{}:{}", ip, port), is_https, &config).await
        }
        ResolveResult::Dns { hostname, port } => {
            debug!(
                client = %client_addr,
                host = %hostname,
                port = port,
                "HTTP request via DNS"
            );
            forward_http_request(req, format!("{}:{}", hostname, port), is_https, &config).await
        }
        ResolveResult::Proxy { proxy_url, original_host, original_port, .. } => {
            debug!(
                client = %client_addr,
                host = %original_host,
                port = original_port,
                proxy = %proxy_url,
                "HTTP request via upstream proxy"
            );
            forward_http_via_proxy(req, proxy_url).await
        }
    }
}

/// Forward an HTTP request directly to the target.
async fn forward_http_request(
    req: Request<Incoming>,
    target_addr: String,
    _is_https: bool,
    _config: &Arc<RwLock<AppConfig>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Connect to target
    let stream = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(target = %target_addr, error = %e, "Failed to connect");
            return Ok(error_response(StatusCode::BAD_GATEWAY, "Failed to connect to target"));
        }
    };

    let io = TokioIo::new(stream);

    // Create HTTP connection
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(c) => c,
        Err(e) => {
            error!(target = %target_addr, error = %e, "HTTP handshake failed");
            return Ok(error_response(StatusCode::BAD_GATEWAY, "HTTP handshake failed"));
        }
    };

    // Spawn connection handler
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(error = %e, "Connection error");
        }
    });

    // Build the request for the target
    let (parts, body) = req.into_parts();
    
    // Create path with query
    let path_and_query = parts.uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(path_and_query);
    
    // Copy headers
    for (name, value) in parts.headers.iter() {
        if name != "proxy-connection" {
            builder = builder.header(name, value);
        }
    }

    let req = builder.body(body).unwrap();

    // Send request
    match sender.send_request(req).await {
        Ok(res) => {
            let (parts, body) = res.into_parts();
            let body = body.map_err(|e| e).boxed();
            Ok(Response::from_parts(parts, body))
        }
        Err(e) => {
            error!(error = %e, "Failed to send request");
            Ok(error_response(StatusCode::BAD_GATEWAY, "Failed to send request"))
        }
    }
}

/// Forward an HTTP request via upstream proxy.
async fn forward_http_via_proxy(
    req: Request<Incoming>,
    proxy_url: String,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Parse proxy URL
    let proxy_uri: Uri = match proxy_url.parse() {
        Ok(u) => u,
        Err(_) => {
            return Ok(error_response(StatusCode::BAD_GATEWAY, "Invalid proxy URL"));
        }
    };

    let proxy_host = proxy_uri.host().unwrap_or("localhost");
    let proxy_port = proxy_uri.port_u16().unwrap_or(3128);
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

    // Connect to proxy
    let stream = match TcpStream::connect(&proxy_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(proxy = %proxy_addr, error = %e, "Failed to connect to proxy");
            return Ok(error_response(StatusCode::BAD_GATEWAY, "Failed to connect to proxy"));
        }
    };

    let io = TokioIo::new(stream);

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Proxy handshake failed");
            return Ok(error_response(StatusCode::BAD_GATEWAY, "Proxy handshake failed"));
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(error = %e, "Proxy connection error");
        }
    });

    // For HTTP proxy, we send the full URL
    let (parts, body) = req.into_parts();
    
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(parts.uri.to_string());  // Full URL for proxy
    
    for (name, value) in parts.headers.iter() {
        if name != "proxy-connection" {
            builder = builder.header(name, value);
        }
    }

    let req = builder.body(body).unwrap();

    match sender.send_request(req).await {
        Ok(res) => {
            let (parts, body) = res.into_parts();
            let body = body.map_err(|e| e).boxed();
            Ok(Response::from_parts(parts, body))
        }
        Err(e) => {
            error!(error = %e, "Failed to send request to proxy");
            Ok(error_response(StatusCode::BAD_GATEWAY, "Proxy request failed"))
        }
    }
}

/// Bidirectional tunnel between two streams.
async fn tunnel<A, B>(mut a: A, mut b: B) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (bytes_a_to_b, bytes_b_to_a) = tokio::io::copy_bidirectional(&mut a, &mut b).await?;
    debug!(
        client_to_server = bytes_a_to_b,
        server_to_client = bytes_b_to_a,
        "Tunnel closed"
    );
    Ok(())
}

/// Parse CONNECT target (host:port).
fn parse_connect_target(uri: &Uri) -> Option<(String, u16)> {
    // CONNECT requests have authority in URI
    if let Some(authority) = uri.authority() {
        let host = authority.host().to_string();
        let port = authority.port_u16().unwrap_or(443);
        return Some((host, port));
    }
    
    // Fallback: try parsing path as host:port
    let path = uri.path();
    if !path.is_empty() && path != "/" {
        let parts: Vec<&str> = path.split(':').collect();
        if parts.len() == 2 {
            if let Ok(port) = parts[1].parse::<u16>() {
                return Some((parts[0].to_string(), port));
            }
        }
        // Default to port 443
        return Some((path.to_string(), 443));
    }
    
    None
}

/// Create an empty body.
fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Create an error response.
fn error_response(status: StatusCode, message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .header("Proxy-Agent", "host-proxy")
        .body(Full::new(Bytes::from(message.to_string())).map_err(|never| match never {}).boxed())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_target() {
        // CONNECT requests use the authority format (host:port)
        // hyper parses "host:port" as authority
        let uri: Uri = "example.com:443".parse().unwrap();
        let result = parse_connect_target(&uri);
        assert_eq!(result, Some(("example.com".to_string(), 443)));
    }

    #[test]
    fn test_parse_connect_custom_port() {
        let uri: Uri = "example.com:8443".parse().unwrap();
        let result = parse_connect_target(&uri);
        assert_eq!(result, Some(("example.com".to_string(), 8443)));
    }

    #[test]
    fn test_parse_connect_default_port() {
        // When no port is provided, default to 443
        let uri: Uri = "example.com".parse().unwrap();
        let result = parse_connect_target(&uri);
        assert_eq!(result, Some(("example.com".to_string(), 443)));
    }
}
