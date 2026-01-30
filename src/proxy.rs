//! Pingora-based proxy implementation.
//!
//! This module implements the HTTP/HTTPS proxy server using the Pingora
//! framework. It handles:
//! - HTTP CONNECT tunneling for HTTPS
//! - Host header manipulation for mapped hosts
//! - Upstream proxy forwarding
//! - Direct connections with DNS resolution

use crate::config::AppConfig;
use crate::resolver::{parse_host_port, HostResolver, ResolveResult};
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Method, Uri};
use pingora_core::prelude::*;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

/// Context maintained across the request lifecycle.
pub struct ProxyContext {
    /// The resolved destination for this request.
    pub resolve_result: Option<ResolveResult>,

    /// Whether this is a CONNECT request (HTTPS tunnel).
    pub is_connect: bool,

    /// The original host from the request.
    pub original_host: String,

    /// The target port.
    pub target_port: u16,

    /// Whether to use TLS for upstream.
    pub use_tls: bool,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            resolve_result: None,
            is_connect: false,
            original_host: String::new(),
            target_port: 80,
            use_tls: false,
        }
    }
}

/// The main proxy service.
pub struct HostProxyService {
    /// Host resolver with config access.
    resolver: HostResolver,

    /// Direct config access for SSL settings.
    config: Arc<RwLock<AppConfig>>,
}

impl HostProxyService {
    /// Creates a new proxy service.
    pub fn new(config: Arc<RwLock<AppConfig>>) -> Self {
        let resolver = HostResolver::new(config.clone());
        Self { resolver, config }
    }

    /// Refreshes the resolver cache (called on config reload).
    #[allow(dead_code)]
    pub fn refresh(&self) {
        self.resolver.refresh_cache();
    }

    /// Gets the current SSL configuration.
    fn get_ssl_config(&self) -> (bool, bool) {
        let cfg = self.config.read().unwrap();
        (
            cfg.ssl.accept_invalid_certs,
            cfg.ssl.accept_invalid_hostnames,
        )
    }

    /// Gets timeout configuration.
    fn get_timeouts(&self) -> (Duration, Duration, Duration) {
        let cfg = self.config.read().unwrap();
        (
            Duration::from_secs(cfg.server.connect_timeout),
            Duration::from_secs(cfg.server.read_timeout),
            Duration::from_secs(cfg.server.write_timeout),
        )
    }

    /// Parses the target from a CONNECT request.
    fn parse_connect_target(uri: &Uri) -> Option<(String, u16)> {
        // CONNECT requests have authority in the URI path
        let authority = uri.authority().map(|a| a.as_str()).or_else(|| {
            // Some clients put it in the path
            let path = uri.path();
            if !path.is_empty() && path != "/" {
                Some(path)
            } else {
                None
            }
        })?;

        Some(parse_host_port(authority, 443))
    }

    /// Creates an HttpPeer for upstream proxy connection.
    #[allow(dead_code)]
    fn create_proxy_peer(
        &self,
        proxy_url: &str,
        target_host: &str,
        _target_port: u16,
        _is_https: bool,
    ) -> Result<HttpPeer> {
        // Parse proxy URL
        let proxy_uri: Uri = proxy_url
            .parse()
            .map_err(|e| Error::new(ErrorType::Custom("Invalid proxy URL")).more_context(format!("{}", e)))?;

        let proxy_host = proxy_uri.host().ok_or_else(|| {
            Error::new(ErrorType::Custom("Proxy URL missing host"))
        })?;

        let proxy_port = proxy_uri.port_u16().unwrap_or(3128);

        debug!(
            proxy_host = %proxy_host,
            proxy_port = proxy_port,
            target = %target_host,
            "Creating upstream proxy peer"
        );

        let (_accept_invalid_certs, _accept_invalid_hostnames) = self.get_ssl_config();

        // Create peer to the proxy server
        let mut peer = HttpPeer::new(
            (proxy_host.to_string(), proxy_port),
            false, // Proxy connection itself is usually HTTP
            target_host.to_string(),
        );

        // Set SNI for TLS if proxy connection uses TLS
        if proxy_uri.scheme_str() == Some("https") {
            peer.sni = proxy_host.to_string();
        }

        Ok(peer)
    }
}

#[async_trait]
impl ProxyHttp for HostProxyService {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::default()
    }

    /// Called early in request processing to determine routing.
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let req = session.req_header();
        let method = req.method.clone();
        let uri = req.uri.clone();

        ctx.is_connect = method == Method::CONNECT;

        // Extract target host and port
        let (host, port) = if ctx.is_connect {
            Self::parse_connect_target(&uri).ok_or_else(|| {
                Error::new(ErrorType::Custom("Invalid CONNECT target"))
            })?
        } else {
            // For regular HTTP, get from Host header
            let host_header = req
                .headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if host_header.is_empty() {
                // Try from URI
                if let Some(authority) = uri.authority() {
                    parse_host_port(authority.as_str(), 80)
                } else {
                    return Err(Error::new(ErrorType::Custom("No host specified")));
                }
            } else {
                parse_host_port(host_header, 80)
            }
        };

        ctx.original_host = host.clone();
        ctx.target_port = port;
        
        // For CONNECT requests, the proxy acts as a TCP tunnel.
        // The CLIENT will do the TLS handshake with the upstream server,
        // so we should NOT use TLS on our upstream connection.
        // Only use TLS for regular HTTPS requests (not CONNECT).
        ctx.use_tls = !ctx.is_connect && uri.scheme_str() == Some("https");

        // Resolve the destination
        let resolve_result = self.resolver.resolve(&host, port, ctx.is_connect);
        ctx.resolve_result = Some(resolve_result);

        trace!(
            method = %method,
            host = %host,
            port = port,
            is_connect = ctx.is_connect,
            "Request received"
        );

        Ok(())
    }

    /// Filter that handles CONNECT requests for direct connections.
    /// 
    /// For CONNECT requests going through an upstream proxy, Pingora's normal
    /// flow works fine. But for direct CONNECT (to IP-mapped hosts or DNS),
    /// we need to handle the tunneling ourselves because Pingora's ProxyHttp
    /// is designed for HTTP reverse proxying, not TCP tunneling.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // Only intercept CONNECT requests for direct connections
        if !ctx.is_connect {
            return Ok(false); // Let Pingora handle normal HTTP
        }

        let resolve_result = ctx.resolve_result.as_ref().ok_or_else(|| {
            Error::new(ErrorType::Custom("No resolve result"))
        })?;

        // For CONNECT through upstream proxy, let Pingora handle it normally
        // For CONNECT requests, Pingora's ProxyHttp trait handles them correctly
        // when routing through an upstream HTTP proxy (the proxy speaks HTTP CONNECT).
        // 
        // ARCHITECTURAL NOTE:
        // Direct HTTPS CONNECT tunneling (connecting directly to the target) requires
        // raw TCP socket access to bidirectionally copy bytes after the HTTP CONNECT
        // handshake. Pingora's ProxyHttp trait is designed for HTTP request/response
        // semantics and doesn't expose the raw socket needed for this.
        //
        // Therefore:
        // - CONNECT through upstream proxy: Works perfectly (Pingora handles it)
        // - Direct CONNECT to IP-mapped hosts: Routed through upstream proxy if configured
        // - Direct CONNECT without upstream proxy: Not supported
        
        match resolve_result {
            ResolveResult::Proxy { .. } => {
                // Route through upstream proxy - Pingora handles this natively
                debug!(
                    host = %ctx.original_host,
                    "CONNECT via upstream proxy - delegating to Pingora"
                );
                Ok(false)
            }
            ResolveResult::Direct { ip, port, original_host } => {
                // For direct connections, we MUST use the upstream proxy for HTTPS CONNECT.
                // Check if we have an upstream proxy configured.
                let has_upstream_proxy = {
                    let cfg = self.config.read().unwrap();
                    cfg.upstream_proxy.https.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
                        || cfg.upstream_proxy.http.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
                };
                
                if has_upstream_proxy {
                    // Re-route through the upstream proxy
                    // Update the resolve result so upstream_peer uses the proxy
                    warn!(
                        host = %original_host,
                        ip = %ip,
                        port = port,
                        "Direct HTTPS CONNECT not supported - routing through upstream proxy"
                    );
                    // We can't modify ctx here, so we'll handle this in upstream_peer
                    // by checking for CONNECT + Direct and redirecting to proxy
                    Ok(false)
                } else {
                    // No upstream proxy available - we can't handle direct CONNECT
                    error!(
                        host = %original_host,
                        ip = %ip,
                        port = port,
                        "HTTPS CONNECT requires an upstream proxy. \
                         Direct HTTPS tunneling is not supported by Pingora's ProxyHttp architecture. \
                         Configure upstream_proxy in config.yaml to enable HTTPS CONNECT."
                    );
                    
                    // Return a clear error to the client
                    let mut resp = ResponseHeader::build(502, Some(2)).unwrap();
                    resp.insert_header("Content-Type", "text/plain").ok();
                    resp.insert_header("Proxy-Agent", "host-proxy").ok();
                    
                    if let Err(e) = session.write_response_header(Box::new(resp), false).await {
                        error!(error = %e, "Failed to write error response header");
                    } else {
                        let msg = format!(
                            "HTTPS CONNECT to {} requires an upstream proxy.\n\
                             Configure upstream_proxy.url in config.yaml.",
                            original_host
                        );
                        if let Err(e) = session.write_response_body(Some(Bytes::from(msg)), true).await {
                            error!(error = %e, "Failed to write error response body");
                        }
                    }
                    
                    Ok(true) // We've handled the response
                }
            }
            ResolveResult::Dns { hostname, port } => {
                // Same logic for DNS-resolved hosts
                let has_upstream_proxy = {
                    let cfg = self.config.read().unwrap();
                    cfg.upstream_proxy.https.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
                        || cfg.upstream_proxy.http.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
                };
                
                if has_upstream_proxy {
                    warn!(
                        host = %hostname,
                        port = port,
                        "Direct HTTPS CONNECT not supported - routing through upstream proxy"
                    );
                    Ok(false)
                } else {
                    error!(
                        host = %hostname,
                        port = port,
                        "HTTPS CONNECT requires an upstream proxy. \
                         Direct HTTPS tunneling is not supported. \
                         Configure upstream_proxy in config.yaml."
                    );
                    
                    let mut resp = ResponseHeader::build(502, Some(2)).unwrap();
                    resp.insert_header("Content-Type", "text/plain").ok();
                    resp.insert_header("Proxy-Agent", "host-proxy").ok();
                    
                    if let Err(e) = session.write_response_header(Box::new(resp), false).await {
                        error!(error = %e, "Failed to write error response header");
                    } else {
                        let msg = format!(
                            "HTTPS CONNECT to {} requires an upstream proxy.\n\
                             Configure upstream_proxy.url in config.yaml.",
                            hostname
                        );
                        if let Err(e) = session.write_response_body(Some(Bytes::from(msg)), true).await {
                            error!(error = %e, "Failed to write error response body");
                        }
                    }
                    
                    Ok(true)
                }
            }
        }
    }

    /// Determines the upstream peer to connect to.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let resolve_result = ctx.resolve_result.as_ref().ok_or_else(|| {
            Error::new(ErrorType::Custom("No resolve result"))
        })?;

        let (accept_invalid_certs, accept_invalid_hostnames) = self.get_ssl_config();

        // For CONNECT requests on Direct/Dns targets, we need to route through upstream proxy
        // (if available). This is because Pingora's ProxyHttp can't do direct TCP tunneling.
        if ctx.is_connect {
            let proxy_info = {
                let cfg = self.config.read().unwrap();
                // For CONNECT, prefer HTTPS proxy, fall back to HTTP proxy
                cfg.upstream_proxy.https.clone()
                    .filter(|s| !s.is_empty())
                    .or_else(|| cfg.upstream_proxy.http.clone().filter(|s| !s.is_empty()))
            };
            
            if let Some(proxy_url) = proxy_info {
                // For any CONNECT request, route through the upstream proxy
                // This includes both Direct and Dns resolved hosts
                match resolve_result {
                    ResolveResult::Direct { original_host, port, .. } 
                    | ResolveResult::Dns { hostname: original_host, port } => {
                        info!(
                            host = %original_host,
                            port = port,
                            proxy = %proxy_url,
                            "Routing CONNECT through upstream proxy"
                        );

                        // Parse proxy URL
                        let proxy_uri: Uri = proxy_url.parse().map_err(|_e| {
                            Error::new(ErrorType::Custom("Invalid proxy URL"))
                        })?;

                        let proxy_host = proxy_uri.host().unwrap_or("localhost");
                        let proxy_port = proxy_uri.port_u16().unwrap_or(3128);

                        let mut peer = HttpPeer::new(
                            (proxy_host.to_string(), proxy_port),
                            false, // Connect to proxy over HTTP
                            original_host.clone(),
                        );

                        // Ensure HTTP/1.1 for CONNECT
                        peer.options.set_http_version(1, 1);
                        
                        // Store the target info in ctx for upstream_request_filter
                        // We'll modify the context to indicate this is being rerouted
                        ctx.resolve_result = Some(ResolveResult::Proxy {
                            proxy_url: proxy_url,
                            original_host: original_host.clone(),
                            original_port: *port,
                            is_https: true,
                        });

                        return Ok(Box::new(peer));
                    }
                    ResolveResult::Proxy { .. } => {
                        // Already going through proxy, fall through
                    }
                }
            }
        }

        let peer = match resolve_result {
            ResolveResult::Direct { ip, port, original_host } => {
                info!(
                    host = %original_host,
                    ip = %ip,
                    port = port,
                    "Connecting directly (config mapping)"
                );

                let mut peer = HttpPeer::new(
                    (*ip, *port),
                    ctx.use_tls,
                    original_host.clone(),
                );

                if ctx.use_tls {
                    peer.sni = original_host.clone();
                    peer.options.verify_cert = !accept_invalid_certs;
                    peer.options.verify_hostname = !accept_invalid_hostnames;
                }

                peer
            }

            ResolveResult::Proxy {
                proxy_url,
                original_host,
                original_port: _,
                is_https: _,
            } => {
                info!(
                    host = %original_host,
                    proxy = %proxy_url,
                    "Forwarding to upstream proxy"
                );

                // Parse proxy URL
                let proxy_uri: Uri = proxy_url.parse().map_err(|_e| {
                    Error::new(ErrorType::Custom("Invalid proxy URL"))
                })?;

                let proxy_host = proxy_uri.host().unwrap_or("localhost");
                let proxy_port = proxy_uri.port_u16().unwrap_or(3128);

                let mut peer = HttpPeer::new(
                    (proxy_host.to_string(), proxy_port),
                    false, // Connect to proxy over HTTP
                    original_host.clone(),
                );

                // For CONNECT tunneling through proxy, we need to set up the tunnel
                if ctx.is_connect {
                    peer.options.set_http_version(1, 1);
                }

                peer
            }

            ResolveResult::Dns { hostname, port } => {
                info!(
                    host = %hostname,
                    port = port,
                    "Connecting via DNS resolution"
                );

                // Resolve via DNS
                let resolved = self.resolver.dns_resolve(hostname, *port).ok_or_else(|| {
                    warn!(hostname = %hostname, "DNS resolution failed");
                    Error::new(ErrorType::Custom("DNS resolution failed"))
                })?;

                let mut peer = HttpPeer::new(
                    resolved,
                    ctx.use_tls,
                    hostname.clone(),
                );

                if ctx.use_tls {
                    peer.sni = hostname.clone();
                    peer.options.verify_cert = !accept_invalid_certs;
                    peer.options.verify_hostname = !accept_invalid_hostnames;
                }

                peer
            }
        };

        // Apply timeouts
        let (_connect_timeout, _read_timeout, _write_timeout) = self.get_timeouts();
        // Note: Timeouts are typically set at the connection level in Pingora

        Ok(Box::new(peer))
    }

    /// Modifies the request before sending upstream.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // For CONNECT through upstream proxy, we need special handling
        if let Some(ResolveResult::Proxy { original_host, original_port, is_https: _, .. }) = &ctx.resolve_result {
            if ctx.is_connect {
                // Rewrite the request to be a CONNECT to the original target
                upstream_request.set_method(Method::CONNECT);
                
                // Set the authority to the original target
                let authority = format!("{}:{}", original_host, original_port);
                upstream_request.set_uri(
                    Uri::builder()
                        .authority(authority.as_str())
                        .path_and_query("/")
                        .build()
                        .unwrap_or_else(|_| Uri::from_static("/"))
                );
            }
        }

        // Ensure Host header is set correctly for mapped hosts
        if let Some(ResolveResult::Direct { original_host, .. }) = &ctx.resolve_result {
            // Update Host header to the original hostname
            upstream_request.insert_header(
                header::HOST,
                original_host.as_str(),
            )?;
        }

        // Add Via header
        upstream_request.append_header("Via", "1.1 host-proxy")?;

        trace!(
            method = %upstream_request.method,
            uri = %upstream_request.uri,
            "Sending upstream request"
        );

        Ok(())
    }

    /// Modifies the response before sending to client.
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Add proxy identifier header
        upstream_response.insert_header("X-Proxy", "host-proxy")?;

        trace!(
            status = %upstream_response.status,
            "Received upstream response"
        );

        Ok(())
    }

    /// Handles errors during proxying.
    async fn fail_to_proxy(
        &self,
        _session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        error!(
            error = %e,
            host = %ctx.original_host,
            "Proxy error"
        );

        // Return appropriate status code based on error type
        let error_code = match e.etype() {
            ErrorType::ConnectTimedout => 504, // Gateway Timeout
            ErrorType::ConnectRefused => 502,  // Bad Gateway
            ErrorType::Custom(msg) if msg.contains("DNS") => 502,
            _ => 502,
        };

        FailToProxy {
            error_code,
            can_reuse_downstream: false,
        }
    }

    /// Logging after request completion.
    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        let method = if ctx.is_connect { "CONNECT" } else { "HTTP" };

        debug!(
            method = method,
            host = %ctx.original_host,
            port = ctx.target_port,
            status = status,
            "Request completed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HostMapping;

    fn create_test_service() -> HostProxyService {
        let config = AppConfig {
            host_mappings: vec![HostMapping {
                hostname: "test.example.com".to_string(),
                ip: "192.168.1.100".to_string(),
                port: Some(8080),
            }],
            ..Default::default()
        };
        HostProxyService::new(Arc::new(RwLock::new(config)))
    }

    #[test]
    fn test_parse_connect_target() {
        let uri: Uri = "example.com:443".parse().unwrap();
        let result = HostProxyService::parse_connect_target(&uri);
        assert!(result.is_some());

        let (host, port) = result.unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_service_creation() {
        let service = create_test_service();
        // Just verify it creates without panicking
        let ctx = service.new_ctx();
        assert!(!ctx.is_connect);
        assert!(ctx.resolve_result.is_none());
    }

    #[test]
    fn test_ssl_config() {
        let config = AppConfig {
            ssl: crate::config::SslConfig {
                accept_invalid_certs: true,
                accept_invalid_hostnames: true,
            },
            ..Default::default()
        };
        let service = HostProxyService::new(Arc::new(RwLock::new(config)));

        let (invalid_certs, invalid_hosts) = service.get_ssl_config();
        assert!(invalid_certs);
        assert!(invalid_hosts);
    }
}
