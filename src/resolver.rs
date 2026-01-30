//! Host resolution logic for the proxy.
//!
//! This module implements the resolution priority:
//! 1. Config mappings (exact match)
//! 2. Upstream proxy (if configured and host not in no_proxy)
//! 3. DNS resolution

use crate::config::{AppConfig, HostMapping};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tracing::{debug, trace};

/// Result of host resolution.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolveResult {
    /// Use a direct IP address from config mapping.
    Direct {
        /// The resolved IP address.
        ip: IpAddr,
        /// The port to use (from mapping or original).
        port: u16,
        /// The original hostname for the Host header.
        original_host: String,
    },

    /// Forward to an upstream proxy.
    Proxy {
        /// The proxy URL.
        proxy_url: String,
        /// The original destination.
        original_host: String,
        /// The original port.
        original_port: u16,
        /// Whether this is HTTPS traffic.
        is_https: bool,
    },

    /// Use DNS resolution.
    Dns {
        /// The hostname to resolve.
        hostname: String,
        /// The port to use.
        port: u16,
    },
}

/// Host resolver with cached config lookups.
#[derive(Clone)]
pub struct HostResolver {
    /// Thread-safe reference to the configuration.
    config: Arc<RwLock<AppConfig>>,

    /// Cached hostname lookup map.
    host_map: Arc<RwLock<HashMap<String, HostMapping>>>,
}

impl HostResolver {
    /// Creates a new HostResolver.
    pub fn new(config: Arc<RwLock<AppConfig>>) -> Self {
        let host_map = {
            let cfg = config.read().unwrap();
            cfg.build_host_map()
        };

        Self {
            config,
            host_map: Arc::new(RwLock::new(host_map)),
        }
    }

    /// Refreshes the host map cache from config.
    #[allow(dead_code)]
    pub fn refresh_cache(&self) {
        let new_map = {
            let cfg = self.config.read().unwrap();
            cfg.build_host_map()
        };

        let mut map = self.host_map.write().unwrap();
        *map = new_map;
        debug!("Host resolver cache refreshed");
    }

    /// Resolves a hostname according to the priority order:
    /// 1. Config mappings
    /// 2. Upstream proxy (if configured)
    /// 3. DNS
    pub fn resolve(&self, hostname: &str, port: u16, is_https: bool) -> ResolveResult {
        let hostname_lower = hostname.to_lowercase();

        // 1. Check config mappings first
        {
            let host_map = self.host_map.read().unwrap();
            if let Some(mapping) = host_map.get(&hostname_lower) {
                if let Some(ip) = mapping.ip_addr() {
                    let resolved_port = mapping.port.unwrap_or(port);
                    debug!(
                        hostname = %hostname,
                        ip = %ip,
                        port = resolved_port,
                        "Resolved via config mapping"
                    );
                    return ResolveResult::Direct {
                        ip,
                        port: resolved_port,
                        original_host: hostname.to_string(),
                    };
                }
            }
        }

        // 2. Check upstream proxy
        let config = self.config.read().unwrap();
        let upstream = &config.upstream_proxy;
        let listen_addr = config.server.listen.as_str();

        // Get the appropriate proxy URL (with self-reference filtering)
        let proxy_url = if is_https {
            upstream.effective_https_proxy(Some(listen_addr))
        } else {
            upstream.effective_http_proxy(Some(listen_addr))
        };

        if let Some(ref proxy) = proxy_url {
            // Check if we should bypass the proxy
            if !upstream.should_bypass(hostname) {
                debug!(
                    hostname = %hostname,
                    proxy = %proxy,
                    is_https = is_https,
                    "Forwarding to upstream proxy"
                );
                return ResolveResult::Proxy {
                    proxy_url: proxy.clone(),
                    original_host: hostname.to_string(),
                    original_port: port,
                    is_https,
                };
            } else {
                trace!(hostname = %hostname, "Bypassing proxy (in no_proxy list)");
            }
        }

        // 3. Fall back to DNS
        debug!(hostname = %hostname, port = port, "Using DNS resolution");
        ResolveResult::Dns {
            hostname: hostname.to_string(),
            port,
        }
    }
}



/// Parses a host:port string, using default port if not specified.
#[cfg(test)]
fn parse_host_port(host_header: &str, default_port: u16) -> (String, u16) {
    if let Some(colon_pos) = host_header.rfind(':') {
        // Check if this is an IPv6 address
        if host_header.starts_with('[') {
            // IPv6 with port: [::1]:8080
            if let Some(bracket_pos) = host_header.find(']') {
                if colon_pos > bracket_pos {
                    let host = host_header[..colon_pos].to_string();
                    let port = host_header[colon_pos + 1..]
                        .parse()
                        .unwrap_or(default_port);
                    return (host, port);
                }
            }
            // IPv6 without port
            (host_header.to_string(), default_port)
        } else {
            // IPv4 or hostname with port
            let host = host_header[..colon_pos].to_string();
            let port = host_header[colon_pos + 1..]
                .parse()
                .unwrap_or(default_port);
            (host, port)
        }
    } else {
        (host_header.to_string(), default_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostMapping, UpstreamProxyConfig};

    fn create_test_config() -> Arc<RwLock<AppConfig>> {
        let config = AppConfig {
            host_mappings: vec![
                HostMapping {
                    hostname: "api.example.com".to_string(),
                    ip: "192.168.1.100".to_string(),
                    port: Some(8080),
                },
                HostMapping {
                    hostname: "web.example.com".to_string(),
                    ip: "192.168.1.101".to_string(),
                    port: None,
                },
            ],
            upstream_proxy: UpstreamProxyConfig {
                http: Some("http://proxy.corp:3128".to_string()),
                https: Some("http://proxy.corp:3128".to_string()),
                no_proxy: vec!["localhost".to_string(), ".local".to_string()],
            },
            ..Default::default()
        };
        Arc::new(RwLock::new(config))
    }

    #[test]
    fn test_resolve_config_mapping() {
        let config = create_test_config();
        let resolver = HostResolver::new(config);

        let result = resolver.resolve("api.example.com", 443, true);
        match result {
            ResolveResult::Direct { ip, port, .. } => {
                assert_eq!(ip.to_string(), "192.168.1.100");
                assert_eq!(port, 8080); // Uses mapped port
            }
            _ => panic!("Expected Direct result"),
        }

        let result = resolver.resolve("web.example.com", 80, false);
        match result {
            ResolveResult::Direct { ip, port, .. } => {
                assert_eq!(ip.to_string(), "192.168.1.101");
                assert_eq!(port, 80); // Uses original port
            }
            _ => panic!("Expected Direct result"),
        }
    }

    #[test]
    fn test_resolve_upstream_proxy() {
        let config = create_test_config();
        let resolver = HostResolver::new(config);

        let result = resolver.resolve("external.com", 80, false);
        match result {
            ResolveResult::Proxy {
                proxy_url,
                original_host,
                ..
            } => {
                assert_eq!(proxy_url, "http://proxy.corp:3128");
                assert_eq!(original_host, "external.com");
            }
            _ => panic!("Expected Proxy result"),
        }
    }

    #[test]
    fn test_resolve_bypass_proxy() {
        let config = create_test_config();
        let resolver = HostResolver::new(config);

        // localhost should bypass proxy
        let result = resolver.resolve("localhost", 8080, false);
        match result {
            ResolveResult::Dns { hostname, port } => {
                assert_eq!(hostname, "localhost");
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected Dns result"),
        }

        // .local suffix should bypass proxy
        let result = resolver.resolve("myservice.local", 80, false);
        match result {
            ResolveResult::Dns { hostname, .. } => {
                assert_eq!(hostname, "myservice.local");
            }
            _ => panic!("Expected Dns result"),
        }
    }

    #[test]
    fn test_resolve_no_proxy_configured() {
        let config = Arc::new(RwLock::new(AppConfig::default()));
        let resolver = HostResolver::new(config);

        let result = resolver.resolve("example.com", 80, false);
        match result {
            ResolveResult::Dns { hostname, port } => {
                assert_eq!(hostname, "example.com");
                assert_eq!(port, 80);
            }
            _ => panic!("Expected Dns result"),
        }
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("example.com:8080", 80),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            parse_host_port("example.com", 80),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            parse_host_port("[::1]:8080", 80),
            ("[::1]".to_string(), 8080)
        );
        assert_eq!(parse_host_port("[::1]", 80), ("[::1]".to_string(), 80));
    }

    #[test]
    fn test_case_insensitive_lookup() {
        let config = create_test_config();
        let resolver = HostResolver::new(config);

        let result1 = resolver.resolve("API.EXAMPLE.COM", 443, true);
        let result2 = resolver.resolve("api.example.com", 443, true);

        match (result1, result2) {
            (ResolveResult::Direct { ip: ip1, .. }, ResolveResult::Direct { ip: ip2, .. }) => {
                assert_eq!(ip1, ip2);
            }
            _ => panic!("Expected both to be Direct results"),
        }
    }
}
