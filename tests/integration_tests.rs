//! Integration tests for host-proxy.
//!
//! These tests verify the complete behavior of the proxy components
//! working together.

use host_proxy::config::{AppConfig, ConfigManager, HostMapping, UpstreamProxyConfig};
use host_proxy::resolver::{HostResolver, ResolveResult};
use std::sync::{Arc, RwLock};
use tempfile::NamedTempFile;
use std::io::{Seek, Write};

/// Helper to create a temporary config file.
fn create_temp_config(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}

mod config_tests {
    use super::*;

    #[test]
    fn test_full_config_load() {
        let yaml = r#"
server:
  listen: "127.0.0.1:8080"
  workers: 4
  connect_timeout: 15
  read_timeout: 60
  write_timeout: 60

ssl:
  accept_invalid_certs: true
  accept_invalid_hostnames: true

logging:
  level: "debug"
  output: "stderr"
  format: "json"
  timestamps: true
  include_target: false

host_mappings:
  - hostname: "api.example.com"
    ip: "192.168.1.100"
    port: 8080
  - hostname: "web.example.com"
    ip: "192.168.1.101"

upstream_proxy:
  http: "http://proxy:3128"
  https: "https://proxy:3129"
  no_proxy:
    - "localhost"
    - ".internal"
"#;
        let file = create_temp_config(yaml);
        let config = AppConfig::load(file.path()).unwrap();

        // Server settings
        assert_eq!(config.server.listen, "127.0.0.1:8080");
        assert_eq!(config.server.workers, 4);
        assert_eq!(config.server.connect_timeout, 15);

        // SSL settings
        assert!(config.ssl.accept_invalid_certs);
        assert!(config.ssl.accept_invalid_hostnames);

        // Logging settings
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.output, "stderr");

        // Host mappings
        assert_eq!(config.host_mappings.len(), 2);
        assert_eq!(config.host_mappings[0].hostname, "api.example.com");
        assert_eq!(config.host_mappings[0].port, Some(8080));
        assert_eq!(config.host_mappings[1].port, None);

        // Upstream proxy
        assert_eq!(config.upstream_proxy.http, Some("http://proxy:3128".to_string()));
        assert_eq!(config.upstream_proxy.no_proxy.len(), 2);
    }

    #[test]
    fn test_minimal_config() {
        let yaml = "# Empty config uses defaults\n{}";
        let file = create_temp_config(yaml);
        let config = AppConfig::load(file.path()).unwrap();

        // Should use all defaults
        assert_eq!(config.server.listen, "0.0.0.0:1984");
        assert_eq!(config.logging.level, "info");
        assert!(!config.ssl.accept_invalid_certs);
        assert!(config.host_mappings.is_empty());
    }

    #[test]
    fn test_config_validation_errors() {
        // Invalid IP address
        let yaml = r#"
host_mappings:
  - hostname: "test.com"
    ip: "invalid-ip"
"#;
        let file = create_temp_config(yaml);
        assert!(AppConfig::load(file.path()).is_err());

        // Invalid log level
        let yaml = r#"
logging:
  level: "super-verbose"
"#;
        let file = create_temp_config(yaml);
        assert!(AppConfig::load(file.path()).is_err());
    }

    #[test]
    fn test_config_manager_reload() {
        let yaml = r#"
server:
  listen: "0.0.0.0:8080"
host_mappings:
  - hostname: "test.com"
    ip: "192.168.1.1"
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();
        file.flush().unwrap();

        let manager = ConfigManager::new(file.path()).unwrap();
        let config = manager.get();
        assert_eq!(config.host_mappings.len(), 1);
        assert_eq!(config.server.listen, "0.0.0.0:8080");

        // Update the file
        let new_yaml = r#"
server:
  listen: "0.0.0.0:9090"
host_mappings:
  - hostname: "test.com"
    ip: "192.168.1.1"
  - hostname: "new.com"
    ip: "192.168.1.2"
"#;
        file.rewind().unwrap();
        file.write_all(new_yaml.as_bytes()).unwrap();
        file.flush().unwrap();

        // Reload
        manager.reload().unwrap();
        let config = manager.get();
        assert_eq!(config.host_mappings.len(), 2);
        assert_eq!(config.server.listen, "0.0.0.0:9090");
    }
}

mod resolver_tests {
    use super::*;

    fn create_resolver_with_config(config: AppConfig) -> HostResolver {
        HostResolver::new(Arc::new(RwLock::new(config)))
    }

    #[test]
    fn test_resolution_priority_config_first() {
        let config = AppConfig {
            host_mappings: vec![HostMapping {
                hostname: "api.example.com".to_string(),
                ip: "192.168.1.100".to_string(),
                port: Some(8080),
            }],
            upstream_proxy: UpstreamProxyConfig {
                http: Some("http://proxy:3128".to_string()),
                https: Some("http://proxy:3128".to_string()),
                no_proxy: vec![],
            },
            ..Default::default()
        };
        let resolver = create_resolver_with_config(config);

        // Should resolve to config IP, not go through proxy
        let result = resolver.resolve("api.example.com", 443, true);
        match result {
            ResolveResult::Direct { ip, port, .. } => {
                assert_eq!(ip.to_string(), "192.168.1.100");
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected Direct result, got {:?}", result),
        }
    }

    #[test]
    fn test_resolution_priority_proxy_second() {
        let config = AppConfig {
            host_mappings: vec![], // No mappings
            upstream_proxy: UpstreamProxyConfig {
                http: Some("http://proxy:3128".to_string()),
                https: Some("https://proxy:3129".to_string()),
                no_proxy: vec!["localhost".to_string()],
            },
            ..Default::default()
        };
        let resolver = create_resolver_with_config(config);

        // Should go through proxy
        let result = resolver.resolve("external.com", 80, false);
        match result {
            ResolveResult::Proxy { proxy_url, .. } => {
                assert_eq!(proxy_url, "http://proxy:3128");
            }
            _ => panic!("Expected Proxy result, got {:?}", result),
        }

        // HTTPS should use https proxy
        let result = resolver.resolve("external.com", 443, true);
        match result {
            ResolveResult::Proxy { proxy_url, .. } => {
                assert_eq!(proxy_url, "https://proxy:3129");
            }
            _ => panic!("Expected Proxy result, got {:?}", result),
        }
    }

    #[test]
    fn test_resolution_priority_dns_fallback() {
        let config = AppConfig {
            host_mappings: vec![],
            upstream_proxy: UpstreamProxyConfig::default(), // No proxy
            ..Default::default()
        };
        let resolver = create_resolver_with_config(config);

        // Should fall back to DNS
        let result = resolver.resolve("example.com", 80, false);
        match result {
            ResolveResult::Dns { hostname, port } => {
                assert_eq!(hostname, "example.com");
                assert_eq!(port, 80);
            }
            _ => panic!("Expected Dns result, got {:?}", result),
        }
    }

    #[test]
    fn test_no_proxy_bypass() {
        let config = AppConfig {
            host_mappings: vec![],
            upstream_proxy: UpstreamProxyConfig {
                http: Some("http://proxy:3128".to_string()),
                https: Some("http://proxy:3128".to_string()),
                no_proxy: vec![
                    "localhost".to_string(),
                    ".internal.corp".to_string(),
                    "specific.host.com".to_string(),
                ],
            },
            ..Default::default()
        };
        let resolver = create_resolver_with_config(config);

        // These should bypass proxy and use DNS
        let bypass_hosts = vec![
            "localhost",
            "service.internal.corp",
            "api.internal.corp",
            "specific.host.com",
        ];

        for host in bypass_hosts {
            let result = resolver.resolve(host, 80, false);
            match result {
                ResolveResult::Dns { .. } => {}
                _ => panic!("Expected {} to bypass proxy, got {:?}", host, result),
            }
        }

        // This should go through proxy
        let result = resolver.resolve("external.com", 80, false);
        match result {
            ResolveResult::Proxy { .. } => {}
            _ => panic!("Expected external.com to use proxy, got {:?}", result),
        }
    }

    #[test]
    fn test_case_insensitive_matching() {
        let config = AppConfig {
            host_mappings: vec![HostMapping {
                hostname: "API.Example.COM".to_string(),
                ip: "192.168.1.100".to_string(),
                port: None,
            }],
            ..Default::default()
        };
        let resolver = create_resolver_with_config(config);

        // All case variations should match
        let variations = vec![
            "api.example.com",
            "API.EXAMPLE.COM",
            "Api.Example.Com",
            "API.example.COM",
        ];

        for host in variations {
            let result = resolver.resolve(host, 80, false);
            match result {
                ResolveResult::Direct { ip, .. } => {
                    assert_eq!(ip.to_string(), "192.168.1.100");
                }
                _ => panic!("Expected {} to match config mapping", host),
            }
        }
    }

    #[test]
    fn test_resolver_cache_refresh() {
        let config = Arc::new(RwLock::new(AppConfig {
            host_mappings: vec![HostMapping {
                hostname: "test.com".to_string(),
                ip: "192.168.1.1".to_string(),
                port: None,
            }],
            ..Default::default()
        }));

        let resolver = HostResolver::new(config.clone());

        // Initial resolution
        let result = resolver.resolve("test.com", 80, false);
        match result {
            ResolveResult::Direct { ip, .. } => {
                assert_eq!(ip.to_string(), "192.168.1.1");
            }
            _ => panic!("Expected Direct result"),
        }

        // Update config
        {
            let mut cfg = config.write().unwrap();
            cfg.host_mappings = vec![HostMapping {
                hostname: "test.com".to_string(),
                ip: "192.168.1.2".to_string(), // New IP
                port: None,
            }];
        }

        // Refresh cache
        resolver.refresh_cache();

        // Should now resolve to new IP
        let result = resolver.resolve("test.com", 80, false);
        match result {
            ResolveResult::Direct { ip, .. } => {
                assert_eq!(ip.to_string(), "192.168.1.2");
            }
            _ => panic!("Expected Direct result"),
        }
    }

    #[test]
    fn test_dns_resolution() {
        let config = AppConfig::default();
        let resolver = create_resolver_with_config(config);

        // Test with a host that should resolve via DNS
        // Using localhost which should always resolve
        let resolved = resolver.dns_resolve("localhost", 80);
        assert!(resolved.is_some(), "localhost should resolve");

        // Test with invalid hostname
        let resolved = resolver.dns_resolve("this.host.definitely.does.not.exist.invalid", 80);
        assert!(resolved.is_none(), "invalid host should not resolve");
    }
}

mod upstream_proxy_tests {
    use super::*;

    #[test]
    fn test_no_proxy_patterns() {
        let config = UpstreamProxyConfig {
            http: Some("http://proxy:3128".to_string()),
            no_proxy: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                ".local".to_string(),
                "internal".to_string(),
            ],
            ..Default::default()
        };

        // Exact matches
        assert!(config.should_bypass("localhost"));
        assert!(config.should_bypass("127.0.0.1"));
        assert!(config.should_bypass("LOCALHOST"));

        // Suffix matches
        assert!(config.should_bypass("myhost.local"));
        assert!(config.should_bypass("app.internal"));

        // Should not bypass
        assert!(!config.should_bypass("example.com"));
        assert!(!config.should_bypass("mylocal.host"));
    }

    #[test]
    fn test_effective_proxy_with_defaults() {
        let config = UpstreamProxyConfig {
            http: Some("http://default-proxy:3128".to_string()),
            https: Some("https://default-proxy:3129".to_string()),
            ..Default::default()
        };

        // Upstream proxy only uses config file values, not environment variables
        let http_proxy = config.effective_http_proxy(None);
        let https_proxy = config.effective_https_proxy(None);

        // Should return the config values
        assert_eq!(http_proxy, Some("http://default-proxy:3128".to_string()));
        assert_eq!(https_proxy, Some("https://default-proxy:3129".to_string()));
    }
}

mod host_mapping_tests {
    use super::*;

    #[test]
    fn test_host_mapping_validation() {
        // Valid mapping
        let mapping = HostMapping {
            hostname: "test.com".to_string(),
            ip: "192.168.1.1".to_string(),
            port: Some(8080),
        };
        assert!(mapping.validate().is_ok());

        // Invalid IP
        let mapping = HostMapping {
            hostname: "test.com".to_string(),
            ip: "not-an-ip".to_string(),
            port: None,
        };
        assert!(mapping.validate().is_err());

        // Empty hostname
        let mapping = HostMapping {
            hostname: "".to_string(),
            ip: "192.168.1.1".to_string(),
            port: None,
        };
        assert!(mapping.validate().is_err());
    }

    #[test]
    fn test_host_mapping_ip_parsing() {
        // IPv4
        let mapping = HostMapping {
            hostname: "test.com".to_string(),
            ip: "192.168.1.1".to_string(),
            port: None,
        };
        let ip = mapping.ip_addr().unwrap();
        assert!(ip.is_ipv4());

        // IPv6
        let mapping = HostMapping {
            hostname: "test.com".to_string(),
            ip: "::1".to_string(),
            port: None,
        };
        let ip = mapping.ip_addr().unwrap();
        assert!(ip.is_ipv6());
    }
}
