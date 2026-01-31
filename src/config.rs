//! Configuration management for the host-proxy application.
//!
//! This module handles loading, parsing, validating, and hot-reloading
//! of the YAML configuration file. It uses `notify` for file system
//! watching and `Arc<RwLock>` for thread-safe config access.

use crate::error::{ProxyError, Result};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Server configuration section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ServerConfig {
    /// Address and port to listen on.
    pub listen: String,

    /// Number of worker threads (0 = CPU cores).
    pub workers: usize,

    /// Connection timeout in seconds.
    pub connect_timeout: u64,

    /// Read timeout in seconds.
    pub read_timeout: u64,

    /// Write timeout in seconds.
    pub write_timeout: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:1984".to_string(),
            workers: 0,
            connect_timeout: 10,
            read_timeout: 30,
            write_timeout: 30,
        }
    }
}

/// SSL/TLS configuration section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SslConfig {
    /// Accept invalid/self-signed certificates.
    pub accept_invalid_certs: bool,

    /// Accept invalid hostnames in certificates.
    pub accept_invalid_hostnames: bool,
}

impl Default for SslConfig {
    fn default() -> Self {
        Self {
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable pretty format.
    #[default]
    Pretty,
    /// Compact single-line format.
    Compact,
    /// JSON format for structured logging.
    Json,
}

/// Logging configuration section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error.
    pub level: String,

    /// Output destination: stdout, stderr, or file path.
    pub output: String,

    /// Log format.
    pub format: LogFormat,

    /// Include timestamps in logs.
    pub timestamps: bool,

    /// Include target (module path) in logs.
    pub include_target: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            output: "stdout".to_string(),
            format: LogFormat::Pretty,
            timestamps: true,
            include_target: true,
        }
    }
}

/// Single host-to-IP mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostMapping {
    /// The hostname to match (exact match).
    pub hostname: String,

    /// The IP address to resolve to.
    pub ip: String,

    /// Optional port override.
    pub port: Option<u16>,
}

impl HostMapping {
    /// Validates the host mapping configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate IP address
        self.ip.parse::<IpAddr>().map_err(|_| {
            ProxyError::config_validation(format!("Invalid IP address: {}", self.ip))
        })?;

        // Validate hostname is not empty
        if self.hostname.is_empty() {
            return Err(ProxyError::config_validation("Hostname cannot be empty"));
        }

        Ok(())
    }

    /// Returns the parsed IP address.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip.parse().ok()
    }
}

/// Upstream proxy configuration section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct UpstreamProxyConfig {
    /// HTTP proxy URL.
    pub http: Option<String>,

    /// HTTPS proxy URL.
    pub https: Option<String>,

    /// Hosts to bypass the proxy.
    pub no_proxy: Vec<String>,
}

impl UpstreamProxyConfig {
    /// Gets the HTTP proxy URL from config.
    /// 
    /// Note: We intentionally do NOT read HTTP_PROXY/http_proxy environment variables
    /// because this proxy is typically set as the system proxy. Reading those vars
    /// would cause an infinite loop. Configure upstream proxy in config.yaml only.
    pub fn effective_http_proxy(&self, listen_addr: Option<&str>) -> Option<String> {
        // Filter out self-references to avoid infinite loops
        Self::filter_self_reference(self.http.clone(), listen_addr)
    }

    /// Gets the HTTPS proxy URL from config.
    /// 
    /// Note: We intentionally do NOT read HTTPS_PROXY/https_proxy environment variables
    /// because this proxy is typically set as the system proxy. Reading those vars
    /// would cause an infinite loop. Configure upstream proxy in config.yaml only.
    pub fn effective_https_proxy(&self, listen_addr: Option<&str>) -> Option<String> {
        // Filter out self-references to avoid infinite loops
        Self::filter_self_reference(self.https.clone(), listen_addr)
    }

    /// Gets the no_proxy list from config.
    /// 
    /// Note: We intentionally do NOT read NO_PROXY environment variable
    /// because this proxy is typically set as the system proxy.
    /// Configure no_proxy hosts in config.yaml only.
    pub fn effective_no_proxy(&self) -> Vec<String> {
        self.no_proxy.clone()
    }
    
    /// Filters out proxy URLs that would point back to this proxy instance.
    fn filter_self_reference(proxy: Option<String>, listen_addr: Option<&str>) -> Option<String> {
        let proxy_url = proxy?;
        
        // If we don't know our listen address, we can't filter - return proxy as-is
        let listen = match listen_addr {
            Some(addr) => addr,
            None => return Some(proxy_url),
        };
        
        // Parse the proxy URL to extract host:port
        if let Ok(uri) = proxy_url.parse::<http::Uri>() {
            let proxy_host = uri.host().unwrap_or("");
            let proxy_port = uri.port_u16().unwrap_or(match uri.scheme_str() {
                Some("https") => 443,
                _ => 80,
            });
            
            // Parse listen address
            if let Some((listen_host, listen_port)) = Self::parse_listen_addr(listen) {
                // Check if proxy points to us
                if Self::is_same_host(proxy_host, &listen_host) && proxy_port == listen_port {
                    tracing::debug!(
                        proxy = %proxy_url,
                        listen = %listen,
                        "Ignoring upstream proxy that points to self"
                    );
                    return None;
                }
            }
        }
        
        Some(proxy_url)
    }
    
    /// Parses a listen address like "0.0.0.0:1984" into (host, port).
    fn parse_listen_addr(addr: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let port: u16 = parts[0].parse().ok()?;
            let host = parts[1].to_string();
            Some((host, port))
        } else {
            None
        }
    }
    
    /// Checks if two hosts refer to the same machine.
    fn is_same_host(proxy_host: &str, listen_host: &str) -> bool {
        let proxy_lower = proxy_host.to_lowercase();
        let listen_lower = listen_host.to_lowercase();
        
        // Direct match
        if proxy_lower == listen_lower {
            return true;
        }
        
        // Common localhost variations
        let localhost_variants = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
        let proxy_is_localhost = localhost_variants.contains(&proxy_lower.as_str());
        let listen_is_localhost = localhost_variants.contains(&listen_lower.as_str());
        
        // If both are localhost variants, they're the same
        proxy_is_localhost && listen_is_localhost
    }

    /// Checks if a host should bypass the upstream proxy.
    pub fn should_bypass(&self, host: &str) -> bool {
        let no_proxy = self.effective_no_proxy();
        let host_lower = host.to_lowercase();

        for pattern in &no_proxy {
            let pattern_lower = pattern.to_lowercase();

            // Exact match
            if host_lower == pattern_lower {
                return true;
            }

            // Suffix match (e.g., .local matches foo.local)
            if pattern_lower.starts_with('.') && host_lower.ends_with(&pattern_lower) {
                return true;
            }

            // Also match without leading dot (e.g., local matches foo.local)
            if !pattern_lower.starts_with('.') {
                let suffix = format!(".{}", pattern_lower);
                if host_lower.ends_with(&suffix) {
                    return true;
                }
            }
        }

        false
    }
}

/// Root configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct AppConfig {
    /// Server configuration.
    pub server: ServerConfig,

    /// SSL/TLS configuration.
    pub ssl: SslConfig,

    /// Logging configuration.
    pub logging: LoggingConfig,

    /// Host-to-IP mappings.
    pub host_mappings: Vec<HostMapping>,

    /// Upstream proxy configuration.
    pub upstream_proxy: UpstreamProxyConfig,
}

impl AppConfig {
    /// Loads configuration from a YAML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(ProxyError::ConfigNotFound {
                path: path.display().to_string(),
            });
        }

        let contents = fs::read_to_string(path)?;
        let config: AppConfig =
            serde_yaml::from_str(&contents).map_err(|e| ProxyError::config_parse(e.to_string()))?;

        config.validate()?;

        Ok(config)
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate server listen address
        if self.server.listen.is_empty() {
            return Err(ProxyError::config_validation(
                "Server listen address cannot be empty",
            ));
        }

        // Validate host mappings
        for mapping in &self.host_mappings {
            mapping.validate()?;
        }

        // Validate logging level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.to_lowercase().as_str()) {
            return Err(ProxyError::config_validation(format!(
                "Invalid log level: {}. Must be one of: {:?}",
                self.logging.level, valid_levels
            )));
        }

        Ok(())
    }

    /// Builds a hostname lookup map for O(1) access.
    pub fn build_host_map(&self) -> HashMap<String, HostMapping> {
        self.host_mappings
            .iter()
            .map(|m| (m.hostname.to_lowercase(), m.clone()))
            .collect()
    }
}

/// Thread-safe configuration holder with hot-reload support.
#[derive(Clone)]
pub struct ConfigManager {
    /// Current configuration.
    config: Arc<RwLock<AppConfig>>,

    /// Path to the configuration file.
    config_path: PathBuf,
}

impl ConfigManager {
    /// Creates a new ConfigManager and loads the initial configuration.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config_path = path.as_ref().to_path_buf();
        let config = AppConfig::load(&config_path)?;

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            config_path,
        })
    }

    /// Gets a clone of the current configuration.
    pub fn get(&self) -> AppConfig {
        self.config.read().unwrap().clone()
    }

    /// Gets a reference to the configuration Arc.
    pub fn get_arc(&self) -> Arc<RwLock<AppConfig>> {
        self.config.clone()
    }

    /// Reloads the configuration from disk.
    pub fn reload(&self) -> Result<()> {
        info!("Reloading configuration from {:?}", self.config_path);

        match AppConfig::load(&self.config_path) {
            Ok(new_config) => {
                let mut config = self.config.write().unwrap();
                *config = new_config;
                info!("Configuration reloaded successfully");
                Ok(())
            }
            Err(e) => {
                error!("Failed to reload configuration: {}", e);
                Err(e)
            }
        }
    }

    /// Starts watching the configuration file for changes.
    /// Returns a channel receiver that signals when a reload occurs.
    pub fn start_watcher(&self) -> Result<mpsc::Receiver<()>> {
        let (tx, rx) = mpsc::channel(1);
        let config_path = self.config_path.clone();
        let manager = self.clone();

        std::thread::spawn(move || {
            let (notify_tx, notify_rx) = std::sync::mpsc::channel();

            let mut watcher = match RecommendedWatcher::new(
                move |res: std::result::Result<Event, notify::Error>| {
                    if let Ok(event) = res {
                        if event.kind.is_modify() || event.kind.is_create() {
                            let _ = notify_tx.send(());
                        }
                    }
                },
                NotifyConfig::default(),
            ) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

            // Watch the parent directory to catch file replacements
            let watch_path = config_path.parent().unwrap_or(&config_path);
            if let Err(e) = watcher.watch(watch_path, RecursiveMode::NonRecursive) {
                error!("Failed to watch config directory: {}", e);
                return;
            }

            info!("Started watching configuration file for changes");

            // Debounce: wait a bit after changes before reloading
            let mut last_reload = std::time::Instant::now();
            let debounce_duration = std::time::Duration::from_millis(500);

            loop {
                match notify_rx.recv() {
                    Ok(()) => {
                        let now = std::time::Instant::now();
                        if now.duration_since(last_reload) >= debounce_duration {
                            if manager.reload().is_ok() {
                                last_reload = now;
                                // Notify that config was reloaded
                                let _ = tx.blocking_send(());
                            }
                        } else {
                            debug!("Debouncing config reload");
                        }
                    }
                    Err(_) => {
                        warn!("Config watcher channel closed");
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    fn create_temp_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.server.listen, "0.0.0.0:1984");
        assert_eq!(config.server.workers, 0);
        assert!(!config.ssl.accept_invalid_certs);
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_load_config() {
        let yaml = r#"
server:
  listen: "127.0.0.1:8080"
  workers: 4
ssl:
  accept_invalid_certs: true
logging:
  level: "debug"
  output: "stderr"
host_mappings:
  - hostname: "example.com"
    ip: "192.168.1.1"
    port: 8080
"#;
        let file = create_temp_config(yaml);
        let config = AppConfig::load(file.path()).unwrap();

        assert_eq!(config.server.listen, "127.0.0.1:8080");
        assert_eq!(config.server.workers, 4);
        assert!(config.ssl.accept_invalid_certs);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.host_mappings.len(), 1);
        assert_eq!(config.host_mappings[0].hostname, "example.com");
        assert_eq!(config.host_mappings[0].ip, "192.168.1.1");
        assert_eq!(config.host_mappings[0].port, Some(8080));
    }

    #[test]
    fn test_invalid_ip_address() {
        let yaml = r#"
host_mappings:
  - hostname: "example.com"
    ip: "not.an.ip"
"#;
        let file = create_temp_config(yaml);
        let result = AppConfig::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_log_level() {
        let yaml = r#"
logging:
  level: "invalid"
"#;
        let file = create_temp_config(yaml);
        let result = AppConfig::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_host_lookup() {
        let config = AppConfig {
            host_mappings: vec![
                HostMapping {
                    hostname: "Example.Com".to_string(),
                    ip: "192.168.1.1".to_string(),
                    port: None,
                },
            ],
            ..Default::default()
        };

        // Case-insensitive lookup via build_host_map
        let host_map = config.build_host_map();
        assert!(host_map.get("example.com").is_some());
        assert!(host_map.get("notfound.com").is_none());
    }

    #[test]
    fn test_no_proxy_bypass() {
        let config = UpstreamProxyConfig {
            no_proxy: vec![
                "localhost".to_string(),
                ".local".to_string(),
                "internal.corp".to_string(),
            ],
            ..Default::default()
        };

        assert!(config.should_bypass("localhost"));
        assert!(config.should_bypass("LOCALHOST"));
        assert!(config.should_bypass("foo.local"));
        assert!(config.should_bypass("bar.internal.corp"));
        assert!(!config.should_bypass("example.com"));
    }

    #[test]
    fn test_config_manager() {
        let yaml = r#"
server:
  listen: "0.0.0.0:1984"
logging:
  level: "info"
"#;
        let file = create_temp_config(yaml);
        let manager = ConfigManager::new(file.path()).unwrap();
        
        let config = manager.get();
        assert_eq!(config.server.listen, "0.0.0.0:1984");
    }

    #[test]
    fn test_build_host_map() {
        let config = AppConfig {
            host_mappings: vec![
                HostMapping {
                    hostname: "api.example.com".to_string(),
                    ip: "192.168.1.1".to_string(),
                    port: Some(8080),
                },
                HostMapping {
                    hostname: "web.example.com".to_string(),
                    ip: "192.168.1.2".to_string(),
                    port: None,
                },
            ],
            ..Default::default()
        };

        let map = config.build_host_map();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("api.example.com"));
        assert!(map.contains_key("web.example.com"));
    }

    #[test]
    fn test_self_reference_detection() {
        let config = UpstreamProxyConfig {
            http: Some("http://localhost:1984".to_string()),
            https: Some("http://127.0.0.1:1984".to_string()),
            ..Default::default()
        };

        // Should filter out self-references
        assert!(config.effective_http_proxy(Some("0.0.0.0:1984")).is_none());
        assert!(config.effective_https_proxy(Some("127.0.0.1:1984")).is_none());
        
        // Different port should work
        assert!(config.effective_http_proxy(Some("0.0.0.0:8080")).is_some());
        
        // No listen addr means no filtering
        assert!(config.effective_http_proxy(None).is_some());
    }

    #[test]
    fn test_upstream_proxy_config_only() {
        // Test that upstream proxy only uses config, not environment variables
        let config = UpstreamProxyConfig {
            http: Some("http://config-proxy:3128".to_string()),
            ..Default::default()
        };

        // Should use config value
        let proxy = config.effective_http_proxy(Some("0.0.0.0:1984"));
        assert_eq!(proxy, Some("http://config-proxy:3128".to_string()));
        
        // No proxy configured should return None
        let empty_config = UpstreamProxyConfig::default();
        assert!(empty_config.effective_http_proxy(Some("0.0.0.0:1984")).is_none());
    }
}
