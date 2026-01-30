//! # Host Proxy
//!
//! A DNS bypass HTTP/HTTPS proxy server with configurable host-to-IP mappings.
//!
//! ## Features
//!
//! - **DNS Bypass**: Route specific hostnames to configured IP addresses
//! - **HTTPS Support**: Full CONNECT tunneling for direct connections
//! - **Upstream Proxy**: Forward to upstream proxies when configured
//! - **Hot Reload**: Configuration changes take effect without restart
//! - **Flexible Logging**: Configurable log levels and output destinations
//!
//! ## Resolution Priority
//!
//! 1. Config mappings (exact hostname match)
//! 2. Upstream proxy (if configured and host not in no_proxy)
//! 3. DNS resolution
//!
//! ## Usage
//!
//! ```bash
//! # Set config path via environment
//! export CONFIG_PATH=./config.yaml
//!
//! # Run the proxy
//! host-proxy
//! ```
//!
//! ## Configuration
//!
//! See `config.yaml` for all available options.

mod config;
mod error;
mod logging;
mod proxy;
mod resolver;

use crate::config::{get_config_path, get_log_level_override, ConfigManager};
use crate::proxy::ProxyServer;
use tracing::{error, info};

/// Application entry point.
#[tokio::main]
async fn main() {
    // Load configuration
    let config_path = get_config_path();
    let config_manager = match ConfigManager::new(&config_path) {
        Ok(cm) => cm,
        Err(e) => {
            eprintln!("Failed to load configuration from {:?}: {}", config_path, e);
            std::process::exit(1);
        }
    };

    let config = config_manager.get();

    // Initialize logging
    let log_level_override = get_log_level_override();
    let _log_guard = match logging::init_logging(&config.logging, log_level_override) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("Failed to initialize logging: {}", e);
            std::process::exit(1);
        }
    };

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config_path = %config_path.display(),
        "Starting host-proxy"
    );

    // Create the proxy server
    let config_arc = config_manager.get_arc();
    let proxy_server = ProxyServer::new(config_arc.clone());

    // Start config file watcher for hot reload
    match config_manager.start_watcher() {
        Ok(mut rx) => {
            let proxy_refresh = proxy_server.clone();
            tokio::spawn(async move {
                while rx.recv().await.is_some() {
                    info!("Configuration reloaded successfully");
                    proxy_refresh.refresh();
                }
            });
        }
        Err(e) => {
            error!("Failed to start config watcher: {}", e);
            // Continue without hot reload
        }
    }

    // Run the proxy server
    if let Err(e) = proxy_server.run().await {
        error!(error = %e, "Proxy server error");
        std::process::exit(1);
    }
}
