//! # Host Proxy
//!
//! A DNS bypass HTTP/HTTPS proxy server with configurable host-to-IP mappings.
//!
//! ## Features
//!
//! - **DNS Bypass**: Route specific hostnames to configured IP addresses
//! - **HTTPS Support**: Full CONNECT tunneling with optional SSL error bypass
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
use crate::proxy::HostProxyService;
use pingora_core::prelude::*;
use pingora_proxy::http_proxy_service;
use tracing::{error, info};

/// Application entry point.
fn main() {
    // Load environment variables from .env file
    if let Err(e) = dotenvy::dotenv() {
        // Not an error if .env doesn't exist
        if !matches!(e, dotenvy::Error::Io(_)) {
            eprintln!("Warning: Failed to load .env file: {}", e);
        }
    }

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

    // Create Pingora server
    let mut server = Server::new(None).expect("Failed to create server");
    server.bootstrap();

    // Create the proxy service
    let config_arc = config_manager.get_arc();
    let proxy_service = HostProxyService::new(config_arc.clone());

    // Start config file watcher for hot reload
    // The proxy service shares the config Arc, so reloading the ConfigManager
    // will automatically update the config the proxy sees
    match config_manager.start_watcher() {
        Ok(mut rx) => {
            // Spawn a task to handle config reloads
            std::thread::spawn(move || {
                while rx.blocking_recv().is_some() {
                    info!("Configuration reloaded successfully");
                }
            });
        }
        Err(e) => {
            error!("Failed to start config watcher: {}", e);
            // Continue without hot reload
        }
    }

    // Create HTTP proxy service
    let listen_addr = config.server.listen.clone();
    let mut http_proxy = http_proxy_service(&server.configuration, proxy_service);
    
    http_proxy.add_tcp(&listen_addr);

    info!(listen = %listen_addr, "Proxy server listening");

    // Register and run
    server.add_service(http_proxy);
    server.run_forever();
}
