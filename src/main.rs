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
//! # Run with default config path
//! host-proxy
//!
//! # Run with custom config
//! host-proxy -c /path/to/config.yaml
//!
//! # Run without config (debugging mode)
//! host-proxy -v
//!
//! # Increase verbosity
//! host-proxy -vvvv  # trace level
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

use crate::config::{AppConfig, ConfigManager};
use crate::proxy::ProxyServer;
use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{error, info};

/// A DNS bypass HTTP/HTTPS proxy server with configurable host-to-IP mappings.
#[derive(Parser, Debug)]
#[command(name = "host-proxy")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, env = "CONFIG_PATH")]
    config: Option<PathBuf>,

    /// Listen address (overrides config)
    #[arg(short, long, env = "LISTEN_ADDR")]
    listen: Option<String>,

    /// Increase verbosity (-v info, -vv debug, -vvv trace, -vvvv trace+deps)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Quiet mode (only errors)
    #[arg(short, long)]
    quiet: bool,
}

impl Args {
    /// Converts verbosity count to log level string
    fn log_level(&self) -> Option<String> {
        if self.quiet {
            return Some("error".to_string());
        }
        match self.verbose {
            0 => None, // Use config default
            1 => Some("info".to_string()),
            2 => Some("debug".to_string()),
            3 => Some("trace".to_string()),
            _ => Some("trace".to_string()), // 4+ includes dependency tracing
        }
    }

    /// Whether to include verbose dependency logging
    fn trace_deps(&self) -> bool {
        self.verbose >= 4
    }
}

/// Application entry point.
#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Try to load configuration, use defaults if not found
    let (config, config_manager) = load_config(&args);

    // Initialize logging
    let log_level = args.log_level();
    let _log_guard = match logging::init_logging(&config.logging, log_level.clone(), args.trace_deps()) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("Failed to initialize logging: {}", e);
            std::process::exit(1);
        }
    };

    // Log startup info
    if let Some(ref path) = args.config {
        info!(
            version = env!("CARGO_PKG_VERSION"),
            config_path = %path.display(),
            "Starting host-proxy"
        );
    } else {
        info!(
            version = env!("CARGO_PKG_VERSION"),
            "Starting host-proxy with default configuration"
        );
    }

    // Apply CLI overrides
    let config_arc = if let Some(ref listen) = args.listen {
        let mut modified = config.clone();
        modified.server.listen = listen.clone();
        info!(listen = %listen, "Listen address overridden via CLI");
        Arc::new(RwLock::new(modified))
    } else if let Some(ref manager) = config_manager {
        manager.get_arc()
    } else {
        Arc::new(RwLock::new(config))
    };

    let proxy_server = ProxyServer::new(config_arc.clone());

    // Start config file watcher for hot reload (only if we have a config manager)
    if let Some(manager) = config_manager {
        match manager.start_watcher() {
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
    }

    // Run the proxy server
    if let Err(e) = proxy_server.run().await {
        error!(error = %e, "Proxy server error");
        std::process::exit(1);
    }
}

/// Load configuration from file or use defaults
fn load_config(args: &Args) -> (AppConfig, Option<ConfigManager>) {
    // Determine config path
    let config_path = args.config.clone().or_else(|| {
        // Check default paths
        let defaults = ["./config.yaml", "./config.yml", "/etc/host-proxy/config.yaml"];
        for path in defaults {
            let p = PathBuf::from(path);
            if p.exists() {
                return Some(p);
            }
        }
        None
    });

    match config_path {
        Some(path) => {
            if path.exists() {
                match ConfigManager::new(&path) {
                    Ok(manager) => {
                        let config = manager.get();
                        (config, Some(manager))
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to load config from {:?}: {}", path, e);
                        eprintln!("Using default configuration");
                        (AppConfig::default(), None)
                    }
                }
            } else {
                // Explicitly specified path doesn't exist - warn but continue
                eprintln!("Warning: Config file not found: {:?}", path);
                eprintln!("Using default configuration");
                (AppConfig::default(), None)
            }
        }
        None => {
            // No config file - use defaults silently
            (AppConfig::default(), None)
        }
    }
}
