//! # Host Proxy Library
//!
//! This crate provides a DNS bypass HTTP/HTTPS proxy server with configurable
//! host-to-IP mappings. It's built on the Pingora framework for high performance.
//!
//! ## Modules
//!
//! - [`config`]: Configuration loading, validation, and hot-reload support
//! - [`error`]: Error types and handling
//! - [`logging`]: Logging setup and configuration
//! - [`proxy`]: The main Pingora-based proxy implementation
//! - [`resolver`]: Host resolution logic
//!
//! ## Example
//!
//! ```ignore
//! use host_proxy::config::ConfigManager;
//! use host_proxy::proxy::HostProxyService;
//!
//! // Load configuration
//! let manager = ConfigManager::new("config.yaml")?;
//! let config = manager.get_arc();
//!
//! // Create proxy service
//! let service = HostProxyService::new(config);
//! ```
//!
//! ## Resolution Priority
//!
//! The proxy resolves hostnames in the following order:
//!
//! 1. **Config Mappings**: Exact hostname matches from the configuration file
//! 2. **Upstream Proxy**: If configured and the host is not in the no_proxy list
//! 3. **DNS Resolution**: Standard DNS lookup as fallback

pub mod config;
pub mod error;
pub mod logging;
pub mod proxy;
pub mod resolver;

pub use config::{AppConfig, ConfigManager, HostMapping};
pub use error::{ProxyError, Result};
pub use proxy::HostProxyService;
pub use resolver::{HostResolver, ResolveResult};
