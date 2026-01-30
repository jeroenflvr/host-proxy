//! Error types for the host-proxy application.
//!
//! This module defines all error types used throughout the application,
//! providing structured error handling with context.

use thiserror::Error;

/// Main error type for the host-proxy application.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ProxyError {
    /// Configuration file could not be found.
    #[error("Configuration file not found: {path}")]
    ConfigNotFound { path: String },

    /// Configuration file could not be parsed.
    #[error("Failed to parse configuration: {message}")]
    ConfigParse { message: String },

    /// Configuration validation failed.
    #[error("Invalid configuration: {message}")]
    ConfigValidation { message: String },

    /// Failed to set up file watcher for hot-reload.
    #[error("Failed to set up config file watcher: {message}")]
    WatcherSetup { message: String },

    /// Network-related error.
    #[error("Network error: {message}")]
    Network { message: String },

    /// Upstream proxy error.
    #[error("Upstream proxy error: {message}")]
    UpstreamProxy { message: String },

    /// DNS resolution error.
    #[error("DNS resolution failed for host: {host}")]
    DnsResolution { host: String },

    /// I/O error wrapper.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error for unexpected conditions.
    #[error("Internal error: {message}")]
    Internal { message: String },
}

#[allow(dead_code)]
impl ProxyError {
    /// Creates a new configuration parse error.
    pub fn config_parse(message: impl Into<String>) -> Self {
        Self::ConfigParse {
            message: message.into(),
        }
    }

    /// Creates a new configuration validation error.
    pub fn config_validation(message: impl Into<String>) -> Self {
        Self::ConfigValidation {
            message: message.into(),
        }
    }

    /// Creates a new network error.
    pub fn network(message: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
        }
    }

    /// Creates a new internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

/// Result type alias using ProxyError.
pub type Result<T> = std::result::Result<T, ProxyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ProxyError::ConfigNotFound {
            path: "/etc/config.yaml".to_string(),
        };
        assert!(err.to_string().contains("/etc/config.yaml"));

        let err = ProxyError::config_parse("invalid yaml");
        assert!(err.to_string().contains("invalid yaml"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let proxy_err: ProxyError = io_err.into();
        assert!(matches!(proxy_err, ProxyError::Io(_)));
    }
}
