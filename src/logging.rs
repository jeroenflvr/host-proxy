//! Logging configuration and initialization.
//!
//! This module sets up the tracing subscriber based on the application
//! configuration, supporting stdout, stderr, and file output with
//! configurable formats.

use crate::config::{LogFormat, LoggingConfig};
use std::fs::OpenOptions;
use std::io;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Initializes the logging system based on configuration.
///
/// Returns a guard that must be kept alive for the duration of the program
/// to ensure all logs are flushed.
///
/// # Arguments
///
/// * `config` - The logging configuration
/// * `level_override` - Optional level override from CLI/environment
/// * `trace_deps` - If true, include verbose logging from dependencies
///
/// # Example
///
/// ```ignore
/// let config = LoggingConfig::default();
/// let _guard = init_logging(&config, None, false)?;
/// tracing::info!("Logging initialized");
/// ```
pub fn init_logging(
    config: &LoggingConfig,
    level_override: Option<String>,
    trace_deps: bool,
) -> io::Result<Option<WorkerGuard>> {
    let level = level_override
        .as_ref()
        .unwrap_or(&config.level)
        .to_lowercase();

    // Build the env filter
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Map simple level names to filter directives
        let level_filter = match level.as_str() {
            "trace" => "trace",
            "debug" => "debug",
            "info" => "info",
            "warn" => "warn",
            "error" => "error",
            _ => "info",
        };

        // If trace_deps is enabled, trace everything including dependencies
        if trace_deps {
            EnvFilter::new(level_filter)
        } else {
            // Set default level and reduce noise from dependencies
            EnvFilter::new(format!(
                "{},hyper=warn,rustls=warn,h2=warn",
                level_filter
            ))
        }
    });

    // Create the writer and guard based on output destination
    let (_writer, guard): (Box<dyn io::Write + Send + Sync>, Option<WorkerGuard>) =
        match config.output.to_lowercase().as_str() {
            "stdout" => {
                let (non_blocking, guard) = tracing_appender::non_blocking(io::stdout());
                (Box::new(non_blocking), Some(guard))
            }
            "stderr" => {
                let (non_blocking, guard) = tracing_appender::non_blocking(io::stderr());
                (Box::new(non_blocking), Some(guard))
            }
            path => {
                // File output
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                let (non_blocking, guard) = tracing_appender::non_blocking(file);
                (Box::new(non_blocking), Some(guard))
            }
        };

    // Build and register the subscriber based on format
    match config.format {
        LogFormat::Json => {
            let layer = fmt::layer()
                .json()
                .with_span_events(FmtSpan::CLOSE)
                .with_target(config.include_target);

            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
        }
        LogFormat::Compact => {
            let layer = fmt::layer()
                .compact()
                .with_target(config.include_target);

            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
        }
        LogFormat::Pretty => {
            let layer = fmt::layer()
                .pretty()
                .with_target(config.include_target);

            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
        }
    }

    Ok(guard)
}

/// Parses a log level string to a tracing Level.
#[allow(dead_code)]
pub fn parse_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_level() {
        assert_eq!(parse_level("trace"), Level::TRACE);
        assert_eq!(parse_level("DEBUG"), Level::DEBUG);
        assert_eq!(parse_level("Info"), Level::INFO);
        assert_eq!(parse_level("WARN"), Level::WARN);
        assert_eq!(parse_level("error"), Level::ERROR);
        assert_eq!(parse_level("invalid"), Level::INFO);
    }
}
