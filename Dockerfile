# Build stage - compile the Rust binary with optimizations
FROM --platform=amd64 rust:1.93-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release && rm -rf src target/release/deps/host_proxy*

# Copy actual source code
COPY src ./src

# Build the release binary with full optimizations
ENV RUSTFLAGS="-C target-cpu=native -C opt-level=3 "
RUN cargo build --release --locked

# Strip the binary for smaller size
RUN strip target/release/host-proxy

# Runtime stage - minimal image
FROM --platform=amd64 debian:bookworm-slim AS runtime

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false hostproxy

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/host-proxy /app/host-proxy

# Copy default config (can be overridden with volume mount)
COPY config.yaml /app/config.yaml

# Set ownership
RUN chown -R hostproxy:hostproxy /app

# Run as non-root user
USER hostproxy

# Environment
ENV CONFIG_PATH=/app/config.yaml
ENV RUST_BACKTRACE=1

# Expose default port
EXPOSE 1984

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nc -z localhost 1984 || exit 1

# Run the proxy
ENTRYPOINT ["/app/host-proxy"]
