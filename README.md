# Host Proxy

A high-performance DNS bypass HTTP/HTTPS proxy server with configurable host-to-IP mappings, built with [hyper](https://hyper.rs/).

## Features

- **DNS Bypass**: Route specific hostnames to configured IP addresses
- **HTTPS Support**: Full CONNECT tunneling for secure connections
- **Upstream Proxy**: Forward to upstream HTTP/HTTPS proxies
- **Hot Reload**: Configuration changes take effect without restart
- **Flexible Logging**: Configurable levels, formats, and output destinations
- **High Performance**: Built on the hyper HTTP library

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourname/host-proxy.git
cd host-proxy

# Build release binary
cargo build --release

# Binary will be at target/release/host-proxy
```

## Quick Start

1. **Create configuration file** (`config.yaml`):

```yaml
server:
  listen: "0.0.0.0:1984"

ssl:
  accept_invalid_certs: false

logging:
  level: "info"
  output: "stdout"

host_mappings:
  - hostname: "api.example.com"
    ip: "192.168.1.100"
    port: 8080
```

2. **Set up environment** (optional `.env` file):

```env
CONFIG_PATH=./config.yaml
LOG_LEVEL=debug
```

3. **Run the proxy**:

```bash
./target/release/host-proxy
```

4. **Test it**:

```bash
# HTTP request through proxy
curl -x http://localhost:1984 http://api.example.com/

# HTTPS request through proxy
curl -x http://localhost:1984 https://api.example.com/
```

## Configuration

### Server Settings

```yaml
server:
  listen: "0.0.0.0:1984"  # Address and port to listen on
  workers: 0               # Worker threads (0 = CPU cores)
  connect_timeout: 10      # Connection timeout in seconds
  read_timeout: 30         # Read timeout in seconds
  write_timeout: 30        # Write timeout in seconds
```

### SSL/TLS Settings

```yaml
ssl:
  accept_invalid_certs: false     # Accept self-signed certificates
  accept_invalid_hostnames: false # Accept mismatched hostnames
```

### Logging

```yaml
logging:
  level: "info"           # trace, debug, info, warn, error
  output: "stdout"        # stdout, stderr, or file path
  format: "pretty"        # pretty, compact, json
  timestamps: true        # Include timestamps
  include_target: true    # Include module path
```

### Host Mappings

```yaml
host_mappings:
  - hostname: "api.example.com"
    ip: "192.168.1.100"
    port: 8080              # Optional, defaults to request port
    
  - hostname: "internal.service"
    ip: "10.0.0.50"
```

### Upstream Proxy

```yaml
upstream_proxy:
  http: "http://proxy.corp:3128"   # HTTP proxy
  https: "http://proxy.corp:3128"  # HTTPS proxy
  no_proxy:                         # Bypass list
    - "localhost"
    - "127.0.0.1"
    - ".local"
```

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `CONFIG_PATH` | Path to config file | `./config.yaml` |
| `LOG_LEVEL` | Override log level | `debug` |
| `RUST_LOG` | Fine-grained log control | `host_proxy=debug` |

> **Note**: Upstream proxy settings are configured **only** in `config.yaml`, not via
> environment variables. This prevents infinite loops when host-proxy is set as your
> system's `HTTP_PROXY`/`HTTPS_PROXY`. The proxy also automatically detects and ignores
> upstream proxy URLs that point back to itself.

## Resolution Priority

The proxy resolves hostnames in this order:

1. **Config Mappings**: Exact hostname match in `host_mappings`
2. **Upstream Proxy**: Forward to upstream proxy if configured
3. **DNS Resolution**: Standard DNS lookup as fallback

Hosts in the `no_proxy` list skip the upstream proxy and go directly to DNS.

## Hot Reload

The configuration file is watched for changes. When modified:

- Host mappings are updated immediately
- Existing connections continue normally
- New connections use the new configuration
- No restart required

## Examples

### Development Setup

Redirect API calls to local development server:

```yaml
host_mappings:
  - hostname: "api.production.com"
    ip: "127.0.0.1"
    port: 3000
```

### Corporate Proxy Bypass

Route internal services directly, external through proxy:

```yaml
host_mappings:
  - hostname: "internal.corp.com"
    ip: "10.0.0.100"

upstream_proxy:
  http: "http://proxy.corp:3128"
  https: "http://proxy.corp:3128"
  no_proxy:
    - ".corp.com"
    - "10.0.0.0/8"
```

### Accept Self-Signed Certificates

For testing environments with self-signed certs:

```yaml
ssl:
  accept_invalid_certs: true
  accept_invalid_hostnames: true
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Host Proxy                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐   │
│  │   Client    │───▶│   Resolver   │───▶│  Config   │   │
│  │   Request   │    │              │    │  Mappings │   │
│  └─────────────┘    └──────────────┘    └───────────┘   │
│                            │                            │
│         ┌──────────────────┴─────────────────┐          │
│         ▼                  ▼                 ▼          │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐    │
│  │   Direct    │   │  Upstream   │   │    DNS      │    │
│  │ Connection  │   │   Proxy     │   │ Resolution  │    │
│  └─────────────┘   └─────────────┘   └─────────────┘    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Development

### Running Tests

```bash
cargo test
```

### Running with Debug Logging

```bash
LOG_LEVEL=debug cargo run
```

### Building Release

```bash
cargo build --release
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
