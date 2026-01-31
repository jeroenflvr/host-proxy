# Host Proxy

A high-performance DNS bypass HTTP/HTTPS proxy server with configurable host-to-IP(:Port)mappings, request blacklisting, and debug logging. No admin privileges required. Built with [hyper](https://hyper.rs/).

## Features

- **DNS Bypass**: Route specific hostnames to configured IP addresses
- **HTTPS Support**: Full CONNECT tunneling for secure connections
- **Request Blacklist**: Block requests by host pattern, subdomain wildcards, and HTTP methods
- **Upstream Proxy**: Forward to upstream HTTP/HTTPS proxies
- **Hot Reload**: Configuration changes take effect without restart
- **Debug Logging**: Log query parameters, headers, and request bodies
- **CLI Options**: Override config via command line arguments
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

### Using Docker

```bash
# Build the image
docker build -t host-proxy .

# Run with your config file mounted
docker run -d \
  --name host-proxy \
  -p 1984:1984 \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  host-proxy
```

### Using Docker Compose

```bash
# Start the proxy
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

## Quick Start

1. **Run without config** (uses defaults, listens on `:1984`):

```bash
./host-proxy -v
```

2. **Or create a configuration file** (`config.yaml`):

```yaml
server:
  listen: "0.0.0.0:1984"

host_mappings:
  - hostname: "api.example.com"
    ip: "192.168.1.100"
    port: 8080

blacklist:
  enabled: true
  rules:
    - host: "*.ads.com"
      reason: "Block ads"
```

3. **Run with config**:

```bash
./host-proxy -c config.yaml
```

4. **Test it**:

```bash
# HTTP request through proxy
curl -x http://localhost:1984 http://api.example.com/

# HTTPS request through proxy
curl -x http://localhost:1984 https://api.example.com/
```

## Command Line Options

```
Usage: host-proxy [OPTIONS]

Options:
  -c, --config <PATH>    Path to configuration file [env: CONFIG_PATH]
  -l, --listen <ADDR>    Listen address (overrides config) [env: LISTEN_ADDR]
  -v, --verbose...       Increase verbosity:
                           -v    info level
                           -vv   debug level (includes headers, query params)
                           -vvv  trace level
                           -vvvv trace level + dependency tracing
  -q, --quiet            Quiet mode (errors only)
  -h, --help             Print help
  -V, --version          Print version
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

### Blacklist

Block requests by host pattern and HTTP method:

```yaml
blacklist:
  enabled: true
  rules:
    # Block all requests to a host
    - host: "ads.example.com"
      reason: "Advertising blocked"
    
    # Block all subdomains (*.tracking.com also matches tracking.com)
    - host: "*.tracking.com"
      reason: "Tracking blocked"
    
    # Block specific HTTP methods only
    - host: "api.example.com"
      methods: ["DELETE", "PUT"]
      reason: "Write operations blocked"
    
    # Block a method globally
    - host: "*"
      methods: ["TRACE"]
      reason: "TRACE disabled for security"
```

Blocked requests return `403 Forbidden` with an `X-Blocked-Reason` header.

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
| `LISTEN_ADDR` | Override listen address | `0.0.0.0:8080` |

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

### Debug Mode

Use `-vv` to see query parameters, headers, and request bodies:

```bash
./host-proxy -vv
```

Example debug output:
```
DEBUG Request received client=127.0.0.1:54321 method=POST uri=http://api.example.com/users?page=1
DEBUG Query parameters client=127.0.0.1:54321 query=page=1
DEBUG Request header client=127.0.0.1:54321 header_name=content-type header_value=application/json
DEBUG Request header client=127.0.0.1:54321 header_name=authorization header_value=[REDACTED]
DEBUG Request body target=192.168.1.100:8080 body={"name":"test"}
```

Sensitive headers (`Authorization`, `Cookie`, `Proxy-Authorization`) are automatically redacted.

### Building Release

```bash
cargo build --release
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
