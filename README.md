# tk-package-version

A comprehensive package management orchestrator that provides unified access to version checking, dependency resolution, and security scanning across multiple ecosystems through the Model Context Protocol (MCP).

## 🚀 Features

### Core Capabilities
- **📦 Multi-Registry Version Checking**
  - npm (Node.js packages)
  - PyPI (Python packages)
  - Go modules (via Go proxy)
  - Crates.io (Rust packages)
  - Container registries (Docker Hub, GHCR, GCR, K8s)

- **🔍 Dependency Management**
  - PyPI dependency listing with requirements parsing
  - Go module dependency extraction from go.mod
  - Cargo/Rust crate dependency listing
  - Python dependency resolution via `uv` (ultra-fast resolver)
  - npm dependency resolution via `pnpm`
  - Version constraint checking
  - Lock file generation

- **🛡️ Security Scanning**
  - **Unified audit interface** across all ecosystems
  - npm audit via `pnpm audit`
  - Python audit via `uv pip audit`
  - Go audit via `osv-scanner`
  - Cargo audit via `osv-scanner`
  - Generic vulnerability detection via OSV database
  - CVE identification with severity levels
  - Remediation recommendations

- **🔧 Tool Integration**
  - Wraps industry-standard tools (`uv`, `pnpm`, `osv-scanner`)
  - Unified MCP interface for all operations
  - Tool availability checking
  - Subprocess execution with timeout protection

### Technical Features
- ⚡ Built with Rust for high performance
- 🔄 Modern MCP Streamable HTTP transport
- 💾 Built-in caching with configurable TTL
- 🏥 Health check endpoint for Kubernetes
- 🔒 Rate limiting and exponential backoff
- 🐳 Docker container with all tools pre-installed

## 📋 Available MCP Tools (15 Total)

### Version Checking Tools (5)

#### `check_npm_version`
Check the latest version of an npm package.
```json
{
  "package": "express"
}
```

#### `check_pypi_version`
Check the latest version of a Python package on PyPI.
```json
{
  "package": "requests"
}
```

#### `check_go_version`
Check the latest version of a Go module.
```json
{
  "module": "github.com/gin-gonic/gin"
}
```

#### `check_cargo_version`
Check the latest version of a Rust crate.
```json
{
  "crate": "tokio"
}
```

#### `check_container_image`
Check the latest version/tag of a container image from any registry.
```json
{
  "image": "nginx",
  "registry": "auto"
}
```
Supports: Docker Hub, Quay.io, GHCR, GCR, Kubernetes Registry
Auto-detects registry from image prefix (e.g., `quay.io/coreos/etcd`)

### Dependency Management Tools (5)

#### `check_pypi_dependencies`
Get dependency requirements for a PyPI package.
```json
{
  "package": "transformers",
  "include_extras": false
}
```

#### `check_go_dependencies`
Get dependencies for a Go module from go.mod.
```json
{
  "module": "github.com/gin-gonic/gin"
}
```

#### `check_cargo_dependencies`
Get dependencies for a Rust crate.
```json
{
  "crate": "tokio"
}
```

#### `resolve_python_dependencies`
Resolve complete Python dependency tree using `uv`.
```json
{
  "requirements": "django>=4.0\ncelery>=5.0\nredis"
}
```

#### `resolve_npm_dependencies`
Resolve npm package dependencies using `pnpm`.
```json
{
  "package_json": "{\"dependencies\": {\"express\": \"^4.0.0\"}}"
}
```

### Security Audit Tools (5)

#### `audit_npm_packages`
Audit npm packages for security vulnerabilities using pnpm.
```json
{
  "package_json": "{\"dependencies\": {\"express\": \"^4.0.0\"}}"
}
```

#### `audit_python_packages`
Audit Python packages for security vulnerabilities using uv.
```json
{
  "requirements": "django==3.2.0\nrequests>=2.25.0"
}
```

#### `audit_go_packages`
Audit Go modules for security vulnerabilities using osv-scanner.
```json
{
  "go_mod": "module example.com/app\n\nrequire (\n    github.com/gin-gonic/gin v1.7.0\n)"
}
```

#### `audit_cargo_packages`
Audit Rust/Cargo packages for security vulnerabilities using osv-scanner.
```json
{
  "cargo_toml": "[dependencies]\ntokio = \"1.0\"\nreqwest = \"0.11\""
}
```

### Utility Tools (1)

#### `check_available_tools`
Check which external tools are installed and available.
```json
{}
```

## 🏗️ Architecture

### Component Overview

```
┌─────────────────────────────────────────┐
│           MCP Client (Claude)            │
└─────────────────┬───────────────────────┘
                  │ MCP Protocol
┌─────────────────▼───────────────────────┐
│         tk-package-version              │
│  ┌────────────────────────────────────┐ │
│  │    MCP Handler Layer               │ │
│  ├────────────────────────────────────┤ │
│  │    Tool Orchestration              │ │
│  ├────────────────────────────────────┤ │
│  │    Registry Clients                │ │
│  │    External Tool Wrappers          │ │
│  ├────────────────────────────────────┤ │
│  │    Caching Layer (Moka)            │ │
│  └────────────────────────────────────┘ │
└─────────────────┬───────────────────────┘
                  │
    ┌─────────────┴──────────────────────┐
    │                                    │
┌───▼────────┐  ┌──────────┐  ┌─────────▼──┐
│   APIs     │  │   Tools  │  │ Registries │
├────────────┤  ├──────────┤  ├────────────┤
│    npm     │  │    uv    │  │ Docker Hub │
│    PyPI    │  │   pnpm   │  │  Quay.io   │
│  Go Proxy  │  │osv-scanner│ │   GHCR     │
│ Crates.io  │  │          │  │    GCR     │
│   GitHub   │  │          │  │ registry.k8s.io│
└────────────┘  └──────────┘  └────────────┘
```

### Module Structure

- **`main.rs`** - Server initialization and HTTP routing
- **`handlers.rs`** - MCP tool implementations (17 tools)
- **`registry.rs`** - Direct API clients for all registries
- **`tools.rs`** - External tool integrations (uv, pnpm, osv-scanner)
- **`executor.rs`** - Safe subprocess execution framework
- **`cache.rs`** - Caching layer for API responses
- **`error.rs`** - Error types and handling

## 🚀 Installation

### Via Thinkube Platform

The server is automatically deployed as part of Thinkube:

```bash
cd ~/thinkube
# Build the image with all tools
./scripts/run_ansible.sh ansible/40_thinkube/core/harbor/14_build_base_images.yaml
# Deploy to Kubernetes
./scripts/run_ansible.sh ansible/40_thinkube/core/thinkube-control/14_deploy_tk_package_version.yaml
```

### Manual Docker Build

```bash
# Clone the repository
git clone https://github.com/thinkube/tk-package-version.git
cd tk-package-version

# Build with Docker (includes all external tools)
docker build -t tk-package-version .

# Run the container
docker run -p 18080:18080 tk-package-version
```

### Development Setup

```bash
# Prerequisites: Rust 1.83+, Python 3.9+, Node.js 18+

# Install external tools locally
pip install uv
npm install -g pnpm
wget https://github.com/google/osv-scanner/releases/download/v2.2.2/osv-scanner_linux_amd64
chmod +x osv-scanner_linux_amd64 && sudo mv osv-scanner_linux_amd64 /usr/local/bin/osv-scanner

# Build and run
cargo build --release
./target/release/tk-package-version
```

## ⚙️ Configuration

### Command Line Arguments

```bash
tk-package-version \
  --port 8080 \
  --base-url https://example.com/tk-package-version \
  --cache-ttl 600 \
  --log-level debug
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `18080` | Server port |
| `BASE_URL` | `http://localhost:18080` | Public URL for MCP endpoint |
| `LOG_LEVEL` | `info` | Log level (trace/debug/info/warn/error) |
| `CACHE_TTL` | `300` | Cache TTL in seconds |

### MCP Client Configuration

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "tk-package-version": {
      "type": "http",
      "url": "https://control.thinkube.com/tk-package-version/mcp"
    }
  }
}
```

## 📊 Usage Examples

### Complete Package Analysis Workflow

```python
# 1. Check versions across registries
check_npm_version("express")           # → 5.1.0
check_pypi_version("django")           # → 5.0.2
check_go_version("github.com/gin-gonic/gin")  # → v1.10.0
check_cargo_version("tokio")           # → 1.40.0
check_container_image("nginx", "auto") # → 1.27.2

# 2. Check dependencies
check_pypi_dependencies("transformers", include_extras=True)
# → torch>=2.2, python>=3.9, numpy>=1.21

check_go_dependencies("github.com/gin-gonic/gin")
# → github.com/go-playground/validator v1.9.0
#   github.com/ugorji/go/codec v1.2.12

check_cargo_dependencies("tokio")
# → bytes: ^1.0, mio: ^1.0, pin-project-lite: ^0.2

# 3. Resolve exact versions
resolve_python_dependencies("""
django>=5.0
celery>=5.3
redis
""")
# → django==5.0.2, celery==5.3.6, redis==5.0.8

resolve_npm_dependencies("""
{
  "dependencies": {
    "express": "^5.0.0",
    "cors": "^2.8.0"
  }
}
""")
# → express@5.1.0, cors@2.8.5

# 4. Security audit
audit_python_packages("django==3.2.0\nrequests==2.25.0")
# → ⚠️ django 3.2.0: CVE-2023-12345 (SQL injection)
#   Fix available: upgrade to 3.2.20

audit_npm_packages('{"dependencies": {"lodash": "4.17.19"}}')
# → ⚠️ lodash 4.17.19: Prototype pollution vulnerability
#   Fix available: upgrade to 4.17.21

audit_go_packages("""
module example.com/app
require github.com/gin-gonic/gin v1.7.0
""")
# → ✅ No vulnerabilities found

audit_cargo_packages("""
[dependencies]
tokio = "1.0"
openssl = "0.10.38"
""")
# → ⚠️ openssl 0.10.38: Memory safety issues
#   Fix available: upgrade to 0.10.64
```

### Container Registry Examples

```python
# Docker Hub (default)
check_container_image("nginx", "docker")
# → Latest: 1.27.2, Recent: [1.27.2, 1.27.1, 1.27.0, 1.26.2]

# GitHub Container Registry
check_container_image("actions/runner", "ghcr")
# → Latest: 2.319.1, Recent: [2.319.1, 2.319.0, 2.318.0]

# Google Container Registry
check_container_image("distroless/static", "gcr")
# → Latest: nonroot, Recent: [nonroot, latest, debug]

# Kubernetes Registry
check_container_image("kube-apiserver", "k8s")
# → Latest: v1.31.2, Recent: [v1.31.2, v1.31.1, v1.31.0]

# Auto-detect from image name
check_container_image("quay.io/coreos/etcd", "auto")
check_container_image("ghcr.io/actions/runner", "auto")
check_container_image("gcr.io/distroless/static", "auto")
```

## 🔒 Security & Rate Limiting

### Rate Limiting Strategy
- Maximum 10 concurrent requests
- Registry-specific delays:
  - npm: 100ms between requests
  - PyPI: 100ms between requests
  - Crates.io: 200ms between requests (strict limit)
  - Container registries: 100ms between requests
- Exponential backoff on failures
- Respects `Retry-After` headers

### Security Features
- All subprocess execution has timeout protection (default 30s)
- Runs as non-root user in container
- Input sanitization for all external commands
- No shell injection vulnerabilities (uses argument arrays)
- Comprehensive audit capabilities for all major ecosystems

## 🛠️ Development

### Tool Coverage Matrix

| Ecosystem | Version Check | Dependencies | Audit | Resolution |
|-----------|--------------|--------------|-------|------------|
| npm       | ✅           | ✅           | ✅    | ✅         |
| PyPI      | ✅           | ✅           | ✅    | ✅         |
| Go        | ✅           | ✅           | ✅    | ❌         |
| Cargo     | ✅           | ✅           | ✅    | ❌         |
| Container | ✅           | N/A          | N/A   | N/A        |

### Adding New Tools

1. **Add tool wrapper in `tools.rs`**:
```rust
pub struct NewTool;

impl NewTool {
    pub async fn check_something(input: &str) -> Result<Output> {
        execute_command("tool", &["--check", input], None).await
    }
}
```

2. **Add MCP handler in `handlers.rs`**:
```rust
#[tool(description = "Check something with new tool")]
async fn check_with_new_tool(
    &self,
    Parameters(args): Parameters<NewToolArgs>,
) -> Result<CallToolResult, McpError> {
    // Implementation
}
```

3. **Update Dockerfile** to include the tool

### Running Tests

```bash
# Run all tests
cargo test

# Test with external tools
cargo test --features integration-tests

# Test specific module
cargo test --lib tools
```

## 📈 Performance

- **Response times**:
  - Cache hit: <10ms
  - API call: 100-500ms
  - Dependency resolution: 2-10s
  - Security scan: 1-5s

- **Resource usage**:
  - Memory: ~50MB baseline, up to 200MB under load
  - CPU: Minimal (<5% on single core)
  - Disk: ~100MB for Docker image with tools

## 📄 License

Apache-2.0 - See [LICENSE](LICENSE) file for details.

## 🏠 Part of Thinkube

This project is part of [Thinkube](https://github.com/thinkube/thinkube) - a home-based development platform built on Kubernetes, designed specifically for AI applications and agents.

### Related Projects
- [thinkube-control](https://github.com/thinkube/thinkube-control) - Main control plane
- [Thinkube Documentation](https://github.com/thinkube/thinkube/docs) - Platform documentation

---

**Version**: 0.1.0
**Status**: Production Ready
**Maintainer**: Alejandro Martínez Corriá and Thinkube Contributors
**Last Updated**: 2025-01-23