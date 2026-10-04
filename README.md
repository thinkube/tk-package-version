# tk-package-version

An MCP server that checks the latest versions of packages on npm, PyPI, Go modules, Cargo crates and container registries, and resolves and audits dependency lists.

## What it does

A Rust server (`src/`) that serves MCP over streamable HTTP at `/mcp` and a health check at `/health`, on port 18080. Version lookups are cached for `CACHE_TTL` seconds (300 by default).

Its 15 tools (`src/handlers.rs`):

| Tool | What it does |
|---|---|
| `check_npm_version` | Latest version of an npm package, from registry.npmjs.org. |
| `check_pypi_version` | Latest version of a Python package, from pypi.org. |
| `check_go_version` | Latest version of a Go module, from proxy.golang.org. |
| `check_go_dependencies` | Direct dependencies of a Go module, from its `go.mod` on proxy.golang.org. |
| `check_cargo_version` | Latest version of a Rust crate, from crates.io. |
| `check_cargo_dependencies` | Dependencies of a Rust crate and their version requirements, from crates.io. |
| `check_container_image` | Latest tag and up to 10 recent tags of an image on Docker Hub, ghcr.io, gcr.io or registry.k8s.io. The registry is taken from the image name unless `registry` is given. |
| `check_pypi_dependencies` | The requirements of a PyPI package and its Python version requirement; extras only when `include_extras` is true. |
| `resolve_python_dependencies` | Resolves a requirements.txt text to exact versions with `uv`. |
| `resolve_npm_dependencies` | Resolves a `package.json` text to exact versions with `pnpm install --dry-run`. |
| `audit_npm_packages` | Runs `pnpm audit` on a `package.json` text and counts vulnerabilities by severity. |
| `audit_python_packages` | Runs `uv pip audit` on a requirements.txt text and lists vulnerable packages and fixed versions. |
| `audit_go_packages` | Runs `osv-scanner` on a `go.mod` text and lists vulnerable packages and fixed versions. |
| `audit_cargo_packages` | Runs `osv-scanner` on a `Cargo.toml` text and lists vulnerable packages and fixed versions. |
| `check_available_tools` | Reports which of `uv`, `pnpm` and `osv-scanner` are installed in the container, with their versions. |

The container image (`Containerfile`) carries `uv`, `pnpm` and `osv-scanner` for the resolve and audit tools.

## How it reaches a user

tk-package-version is a core component, installed by the Thinkube installer with the playbooks of [thinkube](https://github.com/thinkube/thinkube). It is not installed on its own.

- `ansible/40_thinkube/core/harbor-images/14_build_base_images.yaml` clones this repository and builds the image into Harbor.
- `ansible/40_thinkube/core/thinkube-control/14_deploy_tk_package_version.yaml` deploys it in the `thinkube-control` namespace and routes `https://control.<domain>/tk-package-version` to it.
- `ansible/40_thinkube/core/thinkube-control/13_configure_code_server.yaml` registers it with Claude Code in code-server as the MCP server `tk-package-version`, at `https://control.<domain>/tk-package-version/mcp`.

## Configuration

Set by command-line flag or environment variable (`src/main.rs`):

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `18080` | Port to listen on |
| `BASE_URL` | none, required | Public address, written to the log. The server does not start without it. The deploy playbook sets it to `https://control.<domain>/tk-package-version`. |
| `LOG_LEVEL` | `info` | Log level |
| `CACHE_TTL` | `300` | Seconds a version lookup stays cached |

## Working on it

```bash
cargo build --release
cargo run -- --port 18080 --base-url http://localhost:18080
```

The MCP endpoint is then at `http://localhost:18080/mcp`. The resolve and audit tools need `uv`, `pnpm` and `osv-scanner` on `PATH`.

## License

Apache License 2.0 - See [LICENSE](LICENSE)

## Copyright

Copyright Alejandro Martínez Corriá and the Thinkube contributors
