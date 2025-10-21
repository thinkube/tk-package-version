// Copyright 2025 Alejandro Martínez Corriá and the Thinkube contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cache::{VersionCache, CachedVersion};
use crate::registry::RegistryClient;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{
        router::tool::ToolRouter,
        wrapper::Parameters,
    },
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info};

// Input structs for tools
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct NpmPackageArgs {
    /// The npm package name to check
    pub package: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PyPiPackageArgs {
    /// The Python package name to check
    pub package: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GoModuleArgs {
    /// The Go module path (e.g., github.com/user/repo)
    pub module: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CargoCrateArgs {
    /// The Rust crate name
    #[serde(rename = "crate")]
    pub crate_name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GoDependenciesArgs {
    /// The Go module path (e.g., github.com/user/repo)
    pub module: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CargoDependenciesArgs {
    /// The Rust crate name
    #[serde(rename = "crate")]
    pub crate_name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ContainerImageArgs {
    /// The container image (e.g., nginx, ghcr.io/owner/image, gcr.io/project/image)
    pub image: String,
    /// Registry to use (docker, ghcr, gcr, or auto-detect from image name)
    #[serde(default = "default_registry")]
    pub registry: String,
}

fn default_registry() -> String {
    "auto".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PyPiDependenciesArgs {
    /// The Python package name to check dependencies for
    pub package: String,
    /// Include optional/extra dependencies (default: false)
    #[serde(default)]
    pub include_extras: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ResolvePythonArgs {
    /// Python requirements (same format as requirements.txt)
    pub requirements: String,
}


#[derive(Debug, serde::Deserialize, schemars::JsonSchema, Default)]
pub struct EmptyArgs {}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditNpmArgs {
    /// package.json content as string
    pub package_json: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditPythonArgs {
    /// Python requirements (same format as requirements.txt)
    pub requirements: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditGoArgs {
    /// go.mod file content as string
    pub go_mod: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditCargoArgs {
    /// Cargo.toml file content as string
    pub cargo_toml: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ResolveDependenciesArgs {
    /// package.json content as string
    pub package_json: String,
}

#[derive(Clone)]
pub struct PackageVersionServer {
    cache: Arc<VersionCache>,
    registry_client: Arc<RegistryClient>,
    tool_router: ToolRouter<PackageVersionServer>,
}

#[tool_router]
impl PackageVersionServer {
    pub fn new(cache_ttl: u64) -> Self {
        Self {
            cache: Arc::new(VersionCache::new(cache_ttl)),
            registry_client: Arc::new(RegistryClient::new()),
            tool_router: Self::tool_router(),
        }
    }

    async fn check_version(&self, registry: &str, package: &str) -> Result<String, crate::error::PackageVersionError> {
        let cache_key = VersionCache::create_key(registry, package);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Cache hit for {}:{}", registry, package);
            return Ok(cached.latest_version);
        }

        // Fetch from registry
        debug!("Cache miss for {}:{}, fetching from registry", registry, package);
        let version = match registry {
            "npm" => self.registry_client.get_npm_version(package).await?,
            "pypi" => self.registry_client.get_pypi_version(package).await?,
            "go" => self.registry_client.get_go_version(package).await?,
            "cargo" => self.registry_client.get_cargo_version(package).await?,
            _ => return Err(crate::error::PackageVersionError::RegistryError(
                format!("Unknown registry: {}", registry)
            )),
        };

        // Cache the result
        let cached = CachedVersion {
            package_name: package.to_string(),
            latest_version: version.clone(),
            cached_at: chrono::Utc::now(),
        };
        self.cache.insert(cache_key, cached).await;

        Ok(version)
    }

    #[tool(description = "Check the latest version of an npm package")]
    async fn check_npm_version(
        &self,
        Parameters(args): Parameters<NpmPackageArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Checking npm package: {}", args.package);

        match self.check_version("npm", &args.package).await {
            Ok(version) => Ok(CallToolResult::success(vec![Content::text(
                format!("Latest version of {} on npm: {}", args.package, version)
            )])),
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to check version: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Check the latest version of a Python package on PyPI")]
    async fn check_pypi_version(
        &self,
        Parameters(args): Parameters<PyPiPackageArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Checking PyPI package: {}", args.package);

        match self.check_version("pypi", &args.package).await {
            Ok(version) => Ok(CallToolResult::success(vec![Content::text(
                format!("Latest version of {} on PyPI: {}", args.package, version)
            )])),
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to check version: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Check the latest version of a Go module")]
    async fn check_go_version(
        &self,
        Parameters(args): Parameters<GoModuleArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Checking Go module: {}", args.module);

        match self.check_version("go", &args.module).await {
            Ok(version) => Ok(CallToolResult::success(vec![Content::text(
                format!("Latest version of {}: {}", args.module, version)
            )])),
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to check version: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Check dependencies for a Go module")]
    async fn check_go_dependencies(
        &self,
        Parameters(args): Parameters<GoDependenciesArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Checking Go module dependencies: {}", args.module);

        match self.registry_client.get_go_dependencies(&args.module).await {
            Ok(deps) => {
                let mut output = vec![format!("Dependencies for Go module {}:", args.module)];

                if deps.is_empty() {
                    output.push("No dependencies found".to_string());
                } else {
                    output.push(format!("\nDirect dependencies ({}):", deps.len()));
                    for dep in deps {
                        output.push(format!("  • {}: {}", dep.name, dep.version));
                    }
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to check dependencies: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Check the latest version of a Rust crate on crates.io")]
    async fn check_cargo_version(
        &self,
        Parameters(args): Parameters<CargoCrateArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Checking Cargo crate: {}", args.crate_name);

        match self.check_version("cargo", &args.crate_name).await {
            Ok(version) => Ok(CallToolResult::success(vec![Content::text(
                format!("Latest version of {} on crates.io: {}", args.crate_name, version)
            )])),
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to check version: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Check dependencies for a Rust crate")]
    async fn check_cargo_dependencies(
        &self,
        Parameters(args): Parameters<CargoDependenciesArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Checking Cargo crate dependencies: {}", args.crate_name);

        match self.registry_client.get_cargo_dependencies(&args.crate_name).await {
            Ok(deps) => {
                let mut output = vec![format!("Dependencies for Rust crate {}:", args.crate_name)];

                if deps.is_empty() {
                    output.push("No dependencies found".to_string());
                } else {
                    output.push(format!("\nDirect dependencies ({}):", deps.len()));
                    for dep in deps {
                        output.push(format!("  • {}: {}", dep.name, dep.version_requirement));
                    }
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to check dependencies: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Check the latest version/tag of a container image from any registry")]
    async fn check_container_image(
        &self,
        Parameters(args): Parameters<ContainerImageArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Checking container image: {} (registry: {})", args.image, args.registry);

        // Auto-detect registry from image name or use specified
        let (registry, image) = if args.registry == "auto" {
            if args.image.starts_with("ghcr.io/") {
                ("ghcr", args.image.strip_prefix("ghcr.io/").unwrap())
            } else if args.image.starts_with("gcr.io/") {
                ("gcr", args.image.strip_prefix("gcr.io/").unwrap())
            } else if args.image.starts_with("registry.k8s.io/") {
                ("k8s", args.image.strip_prefix("registry.k8s.io/").unwrap())
            } else if args.image.contains('/') && !args.image.contains('.') {
                // Default to Docker Hub for images like "nginx/nginx"
                ("docker", args.image.as_str())
            } else {
                ("docker", args.image.as_str())
            }
        } else {
            (args.registry.as_str(), args.image.as_str())
        };

        match self.registry_client.get_container_image_version(registry, image).await {
            Ok(version_info) => {
                let registry_name = match registry {
                    "docker" => "Docker Hub",
                    "ghcr" => "GitHub Container Registry",
                    "gcr" => "Google Container Registry",
                    "k8s" => "Kubernetes Registry",
                    _ => registry,
                };

                let mut output = vec![
                    format!("Container Image: {}", image),
                    format!("Registry: {}", registry_name),
                    format!("Latest tag: {}", version_info.latest_tag),
                ];

                if !version_info.recent_tags.is_empty() {
                    output.push(format!("\nRecent tags ({}):", version_info.recent_tags.len()));
                    for tag in version_info.recent_tags.iter().take(10) {
                        output.push(format!("  • {}", tag));
                    }
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to check image: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Check dependencies and requirements for a PyPI package")]
    async fn check_pypi_dependencies(
        &self,
        Parameters(args): Parameters<PyPiDependenciesArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Checking PyPI dependencies for: {}", args.package);

        match self.registry_client.get_pypi_dependencies(&args.package, args.include_extras).await {
            Ok(deps) => {
                let mut output = vec![format!("Dependencies for {} on PyPI:", args.package)];

                if deps.requires_dist.is_empty() {
                    output.push("No dependencies listed".to_string());
                } else {
                    output.push("\nCore dependencies:".to_string());
                    for dep in &deps.requires_dist {
                        if !dep.contains("; extra ==") || args.include_extras {
                            output.push(format!("  - {}", dep));
                        }
                    }
                }

                if let Some(python_req) = deps.requires_python {
                    output.push(format!("\nPython version requirement: {}", python_req));
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to check dependencies: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Resolve Python dependencies using uv (ultra-fast Python package resolver)")]
    async fn resolve_python_dependencies(
        &self,
        Parameters(args): Parameters<ResolvePythonArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Resolving Python dependencies with uv");

        match crate::tools::UvResolver::resolve_dependencies(&args.requirements).await {
            Ok(result) => {
                let mut output = vec![
                    "Python Dependency Resolution:".to_string(),
                    format!("Resolved {} dependencies in {}ms",
                            result.dependencies.len(),
                            result.resolution_time_ms),
                    String::new(),
                    "Resolved versions:".to_string(),
                ];

                for dep in result.dependencies {
                    output.push(format!("  {}=={}", dep.name, dep.version));
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to resolve dependencies: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Check which external tools are available for package management")]
    async fn check_available_tools(
        &self,
        _params: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Checking available external tools");

        let tools = crate::executor::check_tools().await;

        let mut output = vec![
            "External Tool Availability:".to_string(),
            String::new(),
        ];

        for tool in tools {
            let status = if tool.available { "✅" } else { "❌" };
            let version_str = tool.version.unwrap_or_else(|| "Not installed".to_string());
            output.push(format!("{} {}: {}", status, tool.name, version_str));
        }

        output.push(String::new());
        output.push("Tools provide:".to_string());
        output.push("  • uv: Python dependency resolution and lock files".to_string());
        output.push("  • pnpm: JavaScript package management".to_string());
        output.push("  • osv-scanner: Multi-ecosystem vulnerability scanning".to_string());
        output.push("  • trivy: Container and IaC security scanning".to_string());
        output.push("  • cargo: Rust package management".to_string());

        Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
    }

    #[tool(description = "Audit npm packages for security vulnerabilities using pnpm")]
    async fn audit_npm_packages(
        &self,
        Parameters(args): Parameters<AuditNpmArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Auditing npm packages with pnpm");

        match crate::tools::PnpmManager::audit_packages(&args.package_json).await {
            Ok(result) => {
                let mut output = vec![
                    "NPM Security Audit Results:".to_string(),
                    format!("Total vulnerabilities: {}", result.total),
                ];

                if result.total > 0 {
                    output.push(format!("  Critical: {}", result.critical));
                    output.push(format!("  High: {}", result.high));
                    output.push(format!("  Moderate: {}", result.moderate));
                    output.push(format!("  Low: {}", result.low));

                    if !result.vulnerabilities.is_empty() {
                        output.push("\nDetails:".to_string());
                        for vuln in result.vulnerabilities {
                            output.push(format!("  • {} ({})", vuln.name, vuln.severity));
                            output.push(format!("    {}", vuln.description));
                        }
                    }
                } else {
                    output.push("✅ No vulnerabilities found".to_string());
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to audit packages: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Audit Python packages for security vulnerabilities using uv")]
    async fn audit_python_packages(
        &self,
        Parameters(args): Parameters<AuditPythonArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Auditing Python packages with uv");

        match crate::tools::UvResolver::audit_packages(&args.requirements).await {
            Ok(result) => {
                let mut output = vec![
                    "Python Security Audit Results:".to_string(),
                    format!("Total vulnerabilities: {}", result.total_vulnerabilities),
                ];

                if result.total_vulnerabilities > 0 {
                    output.push("\nVulnerable packages:".to_string());
                    for vuln in result.vulnerabilities {
                        output.push(format!("  • {} {}: {}",
                            vuln.package, vuln.version, vuln.description));
                        if let Some(fix) = vuln.fixed_version {
                            output.push(format!("    Fix available: upgrade to {}", fix));
                        }
                    }
                } else {
                    output.push("✅ No vulnerabilities found".to_string());
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to audit packages: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Audit Go packages for security vulnerabilities")]
    async fn audit_go_packages(
        &self,
        Parameters(args): Parameters<AuditGoArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Auditing Go packages with osv-scanner");

        match crate::tools::OsvScanner::audit_go_mod(&args.go_mod).await {
            Ok(result) => {
                let mut output = vec![
                    "Go Security Audit Results:".to_string(),
                    format!("Total vulnerabilities: {}", result.vulnerabilities.len()),
                ];

                if !result.vulnerabilities.is_empty() {
                    output.push("\nVulnerable packages:".to_string());
                    for vuln in result.vulnerabilities {
                        output.push(format!("  • {} ({}): {}",
                            vuln.affected_package,
                            vuln.affected_versions.join(", "),
                            vuln.summary));
                        if !vuln.fixed_versions.is_empty() {
                            output.push(format!("    Fix available: upgrade to {}",
                                vuln.fixed_versions.join(" or ")));
                        }
                    }
                } else {
                    output.push("✅ No vulnerabilities found".to_string());
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to audit packages: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Audit Rust packages for security vulnerabilities")]
    async fn audit_cargo_packages(
        &self,
        Parameters(args): Parameters<AuditCargoArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Auditing Cargo packages with osv-scanner");

        match crate::tools::OsvScanner::audit_cargo_toml(&args.cargo_toml).await {
            Ok(result) => {
                let mut output = vec![
                    "Rust/Cargo Security Audit Results:".to_string(),
                    format!("Total vulnerabilities: {}", result.vulnerabilities.len()),
                ];

                if !result.vulnerabilities.is_empty() {
                    output.push("\nVulnerable packages:".to_string());
                    for vuln in result.vulnerabilities {
                        output.push(format!("  • {} ({}): {}",
                            vuln.affected_package,
                            vuln.affected_versions.join(", "),
                            vuln.summary));
                        if !vuln.fixed_versions.is_empty() {
                            output.push(format!("    Fix available: upgrade to {}",
                                vuln.fixed_versions.join(" or ")));
                        }
                    }
                } else {
                    output.push("✅ No vulnerabilities found".to_string());
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to audit packages: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }

    #[tool(description = "Resolve npm package dependencies using pnpm")]
    async fn resolve_npm_dependencies(
        &self,
        Parameters(args): Parameters<ResolveDependenciesArgs>,
    ) -> Result<CallToolResult, McpError> {
        info!("Resolving npm dependencies with pnpm");

        match crate::tools::PnpmManager::resolve_dependencies(&args.package_json).await {
            Ok(result) => {
                let mut output = vec![
                    "NPM Dependency Resolution:".to_string(),
                    format!("Resolved {} packages in {}ms",
                            result.packages.len(),
                            result.resolution_time_ms),
                    String::new(),
                    "Resolved versions:".to_string(),
                ];

                for pkg in result.packages {
                    output.push(format!("  {}@{}", pkg.name, pkg.version));
                }

                Ok(CallToolResult::success(vec![Content::text(output.join("\n"))]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode(-32603),
                format!("Failed to resolve dependencies: {}", e),
                Some(json!({ "error": e.to_string() }))
            ))
        }
    }
}

#[tool_handler]
impl ServerHandler for PackageVersionServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_03_26,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation {
                name: "tk-package-version".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("Thinkube Package Version Checker".to_string()),
                website_url: Some("https://github.com/thinkube/tk-package-version".to_string()),
                icons: None,
            },
            instructions: Some(
                "This server provides tools to check the latest versions of packages across multiple registries: npm, PyPI, Go modules, Cargo crates, and Docker images. All version checks are cached for 5 minutes to avoid excessive API calls."
                .to_string()
            ),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Ok(self.get_info())
    }
}