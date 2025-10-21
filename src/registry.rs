// Copyright 2025 Alejandro Martínez Corriá and the Thinkube contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{PackageVersionError, Result};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};
use tracing::{debug, warn};

#[derive(Debug, Deserialize, Clone)]
pub struct PyPiDependencies {
    pub requires_dist: Vec<String>,
    pub requires_python: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GoDependency {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct CargoDependency {
    pub name: String,
    pub version_requirement: String,
}

#[derive(Debug, Clone)]
pub struct ContainerImageInfo {
    pub latest_tag: String,
    pub recent_tags: Vec<String>,
}

pub struct RegistryClient {
    client: Client,
    // Rate limiting: max 10 concurrent requests
    semaphore: Arc<Semaphore>,
    // Minimum delay between requests to same registry (ms)
    min_request_delay: Duration,
}

impl RegistryClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("tk-package-version/0.1.0 (https://github.com/thinkube/tk-package-version)")
                // Add respect for rate limits
                .default_headers({
                    let mut headers = reqwest::header::HeaderMap::new();
                    headers.insert("X-Purpose", "version-checking".parse().unwrap());
                    headers
                })
                .build()
                .expect("Failed to build HTTP client"),
            semaphore: Arc::new(Semaphore::new(10)), // Max 10 concurrent requests
            min_request_delay: Duration::from_millis(100), // 100ms between requests
        }
    }

    async fn rate_limited_request(&self, url: &str) -> Result<reqwest::Response> {
        // Acquire semaphore permit for rate limiting
        let _permit = self.semaphore.acquire().await
            .map_err(|e| PackageVersionError::RegistryError(format!("Semaphore error: {}", e)))?;

        // Small delay to avoid hammering APIs
        sleep(self.min_request_delay).await;

        // Retry logic with exponential backoff
        let mut retries = 0;
        let max_retries = 3;
        let mut delay = Duration::from_millis(500);

        loop {
            match self.client.get(url).send().await {
                Ok(response) => {
                    // Check for rate limiting headers
                    if let Some(retry_after) = response.headers().get("retry-after") {
                        if let Ok(seconds) = retry_after.to_str().unwrap_or("0").parse::<u64>() {
                            warn!("Rate limited by server, waiting {} seconds", seconds);
                            sleep(Duration::from_secs(seconds)).await;
                            continue;
                        }
                    }

                    // Check for 429 Too Many Requests
                    if response.status() == 429 {
                        warn!("Rate limited (429), backing off");
                        sleep(delay).await;
                        delay *= 2;
                        retries += 1;
                        if retries >= max_retries {
                            return Err(PackageVersionError::RegistryError(
                                "Rate limited after max retries".to_string()
                            ));
                        }
                        continue;
                    }

                    return Ok(response);
                }
                Err(e) if retries < max_retries => {
                    warn!("Request failed, retrying: {}", e);
                    sleep(delay).await;
                    delay *= 2;
                    retries += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    // NPM Registry - Rate limit: 250 req/min for anonymous
    pub async fn get_npm_version(&self, package: &str) -> Result<String> {
        let url = format!("https://registry.npmjs.org/{}/latest", package);
        debug!("Fetching NPM package version: {}", package);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(PackageVersionError::PackageNotFound(package.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("NPM API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct NpmPackage {
            version: String,
        }

        let npm_package: NpmPackage = response.json().await?;
        Ok(npm_package.version)
    }

    // PyPI Registry - No hard rate limit but be respectful
    pub async fn get_pypi_version(&self, package: &str) -> Result<String> {
        let url = format!("https://pypi.org/pypi/{}/json", package);
        debug!("Fetching PyPI package version: {}", package);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(PackageVersionError::PackageNotFound(package.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("PyPI API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct PyPiResponse {
            info: PyPiInfo,
        }

        #[derive(Deserialize)]
        struct PyPiInfo {
            version: String,
        }

        let pypi_response: PyPiResponse = response.json().await?;
        Ok(pypi_response.info.version)
    }

    // Go Proxy - Google's proxy, very generous limits
    pub async fn get_go_version(&self, module: &str) -> Result<String> {
        let url = format!("https://proxy.golang.org/{}/@latest", module);
        debug!("Fetching Go module version: {}", module);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 || response.status() == 410 {
                return Err(PackageVersionError::PackageNotFound(module.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("Go proxy API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct GoProxyResponse {
            #[serde(rename = "Version")]
            version: String,
        }

        let go_response: GoProxyResponse = response.json().await?;
        Ok(go_response.version)
    }

    // Crates.io - Rate limit: 1 req/sec sustained, burst to 10
    pub async fn get_cargo_version(&self, package: &str) -> Result<String> {
        // Extra delay for crates.io's strict rate limit
        sleep(Duration::from_millis(200)).await;

        let url = format!("https://crates.io/api/v1/crates/{}", package);
        debug!("Fetching Cargo package version: {}", package);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(PackageVersionError::PackageNotFound(package.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("Crates.io API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct CratesResponse {
            #[serde(rename = "crate")]
            crate_info: CrateInfo,
        }

        #[derive(Deserialize)]
        struct CrateInfo {
            max_stable_version: Option<String>,
            max_version: String,
        }

        let crates_response: CratesResponse = response.json().await?;
        Ok(crates_response.crate_info.max_stable_version
            .unwrap_or(crates_response.crate_info.max_version))
    }

    // Get PyPI package dependencies
    pub async fn get_pypi_dependencies(&self, package: &str, _include_extras: bool) -> Result<PyPiDependencies> {
        let url = format!("https://pypi.org/pypi/{}/json", package);
        debug!("Fetching PyPI dependencies for: {}", package);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(PackageVersionError::PackageNotFound(package.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("PyPI API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct PyPiResponse {
            info: PyPiInfo,
        }

        #[derive(Deserialize)]
        struct PyPiInfo {
            requires_dist: Option<Vec<String>>,
            requires_python: Option<String>,
        }

        let pypi_response: PyPiResponse = response.json().await?;
        Ok(PyPiDependencies {
            requires_dist: pypi_response.info.requires_dist.unwrap_or_default(),
            requires_python: pypi_response.info.requires_python,
        })
    }

    pub async fn get_go_dependencies(&self, module: &str) -> Result<Vec<GoDependency>> {
        // First get the latest version
        let url = format!("https://proxy.golang.org/{}/@latest", module);
        debug!("Fetching Go module info for: {}", module);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(PackageVersionError::PackageNotFound(module.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("Go proxy API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct GoModuleInfo {
            #[serde(rename = "Version")]
            version: String,
        }

        let info: GoModuleInfo = response.json().await?;

        // Fetch go.mod file for the latest version
        let mod_url = format!("https://proxy.golang.org/{}/@v/{}.mod", module, info.version);
        let mod_response = self.rate_limited_request(&mod_url).await?;

        if !mod_response.status().is_success() {
            // Module might not have dependencies
            return Ok(Vec::new());
        }

        let mod_content = mod_response.text().await?;
        let mut dependencies = Vec::new();

        // Parse go.mod file (simple parsing for direct dependencies)
        let mut in_require_block = false;
        for line in mod_content.lines() {
            let line = line.trim();
            if line == "require (" {
                in_require_block = true;
                continue;
            }
            if in_require_block && line == ")" {
                break;
            }
            if in_require_block {
                // Parse lines like: github.com/pkg/errors v0.9.1
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && !parts[0].starts_with("//") {
                    dependencies.push(GoDependency {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                    });
                }
            } else if line.starts_with("require ") {
                // Single line require: require github.com/pkg/errors v0.9.1
                let parts: Vec<&str> = line[8..].split_whitespace().collect();
                if parts.len() >= 2 {
                    dependencies.push(GoDependency {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                    });
                }
            }
        }

        Ok(dependencies)
    }

    pub async fn get_cargo_dependencies(&self, crate_name: &str) -> Result<Vec<CargoDependency>> {
        let url = format!("https://crates.io/api/v1/crates/{}", crate_name);
        debug!("Fetching Cargo crate dependencies for: {}", crate_name);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(PackageVersionError::PackageNotFound(crate_name.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("crates.io API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct CrateResponse {
            #[serde(rename = "crate")]
            crate_info: CrateInfo,
        }

        #[derive(Deserialize)]
        struct CrateInfo {
            max_version: String,
        }

        let crate_response: CrateResponse = response.json().await?;

        // Find the latest stable version
        let latest_version = &crate_response.crate_info.max_version;

        // Get dependencies for the latest version
        let deps_url = format!("https://crates.io/api/v1/crates/{}/{}/dependencies",
                              crate_name, latest_version);
        let deps_response = self.rate_limited_request(&deps_url).await?;

        if !deps_response.status().is_success() {
            // Crate might not have dependencies
            return Ok(Vec::new());
        }

        #[derive(Deserialize)]
        struct DependenciesResponse {
            dependencies: Vec<Dependency>,
        }

        #[derive(Deserialize)]
        struct Dependency {
            #[serde(rename = "crate_id")]
            name: String,
            req: String,
            kind: String,
        }

        let deps: DependenciesResponse = deps_response.json().await?;

        // Filter to only normal dependencies (not dev or build)
        let dependencies = deps.dependencies
            .into_iter()
            .filter(|d| d.kind == "normal")
            .map(|d| CargoDependency {
                name: d.name,
                version_requirement: d.req,
            })
            .collect();

        Ok(dependencies)
    }

    pub async fn get_container_image_version(&self, registry: &str, image: &str) -> Result<ContainerImageInfo> {
        match registry {
            "docker" => self.get_docker_image_info(image).await,
            "ghcr" => self.get_ghcr_image_info(image).await,
            "gcr" => self.get_gcr_image_info(image).await,
            "k8s" => self.get_k8s_image_info(image).await,
            _ => Err(PackageVersionError::RegistryError(
                format!("Unknown container registry: {}", registry)
            ))
        }
    }

    async fn get_docker_image_info(&self, image: &str) -> Result<ContainerImageInfo> {
        let (namespace, repo) = if image.contains('/') {
            let parts: Vec<&str> = image.splitn(2, '/').collect();
            (parts[0], parts[1])
        } else {
            ("library", image)
        };

        let url = format!("https://hub.docker.com/v2/repositories/{}/{}/tags?page_size=25", namespace, repo);
        debug!("Fetching Docker Hub tags for {}/{}", namespace, repo);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(PackageVersionError::PackageNotFound(image.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("Docker Hub API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct DockerResponse {
            results: Vec<DockerTag>,
        }

        #[derive(Deserialize)]
        struct DockerTag {
            name: String,
        }

        let docker_response: DockerResponse = response.json().await?;
        let tags: Vec<String> = docker_response.results
            .into_iter()
            .map(|t| t.name)
            .collect();

        let latest = tags.iter()
            .find(|t| *t == "latest")
            .or_else(|| tags.first())
            .ok_or_else(|| PackageVersionError::RegistryError("No tags found".to_string()))?
            .clone();

        Ok(ContainerImageInfo {
            latest_tag: latest,
            recent_tags: tags,
        })
    }


    async fn get_ghcr_image_info(&self, image: &str) -> Result<ContainerImageInfo> {
        // GitHub Container Registry uses OCI Distribution API
        // Format: owner/image or org/image
        let parts: Vec<&str> = image.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(PackageVersionError::RegistryError(
                format!("Invalid GHCR image format: {}", image)
            ));
        }

        // GHCR requires authentication for most images, but we can try public access
        let url = format!("https://ghcr.io/v2/{}/{}/tags/list", parts[0], parts[1]);
        debug!("Fetching GHCR tags for {}", image);

        let response = self.client
            .get(&url)
            .header("Accept", "application/vnd.docker.distribution.manifest.v2+json")
            .send()
            .await?;

        if !response.status().is_success() {
            // Try using GitHub API as fallback
            return self.get_ghcr_via_github_api(parts[0], parts[1]).await;
        }

        #[derive(Deserialize)]
        struct TagsResponse {
            tags: Vec<String>,
        }

        let tags_response: TagsResponse = response.json().await?;
        let tags = tags_response.tags;

        let latest = tags.iter()
            .find(|t| *t == "latest")
            .or_else(|| tags.first())
            .ok_or_else(|| PackageVersionError::RegistryError("No tags found".to_string()))?
            .clone();

        Ok(ContainerImageInfo {
            latest_tag: latest,
            recent_tags: tags,
        })
    }

    async fn get_ghcr_via_github_api(&self, owner: &str, repo: &str) -> Result<ContainerImageInfo> {
        // GitHub API fallback for public packages
        let url = format!("https://api.github.com/users/{}/packages/container/{}/versions", owner, repo);
        debug!("Fetching GHCR tags via GitHub API for {}/{}", owner, repo);

        let response = self.client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(PackageVersionError::RegistryError(
                format!("GitHub API returned status: {} for {}/{}", response.status(), owner, repo)
            ));
        }

        #[derive(Deserialize)]
        struct GitHubPackageVersion {
            metadata: Metadata,
        }

        #[derive(Deserialize)]
        struct Metadata {
            container: Container,
        }

        #[derive(Deserialize)]
        struct Container {
            tags: Vec<String>,
        }

        let versions: Vec<GitHubPackageVersion> = response.json().await?;
        let mut all_tags = Vec::new();

        for version in versions.iter().take(10) {
            all_tags.extend(version.metadata.container.tags.clone());
        }

        let latest = all_tags.iter()
            .find(|t| *t == "latest")
            .or_else(|| all_tags.first())
            .ok_or_else(|| PackageVersionError::RegistryError("No tags found".to_string()))?
            .clone();

        Ok(ContainerImageInfo {
            latest_tag: latest,
            recent_tags: all_tags,
        })
    }

    async fn get_gcr_image_info(&self, image: &str) -> Result<ContainerImageInfo> {
        // Google Container Registry uses OCI Distribution API
        // Format: project-id/image
        let url = format!("https://gcr.io/v2/{}/tags/list", image);
        debug!("Fetching GCR tags for {}", image);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(PackageVersionError::PackageNotFound(image.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("GCR API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct TagsResponse {
            tags: Option<Vec<String>>,
        }

        let tags_response: TagsResponse = response.json().await?;
        let tags = tags_response.tags.unwrap_or_default();

        if tags.is_empty() {
            return Err(PackageVersionError::RegistryError("No tags found".to_string()));
        }

        let latest = tags.iter()
            .find(|t| *t == "latest")
            .or_else(|| tags.first())
            .ok_or_else(|| PackageVersionError::RegistryError("No tags found".to_string()))?
            .clone();

        Ok(ContainerImageInfo {
            latest_tag: latest,
            recent_tags: tags,
        })
    }

    async fn get_k8s_image_info(&self, image: &str) -> Result<ContainerImageInfo> {
        // Kubernetes registry (registry.k8s.io)
        let url = format!("https://registry.k8s.io/v2/{}/tags/list", image);
        debug!("Fetching Kubernetes registry tags for {}", image);

        let response = self.rate_limited_request(&url).await?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(PackageVersionError::PackageNotFound(image.to_string()));
            }
            return Err(PackageVersionError::RegistryError(
                format!("Kubernetes registry API returned status: {}", response.status())
            ));
        }

        #[derive(Deserialize)]
        struct TagsResponse {
            tags: Option<Vec<String>>,
        }

        let tags_response: TagsResponse = response.json().await?;
        let tags = tags_response.tags.unwrap_or_default();

        if tags.is_empty() {
            return Err(PackageVersionError::RegistryError("No tags found".to_string()));
        }

        // For k8s, prefer versioned tags over "latest"
        let latest = tags.iter()
            .filter(|t| !t.contains("rc") && !t.contains("alpha") && !t.contains("beta"))
            .max()
            .or_else(|| tags.first())
            .ok_or_else(|| PackageVersionError::RegistryError("No tags found".to_string()))?
            .clone();

        Ok(ContainerImageInfo {
            latest_tag: latest,
            recent_tags: tags,
        })
    }
}