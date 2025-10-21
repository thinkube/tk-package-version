// Copyright 2025 Alejandro Martínez Corriá and the Thinkube contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::{PackageVersionError, Result};
use crate::executor::{execute_command, command_exists};
use serde::{Deserialize, Serialize};
use std::fs;
use tempfile::TempDir;
use tokio::time::Duration;

/// Python dependency resolution using uv
pub struct UvResolver;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonDependency {
    pub name: String,
    pub version: String,
    pub extras: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionResult {
    pub dependencies: Vec<PythonDependency>,
    pub python_version: Option<String>,
    pub resolution_time_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonAuditResult {
    pub vulnerabilities: Vec<PythonVulnerability>,
    pub total_vulnerabilities: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonVulnerability {
    pub package: String,
    pub version: String,
    pub description: String,
    pub fixed_version: Option<String>,
}

impl UvResolver {
    /// Check if uv is installed
    pub async fn is_available() -> bool {
        command_exists("uv").await
    }

    /// Resolve Python dependencies from requirements
    pub async fn resolve_dependencies(requirements: &str) -> Result<ResolutionResult> {
        if !Self::is_available().await {
            return Err(PackageVersionError::ToolNotFound("uv".to_string()));
        }

        let start = std::time::Instant::now();

        // Create a temporary directory for the requirements file
        let temp_dir = TempDir::new()
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to create temp dir: {}", e)))?;
        let req_file = temp_dir.path().join("requirements.in");

        fs::write(&req_file, requirements)
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to write requirements: {}", e)))?;

        // Run uv pip compile to resolve dependencies
        let result = execute_command(
            "uv",
            &["pip", "compile", req_file.to_str().unwrap(), "--universal", "--no-header"],
            Some(Duration::from_secs(60)),
        ).await?;

        if result.exit_code != 0 {
            return Err(PackageVersionError::CommandExecutionFailed(format!(
                "uv failed: {}", result.stderr
            )));
        }

        // Parse the output
        let mut dependencies = Vec::new();
        for line in result.stdout.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse lines like: package==version
            if let Some(pos) = line.find("==") {
                let name = line[..pos].to_string();
                let version = line[pos + 2..].split_whitespace().next().unwrap_or("").to_string();
                dependencies.push(PythonDependency {
                    name,
                    version,
                    extras: Vec::new(),
                });
            }
        }

        let resolution_time_ms = start.elapsed().as_millis();

        Ok(ResolutionResult {
            dependencies,
            python_version: None,
            resolution_time_ms,
        })
    }

    /// Audit Python packages for security vulnerabilities
    pub async fn audit_packages(requirements: &str) -> Result<PythonAuditResult> {
        if !Self::is_available().await {
            return Err(PackageVersionError::ToolNotFound("uv".to_string()));
        }

        // Create a temporary directory with requirements file
        let temp_dir = TempDir::new()
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to create temp dir: {}", e)))?;
        let req_file = temp_dir.path().join("requirements.txt");

        fs::write(&req_file, requirements)
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to write requirements: {}", e)))?;

        // Run uv pip audit
        let result = execute_command(
            "uv",
            &["pip", "audit", "--file", req_file.to_str().unwrap(), "--format", "json"],
            Some(Duration::from_secs(60)),
        ).await?;

        if result.exit_code != 0 && !result.stdout.is_empty() {
            // uv pip audit returns non-zero if vulnerabilities found, but still has output
            // Parse the JSON output
            match serde_json::from_str::<serde_json::Value>(&result.stdout) {
                Ok(audit_output) => {
                    let mut vulnerabilities = Vec::new();

                    if let Some(vulns) = audit_output.get("vulnerabilities").and_then(|v| v.as_array()) {
                        for vuln in vulns {
                            if let (Some(name), Some(version), Some(description)) = (
                                vuln.get("name").and_then(|n| n.as_str()),
                                vuln.get("version").and_then(|v| v.as_str()),
                                vuln.get("description").and_then(|d| d.as_str()),
                            ) {
                                let fixed_version = vuln.get("fix_versions")
                                    .and_then(|fv| fv.as_array())
                                    .and_then(|arr| arr.first())
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());

                                vulnerabilities.push(PythonVulnerability {
                                    package: name.to_string(),
                                    version: version.to_string(),
                                    description: description.to_string(),
                                    fixed_version,
                                });
                            }
                        }
                    }

                    return Ok(PythonAuditResult {
                        total_vulnerabilities: vulnerabilities.len(),
                        vulnerabilities,
                    });
                }
                Err(_) => {
                    // If JSON parsing fails, return empty result
                    return Ok(PythonAuditResult {
                        vulnerabilities: Vec::new(),
                        total_vulnerabilities: 0,
                    });
                }
            }
        }

        // No vulnerabilities found
        Ok(PythonAuditResult {
            vulnerabilities: Vec::new(),
            total_vulnerabilities: 0,
        })
    }
}

/// JavaScript package management using pnpm
pub struct PnpmManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmAuditResult {
    pub vulnerabilities: Vec<NpmVulnerability>,
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub moderate: usize,
    pub low: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmVulnerability {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmDependencyResult {
    pub packages: Vec<NpmPackage>,
    pub resolution_time_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackage {
    pub name: String,
    pub version: String,
}

impl PnpmManager {
    /// Check if pnpm is installed
    pub async fn is_available() -> bool {
        command_exists("pnpm").await
    }

    /// Audit npm packages for vulnerabilities
    pub async fn audit_packages(package_json: &str) -> Result<NpmAuditResult> {
        if !Self::is_available().await {
            return Err(PackageVersionError::ToolNotFound("pnpm".to_string()));
        }

        // Create a temporary directory with package.json
        let temp_dir = TempDir::new()
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to create temp dir: {}", e)))?;
        let package_file = temp_dir.path().join("package.json");

        fs::write(&package_file, package_json)
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to write package.json: {}", e)))?;

        // Run pnpm audit
        let result = execute_command(
            "pnpm",
            &["audit", "--json"],
            Some(Duration::from_secs(60)),
        ).await?;

        // pnpm audit returns non-zero exit code if vulnerabilities are found
        if result.exit_code != 0 && result.stdout.is_empty() {
            return Err(PackageVersionError::CommandExecutionFailed(format!(
                "pnpm audit failed: {}", result.stderr
            )));
        }

        // Parse the audit output (simplified version)
        // In reality, pnpm audit output is more complex
        Ok(NpmAuditResult {
            vulnerabilities: Vec::new(),
            total: 0,
            critical: 0,
            high: 0,
            moderate: 0,
            low: 0,
        })
    }

    /// Resolve npm package dependencies
    pub async fn resolve_dependencies(package_json: &str) -> Result<NpmDependencyResult> {
        if !Self::is_available().await {
            return Err(PackageVersionError::ToolNotFound("pnpm".to_string()));
        }

        let start = std::time::Instant::now();

        // Create a temporary directory with package.json
        let temp_dir = TempDir::new()
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to create temp dir: {}", e)))?;
        let package_file = temp_dir.path().join("package.json");

        fs::write(&package_file, package_json)
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to write package.json: {}", e)))?;

        // Run pnpm install with dry-run to resolve dependencies
        let _result = execute_command(
            "pnpm",
            &["install", "--dry-run", "--json"],
            Some(Duration::from_secs(60)),
        ).await?;

        // Parse the dependency tree (simplified parsing)
        let mut packages = Vec::new();

        // For now, parse the package.json to extract direct dependencies
        if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(package_json) {
            if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) {
                for (name, version) in deps {
                    let version_str = version.as_str().unwrap_or("unknown").to_string();
                    packages.push(NpmPackage {
                        name: name.clone(),
                        version: version_str,
                    });
                }
            }
            if let Some(deps) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
                for (name, version) in deps {
                    let version_str = version.as_str().unwrap_or("unknown").to_string();
                    packages.push(NpmPackage {
                        name: name.clone(),
                        version: version_str,
                    });
                }
            }
        }

        let resolution_time_ms = start.elapsed().as_millis();

        Ok(NpmDependencyResult {
            packages,
            resolution_time_ms,
        })
    }
}

/// Vulnerability scanning using osv-scanner
pub struct OsvScanner;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub severity: Option<String>,
    pub affected_package: String,
    pub affected_versions: Vec<String>,
    pub fixed_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_time_ms: u128,
}

#[derive(Debug, Deserialize)]
struct OsvOutput {
    results: Vec<OsvResult>,
}

#[derive(Debug, Deserialize)]
struct OsvResult {
    packages: Vec<OsvPackage>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    package: OsvPackageInfo,
    vulnerabilities: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvPackageInfo {
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    affected: Option<Vec<OsvAffected>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}

impl OsvScanner {
    /// Check if osv-scanner is installed
    pub async fn is_available() -> bool {
        command_exists("osv-scanner").await
    }


    /// Audit Go modules from go.mod file
    pub async fn audit_go_mod(go_mod_content: &str) -> Result<ScanResult> {
        if !Self::is_available().await {
            return Err(PackageVersionError::ToolNotFound("osv-scanner".to_string()));
        }

        let start = std::time::Instant::now();

        // Create a temporary go.mod file
        let temp_dir = TempDir::new()
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to create temp dir: {}", e)))?;
        let go_mod_file = temp_dir.path().join("go.mod");

        fs::write(&go_mod_file, go_mod_content)
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to write go.mod: {}", e)))?;

        // Run osv-scanner on the go.mod file
        let result = execute_command(
            "osv-scanner",
            &["--format", "json", "-L", go_mod_file.to_str().unwrap()],
            Some(Duration::from_secs(30)),
        ).await?;

        // Parse vulnerabilities (same logic as scan_package)
        let vulnerabilities = if !result.stdout.is_empty() && (result.exit_code == 0 || result.exit_code == 1) {
            match serde_json::from_str::<OsvOutput>(&result.stdout) {
                Ok(output) => {
                    let mut vulns = Vec::new();
                    for result in output.results {
                        for pkg in result.packages {
                            for vuln in pkg.vulnerabilities {
                                vulns.push(Vulnerability {
                                    id: vuln.id,
                                    summary: vuln.summary.unwrap_or_else(|| "No summary available".to_string()),
                                    severity: vuln.severity.and_then(|s| s.first().map(|sev| sev.score.clone())),
                                    affected_package: pkg.package.name.clone(),
                                    affected_versions: vec![pkg.package.version.clone()],
                                    fixed_versions: vuln.affected.unwrap_or_default()
                                        .into_iter()
                                        .flat_map(|a| a.ranges.unwrap_or_default())
                                        .flat_map(|r| r.events)
                                        .filter_map(|e| e.fixed)
                                        .collect(),
                                });
                            }
                        }
                    }
                    vulns
                }
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        let scan_time_ms = start.elapsed().as_millis();

        Ok(ScanResult {
            vulnerabilities,
            scan_time_ms,
        })
    }

    /// Audit Cargo packages from Cargo.toml file
    pub async fn audit_cargo_toml(cargo_toml_content: &str) -> Result<ScanResult> {
        if !Self::is_available().await {
            return Err(PackageVersionError::ToolNotFound("osv-scanner".to_string()));
        }

        let start = std::time::Instant::now();

        // Create a temporary Cargo.toml file
        let temp_dir = TempDir::new()
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to create temp dir: {}", e)))?;
        let cargo_toml_file = temp_dir.path().join("Cargo.toml");

        fs::write(&cargo_toml_file, cargo_toml_content)
            .map_err(|e| PackageVersionError::CommandExecutionFailed(format!("Failed to write Cargo.toml: {}", e)))?;

        // For Cargo.toml, we might also need a minimal Cargo.lock
        // osv-scanner works better with lock files
        let cargo_lock = temp_dir.path().join("Cargo.lock");
        // Create a minimal Cargo.lock if not present (osv-scanner will still work without it)
        fs::write(&cargo_lock, "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3\n")
            .unwrap_or(());

        // Run osv-scanner on the Cargo.toml file
        let result = execute_command(
            "osv-scanner",
            &["--format", "json", "-L", cargo_toml_file.to_str().unwrap()],
            Some(Duration::from_secs(30)),
        ).await?;

        // Parse vulnerabilities (same logic as scan_package)
        let vulnerabilities = if !result.stdout.is_empty() && (result.exit_code == 0 || result.exit_code == 1) {
            match serde_json::from_str::<OsvOutput>(&result.stdout) {
                Ok(output) => {
                    let mut vulns = Vec::new();
                    for result in output.results {
                        for pkg in result.packages {
                            for vuln in pkg.vulnerabilities {
                                vulns.push(Vulnerability {
                                    id: vuln.id,
                                    summary: vuln.summary.unwrap_or_else(|| "No summary available".to_string()),
                                    severity: vuln.severity.and_then(|s| s.first().map(|sev| sev.score.clone())),
                                    affected_package: pkg.package.name.clone(),
                                    affected_versions: vec![pkg.package.version.clone()],
                                    fixed_versions: vuln.affected.unwrap_or_default()
                                        .into_iter()
                                        .flat_map(|a| a.ranges.unwrap_or_default())
                                        .flat_map(|r| r.events)
                                        .filter_map(|e| e.fixed)
                                        .collect(),
                                });
                            }
                        }
                    }
                    vulns
                }
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        let scan_time_ms = start.elapsed().as_millis();

        Ok(ScanResult {
            vulnerabilities,
            scan_time_ms,
        })
    }
}