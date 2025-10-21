// Copyright 2025 Alejandro Martínez Corriá and the Thinkube contributors
// SPDX-License-Identifier: Apache-2.0

use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn, error};

use crate::error::{PackageVersionError, Result};

/// Maximum time a command can run before being killed
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Result from executing an external command
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Execute a command with timeout and error handling
pub async fn execute_command(
    program: &str,
    args: &[&str],
    timeout_duration: Option<Duration>,
) -> Result<CommandResult> {
    debug!("Executing command: {} {:?}", program, args);

    let timeout_duration = timeout_duration.unwrap_or(DEFAULT_TIMEOUT);

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let result = timeout(timeout_duration, async {
        let output = cmd.output().await?;
        Ok::<_, std::io::Error>(output)
    }).await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let exit_code = output.status.code().unwrap_or(-1);

            if !output.status.success() {
                warn!("Command failed with exit code {}: {} {:?}", exit_code, program, args);
                debug!("stderr: {}", stderr);
            }

            Ok(CommandResult {
                stdout,
                stderr,
                exit_code,
            })
        }
        Ok(Err(e)) => {
            error!("Failed to execute command: {}", e);
            Err(PackageVersionError::CommandExecutionFailed(format!(
                "Failed to execute {}: {}", program, e
            )))
        }
        Err(_) => {
            warn!("Command timed out after {:?}: {} {:?}", timeout_duration, program, args);
            Ok(CommandResult {
                stdout: String::new(),
                stderr: format!("Command timed out after {:?}", timeout_duration),
                exit_code: -1,
            })
        }
    }
}


/// Check if a command is available in the system
pub async fn command_exists(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Information about an installed tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub available: bool,
    pub version: Option<String>,
}

/// Check if required tools are installed
pub async fn check_tools() -> Vec<ToolInfo> {
    let tools = vec![
        ("uv", vec!["--version"]),
        ("pnpm", vec!["--version"]),
        ("osv-scanner", vec!["--version"]),
        ("trivy", vec!["--version"]),
        ("cargo", vec!["--version"]),
    ];

    let mut tool_info = Vec::new();

    for (name, version_args) in tools {
        let available = command_exists(name).await;
        let version = if available {
            execute_command(name, &version_args, Some(Duration::from_secs(5)))
                .await
                .ok()
                .and_then(|r| {
                    if r.exit_code == 0 {
                        Some(r.stdout.lines().next().unwrap_or("").to_string())
                    } else {
                        None
                    }
                })
        } else {
            None
        };

        tool_info.push(ToolInfo {
            name: name.to_string(),
            available,
            version,
        });
    }

    tool_info
}