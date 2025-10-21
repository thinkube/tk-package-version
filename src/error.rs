// Copyright 2025 Alejandro Martínez Corriá and the Thinkube contributors
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PackageVersionError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Registry API error: {0}")]
    RegistryError(String),

    #[error("Package not found: {0}")]
    PackageNotFound(String),

    #[error("Command execution failed: {0}")]
    CommandExecutionFailed(String),

    #[error("Tool not found: {0}")]
    ToolNotFound(String),
}

pub type Result<T> = std::result::Result<T, PackageVersionError>;