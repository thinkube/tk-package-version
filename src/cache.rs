// Copyright 2025 Alejandro Martínez Corriá and the Thinkube contributors
// SPDX-License-Identifier: Apache-2.0

use moka::future::Cache;
use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedVersion {
    pub package_name: String,
    pub latest_version: String,
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

pub struct VersionCache {
    cache: Cache<String, CachedVersion>,
}

impl VersionCache {
    pub fn new(ttl_seconds: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_seconds))
            .max_capacity(10000)
            .build();

        Self { cache }
    }

    pub async fn get(&self, key: &str) -> Option<CachedVersion> {
        self.cache.get(key).await
    }

    pub async fn insert(&self, key: String, value: CachedVersion) {
        self.cache.insert(key, value).await;
    }

    pub fn create_key(registry: &str, package: &str) -> String {
        format!("{}:{}", registry, package)
    }
}