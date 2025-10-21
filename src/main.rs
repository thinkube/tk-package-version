// Copyright 2025 Alejandro Martínez Corriá and the Thinkube contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use axum::{routing::get, Router, Json};
use clap::Parser;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use serde_json::json;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod handlers;
mod registry;
mod cache;
mod error;
mod executor;
mod tools;

use handlers::PackageVersionServer;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, env = "PORT", default_value = "18080")]
    port: u16,

    /// Base URL for the server
    #[arg(short, long, env = "BASE_URL", default_value = "http://localhost:18080")]
    base_url: String,

    /// Log level
    #[arg(short, long, env = "LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Cache TTL in seconds
    #[arg(long, env = "CACHE_TTL", default_value = "300")]
    cache_ttl: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("tk_package_version={},tower_http=debug", args.log_level).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting tk-package-version MCP server");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Base URL: {}", args.base_url);
    info!("Port: {}", args.port);

    // Create the MCP service with Streamable HTTP transport
    let service = StreamableHttpService::new(
        move || Ok(PackageVersionServer::new(args.cache_ttl)),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // Create the HTTP router with health endpoint and MCP endpoint
    let app = Router::new()
        .route("/health", get(health_handler))
        .nest_service("/mcp", service)
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive())
        );

    // Start the server
    let addr = format!("0.0.0.0:{}", args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Server listening on {}", addr);
    info!("Health endpoint: http://{}:{}/health", "0.0.0.0", args.port);
    info!("MCP endpoint: {}/mcp", args.base_url);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
            info!("Shutting down gracefully...");
        })
        .await?;

    Ok(())
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "tk-package-version",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
