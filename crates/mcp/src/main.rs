//! Cedar MCP Server Binary
//!
//! Runs the Cedar MCP server for AI agent policy management.

use sondera_mcp::CedarMcpServer;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let server = CedarMcpServer::new();
    info!("Starting Cedar MCP server on stdio");
    server.run_stdio().await?;
    Ok(())
}
