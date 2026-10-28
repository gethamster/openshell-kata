//! Trusted read-only Kubernetes observer for node-owned preboot launch intent.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_writer(std::io::stderr)
        .init();
    openshell_kata::node_intent::run_node_intent().await
}
