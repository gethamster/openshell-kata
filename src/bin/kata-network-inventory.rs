use anyhow::Result;
use clap::Parser;
use openshell_kata::inventory::{InventoryCli, TransportCli, run_inventory, run_transport};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    if std::env::args()
        .nth(1)
        .is_some_and(|argument| matches!(argument.as_str(), "publish" | "courier"))
    {
        run_transport(TransportCli::parse()).await
    } else {
        run_inventory(InventoryCli::parse()).await
    }
}
