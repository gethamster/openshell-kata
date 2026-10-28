//! Local development and qualification tools; no Python interpreter required.
#[path = "../devtools/mod.rs"]
mod devtools;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devtools::main().await
}
