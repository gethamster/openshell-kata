//! Trusted Kubernetes lifecycle entrypoint for isolated Rust Kata guests.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    openshell_kata::kubernetes::run().await
}
