use clap::Parser;
use openshell_kata::{
    config::Config, driver::Driver,
    proto::openshell::compute::v1::compute_driver_server::ComputeDriverServer,
};
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    sync::Arc,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Arc::new(Config::parse());
    config.validate()?;
    if let Some(parent) = config.socket.parent() {
        if !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!("driver socket parent must be a private directory");
        }
    }
    if config.socket.exists() {
        anyhow::bail!(
            "driver socket already exists; remove only after verifying no active adapter"
        );
    }
    let listener = UnixListener::bind(&config.socket)?;
    std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o600))?;
    let driver = Driver::new(config.clone())?;
    let shutdown_driver = driver.clone();
    tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(driver))
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    shutdown_driver.close().await;
    std::fs::remove_file(&config.socket)?;
    Ok(())
}
