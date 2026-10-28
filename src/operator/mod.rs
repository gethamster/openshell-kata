//! Trusted startup preparation and bounded local driver readiness checks.

mod registry;
mod trust;

use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

/// Operator-owned startup inputs, never selected by sandbox requests.
#[derive(Clone, Debug)]
pub struct Prepare {
    pub registry_dir: PathBuf,
    pub system_ca: PathBuf,
    pub platform_ca: PathBuf,
    pub output: PathBuf,
}

/// Validate all retained records before restoring modes and publishing trust.
///
/// Record contents are never read. This runs before the adapter starts, with
/// exclusive startup ownership of the registry and trust output directory.
///
/// # Errors
/// Rejects unexpected ownership, links, public permissions, types, oversized CA
/// inputs, replacement races, or filesystem failures.
pub fn prepare(inputs: &Prepare) -> Result<()> {
    for path in [
        &inputs.registry_dir,
        &inputs.system_ca,
        &inputs.platform_ca,
        &inputs.output,
    ] {
        validate_path(path)?;
    }
    let registry = registry::ValidatedRegistry::inspect(&inputs.registry_dir)?;
    let bundle = trust::bundle(&inputs.system_ca, &inputs.platform_ca)?;
    let output = trust::Output::open(&inputs.output)?;
    if let Some(registry) = registry {
        registry.restore()?;
    }
    output.publish(&bundle)
}

/// Connect to an absolute Unix socket within a one-second deadline.
///
/// # Errors
/// Rejects relative paths, missing/refused sockets and connection deadlines.
pub async fn socket_ready(socket: &Path) -> Result<()> {
    validate_path(socket)?;
    tokio::time::timeout(
        Duration::from_secs(1),
        tokio::net::UnixStream::connect(socket),
    )
    .await
    .context("driver socket readiness timed out")?
    .context("driver socket is unavailable")?;
    Ok(())
}

fn validate_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir)),
        "operator path must be absolute without parent components"
    );
    Ok(())
}
