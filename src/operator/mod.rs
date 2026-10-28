//! Trusted startup preparation and bounded local driver readiness checks.

mod inventory;
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
    /// Optional whole hosted-state migration, including keys and stable locks.
    pub state_dir: Option<PathBuf>,
    /// Optional owned private socket directory beneath the shared mount root.
    pub driver_dir: Option<PathBuf>,
    /// Recovery registry; must equal `state_dir/registry` during full migration.
    pub registry_dir: PathBuf,
    /// Trusted public system CA bundle, bounded independently of platform trust.
    pub system_ca: PathBuf,
    /// Trusted platform CA input; projected operator-owned symlinks are allowed.
    pub platform_ca: PathBuf,
    /// CA bundle output inside a private owned child directory.
    pub output: PathBuf,
}

/// Validate all retained records before restoring modes and publishing trust.
///
/// State contents are never read, renamed or replaced. Legacy key-only folders
/// stay key-only; this function never invents metadata or a lifetime lease.
/// Only known public-key files and empty stable locks may have legacy other-read
/// permission. Retained directories become `0700` and files `0600` in place.
///
/// Run after quiescing the owner and taking its encrypted backup. This requires
/// exclusive startup ownership of state and control directories; held locks
/// detect busy known identities but cannot exclude an unrelated new writer.
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
    for path in inputs.state_dir.iter().chain(inputs.driver_dir.iter()) {
        validate_path(path)?;
    }
    if let Some(state) = &inputs.state_dir {
        ensure!(
            inputs.registry_dir == state.join("registry"),
            "registry must be the exact state/registry child"
        );
        ensure!(
            !inputs.output.starts_with(state)
                && inputs
                    .driver_dir
                    .as_ref()
                    .is_none_or(|driver| !driver.starts_with(state)),
            "control and trust output must be outside retained state"
        );
    }
    let state = inputs
        .state_dir
        .as_deref()
        .map(inventory::Tree::inspect)
        .transpose()?
        .flatten();
    let registry = if inputs.state_dir.is_none() {
        registry::ValidatedRegistry::inspect(&inputs.registry_dir)?
    } else {
        None
    };
    let bundle = trust::bundle(&inputs.system_ca, &inputs.platform_ca)?;
    if let Some(driver) = &inputs.driver_dir {
        trust::private_directory(driver)?;
    }
    let output = trust::Output::open(&inputs.output)?;
    if let Some(registry) = registry {
        registry.restore()?;
    }
    if let Some(state) = state {
        state.restore()?;
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
