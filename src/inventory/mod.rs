//! Cacheless infrastructure observations for short-lived hosted deny inventories.
mod config;
mod dns;
mod kube;
mod publication;
mod transport;
mod transport_cli;
pub use transport_cli::{TransportCli, run_transport};

use crate::network::InfrastructureInventory;
use anyhow::{Context, Result, ensure};
use clap::Parser;
pub use config::InventoryConfig;
use std::{
    collections::BTreeSet,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Observe Kubernetes and trusted recursive DNS, then atomically publish deny IPs.
#[derive(Debug, Parser)]
#[command(
    after_help = "ConfigMap modes: publish --config PATH [--once]; courier --config PATH [--once]."
)]
pub struct InventoryCli {
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub once: bool,
}

pub async fn run_inventory(cli: InventoryCli) -> Result<()> {
    let config = InventoryConfig::load(&cli.config)?;
    publication::prepare(&config.output_path)?;
    loop {
        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(15), refresh(&config)).await;
        match result {
            Ok(Ok(inventory)) => tracing::info!(
                generation = inventory.generation,
                expires = inventory.expires_at_unix,
                "infrastructure inventory published"
            ),
            Ok(Err(error)) if cli.once => return Err(error),
            Err(error) if cli.once => return Err(error.into()),
            Ok(Err(error)) => {
                tracing::warn!(%error,"inventory refresh failed; previous inventory will expire")
            }
            Err(error) => {
                tracing::warn!(%error,"inventory refresh deadline exceeded; previous inventory will expire")
            }
        }
        if cli.once {
            return Ok(());
        }
        tokio::select! { _=tokio::signal::ctrl_c()=>return Ok(()),_=tokio::time::sleep_until(started+Duration::from_secs(config.refresh_secs))=>{} }
    }
}

async fn refresh(config: &InventoryConfig) -> Result<InfrastructureInventory> {
    config.validate()?;
    let observed = SystemTime::now();
    let mut monotonic_deadline =
        tokio::time::Instant::now() + Duration::from_secs(config.freshness_secs);
    let mut footprint = kube::observe(config).await?;
    footprint
        .names
        .extend(config.protected_hostnames.iter().cloned());
    ensure!(
        footprint.names.len() <= 256,
        "too many infrastructure DNS names"
    );
    let mut deadline = observed + Duration::from_secs(config.freshness_secs);
    for name in &footprint.names {
        let answer = dns::observe(config, name).await?;
        deadline = deadline.min(answer.valid_until);
        monotonic_deadline = monotonic_deadline.min(answer.monotonic_deadline);
        footprint.cidrs.extend(answer.cidrs);
    }
    footprint.cidrs.extend(
        config
            .baseline_denied_cidrs
            .iter()
            .map(|s| s.parse::<ipnet::IpNet>().map(|net| net.trunc().to_string()))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?,
    );
    ensure!(
        !footprint.cidrs.is_empty() && footprint.cidrs.len() <= 4096,
        "empty or excessive infrastructure footprint"
    );
    let (issued, expires) = publication_times(deadline, monotonic_deadline, SystemTime::now())?;
    ensure!(
        expires > issued,
        "infrastructure observation expired before publication"
    );
    let inventory = InfrastructureInventory {
        version: 1,
        generation: publication::next_generation(&config.output_path)?,
        issued_at_unix: issued,
        expires_at_unix: expires,
        denied_cidrs: footprint.cidrs.into_iter().collect(),
    };
    inventory
        .validate_at(issued)
        .context("invalid completed inventory")?;
    publication::publish(&config.output_path, &inventory)?;
    Ok(inventory)
}

fn publication_times(
    deadline: SystemTime,
    monotonic_deadline: tokio::time::Instant,
    completed: SystemTime,
) -> Result<(u64, u64)> {
    let remaining = monotonic_deadline
        .checked_duration_since(tokio::time::Instant::now())
        .context("monotonic infrastructure observation expired")?;
    Ok((
        completed.duration_since(UNIX_EPOCH)?.as_secs(),
        deadline
            .min(completed + remaining)
            .duration_since(UNIX_EPOCH)?
            .as_secs(),
    ))
}

#[cfg(test)]
mod tests;
