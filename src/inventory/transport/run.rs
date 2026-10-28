//! Publish fresh observations and copy them without renewing their lease.
use super::{
    CourierConfig, Cursor, InventoryConfig, PublisherConfig, Result, api::Api, committed,
    inventory, publication, replacement, retained, unix_now,
};
use std::{path::Path, time::Duration};

// One generated observation and at most three bounded API operations fit the
// fifteen-second network budget; an ambiguous PUT receives one reconciliation GET.
pub(super) async fn publish_once(config: &PublisherConfig, source: &InventoryConfig) -> Result<()> {
    let api = Api::publisher(source);
    let target = config.target();
    let before = api.get(&target).await?;
    target.observe(&before)?;
    let next =
        tokio::time::timeout(Duration::from_secs(6), super::super::refresh(source)).await??;
    let (replace, rv) = replacement(&target, &before, &next)?;
    match api.put(&target, &replace).await {
        Ok(result) if committed(&target, &result, &next, &rv).is_ok() => Ok(()),
        _ => committed(&target, &api.get(&target).await?, &next, &rv),
    }
}

/// Generate fresh deny inventories and CAS-write only one precreated ConfigMap.
pub(crate) async fn run_publisher(path: &Path, once: bool) -> Result<()> {
    let config = PublisherConfig::load(path)?;
    let source = InventoryConfig::load(&config.inventory_config_file)?;
    publication::prepare(&source.output_path)?;
    loop {
        let start = tokio::time::Instant::now();
        let result = publish_once(&config, &source).await;
        if once {
            return result;
        }
        if let Err(error) = result {
            tracing::warn!(%error,"inventory publication failed; authority will expire");
        }
        tokio::select! {_=tokio::signal::ctrl_c()=>return Ok(()),_=tokio::time::sleep_until(start+Duration::from_secs(source.refresh_secs))=>{}}
    }
}

pub(super) async fn courier_once(
    config: &CourierConfig,
    cursor: &mut Option<Cursor>,
) -> Result<()> {
    let target = config.target();
    let reply = Api::courier(config).get(&target).await?;
    let (_, bytes) = target.observe(&reply)?;
    let now = unix_now()?;
    let value = inventory(&bytes, now)?;
    if let Some(previous) = cursor.as_ref()
        && !previous.admit(&value)?
    {
        return Ok(());
    }
    let next = Cursor::from_value(value, now)?;
    publication::publish(&config.output_path, &next.value)?;
    *cursor = Some(next);
    Ok(())
}

/// Read one exact ConfigMap directly; leave its original expiry untouched.
pub(crate) async fn run_courier(path: &Path, once: bool) -> Result<()> {
    let config = CourierConfig::load(path)?;
    let mut cursor = retained(&config.output_path)?;
    loop {
        let start = tokio::time::Instant::now();
        let result = courier_once(&config, &mut cursor).await;
        if once {
            return result;
        }
        if let Err(error) = result {
            tracing::warn!(%error,"inventory courier failed; previous file will expire");
        }
        tokio::select! {_=tokio::signal::ctrl_c()=>return Ok(()),_=tokio::time::sleep_until(start+Duration::from_millis(config.poll_millis))=>{}}
    }
}
