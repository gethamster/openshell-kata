//! Validate stock CLI tar downloads before its local extractor sees any bytes.
use crate::{supervisor::Runtime, upload::receive_validated_archive};
use anyhow::{Context, Result, bail};
use russh::{Channel, server::Msg};
use std::{sync::Arc, time::Duration};

/// The pinned upstream CLI uses this exact prefix for file and directory sync.
pub fn is_archive_command(command: &str) -> bool {
    command.starts_with("tar cf - -C ")
}

pub async fn serve(channel: Channel<Msg>, runtime: Arc<Runtime>, command: &str) -> Result<()> {
    let _permit = runtime
        .transfer_slots
        .clone()
        .try_acquire_owned()
        .context("file transfer concurrency limit reached")?;
    let policy = runtime
        .vm_policy
        .as_ref()
        .map(|p| p.filesystem)
        .unwrap_or_default();
    let mut child = runtime.guest.exec(&runtime.config, command)?;
    child.stdin.take();
    let stdout = child.stdout.take().context("download stdout unavailable")?;
    let mut stderr = child.stderr.take().context("download stderr unavailable")?;
    let operation = async {
        let stage = receive_validated_archive(stdout, tokio::io::sink(), &policy);
        let errors = async { tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await };
        let (archive, _, status) = tokio::try_join!(
            stage,
            async { errors.await.map_err(anyhow::Error::from) },
            async { child.wait().await.map_err(anyhow::Error::from) }
        )?;
        if !status.success() {
            bail!("guest archive creation failed");
        }
        archive.replay_to(channel.make_writer()).await?;
        channel.exit_status(0).await?;
        channel.eof().await?;
        channel.close().await?;
        Ok(())
    };
    tokio::select! {
        ()=runtime.cancel.cancelled()=>bail!("download cancelled"),
        result=tokio::time::timeout(Duration::from_secs(600),operation)=>result.context("download timed out")?,
    }
}
