use crate::{
    boundary::filesystem::{FilesystemPolicy, ImportStore, private_transfer_directory},
    config::shell_quote,
    supervisor::Runtime,
};
use anyhow::{Context, Result, bail};
use russh::{Channel, server::Msg};
use serde::Deserialize;
use std::{path::Component, path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::task::AbortOnDropHandle;

const MAX_PLAN_BYTES: usize = 16 * 1024;
const ACK_INTERVAL: u64 = 256 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadPlan {
    pub destination_directory: String,
    pub expected_destination: Option<Destination>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub path: String,
    pub kind: String,
}
impl UploadPlan {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PLAN_BYTES {
            bail!("upload plan too large");
        }
        let plan: Self = serde_json::from_slice(bytes).context("invalid upload plan")?;
        if plan.destination_directory.chars().any(char::is_control)
            || plan.expected_destination.as_ref().is_some_and(|expected| {
                expected.path.chars().any(char::is_control)
                    || !matches!(expected.kind.as_str(), "directory" | "file" | "missing")
            })
        {
            bail!("invalid upload destination metadata");
        }
        let path = Path::new(&plan.destination_directory);
        if !(plan.destination_directory == "/sandbox"
            || plan.destination_directory.starts_with("/sandbox/"))
            || path.components().any(|p| matches!(p, Component::ParentDir))
        {
            bail!("upload destination must be inside /sandbox");
        }
        Ok(plan)
    }
    fn command(&self) -> Result<String> {
        let destination = shell_quote(&self.destination_directory);
        let check = if let Some(expected) = &self.expected_destination {
            let path = shell_quote(&expected.path);
            match expected.kind.as_str() {
                "directory" => format!("test -d {path}"),
                "file" => format!("test -f {path}"),
                "missing" => format!("test ! -e {path} && test ! -L {path}"),
                _ => bail!("invalid expected destination kind"),
            }
        } else {
            "true".to_owned()
        };
        Ok(format!(
            "({check}) || exit 73; mkdir -p {destination} && exec tar -xf - -C {destination}"
        ))
    }
}

/// Forward archive data with consumption acknowledgments and bounded buffers.
pub async fn transfer_archive<R, W, A>(
    mut input: R,
    mut extraction: W,
    mut acknowledgments: A,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    A: AsyncWrite + Unpin,
{
    acknowledge(&mut acknowledgments, 0).await?;
    let mut buffer = [0_u8; 32 * 1024];
    let mut total = 0_u64;
    let mut last_ack = 0;
    loop {
        let count = tokio::time::timeout(IDLE_TIMEOUT, input.read(&mut buffer))
            .await
            .context("upload input idle timeout")??;
        if count == 0 {
            break;
        }
        tokio::time::timeout(IDLE_TIMEOUT, extraction.write_all(&buffer[..count]))
            .await
            .context("upload destination idle timeout")??;
        total = total
            .checked_add(u64::try_from(count)?)
            .context("upload size overflow")?;
        if total - last_ack >= ACK_INTERVAL {
            acknowledge(&mut acknowledgments, total).await?;
            last_ack = total;
        }
    }
    tokio::time::timeout(IDLE_TIMEOUT, extraction.shutdown())
        .await
        .context("upload destination shutdown timeout")??;
    Ok(total)
}

async fn acknowledge(writer: &mut (impl AsyncWrite + Unpin), total: u64) -> Result<()> {
    tokio::time::timeout(IDLE_TIMEOUT, async {
        writer.write_u64(total).await?;
        writer.flush().await
    })
    .await
    .context("upload acknowledgment idle timeout")??;
    Ok(())
}

/// A fully validated archive held in a private host store until replay ends.
pub struct ValidatedUpload {
    archive: tokio::fs::File,
    received_bytes: u64,
    _store: tempfile::TempDir,
}
impl ValidatedUpload {
    pub fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Only validated, normalized archives can reach a guest extractor.
    pub async fn replay_to(mut self, mut extraction: impl AsyncWrite + Unpin) -> Result<()> {
        tokio::io::copy(&mut self.archive, &mut extraction).await?;
        extraction.shutdown().await?;
        Ok(())
    }
}

/// Receive with bounded disk usage and flow-control ACKs. The final success ACK
/// belongs to the caller after guest extraction completes, not to this stage.
pub async fn receive_validated_archive<R, A>(
    input: R,
    acknowledgments: A,
    policy: &FilesystemPolicy,
) -> Result<ValidatedUpload>
where
    R: AsyncRead + Unpin,
    A: AsyncWrite + Unpin,
{
    policy.validate()?;
    let spool = tempfile::tempfile().context("create private upload spool")?;
    let mut spool = tokio::fs::File::from_std(spool);
    let received_bytes = tokio::time::timeout(
        TRANSFER_TIMEOUT,
        transfer_archive(
            input.take(policy.wire_limit() + 1),
            &mut spool,
            acknowledgments,
        ),
    )
    .await
    .context("upload transfer deadline exceeded")??;
    if received_bytes > policy.wire_limit() {
        bail!("upload exceeds archive wire quota");
    }
    let mut spool = spool.into_std().await;
    let policy = *policy;
    let (archive, store) = tokio::task::spawn_blocking(move || {
        use std::io::{Seek, SeekFrom};
        spool.seek(SeekFrom::Start(0))?;
        let directory = private_transfer_directory().context("create private transfer store")?;
        let store = ImportStore::open(directory.path())?;
        let id = store.import_tar(spool, &policy)?;
        let archive = store.open_archive(&id)?;
        Ok::<_, anyhow::Error>((archive, directory))
    })
    .await??;
    Ok(ValidatedUpload {
        archive: tokio::fs::File::from_std(archive),
        received_bytes,
        _store: store,
    })
}

pub async fn serve(channel: Channel<Msg>, runtime: Arc<Runtime>) -> Result<()> {
    let (mut read, write) = channel.split();
    let mut input = BufReader::new(read.make_reader());
    let mut line = Vec::new();
    let read_plan = async {
        loop {
            let byte = input
                .read_u8()
                .await
                .context("upload plan ended before newline")?;
            line.push(byte);
            if line.len() > MAX_PLAN_BYTES {
                bail!("upload plan too large");
            }
            if byte == b'\n' {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! { result = tokio::time::timeout(IDLE_TIMEOUT, read_plan) => result.context("upload plan timeout")??, () = runtime.cancel.cancelled() => bail!("sandbox stopped during upload plan") }
    let plan = UploadPlan::parse(&line)?;
    let _transfer_permit = runtime
        .transfer_slots
        .clone()
        .try_acquire_owned()
        .context("sandbox transfer capacity exhausted")?;
    let policy = runtime
        .vm_policy
        .as_ref()
        .map(|policy| policy.filesystem)
        .unwrap_or_default();
    let upload = tokio::select! {
        result = receive_validated_archive(&mut input, write.make_writer(), &policy) => result?,
        () = runtime.cancel.cancelled() => bail!("sandbox stopped during upload validation"),
    };
    let total = upload.received_bytes();
    let mut child = runtime.guest.exec(&runtime.config, &plan.command()?)?;
    let stdin = child.stdin.take().context("guest stdin unavailable")?;
    let mut stderr = child.stderr.take().context("guest stderr unavailable")?;
    let mut stdout = child.stdout.take().context("guest stdout unavailable")?;
    let mut errors = write.make_writer_ext(Some(1));
    let mut output = write.make_writer_ext(Some(1));
    let drains = AbortOnDropHandle::new(tokio::spawn(async move {
        let (a, b) = tokio::join!(
            tokio::io::copy(&mut stderr, &mut errors),
            tokio::io::copy(&mut stdout, &mut output)
        );
        a?;
        b?;
        Ok::<_, std::io::Error>(())
    }));
    let transfer = async {
        upload.replay_to(stdin).await?;
        child.wait().await.context("wait for guest extraction")
    };
    tokio::pin!(transfer);
    let result = tokio::select! {
        result = tokio::time::timeout(TRANSFER_TIMEOUT, &mut transfer) => {
            let status = result.context("guest extraction deadline exceeded")??;
            if status.success() { acknowledge(&mut write.make_writer(), total).await?; }
            status
        }
        () = runtime.cancel.cancelled() => { bail!("sandbox stopped during upload"); }
    };
    tokio::select! {
        result=tokio::time::timeout(IDLE_TIMEOUT,drains)=>result.context("guest extraction output did not close")???,
        ()=runtime.cancel.cancelled()=>bail!("sandbox stopped while closing upload"),
    }
    write
        .exit_status(u32::try_from(result.code().unwrap_or(1)).unwrap_or(1))
        .await?;
    write.eof().await?;
    write.close().await?;
    Ok(())
}
