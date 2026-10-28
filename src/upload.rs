use crate::{config::shell_quote, supervisor::Runtime};
use anyhow::{Context, Result, bail};
use russh::{Channel, server::Msg};
use serde::Deserialize;
use std::{path::Component, path::Path, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::task::AbortOnDropHandle;

const MAX_PLAN_BYTES: usize = 16 * 1024;
const ACK_INTERVAL: u64 = 256 * 1024;

#[derive(Debug, Deserialize)]
pub struct UploadPlan {
    pub destination_directory: String,
    pub expected_destination: Option<Destination>,
}
#[derive(Debug, Deserialize)]
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
    acknowledgments.write_u64(0).await?;
    acknowledgments.flush().await?;
    let mut buffer = [0_u8; 32 * 1024];
    let mut total = 0_u64;
    let mut last_ack = 0;
    loop {
        let count = input.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        extraction.write_all(&buffer[..count]).await?;
        total = total
            .checked_add(u64::try_from(count)?)
            .context("upload size overflow")?;
        if total - last_ack >= ACK_INTERVAL {
            acknowledgments.write_u64(total).await?;
            acknowledgments.flush().await?;
            last_ack = total;
        }
    }
    extraction.shutdown().await?;
    Ok(total)
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
    tokio::select! { result = read_plan => result?, () = runtime.cancel.cancelled() => bail!("sandbox stopped during upload plan") }
    let plan = UploadPlan::parse(&line)?;
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
    let transfer = transfer_archive(&mut input, stdin, write.make_writer());
    tokio::pin!(transfer);
    let result = tokio::select! {
        result = &mut transfer => {
            let total = result?;
            let status = child.wait().await?;
            if status.success() { let mut acks = write.make_writer(); acks.write_u64(total).await?; acks.flush().await?; }
            status
        }
        status = child.wait() => { status? }
        () = runtime.cancel.cancelled() => { child.kill().await?; bail!("sandbox stopped during upload"); }
    };
    drains.await??;
    write
        .exit_status(u32::try_from(result.code().unwrap_or(1)).unwrap_or(1))
        .await?;
    write.eof().await?;
    write.close().await?;
    Ok(())
}
