use super::{
    BrokerHandle, FenceProof, FenceSpec, NetworkPolicy, bind_broker, install_fence, remove_fence,
    verify_fence,
};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

/// Standalone outer-host network broker and fence operations.
#[derive(Debug, Parser)]
pub struct NetworkCli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Debug, Subcommand)]
enum Command {
    Broker {
        #[arg(long)]
        bind: SocketAddr,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        control: PathBuf,
    },
    Install {
        #[arg(long)]
        spec: PathBuf,
    },
    Verify {
        #[arg(long)]
        proof: PathBuf,
    },
    Remove {
        #[arg(long)]
        proof: PathBuf,
    },
    Plan {
        #[arg(long)]
        spec: PathBuf,
    },
    Update {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        nonce: String,
    },
    Inspect {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        nonce: String,
    },
    Stop {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        nonce: String,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum ControlRequest {
    Update {
        nonce: String,
        policy: NetworkPolicy,
    },
    Inspect {
        nonce: String,
    },
    Stop {
        nonce: String,
    },
}
impl ControlRequest {
    fn nonce(&self) -> &str {
        match self {
            Self::Update { nonce, .. } | Self::Inspect { nonce } | Self::Stop { nonce } => nonce,
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
struct ControlResponse {
    nonce: String,
    generation: u64,
    policy: NetworkPolicy,
    stopping: bool,
    #[serde(default)]
    active_connections: usize,
}

async fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
    if bytes.len() > 1024 * 1024 {
        bail!("network configuration exceeds size limit");
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn nonce_valid(nonce: &str) -> bool {
    (16..=128).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
async fn request_control(path: &Path, request: ControlRequest) -> Result<ControlResponse> {
    let mut stream = UnixStream::connect(path).await?;
    let mut bytes = serde_json::to_vec(&request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    let mut result = Vec::new();
    let mut reader = BufReader::new(stream);
    (&mut reader)
        .take(65537)
        .read_until(b'\n', &mut result)
        .await?;
    if result.len() > 65536 {
        bail!("oversized broker response");
    }
    let response: ControlResponse =
        serde_json::from_slice(&result).context("broker control request failed")?;
    if response.nonce != request.nonce() {
        bail!("broker control nonce mismatch");
    }
    Ok(response)
}
async fn control_connection(stream: UnixStream, broker: &BrokerHandle) -> Result<bool> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        (&mut reader).take(65537).read_until(b'\n', &mut bytes),
    )
    .await??;
    if bytes.len() > 65536 {
        bail!("oversized broker control request");
    }
    let request: ControlRequest = serde_json::from_slice(&bytes)?;
    if !nonce_valid(request.nonce()) {
        bail!("invalid broker request nonce");
    }
    let stopping = matches!(request, ControlRequest::Stop { .. });
    if let ControlRequest::Update { policy, .. } = &request {
        broker.replace_policy(policy.clone()).await?;
    }
    let (generation, policy) = broker.snapshot().await?;
    let response = ControlResponse {
        nonce: request.nonce().into(),
        generation,
        policy,
        stopping,
        active_connections: broker.active_connections().await,
    };
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.shutdown().await?;
    Ok(stopping)
}

struct SocketFile(PathBuf);
impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
async fn run_broker(address: SocketAddr, policy_path: &Path, control: &Path) -> Result<()> {
    let parent = control
        .parent()
        .context("broker control directory required")?;
    if !parent.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    if parent.metadata()?.permissions().mode() & 0o077 != 0 {
        bail!("broker control directory must be private (0700)");
    }
    let listener = UnixListener::bind(control).context("binding private broker control socket")?;
    std::fs::set_permissions(control, std::fs::Permissions::from_mode(0o600))?;
    let _socket = SocketFile(control.into());
    let broker = bind_broker(address, read_json(policy_path).await?).await?;
    let (generation, policy) = broker.snapshot().await?;
    println!(
        "{}",
        serde_json::json!({"ready":true,"address":broker.local_addr(),"generation":generation,"policy":policy})
    );
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            accepted=listener.accept()=>{let(stream,_)=accepted?;match control_connection(stream,&broker).await{Ok(true)=>break,Ok(false)=>{},Err(error)=>tracing::warn!(%error,"broker control rejected")}}
        }
    }
    broker.shutdown().await
}

/// Execute one host-side operation; structured output goes to stdout.
pub async fn run_network(cli: NetworkCli) -> Result<()> {
    match cli.command {
        Command::Broker {
            bind,
            policy,
            control,
        } => run_broker(bind, &policy, &control).await,
        Command::Install { spec } => {
            let proof = install_fence(read_json::<FenceSpec>(&spec).await?).await?;
            println!("{}", serde_json::to_string(&proof)?);
            Ok(())
        }
        Command::Verify { proof } => {
            verify_fence(&read_json::<FenceProof>(&proof).await?).await?;
            println!("{{\"verified\":true}}");
            Ok(())
        }
        Command::Remove { proof } => {
            remove_fence(&read_json::<FenceProof>(&proof).await?).await?;
            println!("{{\"removed\":true}}");
            Ok(())
        }
        Command::Plan { spec } => {
            print!("{}", read_json::<FenceSpec>(&spec).await?.rules()?);
            Ok(())
        }
        Command::Update {
            control,
            policy,
            nonce,
        } => {
            if !nonce_valid(&nonce) {
                bail!("invalid broker request nonce");
            }
            let result = request_control(
                &control,
                ControlRequest::Update {
                    nonce,
                    policy: read_json(&policy).await?,
                },
            )
            .await?;
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        }
        Command::Inspect { control, nonce } => {
            if !nonce_valid(&nonce) {
                bail!("invalid broker request nonce");
            }
            let result = request_control(&control, ControlRequest::Inspect { nonce }).await?;
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        }
        Command::Stop { control, nonce } => {
            if !nonce_valid(&nonce) {
                bail!("invalid broker request nonce");
            }
            let result = request_control(&control, ControlRequest::Stop { nonce }).await?;
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        }
    }
}
