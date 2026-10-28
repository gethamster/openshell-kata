use anyhow::{Context, Result, bail};
use clap::Parser;
use openshell_kata::runtime::{
    lifecycle::{self, Settings, WatchJob},
    model::Action,
    watchdog,
};
use std::path::PathBuf;

/// Local or self-hosted Kata lifecycle with fresh external enforcement proofs.
#[derive(Debug, Parser)]
struct Arguments {
    action: String,
    id: String,
    #[arg(long)]
    policy_file: Option<PathBuf>,
    #[arg(long)]
    proof_nonce: Option<String>,
    #[arg(long, default_value = "openshell-kata-enforcement")]
    vm: String,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long, default_value = "/opt/openshell-kata/kata-runtime")]
    node_binary: PathBuf,
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Arguments::parse();
    if args.action == "reap-shim" {
        let count = openshell_kata::runtime::containerd::reap_shim(
            &args.id,
            args.proof_nonce
                .as_deref()
                .context("reap-shim requires creation nonce")?,
        )
        .await?;
        println!("{}", serde_json::json!({"reaped":count}));
        return Ok(());
    }
    if args.action == "set-spec" {
        if !cfg!(target_os = "linux") {
            bail!("containerd update runs on the Linux node only");
        }
        openshell_kata::runtime::containerd::set_spec(
            &args.id,
            args.proof_nonce
                .as_deref()
                .context("set-spec requires creation nonce")?,
            std::fs::read(args.policy_file.context("set-spec requires a spec file")?)?,
        )
        .await?;
        println!("{{}}");
        return Ok(());
    }
    if args.action == "watchdog" {
        if !cfg!(target_os = "linux") {
            bail!("watchdog runs on the Linux node only");
        }
        let job: WatchJob = serde_json::from_slice(&std::fs::read(&args.id)?)?;
        watchdog::watch_cgroup_ready(&job.cgroup, job.deadline, Some(&job.ready)).await?;
        return Ok(());
    }
    let root = match args
        .state_dir
        .or_else(|| std::env::var_os("OPENSHELL_KATA_STATE_DIR").map(PathBuf::from))
    {
        Some(root) => root,
        None => std::env::current_dir()?.join(".local/runtime"),
    };
    let settings = Settings {
        vm: args.vm,
        state_dir: root,
        node_binary: args.node_binary,
    };
    let action: Action = args.action.parse().context("invalid runtime action")?;
    let value = lifecycle::execute(
        &settings,
        action,
        &args.id,
        args.policy_file.as_deref(),
        args.proof_nonce.as_deref(),
    )
    .await?;
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}
