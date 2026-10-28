//! Isolated local tooling for the pinned official OpenShell gateway and CLI.
mod e2e;
mod gateway;
mod local;
mod services;
mod tools;
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use local::Local;
#[cfg(test)]
use local::require_success;
#[cfg(test)]
use sha2::Digest;
use std::path::PathBuf;
use tools::verify_protocol;

#[derive(Parser)]
struct Arguments {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Save this run's logs and JSON evidence in an explicit directory.
    #[arg(long)]
    evidence_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run the official CLI with isolated local state.
    Cli {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Preserve or generate local PKI and register the local gateway.
    SetupGateway,
    /// Start or stop this checkout's local processes.
    Services {
        #[command(subcommand)]
        command: services::Action,
    },
    /// Download and verify the pinned official OpenShell binaries.
    FetchOpenshell,
    /// Verify pinned protocol source bytes.
    VerifyUpstream,
    /// Exercise the official CLI against the running local adapter.
    E2e {
        #[arg(long)]
        resume: bool,
        #[arg(long)]
        policy: PathBuf,
    },
}
pub async fn main() -> Result<()> {
    let args = Arguments::parse();
    let local = Local::new(args.root)?;
    let local = if let Some(evidence) = args.evidence_dir {
        if !evidence.is_absolute() {
            bail!("--evidence-dir must be absolute");
        }
        Local { evidence, ..local }
    } else {
        local
    };
    match args.command {
        Action::Cli { args } => {
            use std::os::unix::process::CommandExt;
            let error = std::process::Command::new(local.state.join("bin/openshell"))
                .args(args)
                .env_clear()
                .envs(local.environment()?)
                .current_dir(&local.root)
                .exec();
            return Err(error.into());
        }
        Action::SetupGateway => gateway::setup(&local).await?,
        Action::Services { command } => services::execute(&local, command).await?,
        Action::FetchOpenshell => tools::fetch(&local).await?,
        Action::VerifyUpstream => verify_protocol(&local.root)?,
        Action::E2e { resume, policy } => {
            if !policy.is_absolute() || !policy.is_file() {
                bail!("--policy must name an existing absolute native OpenShell policy file");
            }
            e2e::execute(&local, resume, &policy).await?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    fn fixture(script: &str) -> anyhow::Result<(tempfile::TempDir, Local)> {
        let root = tempfile::tempdir()?;
        let binary = root.path().join(".local/bin/openshell");
        std::fs::create_dir_all(binary.parent().expect("binary has parent"))?;
        std::fs::write(&binary, format!("#!/bin/sh\n{script}"))?;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))?;
        let local = Local::new(root.path())?;
        Ok((root, local))
    }

    #[test]
    fn credential_environment_is_not_inherited() -> anyhow::Result<()> {
        let (_root, local) = fixture("exit 0\n")?;
        let environment = local.environment()?;
        assert!(!environment.contains_key(std::ffi::OsStr::new("OPENAI_API_KEY")));
        assert!(!environment.contains_key(std::ffi::OsStr::new("AWS_SECRET_ACCESS_KEY")));
        assert_eq!(
            environment.get(std::ffi::OsStr::new("OPENSHELL_KATA_STATE_DIR")),
            Some(&local.state.join("runtime").into_os_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn failure_is_recorded_before_returning() -> anyhow::Result<()> {
        let (_root, local) = fixture("echo output\necho 'expected failure' >&2\nexit 7\n")?;
        let output = local
            .cli(&["test"], Duration::from_secs(2), Some("failure"))
            .await?;
        assert_eq!(output.status.code(), Some(7));
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(local.evidence.join("failure.json"))?)?;
        assert_eq!(record["exit_code"], 7);
        assert_eq!(record["stdout"], "output\n");
        assert!(require_success(output).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn timeout_closes_descendant_output_pipes() -> anyhow::Result<()> {
        let (_root, local) = fixture("sleep 30 &\nwait\n")?;
        let started = Instant::now();
        let error = local
            .cli(&["test"], Duration::from_millis(100), Some("timeout"))
            .await
            .expect_err("timeout must fail");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(local.evidence.join("timeout.json"))?)?;
        assert_eq!(record["timed_out"], true);
        Ok(())
    }

    #[test]
    fn checksum_manifest_cannot_escape_protocol_directory() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::create_dir(root.path().join("proto"))?;
        std::fs::write(root.path().join("outside"), b"data")?;
        let digest = format!("{:x}", sha2::Sha256::digest(b"data"));
        std::fs::write(
            root.path().join("proto/SHA256SUMS"),
            format!("{digest}  ../outside\n"),
        )?;
        assert!(verify_protocol(root.path()).is_err());
        Ok(())
    }
}
