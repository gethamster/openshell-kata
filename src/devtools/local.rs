use anyhow::{Context, Result, bail};
use serde_json::json;
use std::os::unix::process::CommandExt;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::{Duration, Instant},
};
use tokio::process::Command;

pub const GATEWAY: &str = "kata-rust";
pub const PORT: u16 = 29670;

#[derive(Clone, Debug)]
pub struct Local {
    pub root: PathBuf,
    pub state: PathBuf,
    pub evidence: PathBuf,
}
impl Local {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root
            .as_ref()
            .canonicalize()
            .context("locating repository root")?;
        let state = root.join(".local");
        private_directory(&state)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let evidence = root
            .join("evidence/local-runs")
            .join(format!("{timestamp}-{}", std::process::id()));
        Ok(Self {
            evidence,
            root,
            state,
        })
    }
    pub fn environment(&self) -> Result<BTreeMap<OsString, OsString>> {
        let mut environment: BTreeMap<_, _> = [
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            "LANG",
            "LC_CTYPE",
            "SHELL",
            "LLVM_PROFILE_FILE",
        ]
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| (OsString::from(key), value)))
        .collect();
        for (key, name) in [
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_DATA_HOME", "data"),
        ] {
            let directory = self.state.join(name);
            private_directory(&directory)?;
            environment.insert(key.into(), directory.into_os_string());
        }
        environment.insert(
            "OPENSHELL_LOCAL_TLS_DIR".into(),
            self.state.join("tls").into_os_string(),
        );
        environment.insert("OPENSHELL_GATEWAY_NAME".into(), GATEWAY.into());
        environment.insert(
            "OPENSHELL_KATA_STATE_DIR".into(),
            self.state.join("runtime").into_os_string(),
        );
        Ok(environment)
    }
    pub fn command(&self, program: impl AsRef<OsStr>) -> Result<Command> {
        let mut command = Command::new(program);
        command
            .env_clear()
            .envs(self.environment()?)
            .current_dir(&self.root)
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        Ok(command)
    }
    pub async fn cli(
        &self,
        args: &[&str],
        timeout: Duration,
        label: Option<&str>,
    ) -> Result<Output> {
        let started = Instant::now();
        let result = run(
            self.command(self.state.join("bin/openshell"))?.args(args),
            timeout,
        )
        .await;
        if let Some(label) = label {
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                bail!("invalid evidence label");
            }
            std::fs::create_dir_all(&self.evidence)?;
            let record = match &result {
                Ok(output) => {
                    json!({"command": std::iter::once("openshell").chain(args.iter().copied()).collect::<Vec<_>>(), "exit_code": output.status.code(), "duration_seconds": started.elapsed().as_secs_f64(), "stdout": String::from_utf8_lossy(&output.stdout), "stderr": String::from_utf8_lossy(&output.stderr), "timed_out": false})
                }
                Err(error) => {
                    json!({"command": args, "duration_seconds": started.elapsed().as_secs_f64(), "timed_out": error.to_string().contains("timed out"), "error": error.to_string()})
                }
            };
            std::fs::write(
                self.evidence.join(format!("{label}.json")),
                serde_json::to_vec_pretty(&record)?,
            )?;
        }
        result
    }
    pub async fn checked_cli(
        &self,
        args: &[&str],
        timeout: Duration,
        label: Option<&str>,
    ) -> Result<Output> {
        require_success(self.cli(args, timeout, label).await?)
    }
}

pub fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            bail!("local state must be a real directory");
        }
    } else {
        std::fs::create_dir_all(path)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub async fn run(command: &mut Command, timeout: Duration) -> Result<Output> {
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pid = child.id().context("missing child process ID")?;
    let mut waiter = tokio::spawn(child.wait_with_output());
    match tokio::time::timeout(timeout, &mut waiter).await {
        Ok(result) => result?.context("waiting for local command"),
        Err(_) => {
            signal_group(pid, "TERM").await?;
            if tokio::time::timeout(Duration::from_secs(2), &mut waiter)
                .await
                .is_err()
            {
                signal_group(pid, "KILL").await?;
                let _ = waiter.await?;
            }
            bail!(
                "local command timed out after {} seconds",
                timeout.as_secs_f64()
            );
        }
    }
}

async fn signal_group(pid: u32, signal: &str) -> Result<()> {
    // This ID belongs to a child we still own, created in its own process group.
    let _ = Command::new("/bin/kill")
        .args([format!("-{signal}"), "--".into(), format!("-{pid}")])
        .output()
        .await?;
    Ok(())
}

pub fn require_success(output: Output) -> Result<Output> {
    if !output.status.success() {
        bail!(
            "local command failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output)
}
