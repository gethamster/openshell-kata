use super::local::{Local, PORT};
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
        process::CommandExt,
    },
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Subcommand)]
pub enum Action {
    /// Start the adapter in strict mode with an explicit operator VM profile.
    Start {
        #[arg(long)]
        vm_policy: PathBuf,
        #[arg(long)]
        adapter: Option<PathBuf>,
        #[arg(long)]
        runtime: Option<PathBuf>,
        /// Match an operator-owned immutable template to the prepared local image.
        #[arg(long)]
        guest_image: Option<String>,
    },
    /// Stop processes whose recorded start identity still matches.
    Stop,
}
#[derive(Debug, Deserialize, Serialize)]
struct Process {
    pid: u32,
    executable: PathBuf,
    started: String,
}
type Processes = BTreeMap<String, Process>;

pub async fn execute(local: &Local, action: Action) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(local.state.join("services.lock"))?;
    lock.try_lock()
        .context("another local service operation is running")?;
    match action {
        Action::Start {
            vm_policy,
            adapter,
            runtime,
            guest_image,
        } => start(local, vm_policy, adapter, runtime, guest_image).await,
        Action::Stop => stop(local).await,
    }
}
fn clear_socket(local: &Local) -> Result<()> {
    let path = local.state.join("driver.sock");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let owner = std::fs::metadata(&local.state)?.uid();
    if !metadata.file_type().is_socket() || metadata.uid() != owner {
        bail!("unexpected driver socket type or ownership");
    }
    match UnixStream::connect(&path) {
        Ok(_) => bail!("a live adapter already owns the driver socket"),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) => {}
        Err(error) => return Err(error).context("checking stale driver socket"),
    }
    std::fs::remove_file(path)?;
    Ok(())
}
fn query(pid: u32, field: &str) -> Result<Option<String>> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", field])
        .output()?;
    Ok(output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned()))
}
fn current(process: &Process) -> Result<bool> {
    let Some(started) = query(process.pid, "lstart=")? else {
        return Ok(false);
    };
    if started != process.started {
        bail!("refusing reused local process ID");
    }
    let Some(command) = query(process.pid, "command=")? else {
        return Ok(false);
    };
    if !command.contains(&*process.executable.to_string_lossy()) {
        bail!("refusing unexpected executable at recorded process ID");
    }
    let Some(group) = query(process.pid, "pgid=")? else {
        return Ok(false);
    };
    if group.parse::<u32>()? != process.pid {
        bail!("refusing unexpected local process group");
    }
    Ok(true)
}
fn signal(process: &Process, signal: &str) -> Result<()> {
    if current(process)? {
        let status = Command::new("/bin/kill")
            .args([
                format!("-{signal}"),
                "--".into(),
                format!("-{}", process.pid),
            ])
            .status()?;
        if !status.success() && current(process)? {
            bail!("could not signal local process group");
        }
    }
    Ok(())
}
pub async fn stop(local: &Local) -> Result<()> {
    let record = local.state.join("processes.json");
    if !record.exists() {
        return clear_socket(local);
    }
    let processes: Processes = serde_json::from_slice(&std::fs::read(&record)?)?;
    stop_processes(&processes).await?;
    std::fs::remove_file(record)?;
    clear_socket(local)
}
async fn stop_processes(processes: &Processes) -> Result<()> {
    for process in processes.values() {
        signal(process, "INT")?;
    }
    for _ in 0..50 {
        if processes
            .values()
            .map(current)
            .collect::<Result<Vec<_>>>()?
            .iter()
            .all(|alive| !alive)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for process in processes.values() {
        signal(process, "KILL")?;
    }
    Ok(())
}
fn save_record(local: &Local, processes: &Processes) -> Result<()> {
    let temporary = local.state.join("processes.json.tmp");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
    let file = options.open(&temporary)?;
    serde_json::to_writer_pretty(&file, processes)?;
    file.sync_all()?;
    std::fs::rename(temporary, local.state.join("processes.json"))?;
    Ok(())
}
async fn start(
    local: &Local,
    vm_policy: PathBuf,
    adapter: Option<PathBuf>,
    runtime: Option<PathBuf>,
    guest_image: Option<String>,
) -> Result<()> {
    if !vm_policy.is_absolute() || !vm_policy.is_file() {
        bail!("--vm-policy must name an existing absolute JSON profile");
    }
    if let Some(image) = &guest_image {
        openshell_kata::hosted::validate_image(image)?;
    }
    if local.state.join("processes.json").exists() {
        bail!("process record exists; inspect or stop local services first");
    }
    clear_socket(local)?;
    std::fs::create_dir_all(&local.evidence)?;
    let adapter = adapter
        .unwrap_or_else(|| local.root.join("target/debug/openshell-kata"))
        .canonicalize()?;
    let runtime = runtime
        .unwrap_or_else(|| local.root.join("target/debug/kata-runtime"))
        .canonicalize()?;
    let gateway = local.state.join("bin/openshell-gateway").canonicalize()?;
    let mut adapter_command = Command::new(&adapter);
    adapter_command
        .arg("--socket")
        .arg(local.state.join("driver.sock"))
        .args(["--gateway", &format!("https://127.0.0.1:{PORT}")])
        .arg("--gateway-ca")
        .arg(local.state.join("tls/ca.crt"))
        .arg("--lifecycle")
        .arg(runtime)
        .arg("--vm-policy")
        .arg(vm_policy);
    if let Some(image) = guest_image {
        adapter_command.args(["--guest-image", &image]);
    }
    let mut gateway_command = Command::new(&gateway);
    gateway_command
        .arg("--config")
        .arg(local.state.join("gateway.toml"))
        .args(["--health-port", &(PORT + 1).to_string()]);
    let mut processes = Processes::new();
    let outcome = async {
        for (name, executable, mut command) in [
            ("adapter", adapter, adapter_command),
            ("gateway", gateway, gateway_command),
        ] {
            let log = OpenOptions::new()
                .append(true)
                .create(true)
                .open(local.evidence.join(format!("{name}.log")))?;
            command
                .current_dir(&local.root)
                .env_clear()
                .envs(local.environment()?)
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .process_group(0);
            let mut child = command.spawn()?;
            let pid = child.id();
            let started = match query(pid, "lstart=") {
                Ok(Some(started)) => started,
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(result.err().unwrap_or_else(|| {
                        anyhow::anyhow!("local service exited during startup")
                    }));
                }
            };
            processes.insert(
                name.to_owned(),
                Process {
                    pid,
                    executable,
                    started,
                },
            );
            save_record(local, &processes)?;
            if name == "adapter" {
                for attempt in 0..100 {
                    if child.try_wait()?.is_some() {
                        bail!("adapter exited; inspect evidence/adapter.log");
                    }
                    if UnixStream::connect(local.state.join("driver.sock")).is_ok() {
                        break;
                    }
                    if attempt == 99 {
                        bail!("adapter did not bind its Unix socket");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        for _ in 0..50 {
            if local
                .cli(
                    &["gateway", "info", "--output", "json"],
                    Duration::from_secs(3),
                    None,
                )
                .await
                .is_ok_and(|o| o.status.success())
            {
                println!("Local adapter and gateway are ready");
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("gateway did not become ready; inspect evidence/gateway.log")
    }
    .await;
    if outcome.is_err() {
        stop_processes(&processes)
            .await
            .context("cleaning up failed service startup")?;
        let record = local.state.join("processes.json");
        if record.exists() {
            std::fs::remove_file(record)?;
        }
        clear_socket(local)?;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_socket_removal_preserves_live_listeners_and_unexpected_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let local = Local::new(root.path())?;
        let path = local.state.join("driver.sock");
        std::fs::write(&path, b"do not remove")?;
        assert!(clear_socket(&local).is_err());
        assert_eq!(std::fs::read(&path)?, b"do not remove");
        std::fs::remove_file(&path)?;
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        assert!(clear_socket(&local).is_err());
        // Drain the successful liveness probe before dropping the listener.
        // macOS can retain an unaccepted connection in the socket backlog.
        let (probe, _) = listener.accept()?;
        drop(probe);
        drop(listener);
        // A concurrent spawn can briefly retain a CLOEXEC descriptor before
        // exec; wait for the kernel to finish retiring the closed listener.
        let mut cleared = false;
        for _ in 0..100 {
            if clear_socket(&local).is_ok() {
                cleared = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        anyhow::ensure!(cleared, "closed listener did not retire");
        assert!(!path.exists());
        Ok(())
    }
    #[test]
    fn reused_process_identity_is_never_signalled() -> Result<()> {
        let process = Process {
            pid: std::process::id(),
            executable: std::env::current_exe()?,
            started: "not-this-start-time".into(),
        };
        assert!(current(&process).is_err());
        assert!(signal(&process, "TERM").is_err());
        Ok(())
    }
    #[test]
    fn records_are_atomic_private_and_round_trip() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        let local = Local::new(root.path())?;
        let processes = BTreeMap::from([(
            "test".into(),
            Process {
                pid: 1,
                executable: "/test".into(),
                started: "then".into(),
            },
        )]);
        save_record(&local, &processes)?;
        save_record(&local, &processes)?;
        let path = local.state.join("processes.json");
        let read: Processes = serde_json::from_slice(&std::fs::read(&path)?)?;
        assert_eq!(read["test"].started, "then");
        assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        assert!(!local.state.join("processes.json.tmp").exists());
        Ok(())
    }
}
