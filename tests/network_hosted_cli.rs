use anyhow::{Context, Result, ensure};
use openshell_kata::network::{HostedControlRequest, HostedControlResponse};
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::Command,
};

async fn invoke(
    control: &Path,
    action: &str,
    request: &HostedControlRequest,
) -> Result<HostedControlResponse> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args([
            action,
            "--control",
            control.to_str().context("control path")?,
            "--request",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    child
        .stdin
        .take()
        .context("stdin")?
        .write_all(&serde_json::to_vec(request)?)
        .await?;
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[tokio::test]
async fn hosted_cli_starts_denied_authorizes_with_bound_stdin_and_stops_after_drain() -> Result<()>
{
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let control = root.path().join("control.sock");
    let config = root.path().join("config.json");
    let inventory = root.path().join("inventory.json");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let binding = json!({"workspace":"tenant","namespace_uid":uuid::Uuid::new_v4().to_string(),"sandbox_id":uuid::Uuid::new_v4().to_string(),"launch_nonce":uuid::Uuid::new_v4().to_string(),"expires_at_unix":now+600});
    let inv = json!({"version":1,"generation":1,"issued_at_unix":now,"expires_at_unix":now+60,"denied_cidrs":["10.0.0.0/8"]});
    tokio::fs::write(&config,serde_json::to_vec(&json!({"version":1,"operator_ceiling":{"tcp_allow":[]},"initial_ceiling":{"tcp_allow":[]},"binding":binding,"protected_hostname_suffixes":["cluster.local"],"baseline_denied_cidrs":[],"authorization_lease_secs":30}))?).await?;
    tokio::fs::write(&inventory, serde_json::to_vec(&inv)?).await?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args([
            "broker-hosted",
            "--bind",
            "127.0.0.1:0",
            "--config",
            config.to_str().context("config")?,
            "--inventory",
            inventory.to_str().context("inventory")?,
            "--control",
            control.to_str().context("control")?,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        BufReader::new(child.stdout.take().context("stdout")?).read_line(&mut line),
    )
    .await??;
    let envelope: Value = serde_json::from_str(&line)?;
    assert_eq!(envelope["ready"], true);
    let initial: HostedControlResponse = serde_json::from_value(envelope["state"].clone())?;
    assert_eq!(initial.authorization_expires_at_unix, 0);
    assert_eq!(initial.generation, 1);
    assert_eq!(
        std::fs::metadata(&control)?.permissions().mode() & 0o777,
        0o600
    );
    let nonce = uuid::Uuid::new_v4().to_string();
    let ready = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args([
            "hosted-ready",
            "--control",
            control.to_str().context("control")?,
            "--nonce",
            &nonce,
        ])
        .output()
        .await?;
    ensure!(ready.status.success(), "ready failed");
    let ready: HostedControlResponse = serde_json::from_slice(&ready.stdout)?;
    assert_eq!(ready.nonce, nonce);
    assert_eq!(ready.startup_epoch, initial.startup_epoch);
    assert_eq!(ready.config_sha256, initial.config_sha256);
    let authorize = HostedControlRequest::Authorize {
        binding: initial.binding.clone(),
        startup_epoch: initial.startup_epoch.clone(),
        expected_generation: 1,
        nonce: uuid::Uuid::new_v4().to_string(),
        policy: Default::default(),
        inventory: serde_json::from_value(inv)?,
    };
    let accepted = invoke(&control, "hosted-authorize", &authorize).await?;
    assert_eq!(accepted.generation, 2);
    assert!(accepted.authorization_expires_at_unix > now);
    let inspect = HostedControlRequest::Inspect {
        binding: initial.binding.clone(),
        startup_epoch: initial.startup_epoch.clone(),
        expected_generation: 2,
        nonce: uuid::Uuid::new_v4().to_string(),
    };
    let inspected = invoke(&control, "hosted-inspect", &inspect).await?;
    assert_eq!(
        inspected.authorization_expires_at_unix,
        accepted.authorization_expires_at_unix
    );
    let wrong = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args([
            "hosted-stop",
            "--control",
            control.to_str().context("control")?,
            "--request",
            config.to_str().context("config")?,
        ])
        .output()
        .await?;
    assert!(!wrong.status.success());
    let mut socket = TcpStream::connect(envelope["address"].as_str().context("address")?).await?;
    socket
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n")
        .await?;
    let stop = HostedControlRequest::Stop {
        binding: initial.binding,
        startup_epoch: initial.startup_epoch,
        expected_generation: 2,
        nonce: uuid::Uuid::new_v4().to_string(),
    };
    let stopped = invoke(&control, "hosted-stop", &stop).await?;
    assert!(stopped.stopping);
    assert_eq!(stopped.active_connections, 0);
    let mut bytes = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut bytes)).await??,
        0
    );
    ensure!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await??
            .success(),
        "broker stopped unsuccessfully"
    );
    assert!(!control.exists());
    Ok(())
}

#[tokio::test]
async fn hosted_cli_rejects_oversized_input_before_contacting_broker() -> Result<()> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args([
            "hosted-authorize",
            "--control",
            "/nonexistent/broker.sock",
            "--request",
            "-",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    child
        .stdin
        .take()
        .context("stdin")?
        .write_all(&vec![b' '; 1024 * 1024 + 1])
        .await?;
    let output = child.wait_with_output().await?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("size limit"));
    Ok(())
}
