use anyhow::{Context, Result};
use serde_json::Value;
use std::{os::unix::fs::PermissionsExt, path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::Command,
};

async fn command(args: &[&str]) -> Result<Value> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(env!("CARGO_BIN_EXE_kata-network"))
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    anyhow::ensure!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn path(path: &Path) -> Result<&str> {
    path.to_str().context("UTF8 fixture path")
}

#[tokio::test]
async fn cli_control_binds_nonces_revokes_connections_and_cleans_socket() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let policy = root.path().join("policy.json");
    let control = root.path().join("control.sock");
    tokio::fs::write(&policy, b"{\"tcp_allow\":[]}").await?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args([
            "broker",
            "--bind",
            "127.0.0.1:0",
            "--policy",
            path(&policy)?,
            "--control",
            path(&control)?,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = BufReader::new(child.stdout.take().context("broker stdout")?);
    let mut line = String::new();
    let count = tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut line)).await??;
    if count == 0 {
        let output = child.wait_with_output().await?;
        anyhow::bail!(
            "broker failed before ready: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let ready: Value = serde_json::from_str(&line)?;
    assert_eq!(ready["ready"], true);
    let address = ready["address"].as_str().context("bound address")?;
    let initial = command(&[
        "inspect",
        "--control",
        path(&control)?,
        "--nonce",
        "inspect-nonce-00001",
    ])
    .await?;
    assert_eq!(initial["nonce"], "inspect-nonce-00001");
    assert_eq!(initial["generation"], 1);
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n")
        .await?;
    for _ in 0..30 {
        let state = command(&[
            "inspect",
            "--control",
            path(&control)?,
            "--nonce",
            "inspect-nonce-00002",
        ])
        .await?;
        if state["active_connections"].as_u64().unwrap_or(0) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let same = command(&[
        "update",
        "--control",
        path(&control)?,
        "--policy",
        path(&policy)?,
        "--nonce",
        "update-nonce-00001",
    ])
    .await?;
    assert_eq!(same["generation"], 1);
    assert_eq!(same["nonce"], "update-nonce-00001");
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stream.read(&mut byte))
            .await
            .is_err(),
        "identical policy must preserve connections"
    );
    tokio::fs::write(
        &policy,
        b"{\"tcp_allow\":[{\"host\":\"example.com\",\"port\":443}]}",
    )
    .await?;
    let changed = command(&[
        "update",
        "--control",
        path(&control)?,
        "--policy",
        path(&policy)?,
        "--nonce",
        "update-nonce-00002",
    ])
    .await?;
    assert_eq!(changed["generation"], 2);
    assert_eq!(changed["active_connections"], 0);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await??,
        0
    );
    tokio::fs::write(
        &policy,
        b"{\"tcp_allow\":[{\"host\":\"*.example.com\",\"port\":443}]}",
    )
    .await?;
    let invalid = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args([
            "update",
            "--control",
            path(&control)?,
            "--policy",
            path(&policy)?,
            "--nonce",
            "update-nonce-00003",
        ])
        .kill_on_drop(true)
        .output()
        .await?;
    assert!(!invalid.status.success());
    let retained = command(&[
        "inspect",
        "--control",
        path(&control)?,
        "--nonce",
        "inspect-nonce-00003",
    ])
    .await?;
    assert_eq!(retained["generation"], 2);
    let stopped = command(&[
        "stop",
        "--control",
        path(&control)?,
        "--nonce",
        "stop-broker-nonce1",
    ])
    .await?;
    assert_eq!(stopped["stopping"], true);
    anyhow::ensure!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await??
            .success(),
        "broker exit"
    );
    assert!(
        !control.exists(),
        "private control socket must be removed on graceful shutdown"
    );
    Ok(())
}

#[tokio::test]
async fn cli_refuses_public_bind_and_unprotected_control_directories() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let policy = root.path().join("policy.json");
    let control = root.path().join("control.sock");
    tokio::fs::write(&policy, b"{\"tcp_allow\":[]}").await?;
    let public = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args([
            "broker",
            "--bind",
            "8.8.8.8:38080",
            "--policy",
            path(&policy)?,
            "--control",
            path(&control)?,
        ])
        .kill_on_drop(true)
        .output()
        .await?;
    assert!(!public.status.success());
    assert!(!control.exists());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))?;
    let exposed = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args([
            "broker",
            "--bind",
            "127.0.0.1:0",
            "--policy",
            path(&policy)?,
            "--control",
            path(&control)?,
        ])
        .kill_on_drop(true)
        .output()
        .await?;
    assert!(!exposed.status.success());
    assert!(String::from_utf8_lossy(&exposed.stderr).contains("0700"));
    assert!(!control.exists());
    Ok(())
}

#[tokio::test]
async fn cli_plan_validates_before_emitting_rules() -> Result<()> {
    let root = tempfile::tempdir()?;
    let spec = root.path().join("spec.json");
    let value = serde_json::json!({"sandbox_id":"test-sandbox","host_veth":"veth-test","ifindex":42,"guest_ip":"10.240.0.2","gateway_ip":"10.240.0.1","guest_mac":"02:00:00:00:00:02","gateway_mac":"02:00:00:00:00:01","broker_port":38080,"proof_nonce":"fixture-proof-nonce-0001"});
    tokio::fs::write(&spec, serde_json::to_vec(&value)?).await?;
    let plan = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args(["plan", "--spec", path(&spec)?])
        .output()
        .await?;
    assert!(plan.status.success());
    let rules = String::from_utf8(plan.stdout)?;
    assert!(rules.contains("policy drop"));
    assert!(rules.contains("oifname \"veth-test\" drop"));
    let mut invalid = value;
    invalid["host_veth"] = "veth;flush ruleset".into();
    tokio::fs::write(&spec, serde_json::to_vec(&invalid)?).await?;
    let rejected = Command::new(env!("CARGO_BIN_EXE_kata-network"))
        .args(["plan", "--spec", path(&spec)?])
        .output()
        .await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    Ok(())
}
