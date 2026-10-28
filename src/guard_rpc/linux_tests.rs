//! Explicit root-only real host-fence proof transport qualification.
use super::*;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::SocketAddr,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the dedicated isolated Linux node/fence qualification fixture"]
async fn live_mtls_rpc_reads_actual_pinned_host_fence() -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "root fixture required"
    );
    let endpoint: SocketAddr = std::env::var("OPENSHELL_KATA_GUARD_RPC_LIVE_ENDPOINT")?.parse()?;
    let node = std::env::var("OPENSHELL_KATA_GUARD_RPC_LIVE_NODE_UID")?;
    let pod = std::env::var("OPENSHELL_KATA_GUARD_RPC_LIVE_POD_UID")?;
    validate_endpoint(endpoint)?;
    canonical_uuid(&node)?;
    canonical_uuid(&pod)?;
    let root = tempfile::tempdir()?;
    super::tls_tests::certificates_for(root.path(), &node)?;
    let der = Command::new("openssl")
        .args(["x509", "-in", "client.crt", "-outform", "DER"])
        .current_dir(root.path())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    ensure!(der.status.success(), "certificate fingerprint failed");
    let server = GuardServerConfig {
        version: 1,
        bind: None,
        certificate_file: root.path().join("server.crt"),
        private_key_file: root.path().join("server.key"),
        client_ca_file: root.path().join("ca.crt"),
        allowed_client_certificate_sha256: vec![format!("{:x}", Sha256::digest(der.stdout))],
    };
    let path = root.path().join("server.json");
    fs::write(&path, serde_json::to_vec(&server)?)?;
    let mut process = None;
    let mut task = None;
    if let Some(binary) = std::env::var_os("OPENSHELL_KATA_GUARD_RPC_LIVE_BINARY") {
        process = Some(
            tokio::process::Command::new(binary)
                .args(["serve", "--config"])
                .arg(&path)
                .args(["--bind", &endpoint.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()?,
        );
    } else {
        task = Some(tokio::spawn(
            async move { serve(&path, Some(endpoint)).await },
        ));
    }
    let ready = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if tokio::net::TcpStream::connect(endpoint).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if ready.is_err() {
        if let Some(task) = task {
            task.abort();
        }
        anyhow::bail!("proof server failed before listening");
    }
    let client = GuardClientConfig {
        version: 1,
        server_ca_file: root.path().join("ca.crt"),
        certificate_file: root.path().join("client.crt"),
        private_key_file: root.path().join("client.key"),
    };
    let nonce = uuid::Uuid::new_v4().to_string();
    let response = verify_remote(endpoint, &node, &client, &pod, &nonce)
        .await
        .context("actual host fence readback over mTLS")?;
    assert_eq!(response.nonce, nonce);
    assert_eq!(response.proof.binding.pod_uid, pod);
    assert_eq!(response.proof.binding.node_uid, node);
    let other = GuardClientConfig {
        certificate_file: root.path().join("other.crt"),
        private_key_file: root.path().join("other.key"),
        ..client.clone()
    };
    assert!(
        verify_remote(endpoint, &node, &other, &pod, &nonce)
            .await
            .is_err(),
        "another signed role must not reach host state"
    );
    assert!(
        verify_remote(
            endpoint,
            &uuid::Uuid::new_v4().to_string(),
            &client,
            &pod,
            &nonce
        )
        .await
        .is_err(),
        "the expected node must still match the returned host proof"
    );
    if let Some(output) = std::env::var_os("OPENSHELL_KATA_GUARD_RPC_LIVE_RESULT") {
        fs::write(Path::new(&output), serde_json::to_vec_pretty(&response)?)?;
    }
    if let Some(task) = task {
        task.abort();
        let _ = task.await;
    }
    if let Some(mut process) = process {
        process.kill().await?;
        let _ = process.wait().await?;
    }
    Ok(())
}
