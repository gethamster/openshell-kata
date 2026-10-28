use anyhow::{Context, Result, ensure};
use openshell_kata::{inventory::InventoryConfig, network::InfrastructureInventory};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::PermissionsExt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::process::Command;

#[tokio::test]
async fn inventory_cli_once_publishes_short_lived_private_file_and_preserves_it_on_failure()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let kubectl = root.path().join("kubectl");
    let kubeconfig = root.path().join("kubeconfig");
    let config_path = root.path().join("operator.json");
    let script=b"#!/bin/sh\n[ -z \"$HTTP_PROXY\" ] || exit 9\ncase \"$*\" in\n*'/api/v1/nodes?'*) printf '%s' '{\"kind\":\"NodeList\",\"metadata\":{\"resourceVersion\":\"1\"},\"items\":[{\"status\":{\"addresses\":[{\"type\":\"InternalIP\",\"address\":\"10.0.0.2\"}]}}]}';;\n*'/api/v1/services?'*) printf '%s' '{\"kind\":\"ServiceList\",\"metadata\":{\"resourceVersion\":\"2\"},\"items\":[]}';;\n*) exit 3;;\nesac\n";
    std::fs::write(&kubectl, script)?;
    std::fs::set_permissions(&kubectl, std::fs::Permissions::from_mode(0o700))?;
    let ca = root.path().join("ca.crt");
    let token = root.path().join("token");
    std::fs::write(&ca, b"CA fixture")?;
    std::fs::write(&token, b"token fixture")?;
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o600))?;
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(
        &kubeconfig,
        serde_json::to_vec(
            &serde_json::json!({"clusters":[{"name":"cluster","cluster":{"server":"https://kubernetes.example.com","certificate-authority":ca}}],"users":[{"name":"inventory","user":{"tokenFile":token}}],"contexts":[{"name":"inventory","context":{"cluster":"cluster","user":"inventory"}}],"current-context":"inventory"}),
        )?,
    )?;
    std::fs::set_permissions(&kubeconfig, std::fs::Permissions::from_mode(0o600))?;
    let config = InventoryConfig {
        version: 1,
        kubectl_path: kubectl.clone(),
        kubectl_sha256: format!("{:x}", Sha256::digest(script)),
        kubeconfig_path: kubeconfig,
        protected_hostnames: vec![],
        resolver_ip: "127.0.0.1".parse()?,
        resolver_port: 53,
        baseline_denied_cidrs: vec!["10.1.0.0/16".into()],
        include_external_names: true,
        refresh_secs: 5,
        freshness_secs: 60,
        query_timeout_secs: 1,
        api_timeout_secs: 2,
        output_path: root.path().join("private/current.json"),
    };
    std::fs::write(&config_path, serde_json::to_vec(&config)?)?;
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let first = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(env!("CARGO_BIN_EXE_kata-network-inventory"))
            .env("HTTP_PROXY", "http://must-not-be-inherited.example.com")
            .args([
                "--config",
                config_path.to_str().context("configuration path")?,
                "--once",
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    ensure!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let before = std::fs::read(&config.output_path)?;
    let inventory: InfrastructureInventory = serde_json::from_slice(&before)?;
    assert!(inventory.denied_cidrs.contains(&"10.0.0.2/32".into()));
    assert!(inventory.denied_cidrs.contains(&"10.1.0.0/16".into()));
    let completed = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    assert!((started..=completed).contains(&inventory.issued_at_unix));
    assert!(inventory.expires_at_unix <= inventory.issued_at_unix + 60);
    assert_eq!(
        std::fs::metadata(&config.output_path)?.permissions().mode() & 0o777,
        0o600
    );
    std::fs::write(kubectl, b"#!/bin/sh\nexit 1\n")?;
    let rejected = Command::new(env!("CARGO_BIN_EXE_kata-network-inventory"))
        .args([
            "--config",
            config_path.to_str().context("configuration path")?,
            "--once",
        ])
        .output()
        .await?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("digest differs"));
    assert_eq!(before, std::fs::read(&config.output_path)?);
    Ok(())
}
