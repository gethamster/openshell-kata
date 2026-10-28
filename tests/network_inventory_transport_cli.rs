use serde_json::json;
use sha2::{Digest, Sha256};
use std::{os::unix::fs::PermissionsExt, process::Command};

#[test]
fn courier_cli_fetches_exact_object_without_extending_authority() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let ca = root.path().join("ca");
    let token = root.path().join("token");
    std::fs::write(&ca, "fixture CA")?;
    std::fs::write(&token, "fixture token")?;
    let kubeconfig = root.path().join("kubeconfig");
    std::fs::write(
        &kubeconfig,
        serde_json::to_vec(
            &json!({"clusters":[{"name":"cluster","cluster":{"server":"https://kubernetes.example.com","certificate-authority":ca}}],"users":[{"name":"inventory","user":{"tokenFile":token}}],"contexts":[{"name":"inventory","context":{"cluster":"cluster","user":"inventory"}}],"current-context":"inventory"}),
        )?,
    )?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let uid = "70997958-0520-45d7-a676-5ca57ee39385";
    let run = "b919d87d-6872-4328-9f72-4a2b4da1be95";
    let inventory = json!({"version":1,"generation":5,"issued_at_unix":now,"expires_at_unix":now+60,"denied_cidrs":["10.0.0.0/8"]});
    let object = root.path().join("object.json");
    std::fs::write(
        &object,
        serde_json::to_vec(
            &json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"namespace":"openshell-system","name":"openshell-network-inventory","uid":uid,"resourceVersion":"42","annotations":{"openshell-kata.io/inventory-run":run}},"data":{"inventory.json":inventory.to_string()}}),
        )?,
    )?;
    let quote =
        |path: &std::path::Path| openshell_kata::config::shell_quote(&path.to_string_lossy());
    let script = format!(
        "#!/bin/sh\nset -eu\n[ \"${{HTTP_PROXY+x}}\" != x ] || exit 90\nprintf '%s\\n' \"$@\" > {}\ncat {}\n",
        quote(&root.path().join("calls")),
        quote(&object)
    );
    let kubectl = root.path().join("kubectl");
    std::fs::write(&kubectl, &script)?;
    std::fs::set_permissions(&kubectl, std::fs::Permissions::from_mode(0o700))?;
    let output = root.path().join("private/current.json");
    let config = root.path().join("courier.json");
    std::fs::write(
        &config,
        serde_json::to_vec(
            &json!({"version":1,"kubectl_path":kubectl,"kubectl_sha256":format!("{:x}",Sha256::digest(script.as_bytes())),"kubeconfig_path":kubeconfig,"namespace":"openshell-system","name":"openshell-network-inventory","uid":uid,"run_uuid":run,"output_path":output,"poll_millis":1000,"api_timeout_secs":1}),
        )?,
    )?;
    let run_command = || {
        Command::new(env!("CARGO_BIN_EXE_kata-network-inventory"))
            .args(["courier", "--config"])
            .arg(&config)
            .arg("--once")
            .env("HTTP_PROXY", "http://untrusted.example:8080")
            .output()
    };
    let result = run_command()?;
    assert!(
        result.status.success(),
        "courier CLI: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&output)?)?;
    assert_eq!(saved, inventory);
    let calls = std::fs::read_to_string(root.path().join("calls"))?;
    assert!(calls.ends_with(
        "get\n--raw\n/api/v1/namespaces/openshell-system/configmaps/openshell-network-inventory\n"
    ));
    let mut wrong: serde_json::Value = serde_json::from_slice(&std::fs::read(&object)?)?;
    wrong["metadata"]["annotations"]["openshell-kata.io/inventory-run"] = json!(uid);
    std::fs::write(&object, serde_json::to_vec(&wrong)?)?;
    assert!(
        !run_command()?.status.success(),
        "replaced run must be rejected"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&output)?)?,
        inventory
    );
    Ok(())
}
