use std::process::Command;

#[test]
fn operator_storage_class_is_required_before_any_kubernetes_mutation() {
    let root = tempfile::tempdir().expect("private fixture");
    let state = root.path().canonicalize().expect("canonical fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_kata-kubernetes"))
        .args([
            "create",
            &uuid::Uuid::new_v4().to_string(),
            "--proof-nonce",
            &uuid::Uuid::new_v4().to_string(),
        ])
        .env_clear()
        .env("OPENSHELL_KATA_STATE_DIR", &state)
        .env("OPENSHELL_KATA_WORKSPACE", "tenant")
        .env(
            "OPENSHELL_KATA_GUEST_IMAGE",
            format!("registry.example/guest@sha256:{}", "a".repeat(64)),
        )
        .env("OPENSHELL_KATA_GUEST_NETWORK_CIDR", "10.176.0.0/16")
        .output()
        .expect("launcher subprocess");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("explicit operator storage class required"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
