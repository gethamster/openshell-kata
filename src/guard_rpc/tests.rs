use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

pub(super) const NODE: &str = "74ad2dbf-d87c-4dcc-96cc-b5ad5f3b324b";
pub(super) const POD: &str = "19de80e8-f423-4317-97c5-f16ee0949568";

#[test]
fn routing_and_challenges_are_closed() {
    for value in [
        "",
        "../secret",
        "00000000-0000-0000-0000-000000000000",
        "74AD2DBF-D87C-4DCC-96CC-B5AD5F3B324B",
    ] {
        assert!(canonical_uuid(value).is_err(), "accepted {value}");
    }
    assert_eq!(
        server_name(NODE).expect("node identity"),
        "runtime-guard.kata-system.internal"
    );
    assert_eq!(
        server_name(POD).expect("another valid node"),
        "runtime-guard.kata-system.internal"
    );
    assert!(validate_endpoint("10.20.30.40:9443".parse().expect("endpoint")).is_ok());
    for value in [
        "127.0.0.1:9443",
        "10.20.30.40:22",
        "8.8.8.8:9443",
        "0.0.0.0:9443",
        "[fd00::1]:9443",
    ] {
        assert!(
            validate_endpoint(value.parse().expect("endpoint")).is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn transport_files_and_config_cannot_select_unsafe_authority() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let cert = root.path().join("cert.pem");
    std::fs::write(&cert, b"fixture certificate")?;
    std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o600))?;
    assert!(read_file(&cert, FileKind::PrivateKey).is_ok());
    std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o644))?;
    assert!(read_file(&cert, FileKind::PrivateKey).is_err());
    assert!(read_file(&cert, FileKind::Public).is_ok());
    std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o666))?;
    assert!(read_file(&cert, FileKind::Public).is_err());
    let link = root.path().join("link");
    symlink(&cert, &link)?;
    assert!(read_file(&link, FileKind::Public).is_err());
    let empty = root.path().join("empty");
    std::fs::write(&empty, [])?;
    assert!(read_file(&empty, FileKind::Public).is_err());
    std::fs::write(&empty, vec![0; 65537])?;
    assert!(read_file(&empty, FileKind::Public).is_err());
    assert!(read_file(std::path::Path::new("relative"), FileKind::Public).is_err());
    assert!(serde_json::from_value::<GuardClientConfig>(serde_json::json!({"version":1,"server_ca_file":cert,"certificate_file":cert,"private_key_file":cert,"insecure":true})).is_err());
    let config = GuardServerConfig {
        version: 1,
        bind: Some("10.20.30.40:9443".parse()?),
        certificate_file: cert.clone(),
        private_key_file: cert.clone(),
        client_ca_file: cert,
        allowed_client_certificate_sha256: vec!["a".repeat(64)],
    };
    config.validate()?;
    assert_eq!(config.bind_address(None)?, "10.20.30.40:9443".parse()?);
    let unbound = GuardServerConfig {
        bind: None,
        ..config.clone()
    };
    assert!(unbound.bind_address(None).is_err());
    assert_eq!(
        unbound.bind_address(Some("10.30.40.50:9443".parse()?))?,
        "10.30.40.50:9443".parse()?
    );
    for invalid in [
        "0.0.0.0:9443",
        "127.0.0.1:9443",
        "10.30.40.50:22",
        "8.8.8.8:9443",
    ] {
        assert!(unbound.bind_address(Some(invalid.parse()?)).is_err());
    }
    for fingerprints in [
        vec![],
        vec!["bad".into()],
        vec!["a".repeat(64); 17],
        vec!["A".repeat(64)],
    ] {
        assert!(
            GuardServerConfig {
                allowed_client_certificate_sha256: fingerprints,
                ..config.clone()
            }
            .validate()
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn untrusted_proof_bytes_cannot_retarget_or_replay_identity() -> anyhow::Result<()> {
    let response = super::tls_tests::proof(POD, nonce())?;
    let mut value = serde_json::to_value(&response)?;
    client::decode(&serde_json::to_vec(&value)?, NODE, POD, nonce())?;
    assert!(client::decode(&vec![b'x'; MAX_PROOF + 1], NODE, POD, nonce()).is_err());
    assert!(client::decode(b"invalid", NODE, POD, nonce()).is_err());
    value["nonce"] = serde_json::json!(POD);
    assert!(client::decode(&serde_json::to_vec(&value)?, NODE, POD, nonce()).is_err());
    value = serde_json::to_value(&response)?;
    value["proof"]["binding"]["pod_uid"] = serde_json::json!(nonce());
    assert!(client::decode(&serde_json::to_vec(&value)?, NODE, POD, nonce()).is_err());
    value = serde_json::to_value(&response)?;
    value["proof"]["binding"]["node_uid"] = serde_json::json!(POD);
    assert!(client::decode(&serde_json::to_vec(&value)?, NODE, POD, nonce()).is_err());
    value = serde_json::to_value(&response)?;
    value["proof"]["binding"]["expires_at_unix"] = serde_json::json!(0);
    assert!(client::decode(&serde_json::to_vec(&value)?, NODE, POD, nonce()).is_err());
    Ok(())
}

pub(super) fn nonce() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE
        .get_or_init(|| uuid::Uuid::new_v4().to_string())
        .as_str()
}
