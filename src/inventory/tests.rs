use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{os::unix::fs::PermissionsExt, path::Path};

pub(super) fn fixture_config(root: &Path) -> Result<InventoryConfig> {
    let kubectl = root.join("kubectl");
    let kubeconfig = root.join("kubeconfig");
    let script = b"#!/bin/sh\nexit 1\n";
    std::fs::write(&kubectl, script)?;
    std::fs::set_permissions(&kubectl, std::fs::Permissions::from_mode(0o700))?;
    let ca = root.join("ca.crt");
    let token = root.join("token");
    std::fs::write(&ca, b"CA fixture")?;
    std::fs::write(&token, b"token fixture")?;
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o600))?;
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(
        &kubeconfig,
        serde_json::to_vec(
            &json!({"clusters":[{"name":"cluster","cluster":{"server":"https://kubernetes.example.com","certificate-authority":ca}}],"users":[{"name":"inventory","user":{"tokenFile":token}}],"contexts":[{"name":"inventory","context":{"cluster":"cluster","user":"inventory"}}],"current-context":"inventory"}),
        )?,
    )?;
    std::fs::set_permissions(&kubeconfig, std::fs::Permissions::from_mode(0o600))?;
    Ok(InventoryConfig {
        version: 1,
        kubectl_path: kubectl,
        kubectl_sha256: format!("{:x}", Sha256::digest(script)),
        kubeconfig_path: kubeconfig,
        protected_hostnames: vec![],
        resolver_ip: "127.0.0.1".parse()?,
        resolver_port: 53,
        baseline_denied_cidrs: vec!["10.0.0.0/8".into()],
        include_external_names: true,
        trusted_external_name_services: vec![],
        refresh_secs: 5,
        freshness_secs: 60,
        query_timeout_secs: 1,
        api_timeout_secs: 2,
        output_path: root.join("private/current.json"),
    })
}

#[test]
fn kube_footprint_includes_nodes_services_and_load_balancers() -> Result<()> {
    let nodes = json!({"kind":"NodeList","metadata":{},"items":[{"status":{"addresses":[{"type":"InternalIP","address":"10.0.0.1"},{"type":"Hostname","address":"node.example.com"}]}}]});
    let services = json!({"kind":"ServiceList","metadata":{},"items":[{"metadata":{"namespace":"infrastructure","name":"protected"},"spec":{"clusterIP":"10.1.0.1","clusterIPs":["10.1.0.1","fd00::1"],"externalIPs":["8.8.4.4"],"externalName":"external.example.com"},"status":{"loadBalancer":{"ingress":[{"ip":"1.1.1.1"},{"hostname":"lb.example.com"}]}}}]});
    let mut result = kube::Footprint::default();
    kube::observe_page(&nodes, "NodeList", &[], &mut result)?;
    kube::observe_page(
        &services,
        "ServiceList",
        &["infrastructure/protected".into()],
        &mut result,
    )?;
    assert!(result.cidrs.contains("10.0.0.1/32"));
    assert!(result.cidrs.contains("fd00::1/128"));
    assert!(result.cidrs.contains("8.8.4.4/32"));
    assert!(result.cidrs.contains("1.1.1.1/32"));
    assert!(result.names.contains("external.example.com"));
    assert!(result.names.contains("lb.example.com"));
    assert!(result.names.contains("node.example.com"));
    Ok(())
}

#[test]
fn partial_or_malformed_kube_observation_is_rejected() {
    for value in [
        json!({"kind":"Status","items":[]}),
        json!({"kind":"NodeList","items":[{"status":{"addresses":[{"type":"InternalIP","address":"invalid"}]}}]}),
        json!({"kind":"NodeList","items":[{}]}),
    ] {
        assert!(
            kube::observe_page(&value, "NodeList", &[], &mut kube::Footprint::default()).is_err()
        );
    }
}

#[test]
fn publication_is_private_atomic_and_generation_survives_restart() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = fixture_config(root.path())?;
    config.validate()?;
    let initial = publication::next_generation(&config.output_path)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let current = InfrastructureInventory {
        version: 1,
        generation: initial + 10_000_000,
        issued_at_unix: now,
        expires_at_unix: now + 60,
        denied_cidrs: vec!["10.0.0.0/8".into()],
    };
    publication::publish(&config.output_path, &current)?;
    assert!(publication::next_generation(&config.output_path)? > current.generation);
    assert_eq!(
        std::fs::metadata(&config.output_path)?.permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(config.output_path.parent().context("parent")?)?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let before = std::fs::read(&config.output_path)?;
    std::fs::set_permissions(&config.output_path, std::fs::Permissions::from_mode(0o644))?;
    assert!(publication::publish(&config.output_path, &current).is_err());
    assert_eq!(before, std::fs::read(&config.output_path)?);
    Ok(())
}

#[tokio::test]
async fn failed_refresh_leaves_previous_inventory_unmodified() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = fixture_config(root.path())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let current = InfrastructureInventory {
        version: 1,
        generation: 1,
        issued_at_unix: now,
        expires_at_unix: now + 60,
        denied_cidrs: vec!["10.0.0.0/8".into()],
    };
    publication::publish(&config.output_path, &current)?;
    let before = std::fs::read(&config.output_path)?;
    assert!(refresh(&config).await.is_err());
    assert_eq!(before, std::fs::read(&config.output_path)?);
    Ok(())
}

#[tokio::test]
async fn kubectl_only_requests_bounded_readonly_node_and_service_pages() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut config = fixture_config(root.path())?;
    let calls = root.path().join("calls");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in\n*'/api/v1/nodes?'*) printf '%s' '{{\"kind\":\"NodeList\",\"metadata\":{{\"resourceVersion\":\"1\"}},\"items\":[{{\"status\":{{\"addresses\":[{{\"type\":\"InternalIP\",\"address\":\"10.0.0.1\"}}]}}}}]}}';;\n*'/api/v1/services?'*) printf '%s' '{{\"kind\":\"ServiceList\",\"metadata\":{{\"resourceVersion\":\"2\"}},\"items\":[]}}';;\n*) exit 1;;\nesac\n",
        calls.display()
    );
    std::fs::write(&config.kubectl_path, &script)?;
    config.kubectl_sha256 = format!("{:x}", Sha256::digest(script.as_bytes()));
    let result = refresh(&config).await?;
    assert!(result.denied_cidrs.contains(&"10.0.0.1/32".into()));
    let requests = std::fs::read_to_string(calls)?;
    assert_eq!(requests.lines().count(), 2);
    assert!(requests.contains("get --raw /api/v1/nodes?limit=200"));
    assert!(requests.contains("get --raw /api/v1/services?limit=200"));
    assert!(!requests.contains("secrets"));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn backward_wall_clock_cannot_extend_dns_observation_lifetime() -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let original = UNIX_EPOCH + Duration::from_secs(1000);
    tokio::time::advance(Duration::from_secs(1)).await;
    let (issued, expires) = publication_times(
        original + Duration::from_secs(2),
        deadline,
        original - Duration::from_secs(10),
    )?;
    assert_eq!(issued, 990);
    assert_eq!(expires, 991);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        publication_times(
            original + Duration::from_secs(2),
            deadline,
            original - Duration::from_secs(10)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn configuration_refuses_unsafe_paths_permissions_and_timing() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = fixture_config(root.path())?;
    let value = serde_json::to_value(&config)?;
    for (field, bad) in [
        ("version", json!(2)),
        ("refresh_secs", json!(11)),
        ("freshness_secs", json!(61)),
        ("query_timeout_secs", json!(6)),
        ("api_timeout_secs", json!(11)),
        ("resolver_port", json!(0)),
        ("output_path", json!("relative/file")),
        ("kubectl_sha256", json!("bad")),
        ("protected_hostnames", json!(["8.8.8.8"])),
        (
            "protected_hostnames",
            json!(["EXAMPLE.COM.", "example.com"]),
        ),
    ] {
        let mut invalid = value.clone();
        invalid[field] = bad;
        assert!(
            serde_json::from_value::<InventoryConfig>(invalid)?
                .validate()
                .is_err(),
            "field {field}"
        );
    }
    let path = root.path().join("operator.json");
    std::fs::write(&path, serde_json::to_vec(&config)?)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    InventoryConfig::load(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    assert!(InventoryConfig::load(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let link = root.path().join("symlink.json");
    std::os::unix::fs::symlink(path, &link)?;
    assert!(InventoryConfig::load(&link).is_err());
    Ok(())
}

#[test]
fn inventory_authentication_rejects_ambient_helpers_credentials_and_insecure_tls() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = fixture_config(root.path())?;
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config.kubeconfig_path)?)?;
    for (section, field, bad) in [
        ("user", "exec", json!({"command":"cloud-auth"})),
        ("user", "auth-provider", json!({"name":"gcp"})),
        ("user", "client-key", json!("/operator/key.pem")),
        ("user", "token", json!("inline")),
        ("cluster", "insecure-skip-tls-verify", json!(true)),
        ("cluster", "proxy-url", json!("http://proxy.example.com")),
    ] {
        let mut invalid = original.clone();
        let target = if section == "user" {
            &mut invalid["users"][0]["user"]
        } else {
            &mut invalid["clusters"][0]["cluster"]
        };
        target[field] = bad;
        std::fs::write(&config.kubeconfig_path, serde_json::to_vec(&invalid)?)?;
        assert!(config.validate().is_err(), "accepted auth field {field}");
    }
    std::fs::write(&config.kubeconfig_path, serde_json::to_vec(&original)?)?;
    let token = root.path().join("token");
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o666))?;
    assert!(config.validate().is_err());
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
    let rotated = root.path().join("rotated-token");
    std::fs::rename(&token, &rotated)?;
    std::os::unix::fs::symlink(&rotated, &token)?;
    config.validate()?;
    Ok(())
}

#[test]
fn external_names_require_exact_operator_trusted_service_identity() -> Result<()> {
    let trusted = ["infrastructure/database".into()];
    for (metadata, expected) in [
        (
            json!({"namespace":"infrastructure","name":"database"}),
            true,
        ),
        (json!({"namespace":"tenant","name":"database"}), false),
        (
            json!({"namespace":"infrastructure","name":"database-copy"}),
            false,
        ),
        (
            json!({"namespace":"infrastructure","name":"DATABASE"}),
            false,
        ),
        (json!({}), false),
    ] {
        let page = json!({"kind":"ServiceList","items":[{"metadata":metadata,"spec":{"externalName":"protected.example.com"}}]});
        let mut footprint = kube::Footprint::default();
        kube::observe_page(&page, "ServiceList", &trusted, &mut footprint)?;
        assert_eq!(footprint.names.contains("protected.example.com"), expected);
    }
    // Old configuration has no trust grants, even when ExternalName collection is enabled.
    let root = tempfile::tempdir()?;
    let mut value = serde_json::to_value(fixture_config(root.path())?)?;
    value
        .as_object_mut()
        .context("configuration")?
        .remove("trusted_external_name_services");
    let config: InventoryConfig = serde_json::from_value(value)?;
    assert!(config.include_external_names && config.trusted_external_name_services.is_empty());
    for invalid in [
        vec!["database"],
        vec!["*/database"],
        vec!["a/b/c"],
        vec!["a/-b"],
        vec!["a/b", "a/b"],
    ] {
        let mut config = fixture_config(root.path())?;
        config.trusted_external_name_services = invalid.into_iter().map(String::from).collect();
        assert!(config.validate().is_err());
    }
    Ok(())
}

#[tokio::test]
async fn untrusted_nxdomain_cannot_block_refresh_but_protected_dns_still_fails_closed() -> Result<()>
{
    use hickory_proto::{
        op::{Message, MessageType, ResponseCode},
        rr::{
            RData, Record, RecordType,
            rdata::{A, AAAA},
        },
    };
    let root = tempfile::tempdir()?;
    let mut config = fixture_config(root.path())?;
    let script = r#"#!/bin/sh
case "$*" in
*'/api/v1/nodes?'*) printf '%s' '{"kind":"NodeList","metadata":{"resourceVersion":"1"},"items":[{"status":{"addresses":[{"type":"InternalIP","address":"10.0.0.1"}]}}]}';;
*'/api/v1/services?'*) printf '%s' '{"kind":"ServiceList","metadata":{"resourceVersion":"1"},"items":[{"metadata":{"namespace":"infrastructure","name":"database"},"spec":{"externalName":"healthy.example.com"}},{"metadata":{"namespace":"tenant","name":"database"},"spec":{"externalName":"unresolved.example.com"}}]}';;
*) exit 1;;
esac
"#;
    std::fs::write(&config.kubectl_path, script)?;
    config.kubectl_sha256 = format!("{:x}", Sha256::digest(script.as_bytes()));
    config.trusted_external_name_services = vec!["infrastructure/database".into()];
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    config.resolver_port = socket.local_addr()?.port();
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = requests.clone();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let dns = tokio::spawn(async move {
        loop {
            let mut buffer = [0; 4096];
            let (size, peer) = tokio::select! {
                result = socket.recv_from(&mut buffer) => result?,
                _ = &mut stopped => break,
            };
            let query = Message::from_vec(&buffer[..size])?;
            let asked = query.queries.first().context("DNS query")?;
            observed
                .lock()
                .expect("request list")
                .push(asked.name().to_ascii());
            let mut reply = Message::query();
            reply.metadata.id = query.metadata.id;
            reply.metadata.message_type = MessageType::Response;
            reply.metadata.recursion_available = true;
            reply.add_query(asked.clone());
            if asked.name().to_ascii() == "healthy.example.com." {
                let data = if asked.query_type() == RecordType::A {
                    RData::A(A("203.0.113.10".parse()?))
                } else {
                    RData::AAAA(AAAA("2001:db8::10".parse()?))
                };
                reply.add_answer(Record::from_rdata(asked.name().clone(), 30, data));
            } else {
                reply.metadata.response_code = ResponseCode::NXDomain;
            }
            socket.send_to(&reply.to_vec()?, peer).await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    let first = refresh(&config).await?;
    let second = refresh(&config).await?;
    assert!(second.generation > first.generation);
    assert!(second.denied_cidrs.contains(&"203.0.113.10/32".into()));
    assert!(
        requests
            .lock()
            .expect("request list")
            .iter()
            .all(|name| name == "healthy.example.com.")
    );
    let before = std::fs::read(&config.output_path)?;
    // Explicitly trusting the Service makes its failure mandatory, as before.
    config
        .trusted_external_name_services
        .push("tenant/database".into());
    assert!(refresh(&config).await.is_err());
    assert_eq!(before, std::fs::read(&config.output_path)?);
    // An explicit protected hostname cannot be bypassed by removing Service trust.
    config.trusted_external_name_services = vec!["infrastructure/missing".into()];
    assert!(refresh(&config).await.is_err());
    assert_eq!(before, std::fs::read(&config.output_path)?);
    config.trusted_external_name_services.clear();
    config.protected_hostnames = vec!["unresolved.example.com".into()];
    assert!(refresh(&config).await.is_err());
    assert_eq!(before, std::fs::read(&config.output_path)?);
    let _ = stop.send(());
    dns.await??;
    Ok(())
}
