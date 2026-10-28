use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;

const UID: &str = "34ab0ea6-e81a-4935-a78a-35304ace16df";
const RUN_ID: &str = "d59743a5-a1d7-4e30-bf95-07782f1afde7";
fn target() -> Target {
    Target {
        namespace: "openshell-system".into(),
        name: "openshell-network-inventory".into(),
        uid: UID.into(),
        run_uuid: RUN_ID.into(),
    }
}
fn fresh(generation: u64) -> InfrastructureInventory {
    let now = unix_now().expect("clock");
    InfrastructureInventory {
        version: 1,
        generation,
        issued_at_unix: now,
        expires_at_unix: now + 60,
        denied_cidrs: vec!["10.0.0.0/8".into()],
    }
}
fn cm(value: Option<&InfrastructureInventory>) -> Value {
    json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"namespace":"openshell-system","name":"openshell-network-inventory","uid":UID,"resourceVersion":"1","annotations":{RUN:RUN_ID}},"data":{KEY:value.map(|v|serde_json::to_string(v).expect("fixture JSON")).unwrap_or_default()}})
}

#[test]
fn only_exact_live_configmap_and_run_are_accepted() -> Result<()> {
    let valid = cm(Some(&fresh(1)));
    target().observe(&valid)?;
    for (field, value) in [
        ("namespace", json!("other")),
        ("name", json!("other")),
        ("uid", json!(RUN_ID)),
        ("resourceVersion", json!("")),
        ("deletionTimestamp", json!("2026-01-01T00:00:00Z")),
    ] {
        let mut wrong = valid.clone();
        wrong["metadata"][field] = value;
        assert!(target().observe(&wrong).is_err(), "metadata {field}");
    }
    let mut wrong = valid.clone();
    wrong["metadata"]["annotations"][RUN] = json!(UID);
    assert!(target().observe(&wrong).is_err());
    for (field, value) in [
        ("immutable", json!(true)),
        ("binaryData", json!({"payload":"YQ=="})),
        ("kind", json!("Secret")),
        ("apiVersion", json!("other")),
        ("data", json!({KEY:"","other":"x"})),
    ] {
        let mut wrong = valid.clone();
        wrong[field] = value;
        assert!(target().observe(&wrong).is_err(), "ConfigMap {field}");
    }
    let mut wrong = valid;
    wrong["data"][KEY] = json!("x".repeat(LIMIT as usize + 1));
    assert!(target().observe(&wrong).is_err());
    Ok(())
}

#[test]
fn publication_requires_generation_and_resource_version_progress() -> Result<()> {
    let previous = fresh(1);
    let next = fresh(2);
    let old = cm(Some(&previous));
    assert!(replacement(&target(), &old, &previous).is_err());
    let (mut replaced, rv) = replacement(&target(), &old, &next)?;
    assert_eq!(replaced["metadata"]["resourceVersion"], rv);
    assert!(committed(&target(), &replaced, &next, &rv).is_err());
    replaced["metadata"]["resourceVersion"] = json!("2");
    committed(&target(), &replaced, &next, &rv)?;
    assert!(committed(&target(), &replaced, &fresh(3), &rv).is_err());
    let (bootstrap, _) = replacement(&target(), &cm(None), &next)?;
    assert_eq!(bootstrap["data"][KEY], serde_json::to_string(&next)?);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn repeated_generation_never_renews_monotonic_authority() -> Result<()> {
    let initial = fresh(2);
    let cursor = Cursor::from_value(initial.clone(), unix_now()?)?;
    assert!(!cursor.admit(&initial)?);
    assert!(cursor.admit(&fresh(1)).is_err());
    let mut changed = initial.clone();
    changed.denied_cidrs = vec!["10.1.0.0/16".into()];
    assert!(cursor.admit(&changed).is_err());
    tokio::time::advance(Duration::from_secs(61)).await;
    assert!(
        cursor.admit(&initial).is_err(),
        "same generation cannot renew after receipt deadline"
    );
    assert!(cursor.admit(&fresh(3))?);
    Ok(())
}

#[test]
fn malformed_stale_future_or_unknown_inventory_is_rejected() {
    let now = unix_now().expect("clock");
    let valid = serde_json::to_value(fresh(1)).expect("JSON");
    for (field, value) in [
        ("version", json!(2)),
        ("generation", json!(0)),
        ("issued_at_unix", json!(now + 1)),
        ("expires_at_unix", json!(now)),
        ("unknown", json!(true)),
        ("denied_cidrs", json!([])),
        ("denied_cidrs", json!(vec!["10.0.0.0/8"; 4097])),
    ] {
        let mut wrong = valid.clone();
        wrong[field] = value;
        assert!(
            inventory(&wrong.to_string(), now).is_err(),
            "invalid {field}"
        );
    }
}

struct Fixture {
    root: tempfile::TempDir,
    source: InventoryConfig,
    courier: CourierConfig,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let mut source = crate::inventory::tests::fixture_config(root.path())?;
        let quote =
            |name: &str| crate::config::shell_quote(&root.path().join(name).to_string_lossy());
        let script = format!(
            r#"#!/bin/sh
set -eu
[ "${{HTTP_PROXY+x}}" != x ] || exit 90
printf '%s\n' "$@" >> {log}
method=''; path=''
for value in "$@"; do
  case "$value" in get|replace) method="$value";; /api/*) path="$value";; esac
done
case "$path" in
  /api/v1/nodes\?*) printf '%s' '{{"kind":"NodeList","metadata":{{"resourceVersion":"1"}},"items":[{{"status":{{"addresses":[{{"type":"InternalIP","address":"10.4.5.6"}}]}}}}]}}'; exit 0;;
  /api/v1/services\?*) printf '%s' '{{"kind":"ServiceList","metadata":{{"resourceVersion":"1"}},"items":[]}}'; exit 0;;
  /api/v1/namespaces/openshell-system/configmaps/openshell-network-inventory) ;;
  *) exit 91;;
esac
if [ "$method" = get ]; then cat {current}; exit; fi
[ "$method" = replace ] || exit 92
cat > {submitted}
mode=$(cat {mode})
[ "$mode" != fail ] || exit 93
sed 's/"resourceVersion":"1"/"resourceVersion":"2"/' {submitted} > {current}
[ "$mode" != lost ] || exit 94
cat {current}
"#,
            log = quote("calls"),
            current = quote("current"),
            submitted = quote("submitted"),
            mode = quote("mode")
        );
        std::fs::write(&source.kubectl_path, &script)?;
        std::fs::write(root.path().join("mode"), "ok")?;
        std::fs::write(root.path().join("current"), serde_json::to_vec(&cm(None))?)?;
        source.kubectl_sha256 = format!("{:x}", Sha256::digest(script.as_bytes()));
        let courier = CourierConfig {
            version: 1,
            kubectl_path: source.kubectl_path.clone(),
            kubectl_sha256: source.kubectl_sha256.clone(),
            kubeconfig_path: source.kubeconfig_path.clone(),
            namespace: target().namespace,
            name: target().name,
            uid: UID.into(),
            run_uuid: RUN_ID.into(),
            output_path: root.path().join("courier/current.json"),
            poll_millis: 1000,
            api_timeout_secs: 1,
        };
        source.validate()?;
        courier.validate()?;
        Ok(Self {
            root,
            source,
            courier,
        })
    }
    fn publisher(&self) -> PublisherConfig {
        PublisherConfig {
            version: 1,
            inventory_config_file: self.root.path().join("source.json"),
            namespace: target().namespace,
            name: target().name,
            uid: UID.into(),
            run_uuid: RUN_ID.into(),
        }
    }
    fn current(&self, value: &Value) -> Result<()> {
        std::fs::write(self.root.path().join("current"), serde_json::to_vec(value)?)?;
        Ok(())
    }
    fn mode(&self, value: &str) -> Result<()> {
        std::fs::write(self.root.path().join("mode"), value)?;
        Ok(())
    }
}

#[tokio::test]
async fn publisher_cas_and_ambiguous_response_reconciliation_are_exact() -> Result<()> {
    for mode in ["ok", "lost", "fail"] {
        let fixture = Fixture::new()?;
        fixture.mode(mode)?;
        let result = run::publish_once(&fixture.publisher(), &fixture.source).await;
        assert_eq!(
            result.is_ok(),
            mode != "fail",
            "PUT mode {mode}: {result:?}"
        );
        let calls = std::fs::read_to_string(fixture.root.path().join("calls"))?;
        assert!(calls.contains("replace\n--raw\n/api/v1/namespaces/openshell-system/configmaps/openshell-network-inventory\n-f\n-\n"));
        assert!(!calls.contains("secrets") && !calls.contains("create"));
        if mode != "fail" {
            let changed: Value =
                serde_json::from_slice(&std::fs::read(fixture.root.path().join("current"))?)?;
            let (_, data) = target().observe(&changed)?;
            inventory(&data, unix_now()?)?;
            assert_eq!(changed["metadata"]["resourceVersion"], "2");
        }
    }
    Ok(())
}

#[tokio::test]
async fn courier_preserves_source_ttl_modes_and_old_file_on_failed_poll() -> Result<()> {
    let fixture = Fixture::new()?;
    let value = fresh(5);
    fixture.current(&cm(Some(&value)))?;
    let mut cursor = None;
    run::courier_once(&fixture.courier, &mut cursor).await?;
    let bytes = std::fs::read(&fixture.courier.output_path)?;
    let saved: InfrastructureInventory = serde_json::from_slice(&bytes)?;
    assert_eq!(saved, value);
    assert_eq!(
        std::fs::metadata(&fixture.courier.output_path)?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(fixture.courier.output_path.parent().expect("parent"))?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let before = cursor.as_ref().expect("cursor").deadline;
    run::courier_once(&fixture.courier, &mut cursor).await?;
    assert_eq!(cursor.as_ref().expect("cursor").deadline, before);
    let mut wrong = cm(Some(&fresh(6)));
    wrong["metadata"]["uid"] = json!(RUN_ID);
    fixture.current(&wrong)?;
    assert!(
        run::courier_once(&fixture.courier, &mut cursor)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&fixture.courier.output_path)?, bytes);
    assert_eq!(
        retained(&fixture.courier.output_path)?
            .expect("restart floor")
            .value
            .generation,
        5
    );
    let calls = std::fs::read_to_string(fixture.root.path().join("calls"))?;
    assert!(!calls.contains("replace") && !calls.contains("services") && !calls.contains("nodes"));
    Ok(())
}

#[tokio::test]
async fn configured_publisher_once_uses_existing_observer_contract() -> Result<()> {
    let fixture = Fixture::new()?;
    let publisher = fixture.publisher();
    std::fs::write(
        &publisher.inventory_config_file,
        serde_json::to_vec(&fixture.source)?,
    )?;
    let path = fixture.root.path().join("publisher.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "version":1,"inventory_config_file":publisher.inventory_config_file,
            "namespace":publisher.namespace,"name":publisher.name,"uid":publisher.uid,
            "run_uuid":publisher.run_uuid
        }))?,
    )?;
    run_publisher(&path, true).await?;
    let remote: Value =
        serde_json::from_slice(&std::fs::read(fixture.root.path().join("current"))?)?;
    let (_, bytes) = target().observe(&remote)?;
    let published = inventory(&bytes, unix_now()?)?;
    let local: InfrastructureInventory =
        serde_json::from_slice(&std::fs::read(&fixture.source.output_path)?)?;
    assert_eq!(
        published, local,
        "transport must preserve exactly the fresh observation"
    );
    Ok(())
}

#[test]
fn transport_config_auth_identity_and_timing_are_closed() -> Result<()> {
    let fixture = Fixture::new()?;
    for mutate in [0, 1, 2, 3, 4] {
        let mut config = fixture.courier.clone();
        match mutate {
            0 => config.poll_millis = 1001,
            1 => config.api_timeout_secs = 0,
            2 => config.uid = "bad".into(),
            3 => config.namespace = "../other".into(),
            _ => config.kubectl_sha256 = "a".repeat(64),
        }
        assert!(config.validate().is_err(), "config variant {mutate}");
    }
    for name in ["", "../x", "a..b", "-bad", "UPPER", "a/b"] {
        let mut target = target();
        target.name = name.into();
        assert!(target.validate().is_err());
    }
    assert!(serde_json::from_value::<PublisherConfig>(json!({"version":1,"inventory_config_file":"/file","namespace":"n","name":"c","uid":UID,"run_uuid":RUN_ID,"extra":true})).is_err());
    Ok(())
}
