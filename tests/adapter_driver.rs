use openshell_kata::{
    config::Config,
    driver::Driver,
    proto::openshell::compute::v1::{self as c, compute_driver_server::ComputeDriver},
};
use std::{os::unix::fs::PermissionsExt, sync::Arc};
use tokio_stream::StreamExt;
use tonic::{Code, Request};

fn config(root: &std::path::Path) -> Arc<Config> {
    Arc::new(Config {
        socket: root.join("driver.sock"),
        gateway: "https://127.0.0.1:1".into(),
        gateway_ca: root.join("missing-ca"),
        lifecycle: root.join("lifecycle"),
        lifecycle_arg: vec![],
        ssh: "/usr/bin/ssh".into(),
        prototype_policy_mode: true,
    })
}
fn sandbox(authentication: Vec<u8>) -> c::DriverSandbox {
    c::DriverSandbox {
        id: "test-sandbox".into(),
        name: "test-name".into(),
        spec: Some(c::DriverSandboxSpec {
            template: Some(c::DriverSandboxTemplate {
                image: "docker:29-dind".into(),
                ..Default::default()
            }),
            command: vec!["sleep".into(), "60".into()],
            launch_authentication: authentication,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn invalid_launch_authentication_never_calls_lifecycle() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let driver = Driver::new(config(root.path()));
    let error = driver
        .create_sandbox(Request::new(c::CreateSandboxRequest {
            sandbox: Some(sandbox(b"{}".to_vec())),
        }))
        .await
        .expect_err("invalid auth rejected");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(
        driver
            .list_sandboxes(Request::new(c::ListSandboxesRequest {}))
            .await?
            .into_inner()
            .sandboxes
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn deletion_failure_keeps_record_for_retry() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let key = root.path().join("host-key");
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()?;
    anyhow::ensure!(status.success(), "fixture key generation failed");
    let metadata=serde_json::json!({"sandbox_id":"test-sandbox","host":"127.0.0.1","port":12345,"username":"sandbox","private_key_path":key,"known_hosts_path":root.path().join("known-hosts")}).to_string();
    let marker = root.path().join("failed-once");
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\ncreate) printf '%s' '{}' ;;\ndelete) if [ ! -f '{}' ]; then touch '{}'; exit 1; fi ;;\nesac\n",
        metadata,
        marker.display(),
        marker.display()
    );
    std::fs::write(root.path().join("lifecycle"), script)?;
    std::fs::set_permissions(
        root.path().join("lifecycle"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    let auth = serde_json::to_vec(
        &serde_json::json!({"supervisor":{"gateway_token":"test-placeholder","ssh_host_private_key":std::fs::read_to_string(&key)?}}),
    )?;
    let driver = Driver::new(config(root.path()));
    driver
        .create_sandbox(Request::new(c::CreateSandboxRequest {
            sandbox: Some(sandbox(auth)),
        }))
        .await?;
    let mut watch = driver
        .watch_sandboxes(Request::new(c::WatchSandboxesRequest::default()))
        .await?
        .into_inner();
    let first_snapshot = tokio::time::timeout(std::time::Duration::from_secs(2), watch.next())
        .await?
        .expect("initial event")?;
    assert!(matches!(
        first_snapshot.payload,
        Some(c::watch_sandboxes_event::Payload::Sandbox(_))
    ));
    let first = driver
        .delete_sandbox(Request::new(c::DeleteSandboxRequest {
            sandbox_id: "test-sandbox".into(),
            ..Default::default()
        }))
        .await;
    assert!(first.is_err());
    let after_failure = tokio::time::timeout(std::time::Duration::from_secs(2), watch.next())
        .await?
        .expect("record retained")?;
    assert!(
        matches!(
            after_failure.payload,
            Some(c::watch_sandboxes_event::Payload::Sandbox(_))
        ),
        "failed deletion must not emit a tombstone"
    );
    assert!(
        driver
            .get_sandbox(Request::new(c::GetSandboxRequest {
                sandbox_id: "test-sandbox".into(),
                ..Default::default()
            }))
            .await
            .is_ok()
    );
    assert!(
        driver
            .delete_sandbox(Request::new(c::DeleteSandboxRequest {
                sandbox_id: "test-sandbox".into(),
                ..Default::default()
            }))
            .await?
            .into_inner()
            .deleted
    );
    assert_eq!(
        driver
            .get_sandbox(Request::new(c::GetSandboxRequest {
                sandbox_id: "test-sandbox".into(),
                ..Default::default()
            }))
            .await
            .expect_err("deleted")
            .code(),
        Code::NotFound
    );
    let deleted = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let event = watch.next().await.expect("live watch")?;
            if let Some(c::watch_sandboxes_event::Payload::Deleted(event)) = event.payload {
                break Ok::<_, tonic::Status>(event);
            }
        }
    })
    .await??;
    assert_eq!(deleted.sandbox_id, "test-sandbox");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(700), watch.next())
            .await
            .is_err(),
        "a watcher must receive each retained deletion only once"
    );
    let mut reconnect = driver
        .watch_sandboxes(Request::new(c::WatchSandboxesRequest::default()))
        .await?
        .into_inner();
    let replay = tokio::time::timeout(std::time::Duration::from_secs(2), reconnect.next())
        .await?
        .expect("retained tombstone")?;
    assert!(
        matches!(
            replay.payload,
            Some(c::watch_sandboxes_event::Payload::Deleted(_))
        ),
        "a reconnected watcher must recover missed deletion"
    );
    let restarted = Driver::new(config(root.path()));
    assert!(
        !restarted
            .delete_sandbox(Request::new(c::DeleteSandboxRequest {
                sandbox_id: "test-sandbox".into(),
                ..Default::default()
            }))
            .await?
            .into_inner()
            .deleted
    );
    let mut after_restart = restarted
        .watch_sandboxes(Request::new(c::WatchSandboxesRequest::default()))
        .await?
        .into_inner();
    let confirmed_absent =
        tokio::time::timeout(std::time::Duration::from_secs(2), after_restart.next())
            .await?
            .expect("confirmed absence tombstone")?;
    assert!(matches!(
        confirmed_absent.payload,
        Some(c::watch_sandboxes_event::Payload::Deleted(_))
    ));
    Ok(())
}

#[tokio::test]
async fn unsupported_contract_major_is_rejected() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let driver = Driver::new(config(root.path()));
    let request = c::GetCapabilitiesRequest {
        gateway: Some(
            openshell_kata::proto::openshell::extension::v1::PeerMetadata {
                protocol_version: Some(
                    openshell_kata::proto::openshell::extension::v1::ProtocolVersion {
                        major: 99,
                        minor: 0,
                    },
                ),
                ..Default::default()
            },
        ),
    };
    assert_eq!(
        driver
            .get_capabilities(Request::new(request))
            .await
            .expect_err("incompatible major")
            .code(),
        Code::FailedPrecondition
    );
    Ok(())
}

#[tokio::test]
async fn stopping_an_unknown_registry_entry_fails_without_claiming_backend_success()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let driver = Driver::new(config(root.path()));
    let error = driver
        .stop_sandbox(Request::new(c::StopSandboxRequest {
            sandbox_id: "unknown-sandbox".into(),
            ..Default::default()
        }))
        .await
        .expect_err("unknown backend state must not be called stopped");
    assert_eq!(error.code(), Code::NotFound);
    Ok(())
}
