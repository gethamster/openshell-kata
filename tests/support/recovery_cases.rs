use super::*;

#[tokio::test]
async fn failed_stop_or_delete_never_keeps_a_closed_runtime_ready() -> anyhow::Result<()> {
    for action in ["stop", "delete"] {
        let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
        let driver =
            Driver::new(fixture.runtime.config.clone()).expect("valid fixture configuration");
        driver
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(fixture.intent()?),
            }))
            .await?;
        driver_ready(&driver).await?;
        let original = fixture.files.path().join("original-lifecycle");
        fs::copy(&fixture.runtime.config.lifecycle, &original)?;
        let marker = fixture.files.path().join("cleanup-failed-once");
        executable(
            &fixture.runtime.config.lifecycle,
            &format!(
                "#!/bin/sh\nif [ \"$1\" = {action} ] && [ ! -f '{}' ]; then touch '{}'; exit 24; fi\nexec /bin/sh '{}' \"$@\"\n",
                marker.display(),
                marker.display(),
                original.display()
            ),
        )?;
        if action == "stop" {
            assert!(
                driver
                    .stop_sandbox(Request::new(c::StopSandboxRequest {
                        sandbox_id: "fixture-id".into(),
                        ..Default::default()
                    }))
                    .await
                    .is_err()
            );
        } else {
            assert!(
                driver
                    .delete_sandbox(Request::new(c::DeleteSandboxRequest {
                        sandbox_id: "fixture-id".into(),
                        ..Default::default()
                    }))
                    .await
                    .is_err()
            );
        }
        let current = driver
            .get_sandbox(Request::new(c::GetSandboxRequest {
                sandbox_id: "fixture-id".into(),
                ..Default::default()
            }))
            .await?
            .into_inner()
            .sandbox
            .expect("retained after failure");
        assert!(
            current
                .status
                .expect("status")
                .conditions
                .iter()
                .all(|condition| condition.r#type != "Ready" || condition.status != "True")
        );
        if action == "stop" {
            driver
                .stop_sandbox(Request::new(c::StopSandboxRequest {
                    sandbox_id: "fixture-id".into(),
                    ..Default::default()
                }))
                .await?;
        }
        driver
            .delete_sandbox(Request::new(c::DeleteSandboxRequest {
                sandbox_id: "fixture-id".into(),
                ..Default::default()
            }))
            .await?;
        fixture.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn transient_start_failure_is_failed_and_can_retry_the_same_transition() -> anyhow::Result<()>
{
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    let driver = Driver::new(fixture.runtime.config.clone()).expect("valid fixture configuration");
    driver
        .create_sandbox(Request::new(c::CreateSandboxRequest {
            sandbox: Some(fixture.intent()?),
        }))
        .await?;
    driver_ready(&driver).await?;
    driver
        .stop_sandbox(Request::new(c::StopSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    let lifecycle = fixture.runtime.config.lifecycle.clone();
    let original = fixture.files.path().join("original-lifecycle");
    fs::copy(&lifecycle, &original)?;
    executable(
        &lifecycle,
        &format!(
            "#!/bin/sh\nif [ \"$1\" = start ] && [ ! -f '{}' ]; then touch '{}'; exit 24; fi\nexec /bin/sh '{}' \"$@\"\n",
            fixture.files.path().join("failed-once").display(),
            fixture.files.path().join("failed-once").display(),
            original.display()
        ),
    )?;
    let authentication = fixture.authentication()?;
    let start = || {
        Request::new(c::StartSandboxRequest {
            sandbox_id: "fixture-id".into(),
            generation_id: "retry-transition".into(),
            expected_runtime_identity: INSTANCE.into(),
            launch_authentication: authentication.clone(),
            ..Default::default()
        })
    };
    assert!(driver.start_sandbox(start()).await.is_err());
    let failed = driver
        .get_sandbox(Request::new(c::GetSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .sandbox
        .expect("failed record");
    assert!(
        failed
            .status
            .expect("failed status")
            .conditions
            .iter()
            .any(|condition| condition.reason == "RuntimeError")
    );
    driver.start_sandbox(start()).await?;
    driver_ready(&driver).await?;
    assert_eq!(
        driver
            .start_sandbox(start())
            .await?
            .into_inner()
            .runtime_identity,
        INSTANCE,
        "successful transition retries are idempotent"
    );
    driver
        .delete_sandbox(Request::new(c::DeleteSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn restart_recovers_stopped_without_credentials_and_requires_fresh_start()
-> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    let mut config = (*fixture.runtime.config).clone();
    config.recovery_dir = Some(fixture.files.path().join("registry"));
    let config = Arc::new(config);
    let driver = Driver::new(config.clone()).expect("valid fixture configuration");
    driver
        .create_sandbox(Request::new(c::CreateSandboxRequest {
            sandbox: Some(fixture.intent()?),
        }))
        .await?;
    driver_ready(&driver).await?;
    driver.close().await;
    drop(driver);
    let recovered = Driver::new(config.clone()).expect("valid fixture configuration");
    recovered.recover().await?;
    assert!(
        fixture.files.path().join("stopped").exists(),
        "startup must stop the retained Pod"
    );
    let record = recovered
        .get_sandbox(Request::new(c::GetSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .sandbox
        .expect("retained record");
    assert!(
        record
            .spec
            .as_ref()
            .expect("retained spec")
            .launch_authentication
            .is_empty(),
        "credentials cannot survive recovery"
    );
    let status = record.status.as_ref().expect("stopped status");
    assert!(
        status
            .conditions
            .iter()
            .any(|c| c.r#type == "Suspended" && c.status == "True")
    );
    assert!(
        !status
            .conditions
            .iter()
            .any(|c| c.r#type == "Ready" && c.status == "True")
    );
    assert_eq!(
        recovered
            .start_sandbox(Request::new(c::StartSandboxRequest {
                sandbox_id: "fixture-id".into(),
                ..Default::default()
            }))
            .await
            .expect_err("fresh gateway authentication required")
            .code(),
        tonic::Code::InvalidArgument
    );
    let next = "db4c1779-8b56-44d7-b3ac-b75c5b34bb27";
    for name in ["route.json", "proof.json"] {
        let path = fixture.files.path().join(name);
        fs::write(&path, fs::read_to_string(&path)?.replace(INSTANCE, next))?;
    }
    let mut authentication: serde_json::Value = serde_json::from_slice(&fixture.authentication()?)?;
    authentication["supervisor"]["gateway_token"] = serde_json::json!("fresh-start-credential");
    let started = recovered
        .start_sandbox(Request::new(c::StartSandboxRequest {
            sandbox_id: "fixture-id".into(),
            expected_runtime_identity: INSTANCE.into(),
            generation_id: "restart-generation".into(),
            launch_authentication: serde_json::to_vec(&authentication)?,
            ..Default::default()
        }))
        .await?
        .into_inner();
    assert_eq!(started.runtime_identity, next);
    driver_ready(&recovered).await?;
    assert!(
        fixture
            .state
            .headers
            .lock()
            .expect("headers")
            .iter()
            .any(|h| h == "Bearer fresh-start-credential")
    );
    let files = fs::read_dir(config.recovery_dir.as_ref().expect("recovery directory"))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(files.len(), 1);
    let value: serde_json::Value = serde_json::from_slice(&fs::read(files[0].path())?)?;
    let bytes: Vec<u8> = serde_json::from_value(value["sandbox"].clone())?;
    let persisted: c::DriverSandbox = prost::Message::decode(bytes.as_slice())?;
    assert!(
        persisted
            .spec
            .expect("persisted spec")
            .launch_authentication
            .is_empty()
    );
    assert_eq!(
        fs::metadata(files[0].path())?.permissions().mode() & 0o777,
        0o600
    );
    recovered
        .delete_sandbox(Request::new(c::DeleteSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    assert_eq!(
        fs::read_dir(config.recovery_dir.as_ref().expect("registry"))?.count(),
        0
    );
    recovered.close().await;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn interrupted_provisioning_and_failed_recovery_never_publish_ready() -> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    let mut config = (*fixture.runtime.config).clone();
    config.recovery_dir = Some(fixture.files.path().join("registry"));
    executable(&config.lifecycle, "#!/bin/sh\nexit 23\n")?;
    let config = Arc::new(config);
    let driver = Driver::new(config.clone()).expect("valid fixture configuration");
    assert!(
        driver
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(fixture.intent()?)
            }))
            .await
            .is_err()
    );
    assert_eq!(
        fs::read_dir(config.recovery_dir.as_ref().expect("registry"))?.count(),
        1,
        "intent must precede backend mutation"
    );
    drop(driver);
    let recovered = Driver::new(config.clone()).expect("valid fixture configuration");
    assert!(
        recovered.recover().await.is_err(),
        "failed backend cleanup prevents startup"
    );
    assert!(
        recovered
            .list_sandboxes(Request::new(c::ListSandboxesRequest {}))
            .await?
            .into_inner()
            .sandboxes
            .is_empty()
    );
    executable(&config.lifecycle, "#!/bin/sh\nprintf '{}'\n")?;
    recovered.recover().await?;
    let observed = recovered
        .get_sandbox(Request::new(c::GetSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .sandbox
        .expect("interrupted intent recovered");
    assert!(
        observed
            .status
            .expect("stopped status")
            .conditions
            .iter()
            .all(|c| c.r#type != "Ready" || c.status == "False")
    );
    assert_eq!(
        recovered
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(fixture.intent()?)
            }))
            .await
            .expect_err("retained resources require fresh Start")
            .code(),
        tonic::Code::FailedPrecondition
    );
    recovered
        .stop_sandbox(Request::new(c::StopSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    recovered
        .delete_sandbox(Request::new(c::DeleteSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    fixture.close().await;
    Ok(())
}
