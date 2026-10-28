use openshell_kata::{
    config::Config, guest::Guest, proto::openshell::compute::v1 as c, ssh, supervisor::Runtime,
};
use russh::{ChannelMsg, client};
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

struct Client;
impl client::Handler for Client {
    type Error = anyhow::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> anyhow::Result<bool> {
        Ok(true)
    }
}
struct Fixture {
    _files: tempfile::TempDir,
    _socket: tempfile::TempDir,
    runtime: Arc<Runtime>,
    listener: tokio::task::JoinHandle<()>,
    client: client::Handle<Client>,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        Self::with_user("sandbox").await
    }
    async fn with_user(user: &str) -> anyhow::Result<Self> {
        let files = tempfile::tempdir()?;
        let key = files.path().join("host-key");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()?;
        anyhow::ensure!(status.success(), "fixture key generation failed");
        let executable = files.path().join("guest-ssh");
        std::fs::write(&executable, b"#!/bin/sh\nfor argument do command=$argument; done\ncase \"$command\" in\n*failure*) echo extractor-failed >&2; exit 23;;\n*'tar -xf'*) cat >/dev/null;;\nfixture-output) printf normal; printf error >&2; exit 7;;\n*) cat;;\nesac\n")?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
        let config = Arc::new(Config {
            socket: files.path().join("driver.sock"),
            gateway: "https://127.0.0.1:1".into(),
            gateway_ca: files.path().join("unused-ca"),
            lifecycle: executable.clone(),
            lifecycle_arg: vec![],
            ssh: executable,
            prototype_policy_mode: true,
        });
        let guest = Guest {
            sandbox_id: "test-id".into(),
            host: "127.0.0.1".into(),
            port: 12345,
            username: "sandbox".into(),
            private_key_path: key.clone(),
            known_hosts_path: files.path().join("unused-hosts"),
        };
        let host_key = std::fs::read_to_string(key)?;
        let authentication = serde_json::to_vec(
            &serde_json::json!({"supervisor":{"gateway_token":"test-placeholder","ssh_host_private_key":host_key}}),
        )?;
        let runtime = Runtime::new(
            c::DriverSandbox {
                id: "test-id".into(),
                name: "test-name".into(),
                spec: Some(c::DriverSandboxSpec::default()),
                ..Default::default()
            },
            config,
            guest,
            authentication,
        )?;
        let (socket, listener) = ssh::listen(runtime.clone(), &host_key).await?;
        let stream = tokio::net::UnixStream::connect(socket.path().join("ssh.sock")).await?;
        let mut client =
            client::connect_stream(Arc::new(client::Config::default()), stream, Client).await?;
        anyhow::ensure!(
            client.authenticate_none(user).await?.success(),
            "fixture authentication failed"
        );
        Ok(Self {
            _files: files,
            _socket: socket,
            runtime,
            listener,
            client,
        })
    }
    async fn close(self) {
        self.runtime.close().await;
        self.listener.abort();
        let _ = self.listener.await;
    }
}

#[tokio::test]
async fn gateway_relayed_system_ssh_username_does_not_select_guest_identity() -> anyhow::Result<()>
{
    let fixture = Fixture::with_user("local-desktop-user").await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel.exec(true, "fixture-output").await?;
    channel.eof().await?;
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        if let ChannelMsg::ExitStatus { exit_status } = message {
            exit = Some(exit_status);
        }
    }
    assert_eq!(exit, Some(7));
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn forwards_stdout_stderr_and_exit_status() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel.exec(true, "fixture-output").await?;
    channel.eof().await?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            _ => {}
        }
    }
    assert_eq!(stdout, b"normal");
    assert_eq!(stderr, b"error");
    assert_eq!(exit, Some(7));
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn invalid_upload_plan_closes_channel_without_waiting_for_eof() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel.data(&b"{invalid}\n"[..]).await?;
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        if let ChannelMsg::ExitStatus { exit_status } = message {
            exit = Some(exit_status);
        }
    }
    assert_eq!(exit, Some(1));
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn failed_extractor_closes_channel_while_client_keeps_input_open() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel
        .data(&b"{\"destination_directory\":\"/sandbox/failure\"}\n"[..])
        .await?;
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        if let ChannelMsg::ExitStatus { exit_status } = message {
            exit = Some(exit_status);
        }
    }
    assert_eq!(exit, Some(23));
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn ssh_upload_reports_final_total_for_multi_megabyte_input() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel
        .data(&b"{\"destination_directory\":\"/sandbox/project\"}\n"[..])
        .await?;
    let bytes = vec![0x71; 2 * 1024 * 1024 + 19];
    channel.data(&bytes[..]).await?;
    channel.eof().await?;
    let mut acks = Vec::new();
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await? {
        match message {
            ChannelMsg::Data { data } => acks.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            _ => {}
        }
    }
    let totals = acks
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_be_bytes(*chunk))
        .collect::<Vec<_>>();
    assert_eq!(totals.first(), Some(&0));
    assert_eq!(totals.last(), Some(&(bytes.len() as u64)));
    assert_eq!(exit, Some(0));
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn cancellation_closes_an_upload_with_an_incomplete_plan() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel.data(&b"{\"destination_"[..]).await?;
    fixture.runtime.cancel.cancel();
    while tokio::time::timeout(Duration::from_secs(5), channel.wait())
        .await?
        .is_some()
    {}
    fixture.close().await;
    Ok(())
}
