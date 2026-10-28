use crate::{
    admission,
    config::{Config, SandboxId, shell_quote},
    guest::Guest,
    proto::openshell::{compute::v1 as c, sandbox::v1 as s, v1 as o},
    ssh,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{collections::VecDeque, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    sync::{Mutex, broadcast, mpsc, watch},
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Ready,
    Stopped,
    Stopping,
    Deleting,
    Failed,
}
#[derive(Clone, Debug)]
pub enum Output {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(u32),
}
#[derive(Deserialize)]
struct Authentication {
    supervisor: SupervisorAuthentication,
}
#[derive(Deserialize)]
struct SupervisorAuthentication {
    gateway_token: String,
    ssh_host_private_key: String,
}

pub fn validate_authentication(bytes: &[u8]) -> Result<()> {
    let auth: Authentication =
        serde_json::from_slice(bytes).context("invalid gateway launch authentication")?;
    if auth.supervisor.gateway_token.is_empty() {
        bail!("gateway token required");
    }
    russh::keys::decode_secret_key(&auth.supervisor.ssh_host_private_key, None)
        .context("invalid gateway SSH host key")?;
    Ok(())
}

/// One runtime generation; credentials never enter guest commands or logs.
pub struct Runtime {
    pub spec: c::DriverSandbox,
    pub id: SandboxId,
    pub instance: String,
    pub config: Arc<Config>,
    pub guest: Guest,
    pub vm_policy: Option<crate::profile::VmPolicy>,
    pub transfer_slots: Arc<tokio::sync::Semaphore>,
    pub operation_slots: Arc<tokio::sync::Semaphore>,
    operator_policy: Option<crate::profile::VmPolicy>,
    pub cancel: CancellationToken,
    pub phase: watch::Sender<Phase>,
    pub output: broadcast::Sender<Output>,
    pub history: Mutex<VecDeque<Output>>,
    pub main_exit: watch::Sender<Option<u32>>,
    authentication: Authentication,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    endpoint: Mutex<Option<tempfile::TempDir>>,
}
impl Runtime {
    pub fn new(
        spec: c::DriverSandbox,
        config: Arc<Config>,
        guest: Guest,
        authentication: Vec<u8>,
    ) -> Result<Arc<Self>> {
        Self::new_with_policy(spec, config, guest, authentication, None, None)
    }
    pub fn new_with_policy(
        mut spec: c::DriverSandbox,
        config: Arc<Config>,
        guest: Guest,
        authentication: Vec<u8>,
        operator_policy: Option<crate::profile::VmPolicy>,
        vm_policy: Option<crate::profile::VmPolicy>,
    ) -> Result<Arc<Self>> {
        let auth: Authentication = serde_json::from_slice(&authentication)
            .context("invalid gateway launch authentication")?;
        // Keep bootstrap credentials only in the private supervisor state;
        // observations and restarted specifications must never echo them.
        spec.spec
            .as_mut()
            .context("missing sandbox spec")?
            .launch_authentication
            .clear();
        let id = SandboxId::parse(&spec.id)?;
        let (phase, _) = watch::channel(Phase::Starting);
        let (output, _) = broadcast::channel(128);
        let (main_exit, _) = watch::channel(None);
        Ok(Arc::new(Self {
            spec,
            id,
            instance: Uuid::new_v4().to_string(),
            config,
            guest,
            vm_policy,
            operator_policy,
            transfer_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            operation_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            cancel: CancellationToken::new(),
            phase,
            output,
            history: Mutex::new(VecDeque::new()),
            main_exit,
            authentication: auth,
            tasks: Mutex::new(Vec::new()),
            endpoint: Mutex::new(None),
        }))
    }
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let (directory, task) = ssh::listen(
            self.clone(),
            &self.authentication.supervisor.ssh_host_private_key,
        )
        .await?;
        let path = directory.path().join("ssh.sock");
        *self.endpoint.lock().await = Some(directory);
        self.tasks.lock().await.push(task);
        let runtime = self.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = runtime.supervise(path).await {
                tracing::error!(sandbox = %runtime.id, error = %error, "supervisor stopped");
                runtime.phase.send_replace(Phase::Failed);
                runtime.cancel.cancel();
                if runtime.vm_policy.is_some()
                    && let Err(stop_error) =
                        crate::guest::lifecycle(&runtime.config, "stop", &runtime.id).await
                {
                    tracing::error!(sandbox=%runtime.id,error=%stop_error,"failed to stop rejected VM");
                }
            }
        });
        self.tasks.lock().await.push(task);
        Ok(())
    }
    pub async fn close(&self) {
        self.cancel.cancel();
        for task in self.tasks.lock().await.drain(..) {
            task.abort();
            let _ = task.await;
        }
        self.endpoint.lock().await.take();
    }
    fn request<T>(&self, message: T) -> Result<Request<T>> {
        let mut request = Request::new(message);
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.authentication.supervisor.gateway_token).parse()?,
        );
        Ok(request)
    }
    async fn client(&self) -> Result<o::open_shell_client::OpenShellClient<Channel>> {
        let ca = tokio::fs::read(&self.config.gateway_ca).await?;
        let channel = Endpoint::from_shared(self.config.gateway.clone())?
            .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)))?
            .connect()
            .await?;
        Ok(o::open_shell_client::OpenShellClient::new(channel))
    }
    async fn supervise(self: &Arc<Self>, ssh_path: PathBuf) -> Result<()> {
        let mut client = self.client().await?;
        let mut attempts = 0;
        let snapshot = loop {
            let request = self.request(s::GetSandboxConfigRequest {
                name: self.spec.name.clone(),
                ..Default::default()
            })?;
            match client.get_sandbox_config(request).await {
                Ok(response) => break response.into_inner(),
                Err(error)
                    if attempts < 60
                        && matches!(
                            error.code(),
                            tonic::Code::NotFound | tonic::Code::Unavailable
                        ) =>
                {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let mut applied = self.vm_policy.clone();
        self.enforce_snapshot(&snapshot, &mut applied).await?;
        self.check_providers(&mut client, &snapshot).await?;
        let pending = o::ReportSandboxConfigurationRequest {
            sandbox_id: self.id.to_string(),
            expected_instance_id: snapshot.configuration_instance_id.clone(),
            admission: Some(o::SandboxConfigurationAdmission {
                instance_id: self.instance.clone(),
                state: 1,
                ..Default::default()
            }),
        };
        client
            .report_sandbox_configuration(self.request(pending)?)
            .await?;
        self.start_main().await?;
        self.report_accepted(&mut client, &snapshot).await?;
        let mut last_snapshot = snapshot;
        let (sender, receiver) = mpsc::channel(32);
        sender
            .send(o::SupervisorMessage {
                payload: Some(o::supervisor_message::Payload::Hello(o::SupervisorHello {
                    sandbox_id: self.id.to_string(),
                    instance_id: self.instance.clone(),
                    connection_epoch: 1,
                    ..Default::default()
                })),
            })
            .await?;
        let mut stream = client
            .connect_supervisor(self.request(ReceiverStream::new(receiver))?)
            .await?
            .into_inner();
        let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                _ = heartbeat.tick() => {
                    if self.vm_policy.is_some() {
                        let snapshot=client.get_sandbox_config(self.request(s::GetSandboxConfigRequest {name:self.spec.name.clone(),..Default::default()})?).await?.into_inner();
                        self.enforce_snapshot(&snapshot,&mut applied).await?;
                        if snapshot!=last_snapshot {
                            self.check_providers(&mut client,&snapshot).await?;
                            self.report_accepted(&mut client,&snapshot).await?;
                            last_snapshot=snapshot;
                        }
                    }
                    sender.send(o::SupervisorMessage { payload: Some(o::supervisor_message::Payload::Heartbeat(o::SupervisorHeartbeat {})) }).await?;
                },
                message = stream.message() => match message?.and_then(|m|m.payload) {
                    Some(o::gateway_message::Payload::SessionAccepted(_)) => {
                        if self.vm_policy.is_some() { self.enforce_snapshot(&last_snapshot,&mut applied).await?; }
                        self.phase.send_replace(Phase::Ready); tracing::info!(sandbox=%self.id,"supervisor connected");
                    },
                    Some(o::gateway_message::Payload::RelayOpen(open)) => {
                        let runtime = self.clone(); let sender = sender.clone(); let path = ssh_path.clone();
                        self.tasks.lock().await.push(tokio::spawn(async move { if let Err(error) = runtime.relay(open, path, sender).await { tracing::warn!(sandbox=%runtime.id,error=%error,"relay failed"); } }));
                    }
                    Some(o::gateway_message::Payload::SessionRejected(_)) => bail!("gateway rejected supervisor session"),
                    None => bail!("gateway closed supervisor session"),
                    _ => {}
                }
            }
        }
    }
    async fn enforce_snapshot(
        &self,
        snapshot: &s::GetSandboxConfigResponse,
        applied: &mut Option<crate::profile::VmPolicy>,
    ) -> Result<()> {
        let Some(operator) = &self.operator_policy else {
            return admission::validate_snapshot(snapshot);
        };
        if !snapshot.configuration_admitted || !snapshot.supervisor_middleware_services.is_empty() {
            bail!("effective configuration is not supported or admitted");
        }
        let native = snapshot
            .policy
            .as_ref()
            .context("effective native policy missing")?;
        let next = operator.compile(native)?;
        let nonce = Uuid::new_v4().to_string();
        let action = if applied.as_ref() == Some(&next) {
            "verify"
        } else {
            "update"
        };
        let verified = crate::guest::lifecycle_with_policy(
            &self.config,
            action,
            &self.id,
            Some(&next),
            &nonce,
        )
        .await?
        .context("missing fresh runtime evidence")?;
        if verified.host != self.guest.host
            || verified.port != self.guest.port
            || verified.username != self.guest.username
            || verified.private_key_path != self.guest.private_key_path
            || verified.known_hosts_path != self.guest.known_hosts_path
        {
            bail!("runtime route changed during verification");
        }
        *applied = Some(next);
        Ok(())
    }
    async fn check_providers(
        &self,
        client: &mut o::open_shell_client::OpenShellClient<Channel>,
        snapshot: &s::GetSandboxConfigResponse,
    ) -> Result<()> {
        let providers = client
            .get_sandbox_provider_environment(self.request(
                o::GetSandboxProviderEnvironmentRequest {
                    sandbox_id: self.id.to_string(),
                    ..Default::default()
                },
            )?)
            .await?
            .into_inner();
        if !providers.environment.is_empty()
            || !providers.dynamic_credentials.is_empty()
            || !providers.static_credential_bindings.is_empty()
            || !providers.files.is_empty()
            || providers.readiness_reason != 0
            || providers.provider_env_revision != snapshot.provider_env_revision
            || providers.provider_attachment_epoch != snapshot.provider_attachment_epoch
            || providers.policy_hash != snapshot.policy_hash
        {
            bail!("provider snapshot is unsupported or does not match effective configuration");
        }
        Ok(())
    }
    async fn report_accepted(
        &self,
        client: &mut o::open_shell_client::OpenShellClient<Channel>,
        snapshot: &s::GetSandboxConfigResponse,
    ) -> Result<()> {
        client
            .report_sandbox_configuration(self.request(o::ReportSandboxConfigurationRequest {
                sandbox_id: self.id.to_string(),
                admission: Some(o::SandboxConfigurationAdmission {
                    instance_id: self.instance.clone(),
                    state: 2,
                    policy_version: snapshot.version,
                    policy_hash: snapshot.policy_hash.clone(),
                    config_revision: snapshot.config_revision,
                    provider_env_revision: snapshot.provider_env_revision,
                    ..Default::default()
                }),
                ..Default::default()
            })?)
            .await?;
        if snapshot.policy_source == s::PolicySource::Sandbox as i32 {
            client
                .report_policy_status(self.request(o::ReportPolicyStatusRequest {
                    sandbox_id: self.id.to_string(),
                    version: snapshot.version,
                    status: 2,
                    load_error: String::new(),
                })?)
                .await?;
        }
        Ok(())
    }
    async fn start_main(self: &Arc<Self>) -> Result<()> {
        let command = self
            .spec
            .spec
            .as_ref()
            .context("missing sandbox spec")?
            .command
            .iter()
            .map(|arg| shell_quote(arg))
            .collect::<Vec<_>>()
            .join(" ");
        if command.is_empty() {
            bail!("canonical main command required");
        }
        let mut child = self.guest.exec(&self.config, &command)?;
        // The canonical main process is noninteractive in this bounded adapter.
        child.stdin.take();
        let stdout = child.stdout.take().context("main stdout unavailable")?;
        let stderr = child.stderr.take().context("main stderr unavailable")?;
        let runtime = self.clone();
        let task = tokio::spawn(async move {
            let out = runtime.capture(stdout, false);
            let err = runtime.capture(stderr, true);
            let wait = async {
                tokio::try_join!(out, err)?;
                child.wait().await.map_err(anyhow::Error::from)
            };
            let code = tokio::select! { () = runtime.cancel.cancelled() => { let _ = child.kill().await; return; }, result = wait => result.ok().and_then(|s|s.code()).and_then(|c|u32::try_from(c).ok()).unwrap_or(1) };
            runtime.main_exit.send_replace(Some(code));
            let _ = runtime.output.send(Output::Exit(code));
        });
        self.tasks.lock().await.push(task);
        Ok(())
    }
    async fn capture<R: AsyncRead + Unpin>(&self, mut reader: R, stderr: bool) -> Result<()> {
        let mut data = vec![0; 32768];
        loop {
            let size = reader.read(&mut data).await?;
            if size == 0 {
                return Ok(());
            }
            let message = if stderr {
                Output::Stderr(data[..size].to_vec())
            } else {
                Output::Stdout(data[..size].to_vec())
            };
            let mut history = self.history.lock().await;
            if history.len() == 64 {
                history.pop_front();
            }
            history.push_back(message.clone());
            let _ = self.output.send(message);
        }
    }
    async fn relay(
        &self,
        open: o::RelayOpen,
        path: PathBuf,
        control: mpsc::Sender<o::SupervisorMessage>,
    ) -> Result<()> {
        let mut child = None;
        let (mut reader, mut writer): (
            Box<dyn AsyncRead + Send + Unpin>,
            Box<dyn AsyncWrite + Send + Unpin>,
        ) = match open.target {
            Some(o::relay_open::Target::Tcp(target)) => {
                let mut process = self.guest.tcp(&self.config, &target.host, target.port)?;
                let out = process.stdout.take().context("TCP stdout unavailable")?;
                let input = process.stdin.take().context("TCP stdin unavailable")?;
                if let Some(mut errors) = process.stderr.take() {
                    tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut errors, &mut tokio::io::sink()).await;
                    });
                }
                child = Some(process);
                (Box::new(out), Box::new(input))
            }
            _ => {
                let (reader, writer) = UnixStream::connect(path).await?.into_split();
                (Box::new(reader), Box::new(writer))
            }
        };
        let (sender, receiver) = mpsc::channel(32);
        sender
            .send(o::RelayFrame {
                payload: Some(o::relay_frame::Payload::Init(o::RelayInit {
                    channel_id: open.channel_id.clone(),
                })),
            })
            .await?;
        let mut client = self.client().await?;
        let mut incoming = client
            .relay_stream(self.request(ReceiverStream::new(receiver))?)
            .await?
            .into_inner();
        control
            .send(o::SupervisorMessage {
                payload: Some(o::supervisor_message::Payload::RelayOpenResult(
                    o::RelayOpenResult {
                        channel_id: open.channel_id,
                        success: true,
                        ..Default::default()
                    },
                )),
            })
            .await?;
        let outgoing = async move {
            let mut data = vec![0; 32768];
            loop {
                let count = reader.read(&mut data).await?;
                if count == 0 {
                    break;
                }
                sender
                    .send(o::RelayFrame {
                        payload: Some(o::relay_frame::Payload::Data(data[..count].to_vec())),
                    })
                    .await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        let inbound = async {
            while let Some(frame) = incoming.message().await? {
                if let Some(o::relay_frame::Payload::Data(data)) = frame.payload {
                    writer.write_all(&data).await?;
                }
            }
            writer.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! { () = self.cancel.cancelled() => {}, result = async { tokio::try_join!(outgoing, inbound) } => { result?; } }
        if let Some(mut child) = child {
            let _ = child.kill().await;
        }
        Ok(())
    }
}
