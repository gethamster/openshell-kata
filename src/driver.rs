use crate::{
    admission,
    config::{Config, SandboxId},
    guest,
    proto::openshell::{compute::v1 as c, extension::v1 as e},
    supervisor::{Phase, Runtime},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

/// The local compute extension and its owned runtime generations.
#[derive(Clone)]
pub struct Driver {
    config: Arc<Config>,
    registry: Arc<RwLock<Registry>>,
    lifecycle: Arc<Mutex<()>>,
}

#[derive(Default)]
struct Registry {
    active: BTreeMap<String, Arc<Runtime>>,
    // Retained until this adapter exits so reconnecting watchers cannot miss
    // successful deletion. A new generation of the same ID replaces its tombstone.
    deleted: BTreeSet<String>,
}
impl Driver {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            registry: Arc::default(),
            lifecycle: Arc::default(),
        }
    }
    pub async fn close(&self) {
        let records: Vec<_> = self
            .registry
            .read()
            .await
            .active
            .values()
            .cloned()
            .collect();
        for runtime in records {
            runtime.close().await;
        }
    }
    async fn record(&self, id: &str) -> Result<Arc<Runtime>, Status> {
        self.registry
            .read()
            .await
            .active
            .get(id)
            .cloned()
            .ok_or_else(|| Status::not_found("sandbox not found"))
    }
    async fn register(&self, id: String, runtime: Arc<Runtime>) {
        let mut registry = self.registry.write().await;
        registry.deleted.remove(&id);
        registry.active.insert(id, runtime);
    }
    async fn deleted(&self, id: String) {
        let mut registry = self.registry.write().await;
        registry.active.remove(&id);
        registry.deleted.insert(id);
    }
    async fn observations(&self) -> Vec<c::WatchSandboxesEvent> {
        let registry = self.registry.read().await;
        registry
            .active
            .values()
            .map(|record| c::WatchSandboxesEvent {
                payload: Some(c::watch_sandboxes_event::Payload::Sandbox(
                    c::WatchSandboxesSandboxEvent {
                        sandbox: Some(Self::observation(record)),
                    },
                )),
            })
            .chain(registry.deleted.iter().map(|id| c::WatchSandboxesEvent {
                payload: Some(c::watch_sandboxes_event::Payload::Deleted(
                    c::WatchSandboxesDeletedEvent {
                        sandbox_id: id.clone(),
                    },
                )),
            }))
            .collect()
    }
    fn observation(runtime: &Runtime) -> c::DriverSandbox {
        let mut sandbox = runtime.spec.clone();
        let phase = *runtime.phase.borrow();
        let mut conditions = vec![c::DriverCondition {
            r#type: "Ready".into(),
            status: if phase == Phase::Ready {
                "True"
            } else {
                "False"
            }
            .into(),
            reason: match phase {
                Phase::Ready => "PrototypeControlReady",
                Phase::Failed => "RuntimeError",
                _ => "Starting",
            }
            .into(),
            message: "Kata guest control; policy qualification is separate".into(),
            ..Default::default()
        }];
        if phase == Phase::Starting {
            conditions.push(c::DriverCondition {
                r#type: "Bootstrapping".into(),
                status: "True".into(),
                reason: "Starting".into(),
                ..Default::default()
            });
        }
        if phase == Phase::Stopped {
            conditions.push(c::DriverCondition {
                r#type: "Suspended".into(),
                status: "True".into(),
                reason: "Stopped".into(),
                ..Default::default()
            });
        }
        sandbox.status = Some(c::DriverSandboxStatus {
            name: sandbox.name.clone(),
            instance_id: runtime.instance.clone(),
            conditions,
            ..Default::default()
        });
        sandbox
    }
}
fn internal(error: impl std::fmt::Display) -> Status {
    tracing::error!(%error,"adapter operation failed");
    Status::internal("isolated guest operation failed; inspect adapter logs")
}

#[tonic::async_trait]
impl c::compute_driver_server::ComputeDriver for Driver {
    async fn get_capabilities(
        &self,
        request: Request<c::GetCapabilitiesRequest>,
    ) -> Result<Response<c::GetCapabilitiesResponse>, Status> {
        if request
            .get_ref()
            .gateway
            .as_ref()
            .and_then(|m| m.protocol_version.as_ref())
            .is_some_and(|v| v.major != 1)
        {
            return Err(Status::failed_precondition(
                "compute contract major version must be 1",
            ));
        }
        Ok(Response::new(c::GetCapabilitiesResponse {
            driver_name:"openshell-kata".into(), driver_version:env!("CARGO_PKG_VERSION").into(), default_image:"docker:29-dind".into(), driver_reports_runtime_readiness:true,
            resource_admission_policy:r#"v1:{"allow_driver_config":false,"resource_admission":{"enabled":true,"required_labels":{"openshell.ai/sandbox-attachable":"true","openshell.ai/sandbox-attachable-workspace":"${workspace}"}}}"#.into(),
            extension:Some(e::PeerMetadata { protocol_version:Some(e::ProtocolVersion { major:1,minor:0 }),implementation_name:"openshell-kata".into(),implementation_version:env!("CARGO_PKG_VERSION").into(),supported_capabilities:vec!["openshell.compute.contract".into()],..Default::default() }),..Default::default()
        }))
    }
    async fn authenticate_sandbox(
        &self,
        _: Request<c::AuthenticateSandboxRequest>,
    ) -> Result<Response<c::AuthenticateSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "gateway supplies launch authentication",
        ))
    }
    async fn validate_sandbox_create(
        &self,
        request: Request<c::ValidateSandboxCreateRequest>,
    ) -> Result<Response<c::ValidateSandboxCreateResponse>, Status> {
        let sandbox = request
            .get_ref()
            .sandbox
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox required"))?;
        SandboxId::parse(&sandbox.id).map_err(|e| Status::invalid_argument(e.to_string()))?;
        admission::validate_request(sandbox, self.config.prototype_policy_mode)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(c::ValidateSandboxCreateResponse {}))
    }
    async fn create_sandbox(
        &self,
        request: Request<c::CreateSandboxRequest>,
    ) -> Result<Response<c::CreateSandboxResponse>, Status> {
        let _guard = self.lifecycle.lock().await;
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox required"))?;
        admission::validate_request(&sandbox, self.config.prototype_policy_mode)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        let id =
            SandboxId::parse(&sandbox.id).map_err(|e| Status::invalid_argument(e.to_string()))?;
        if self.registry.read().await.active.contains_key(id.as_str()) {
            return Ok(Response::new(c::CreateSandboxResponse {
                runtime_identity: id.to_string(),
            }));
        }
        let authentication = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("spec required"))?
            .launch_authentication
            .clone();
        crate::supervisor::validate_authentication(&authentication)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let guest = guest::lifecycle(&self.config, "create", &id)
            .await
            .map_err(internal)?
            .ok_or_else(|| Status::internal("missing guest route"))?;
        let runtime =
            Runtime::new(sandbox, self.config.clone(), guest, authentication).map_err(internal)?;
        self.register(id.to_string(), runtime.clone()).await;
        if let Err(error) = runtime.start().await {
            runtime.phase.send_replace(Phase::Failed);
            runtime.close().await;
            if guest::lifecycle(&self.config, "delete", &id).await.is_ok() {
                self.deleted(id.to_string()).await;
            }
            return Err(internal(error));
        }
        Ok(Response::new(c::CreateSandboxResponse {
            runtime_identity: id.to_string(),
        }))
    }
    async fn get_sandbox(
        &self,
        request: Request<c::GetSandboxRequest>,
    ) -> Result<Response<c::GetSandboxResponse>, Status> {
        let runtime = self.record(&request.get_ref().sandbox_id).await?;
        Ok(Response::new(c::GetSandboxResponse {
            sandbox: Some(Self::observation(&runtime)),
        }))
    }
    async fn list_sandboxes(
        &self,
        _: Request<c::ListSandboxesRequest>,
    ) -> Result<Response<c::ListSandboxesResponse>, Status> {
        Ok(Response::new(c::ListSandboxesResponse {
            sandboxes: self
                .registry
                .read()
                .await
                .active
                .values()
                .map(|r| Self::observation(r))
                .collect(),
        }))
    }
    async fn stop_sandbox(
        &self,
        request: Request<c::StopSandboxRequest>,
    ) -> Result<Response<c::StopSandboxResponse>, Status> {
        let _guard = self.lifecycle.lock().await;
        let runtime = self.record(&request.get_ref().sandbox_id).await?;
        runtime.close().await;
        guest::lifecycle(&self.config, "stop", &runtime.id)
            .await
            .map_err(internal)?;
        runtime.phase.send_replace(Phase::Stopped);
        Ok(Response::new(c::StopSandboxResponse {}))
    }
    async fn start_sandbox(
        &self,
        request: Request<c::StartSandboxRequest>,
    ) -> Result<Response<c::StartSandboxResponse>, Status> {
        let _guard = self.lifecycle.lock().await;
        let request = request.into_inner();
        crate::supervisor::validate_authentication(&request.launch_authentication)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let old = self.record(&request.sandbox_id).await?;
        old.phase.send_replace(Phase::Starting);
        old.close().await;
        let guest = guest::lifecycle(&self.config, "start", &old.id)
            .await
            .map_err(internal)?
            .ok_or_else(|| Status::internal("missing guest route"))?;
        let runtime = Runtime::new(
            old.spec.clone(),
            self.config.clone(),
            guest,
            request.launch_authentication,
        )
        .map_err(internal)?;
        self.register(old.id.to_string(), runtime.clone()).await;
        runtime.start().await.map_err(internal)?;
        Ok(Response::new(c::StartSandboxResponse {
            runtime_identity: old.id.to_string(),
        }))
    }
    async fn suspend_sandbox(
        &self,
        _: Request<c::SuspendSandboxRequest>,
    ) -> Result<Response<c::SuspendSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "memory suspension is not implemented",
        ))
    }
    async fn delete_sandbox(
        &self,
        request: Request<c::DeleteSandboxRequest>,
    ) -> Result<Response<c::DeleteSandboxResponse>, Status> {
        let _guard = self.lifecycle.lock().await;
        let id = request.into_inner().sandbox_id;
        let validated_id =
            SandboxId::parse(&id).map_err(|error| Status::invalid_argument(error.to_string()))?;
        let record = self.registry.read().await.active.get(&id).cloned();
        if let Some(runtime) = &record {
            runtime.close().await;
        }
        // The runtime helper can recover retained state after adapter restart.
        // Its idempotent deletion must confirm absence before we publish it.
        guest::lifecycle(&self.config, "delete", &validated_id)
            .await
            .map_err(internal)?;
        self.deleted(id).await;
        Ok(Response::new(c::DeleteSandboxResponse {
            deleted: record.is_some(),
        }))
    }
    type WatchSandboxesStream = ReceiverStream<Result<c::WatchSandboxesEvent, Status>>;
    async fn watch_sandboxes(
        &self,
        _: Request<c::WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let (sender, receiver) = mpsc::channel(32);
        let driver = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(300));
            let mut announced_deletions = BTreeSet::new();
            loop {
                interval.tick().await;
                for event in driver.observations().await {
                    match &event.payload {
                        Some(c::watch_sandboxes_event::Payload::Deleted(deleted)) => {
                            if !announced_deletions.insert(deleted.sandbox_id.clone()) {
                                continue;
                            }
                        }
                        Some(c::watch_sandboxes_event::Payload::Sandbox(observed)) => {
                            if let Some(sandbox) = &observed.sandbox {
                                announced_deletions.remove(&sandbox.id);
                            }
                        }
                        _ => {}
                    }
                    if sender.send(Ok(event)).await.is_err() {
                        return;
                    }
                }
                if sender.is_closed() {
                    return;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
    async fn ensure_workspace(
        &self,
        _: Request<c::EnsureWorkspaceRequest>,
    ) -> Result<Response<c::EnsureWorkspaceResponse>, Status> {
        Ok(Response::new(c::EnsureWorkspaceResponse {}))
    }
    async fn delete_workspace(
        &self,
        _: Request<c::DeleteWorkspaceRequest>,
    ) -> Result<Response<c::DeleteWorkspaceResponse>, Status> {
        Ok(Response::new(c::DeleteWorkspaceResponse {}))
    }
}
