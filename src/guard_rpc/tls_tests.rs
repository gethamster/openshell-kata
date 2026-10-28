use super::{
    server::{ProofServer, router, tls},
    tests::{NODE, NONCE, POD},
    *,
};
use crate::network::hosted_fence::{HostedFenceIntent, HostedFenceProof, HostedFenceResponse};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server};

fn openssl(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "test certificate generation failed"
    );
    Ok(output.stdout)
}
#[cfg(target_os = "linux")]
pub(super) fn certificates_for(root: &Path, node_uid: &str) -> Result<()> {
    certificates_with_name(root, &server_name(node_uid)?)
}
fn certificates_with_name(root: &Path, server_dns_name: &str) -> Result<()> {
    openssl(
        root,
        &[
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-days",
            "1",
            "-subj",
            "/CN=guard-test-ca",
        ],
    )?;
    for (name, usage) in [
        ("server", "serverAuth"),
        ("client", "clientAuth"),
        ("other", "clientAuth"),
    ] {
        openssl(
            root,
            &[
                "req",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN={name}"),
            ],
        )?;
        fs::write(
            root.join(format!("{name}.ext")),
            format!(
                "basicConstraints=CA:FALSE\nextendedKeyUsage={usage}\nsubjectAltName=DNS:{}\n",
                server_dns_name
            ),
        )?;
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                &format!("{name}.crt"),
                "-days",
                "1",
                "-extfile",
                &format!("{name}.ext"),
            ],
        )?;
        fs::set_permissions(
            root.join(format!("{name}.key")),
            fs::Permissions::from_mode(0o600),
        )?;
    }
    Ok(())
}
pub(super) fn proof(pod: &str, nonce: &str) -> Result<HostedFenceResponse> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let intent = HostedFenceIntent {
        version: 1,
        workspace: "rpc-test".into(),
        namespace_uid: "765466af-2a34-4219-854b-9aaebf0360b4".into(),
        sandbox_id: "rpc-test-sandbox".into(),
        pod_uid: pod.into(),
        launch_nonce: "740768ce-748d-4a63-a97e-47acd67b9d56".into(),
        expires_at_unix: now + 3600,
        broker_pod_uid: "65920ba9-d3ea-4ef0-923b-8845efb1ec98".into(),
        broker_ip: "10.20.0.2".parse()?,
        broker_port: 3128,
        broker_config_sha256: "a".repeat(64),
        controller_cidrs: vec!["10.20.0.3/32".into()],
        guest_ip: "10.20.0.4".parse()?,
        guest_mac: "02:00:00:00:00:01".into(),
        gateway_ip: "169.254.1.1".parse()?,
        gateway_mac: "02:00:00:00:00:02".into(),
        interface: "eth0".into(),
        node_uid: NODE.into(),
        boot_id: "39c21b16-972c-4806-93c0-105511bf5a81".into(),
    };
    Ok(HostedFenceResponse {
        nonce: nonce.into(),
        proof: HostedFenceProof {
            version: 1,
            intent_sha256: intent.sha256()?,
            binding: intent,
            netns_device: 1,
            netns_inode: 2,
            ifindex: 3,
            ingress_link_id: 4,
            egress_link_id: 5,
            ingress_program_id: 6,
            egress_program_id: 7,
            object_sha256: "b".repeat(64),
            installed_at_unix: now,
        },
    })
}
struct Fixture {
    root: tempfile::TempDir,
    address: SocketAddr,
    config: GuardClientConfig,
    calls: Arc<AtomicUsize>,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}
impl Fixture {
    async fn new(
        verifier: impl Fn(&str, &str) -> Result<HostedFenceResponse> + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::with_server_name(verifier, SERVER_NAME).await
    }
    async fn with_server_name(
        verifier: impl Fn(&str, &str) -> Result<HostedFenceResponse> + Send + Sync + 'static,
        name: &str,
    ) -> Result<Self> {
        let root = tempfile::tempdir()?;
        certificates_with_name(root.path(), name)?;
        let config = GuardClientConfig {
            version: 1,
            server_ca_file: root.path().join("ca.crt"),
            certificate_file: root.path().join("client.crt"),
            private_key_file: root.path().join("client.key"),
        };
        let allowed = format!(
            "{:x}",
            Sha256::digest(openssl(
                root.path(),
                &["x509", "-in", "client.crt", "-outform", "DER"]
            )?)
        );
        let cfg = GuardServerConfig {
            version: 1,
            bind: Some("10.20.0.1:9443".parse()?),
            certificate_file: root.path().join("server.crt"),
            private_key_file: root.path().join("server.key"),
            client_ca_file: root.path().join("ca.crt"),
            allowed_client_certificate_sha256: vec![allowed],
        };
        fs::write(
            root.path().join("client.json"),
            serde_json::to_vec(&config)?,
        )?;
        fs::write(root.path().join("server.json"), serde_json::to_vec(&cfg)?)?;
        let config = GuardClientConfig::load(&root.path().join("client.json"))?;
        let cfg = GuardServerConfig::load(&root.path().join("server.json"))?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let server = ProofServer::new(
            NODE.into(),
            cfg.allowed_client_certificate_sha256.clone(),
            Arc::new(move |pod, nonce| {
                called.fetch_add(1, Ordering::SeqCst);
                verifier(pod, nonce)
            }),
        );
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let task = tokio::spawn(
            Server::builder()
                .tls_config(tls(&cfg)?)?
                .add_service(router(server))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    stopped.cancelled_owned(),
                ),
        );
        Ok(Self {
            root,
            address,
            config,
            calls,
            stop,
            task,
        })
    }
    async fn client(
        &self,
        identity: Option<&str>,
        node: &str,
    ) -> Result<wire::node_fence_proof_client::NodeFenceProofClient<tonic::transport::Channel>>
    {
        let mut tls = ClientTlsConfig::new()
            .domain_name(server_name(node)?)
            .ca_certificate(Certificate::from_pem(fs::read(
                self.root.path().join("ca.crt"),
            )?));
        if let Some(name) = identity {
            tls = tls.identity(Identity::from_pem(
                fs::read(self.root.path().join(format!("{name}.crt")))?,
                fs::read(self.root.path().join(format!("{name}.key")))?,
            ));
        }
        let channel = Endpoint::from_shared(format!("https://{}", self.address))?
            .tls_config(tls)?
            .connect_timeout(DEADLINE)
            .connect()
            .await?;
        Ok(wire::node_fence_proof_client::NodeFenceProofClient::new(
            channel,
        ))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

#[tokio::test]
async fn mtls_and_leaf_identity_protect_read_only_proofs() -> Result<()> {
    let f = Fixture::new(proof).await?;
    let response = client::request(f.address, NODE, &f.config, POD, NONCE).await?;
    assert_eq!(response.nonce, NONCE);
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert!(
        f.client(None, NODE).await.is_err() || {
            let mut c = f.client(None, NODE).await?;
            c.verify(wire::VerifyRequest {
                pod_uid: POD.into(),
                nonce: NONCE.into(),
            })
            .await
            .is_err()
        }
    );
    let mut other = f.client(Some("other"), NODE).await?;
    assert_eq!(
        other
            .verify(wire::VerifyRequest {
                pod_uid: POD.into(),
                nonce: NONCE.into()
            })
            .await
            .expect_err("wrong role")
            .code(),
        tonic::Code::PermissionDenied
    );
    assert!(
        client::request(f.address, POD, &f.config, POD, NONCE)
            .await
            .is_err(),
        "the response must still bind the expected node"
    );
    let mut client = f.client(Some("client"), NODE).await?;
    assert_eq!(
        client
            .verify(wire::VerifyRequest {
                pod_uid: "../host".into(),
                nonce: NONCE.into()
            })
            .await
            .expect_err("invalid Pod")
            .code(),
        tonic::Code::InvalidArgument
    );
    assert!(
        client
            .verify(wire::VerifyRequest {
                pod_uid: POD.into(),
                nonce: "x".repeat(4096)
            })
            .await
            .is_err()
    );
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        2,
        "only the authorized and wrong-expected-node requests may read host state"
    );
    Ok(())
}

#[tokio::test]
async fn stale_or_failed_proofs_never_return_success() -> Result<()> {
    let f = Fixture::new(|pod, nonce| {
        let mut response = proof(pod, nonce)?;
        response.nonce = POD.into();
        Ok(response)
    })
    .await?;
    assert!(
        client::request(f.address, NODE, &f.config, POD, NONCE)
            .await
            .is_err()
    );
    let f = Fixture::new(|_, _| anyhow::bail!("private host path /not/exposed")).await?;
    let mut client = f.client(Some("client"), NODE).await?;
    let error = client
        .verify(wire::VerifyRequest {
            pod_uid: POD.into(),
            nonce: NONCE.into(),
        })
        .await
        .expect_err("failed host readback");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(!error.message().contains("private"));
    Ok(())
}

#[tokio::test]
async fn another_ca_and_plaintext_cannot_reach_host_verification() -> Result<()> {
    let f = Fixture::new(proof).await?;
    openssl(
        f.root.path(),
        &[
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "wrong-ca.key",
            "-out",
            "wrong-ca.crt",
            "-days",
            "1",
            "-subj",
            "/CN=untrusted-ca",
        ],
    )?;
    let wrong = GuardClientConfig {
        server_ca_file: f.root.path().join("wrong-ca.crt"),
        ..f.config.clone()
    };
    assert!(
        client::request(f.address, NODE, &wrong, POD, NONCE)
            .await
            .is_err()
    );
    if let Ok(channel) = Endpoint::from_shared(format!("http://{}", f.address))?
        .connect()
        .await
    {
        let mut plaintext = wire::node_fence_proof_client::NodeFenceProofClient::new(channel);
        assert!(
            plaintext
                .verify(wire::VerifyRequest {
                    pod_uid: POD.into(),
                    nonce: NONCE.into()
                })
                .await
                .is_err()
        );
    }
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        0,
        "transport rejection must precede all host access"
    );
    Ok(())
}

#[tokio::test]
async fn a_different_service_san_cannot_impersonate_the_guard_role() -> Result<()> {
    let f = Fixture::with_server_name(proof, "unrelated-role.kata-system.internal").await?;
    assert!(
        client::request(f.address, NODE, &f.config, POD, NONCE)
            .await
            .is_err()
    );
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        0,
        "role SAN rejection must precede host access"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_clients_do_not_release_running_host_verification_capacity() -> Result<()> {
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            let (mutex, wake) = &*self.0;
            *mutex.lock().expect("release test gate") = true;
            wake.notify_all();
        }
    }
    let _release = Release(gate.clone());
    let blocked = gate.clone();
    let f = Fixture::new(move |pod, nonce| {
        let (mutex, wake) = &*blocked;
        let mut ready = mutex.lock().expect("test gate");
        while !*ready {
            ready = wake.wait(ready).expect("test gate");
        }
        proof(pod, nonce)
    })
    .await?;
    let client = f.client(Some("client"), NODE).await?;
    let mut requests = Vec::new();
    for _ in 0..16 {
        let mut client = client.clone();
        requests.push(tokio::spawn(async move {
            client
                .verify(wire::VerifyRequest {
                    pod_uid: POD.into(),
                    nonce: NONCE.into(),
                })
                .await
        }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while f.calls.load(Ordering::SeqCst) < 16 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all admitted host verifications started");
    for request in requests {
        request.abort();
        let _ = request.await;
    }
    let mut client = client;
    let status = client
        .verify(wire::VerifyRequest {
            pod_uid: POD.into(),
            nonce: NONCE.into(),
        })
        .await
        .expect_err("capacity remains reserved until host work stops");
    let (mutex, wake) = &*gate;
    *mutex.lock().expect("release test gate") = true;
    wake.notify_all();
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    Ok(())
}
