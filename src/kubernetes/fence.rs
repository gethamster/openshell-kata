//! Read-only mTLS fence verification against an exact trusted node generation.
use super::{
    broker,
    broker_config::{COMPONENT, Config},
    client::Client,
    model::State,
    policy,
};
use crate::network::hosted_fence::{HostedFenceProof, HostedFenceResponse};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

pub(super) async fn verify(
    client: &Client,
    state: &State,
    guest: &Value,
    nonce: &str,
) -> Result<HostedFenceProof> {
    let image = std::env::var("OPENSHELL_KATA_GUARD_IMAGE")
        .context("immutable trusted guard image required")?;
    let operator = broker::config(state.broker.as_ref().context("broker missing")?)?;
    #[cfg(test)]
    if std::env::var_os("OPENSHELL_KATA_TEST_PROFILE_ROOT").is_some() {
        return verify_with_image(client, state, guest, nonce, &image, &operator).await;
    }
    let tls = crate::guard_rpc::GuardClientConfig::load(&operator.guard_client_tls_config_file)?;
    verify_with_transport(
        client,
        state,
        guest,
        nonce,
        &image,
        &operator,
        move |address, node_uid, pod_uid, challenge| async move {
            crate::guard_rpc::verify_remote(address, &node_uid, &tls, &pod_uid, &challenge).await
        },
    )
    .await
}

async fn verify_with_transport<F, Fut>(
    client: &Client,
    state: &State,
    guest: &Value,
    nonce: &str,
    image: &str,
    operator: &Config,
    request: F,
) -> Result<HostedFenceProof>
where
    F: FnOnce(SocketAddr, String, String, String) -> Fut,
    Fut: Future<Output = Result<HostedFenceResponse>>,
{
    operator.validate()?;
    policy::validate_image(image)?;
    super::broker_config::canonical_uuid(nonce)?;
    let broker = state.broker.as_ref().context("broker identity missing")?;
    let node_name = guest["spec"]["nodeName"]
        .as_str()
        .context("guest node missing")?;
    let guest_uid = guest["metadata"]["uid"]
        .as_str()
        .context("guest UID missing")?;
    super::broker_config::canonical_uuid(guest_uid)?;
    let namespace = client
        .required("namespace", Some(&operator.guard_namespace), None)
        .await?;
    validate_namespace(&namespace, operator)?;
    let inventory = client
        .required("pods", None, Some(&operator.guard_namespace))
        .await?;
    let guards: Vec<_> = inventory["items"]
        .as_array()
        .context("guard inventory missing")?
        .iter()
        .filter(|p| {
            p["metadata"]["labels"][COMPONENT] == "runtime-guard"
                && p["spec"]["nodeName"] == node_name
        })
        .collect();
    ensure!(guards.len() == 1, "exactly one node guard required");
    let guard = guards[0];
    validate_guard(guard, image, &operator.guard_namespace, node_name)?;
    let name = guard["metadata"]["name"]
        .as_str()
        .context("guard name missing")?;
    let uid = guard["metadata"]["uid"]
        .as_str()
        .context("guard UID missing")?;
    super::broker_config::canonical_uuid(uid)?;
    let ip: Ipv4Addr = guard["status"]["podIP"]
        .as_str()
        .context("guard address missing")?
        .parse()?;
    ensure!(ip.is_private(), "guard address must be private IPv4");
    let node = client.required("node", Some(node_name), None).await?;
    let node_uid = node["metadata"]["uid"]
        .as_str()
        .context("node UID missing")?;
    let boot_id = node["status"]["nodeInfo"]["bootID"]
        .as_str()
        .context("node boot identity missing")?;
    super::broker_config::canonical_uuid(node_uid)?;
    super::broker_config::canonical_uuid(boot_id)?;
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        request(
            SocketAddr::from((ip, 9443)),
            node_uid.into(),
            guest_uid.into(),
            nonce.into(),
        ),
    )
    .await
    .context("node fence RPC timed out")??;
    let (after, node_after, namespace_after) = tokio::try_join!(
        client.required("pod", Some(name), Some(&operator.guard_namespace)),
        client.required("node", Some(node_name), None),
        client.required("namespace", Some(&operator.guard_namespace), None)
    )?;
    validate_namespace(&namespace_after, operator)?;
    validate_guard(&after, image, &operator.guard_namespace, node_name)?;
    ensure!(
        after["metadata"]["uid"] == uid
            && after["status"]["podIP"] == ip.to_string()
            && after["spec"]["nodeName"] == node_name
            && node_after["metadata"]["uid"] == node_uid
            && node_after["status"]["nodeInfo"]["bootID"] == boot_id,
        "node guard generation changed during verification"
    );
    ensure!(response.nonce == nonce, "node fence challenge differs");
    response.proof.validate(super::lease::now()?)?;
    let b = &response.proof.binding;
    ensure!(
        b.workspace == state.workspace
            && b.namespace_uid == broker.source_namespace_uid
            && b.sandbox_id == state.sandbox_id
            && b.pod_uid == guest_uid
            && Some(b.launch_nonce.as_str()) == state.launch_nonce.as_deref()
            && Some(b.expires_at_unix) == state.expires_at
            && b.broker_pod_uid == broker.uid
            && b.broker_ip.to_string() == broker.ip
            && b.broker_port == 3128
            && b.broker_config_sha256 == broker.config_sha256
            && b.guest_ip.to_string()
                == guest["status"]["podIP"]
                    .as_str()
                    .context("guest IP missing")?
            && b.node_uid == node_uid
            && b.boot_id == boot_id,
        "node fence intent differs from runtime binding"
    );
    Ok(response.proof)
}
fn validate_namespace(namespace: &Value, operator: &Config) -> Result<()> {
    ensure!(
        namespace["metadata"]["name"] == operator.guard_namespace
            && namespace["metadata"]["uid"] == operator.guard_namespace_uid
            && namespace["metadata"]["deletionTimestamp"].is_null(),
        "trusted guard namespace generation differs"
    );
    Ok(())
}

/// Inject only the proof transport in unit builds; production always uses mTLS RPC.
#[cfg(test)]
pub(super) async fn verify_with_image(
    client: &Client,
    state: &State,
    guest: &Value,
    nonce: &str,
    image: &str,
    operator: &Config,
) -> Result<HostedFenceProof> {
    use std::io::Write;
    let root = client
        .program
        .parent()
        .context("test client directory missing")?
        .to_path_buf();
    verify_with_transport(
        client,
        state,
        guest,
        nonce,
        image,
        operator,
        move |address, node_uid, pod_uid, challenge| async move {
            let mut calls = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(root.join("calls"))?;
            writeln!(
                calls,
                "guard-rpc {address} {node_uid} {pod_uid} {challenge}"
            )?;
            let bytes = std::fs::read(root.join("guard-response.json"))?;
            let mut response: HostedFenceResponse = serde_json::from_slice(&bytes)?;
            if response.nonce == "CHALLENGE" {
                response.nonce = challenge;
            }
            if root.join("guard-replacement.json").exists() {
                std::fs::copy(
                    root.join("guard-replacement.json"),
                    root.join("guard-pod.json"),
                )?;
            }
            Ok(response)
        },
    )
    .await
}

pub(super) fn validate_guard(pod: &Value, image: &str, namespace: &str, node: &str) -> Result<()> {
    let spec = &pod["spec"];
    ensure!(
        pod["metadata"]["namespace"] == namespace
            && pod["metadata"]["labels"][COMPONENT] == "runtime-guard"
            && spec["nodeName"] == node
            && spec["automountServiceAccountToken"] == false
            && ["hostNetwork", "hostPID", "hostIPC"]
                .iter()
                .all(|key| spec.get(key).is_none_or(|v| v == false))
            && ["ephemeralContainers", "initContainers"]
                .iter()
                .all(|key| spec
                    .get(key)
                    .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))),
        "guard namespace or execution boundary differs"
    );
    let containers = spec["containers"]
        .as_array()
        .context("guard container inventory missing")?;
    let statuses = pod["status"]["containerStatuses"]
        .as_array()
        .context("guard status inventory missing")?;
    let expected = std::collections::BTreeSet::from(["node-intent", "proof-server"]);
    let names = containers
        .iter()
        .map(|c| c["name"].as_str().context("guard container name missing"))
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    let status_names = statuses
        .iter()
        .map(|s| s["name"].as_str().context("guard status name missing"))
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        containers.len() == 2
            && names == expected
            && containers.iter().all(|c| c["image"] == image)
            && pod["status"]["phase"] == "Running"
            && statuses.len() == 2
            && status_names == expected
            && statuses
                .iter()
                .all(|s| s["ready"] == true && s["state"]["running"].is_object()),
        "both exact trusted guard containers must be running and ready"
    );
    Ok(())
}
