//! Revalidation of the actual VM, storage, and additive network boundaries.

use super::{client::Client, lease, manifest, model::State, policy};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) struct Observations {
    pub(super) pod: Value,
    pub(super) pvc: Value,
    pub(super) node: Value,
    pub(super) runtime: Value,
    pub(super) policies: Vec<Value>,
}

pub(super) async fn verify(
    client: &Client,
    state: &State,
    storage_class: &str,
    network: &ipnet::IpNet,
) -> Result<(State, Value)> {
    let namespace = client
        .required("namespace", Some(&state.namespace), None)
        .await?;
    policy::check_namespace(&namespace, &state.workspace)?;
    let pod = client
        .required("pod", Some(&state.name), Some(&state.namespace))
        .await?;
    let node_name = pod["spec"]["nodeName"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("guest has no assigned node"))?;
    let pvc = client
        .required("pvc", Some(&state.name), Some(&state.namespace))
        .await?;
    let node = client.required("node", Some(node_name), None).await?;
    let runtime = client
        .required("runtimeclass", Some(manifest::RUNTIME), None)
        .await?;
    let policies = client
        .required("networkpolicies", None, Some(&state.namespace))
        .await?["items"]
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("invalid network policy inventory"))?;
    validate(
        state,
        storage_class,
        &Observations {
            pod,
            pvc,
            node,
            runtime,
            policies,
        },
        network,
    )
}

pub(super) fn validate(
    state: &State,
    storage_class: &str,
    observed: &Observations,
    network: &ipnet::IpNet,
) -> Result<(State, Value)> {
    let expires = lease::expires_at(Some(state.expires_at), 86400, lease::now()?)?;
    let start = observed.pod["status"]["startTime"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Kubelet start time missing"))?;
    let allowed = lease::allowed_seconds(expires, start)?;
    let actual = observed.pod["spec"]["activeDeadlineSeconds"]
        .as_u64()
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| anyhow::anyhow!("Kubelet deadline missing"))?;
    ensure!(
        actual <= allowed,
        "Kubelet deadline exceeds original VM lease"
    );
    policy::require_owned(&observed.pod, &state.name)?;
    let spec = &observed.pod["spec"];
    ensure!(
        spec["runtimeClassName"] == manifest::RUNTIME
            && spec["automountServiceAccountToken"] == false,
        "runtime or token boundary differs"
    );
    ensure!(
        ["hostNetwork", "hostPID", "hostIPC"]
            .iter()
            .all(|name| spec.get(name).is_none_or(|v| v == false)),
        "host namespaces forbidden"
    );
    let expected = manifest::pod(&state.name, &state.namespace, &state.image);
    let containers = spec["containers"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid guest inventory"))?;
    ensure!(
        containers.len() == 1 && containers[0]["image"] == state.image,
        "guest image or sidecars changed"
    );
    ensure!(
        containers[0]["resources"]["limits"] == manifest::limits(),
        "resource boundary differs"
    );
    ensure!(
        containers[0]["command"] == expected["spec"]["containers"][0]["command"]
            && containers[0]["volumeMounts"] == expected["spec"]["containers"][0]["volumeMounts"],
        "guest boot or storage binding changed"
    );
    ensure!(
        spec["serviceAccountName"] == "openshell-sandbox",
        "guest service identity changed"
    );
    validate_volumes(spec, &state.name)?;
    let init = spec["initContainers"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid storage initializer"))?;
    ensure!(
        init.len() == 1
            && init[0]["image"] == state.image
            && init[0]["command"] == expected["spec"]["initContainers"][0]["command"],
        "storage initializer changed"
    );
    policy::require_owned(&observed.pvc, &state.name)?;
    let pvc = &observed.pvc["spec"];
    ensure!(
        pvc["storageClassName"] == storage_class
            && pvc["accessModes"] == json!(["ReadWriteOnce"])
            && pvc["resources"]["requests"]["storage"] == "19Gi",
        "private storage boundary changed"
    );
    let status = &observed.pod["status"];
    let statuses = status["containerStatuses"].as_array();
    ensure!(
        status["phase"] == "Running"
            && statuses.is_some_and(
                |values| !values.is_empty() && values.iter().all(|v| v["ready"] == true)
            ),
        "guest not running"
    );
    ensure!(
        observed.node["metadata"]["labels"]["pool"] == "kata-workers"
            && observed.node["metadata"]["labels"]["katacontainers.io/kata-runtime"] == "true",
        "Kata worker is not qualified"
    );
    ensure!(
        observed.runtime["handler"] == manifest::RUNTIME
            && observed.runtime["metadata"]["annotations"]["katacontainers.io/kata-version"]
                == "4.3.1",
        "runtime class differs from pinned runtime"
    );
    policy::validate_policies(&observed.policies, &observed.pod["metadata"]["labels"])?;
    let identity = observed.pod["metadata"]["uid"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("runtime UID missing"))?;
    uuid::Uuid::parse_str(identity)?;
    if let Some(nonce) = &state.launch_nonce {
        ensure!(
            observed.pod["metadata"]["annotations"]["openshell-kata.io/launch-nonce"] == *nonce,
            "runtime launch generation changed"
        );
    }
    ensure!(
        state.runtime_identity.is_empty() || state.runtime_identity == identity,
        "runtime generation changed"
    );
    let host = status["podIP"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("guest address missing"))?;
    let ip: std::net::IpAddr = host.parse()?;
    ensure!(
        network.contains(&ip) && !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
        "guest address outside operator network"
    );
    let proof = json!({"version":1,"sandbox_id":state.sandbox_id,"workspace":state.workspace,
        "namespace":state.namespace,"runtime_identity":identity,"runtime_class":manifest::RUNTIME,
        "image":state.image,"network":"deny-all-egress","cpu":"2","memory":"4Gi",
        "expires_at_unix":expires,"deadline_enforcement":"kubelet-active-deadline",
        "policy_sha256":format!("{:x}",Sha256::digest(serde_json::to_vec(&observed.policies)?))});
    Ok((
        State {
            host: host.to_owned(),
            runtime_identity: identity.to_owned(),
            ..state.clone()
        },
        proof,
    ))
}

fn validate_volumes(spec: &Value, name: &str) -> Result<()> {
    let volumes = spec["volumes"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid guest volumes"))?;
    ensure!(
        volumes.len() == 2
            && volumes
                .iter()
                .all(|v| v.get("hostPath").is_none() && v.get("projected").is_none()),
        "host or token volume forbidden"
    );
    let data = volumes.iter().find(|v| v["name"] == "data");
    let ssh = volumes.iter().find(|v| v["name"] == "ssh");
    ensure!(
        data.is_some_and(|v| v["persistentVolumeClaim"]["claimName"] == name)
            && ssh.is_some_and(|v| v["secret"]["secretName"] == name),
        "private volume identity changed"
    );
    Ok(())
}
