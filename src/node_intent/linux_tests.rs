//! Actual root Linux filesystem, namespace and production CLI qualification.
use super::*;
use anyhow::Context;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

const NS: &str = "kata-hosted-qualification";
const UID: &str = "11111111-1111-4111-8111-111111111111";
const BUNDLE: &str = "/run/containerd/io.containerd.runtime.v2.task/k8s.io/qualification-sandbox";
const ROOT: &str = "/fixture-api";

fn command(program: &str, args: &[&str]) -> Result<Output> {
    let output = Command::new(program).args(args).output()?;
    ensure!(
        output.status.success(),
        "fixture command failed: {program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}
fn private_dir(path: &str) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn write(path: impl AsRef<Path>, value: &impl serde::Serialize) -> Result<()> {
    fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}
fn snapshot(resource: &str, namespace: &str, name: &str, value: &Value) -> Result<()> {
    write(
        Path::new(ROOT).join(format!("{resource}-{namespace}-{name}.json")),
        value,
    )
}
fn run_cli(binary: &str, case: &str) -> Result<Output> {
    Ok(Command::new(binary)
        .arg("--once")
        .env("UNTRUSTED_MARKER", "must-not-reach-kubectl")
        .env(
            "LLVM_PROFILE_FILE",
            format!("/coverage/raw/node-{case}-%p-%m.profraw"),
        )
        .output()?)
}
fn setup_network() -> Result<()> {
    command("ip", &["netns", "add", NS])?;
    command(
        "ip",
        &[
            "link",
            "add",
            "kata-peer",
            "type",
            "veth",
            "peer",
            "name",
            "kata-outer",
        ],
    )?;
    command(
        "ip",
        &["link", "set", "kata-peer", "address", "02:00:00:00:00:02"],
    )?;
    command("ip", &["link", "set", "kata-outer", "netns", NS])?;
    command(
        "ip",
        &["-n", NS, "link", "set", "kata-outer", "name", "eth0"],
    )?;
    command(
        "ip",
        &[
            "-n",
            NS,
            "link",
            "set",
            "eth0",
            "address",
            "02:00:00:00:00:01",
        ],
    )?;
    command("ip", &["link", "set", "kata-peer", "up"])?;
    command("ip", &["addr", "add", "10.50.0.1/32", "dev", "kata-peer"])?;
    command("ip", &["addr", "add", "10.50.0.3/32", "dev", "kata-peer"])?;
    command("ip", &["addr", "add", "10.50.0.4/32", "dev", "kata-peer"])?;
    command("ip", &["route", "add", "10.50.0.2/32", "dev", "kata-peer"])?;
    command("ip", &["-n", NS, "link", "set", "lo", "up"])?;
    command("ip", &["-n", NS, "link", "set", "eth0", "up"])?;
    command(
        "ip",
        &["-n", NS, "addr", "add", "10.50.0.2/32", "dev", "eth0"],
    )?;
    command(
        "ip",
        &["-n", NS, "route", "add", "10.50.0.1/32", "dev", "eth0"],
    )?;
    command(
        "ip",
        &[
            "-n",
            NS,
            "route",
            "add",
            "default",
            "via",
            "10.50.0.1",
            "dev",
            "eth0",
        ],
    )?;
    command(
        "ip",
        &[
            "-n",
            NS,
            "neigh",
            "add",
            "10.50.0.1",
            "lladdr",
            "02:00:00:00:00:02",
            "nud",
            "permanent",
            "dev",
            "eth0",
        ],
    )?;
    Ok(())
}

#[test]
#[ignore = "requires root in a disposable privileged Linux container with private mount/net namespaces"]
fn actual_node_intent_cli_qualifies_preboot_identity_and_rejects_tampering() -> Result<()> {
    ensure!(
        std::env::var("OPENSHELL_KATA_ISOLATED_LINUX").as_deref() == Ok("1"),
        "explicit isolated Linux fixture opt-in required"
    );
    let binary =
        std::env::var("KATA_NODE_INTENT_BINARY").context("production CLI binary path required")?;
    setup_network()?;
    for directory in [
        ROOT,
        "/etc/openshell-kata",
        "/run/openshell-kata/intents",
        "/run/openshell-kata/fences",
        "/coverage/raw",
        BUNDLE,
    ] {
        private_dir(directory)?;
    }
    let (config, mut guest, mut launch) = super::tests::fixture()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    launch.node["status"]["nodeInfo"]["bootID"] = json!(boot);
    launch.broker["status"]["podIP"] = json!("10.50.0.3");
    guest["metadata"]["annotations"]["openshell-kata.io/broker-ip"] = json!("10.50.0.3");
    launch.controllers["items"][0]["status"]["podIP"] = json!("10.50.0.4");
    let source_name = admission::name(&launch.source_namespace)?;
    let broker_name = admission::name(&launch.broker)?;
    let guest_name = admission::name(&guest)?.to_owned();
    snapshot(
        "namespace",
        "cluster",
        source_name,
        &launch.source_namespace,
    )?;
    snapshot(
        "namespace",
        "cluster",
        "openshell-network",
        &launch.broker_namespace,
    )?;
    snapshot(
        "namespace",
        "cluster",
        "openshell-system",
        &launch.controller_namespace,
    )?;
    snapshot("node", "cluster", "node-a", &launch.node)?;
    snapshot("pod", source_name, &guest_name, &guest)?;
    snapshot("pod", "openshell-network", broker_name, &launch.broker)?;
    snapshot(
        "pods",
        "openshell-network",
        "list",
        &json!({"items":[launch.broker]}),
    )?;
    snapshot("pods", "openshell-system", "list", &launch.controllers)?;
    snapshot(
        "configmap",
        "openshell-network",
        broker_name,
        &launch.configmap,
    )?;
    fs::write(
        "/fixture-api/kubectl.rs",
        include_str!("fixtures/kubectl.rs"),
    )?;
    command(
        "rustc",
        &[
            "--edition",
            "2024",
            "/fixture-api/kubectl.rs",
            "-o",
            "/fixture-api/kubectl",
        ],
    )?;
    let kubectl_sha = format!("{:x}", Sha256::digest(fs::read("/fixture-api/kubectl")?));
    write(
        "/etc/openshell-kata/operator.json",
        config.operator.as_ref().context("fixture operator")?,
    )?;
    fs::write(
        "/etc/openshell-kata/ca.crt",
        "fixture CA only; Kubernetes API is mocked\n",
    )?;
    fs::write("/etc/openshell-kata/token", "noncredential-fixture-token\n")?;
    write(
        "/etc/openshell-kata/kubeconfig.json",
        &json!({"clusters":[{"name":"fixture","cluster":{"server":"https://kubernetes.example.invalid","certificate-authority":"/etc/openshell-kata/ca.crt"}}],"users":[{"name":"fixture","user":{"tokenFile":"/etc/openshell-kata/token"}}],"contexts":[{"name":"fixture","context":{"cluster":"fixture","user":"fixture"}}],"current-context":"fixture"}),
    )?;
    write(
        "/etc/openshell-kata/node-intent.json",
        &json!({"version":1,"node_name":config.node_name,"node_uid":config.node_uid,"boot_id":boot,"kubectl_path":"/fixture-api/kubectl","kubectl_sha256":kubectl_sha,"kubeconfig_path":"/etc/openshell-kata/kubeconfig.json","bundle_root":"/run/containerd/io.containerd.runtime.v2.task/k8s.io","nsenter_path":"/usr/bin/nsenter","ip_path":fs::canonicalize("/usr/sbin/ip")?,"broker_namespace":config.broker_namespace,"broker_namespace_uid":config.broker_namespace_uid,"broker_image":config.broker_image,"guest_image":config.guest_image,"operator_network_config_path":"/etc/openshell-kata/operator.json","controller_namespace":config.controller_namespace,"controller_namespace_uid":config.controller_namespace_uid,"controller_labels":config.controller_labels,"controller_container_images":config.controller_container_images,"controller_init_container_images":config.controller_init_container_images,"controller_restartable_init_containers":config.controller_restartable_init_containers}),
    )?;
    let bundle = json!({"annotations":{"io.kubernetes.cri.container-type":"sandbox","io.kubernetes.cri.sandbox-uid":UID,"io.kubernetes.cri.sandbox-name":guest_name,"io.kubernetes.cri.sandbox-namespace":source_name},"linux":{"namespaces":[{"type":"network","path":format!("/run/netns/{NS}")}]}});
    write(Path::new(BUNDLE).join("config.json"), &bundle)?;
    let first = run_cli(&binary, "first")?;
    ensure!(
        first.status.success(),
        "production first CLI failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let summary: Value = serde_json::from_slice(&first.stdout)?;
    ensure!(
        summary["published"] == 1 && summary["rejected"] == 0,
        "unexpected first CLI summary"
    );
    let path = format!("/run/openshell-kata/intents/{UID}.json");
    let intent: crate::network::hosted_fence::HostedFenceIntent =
        serde_json::from_slice(&fs::read(&path)?)?;
    intent.validate(host::now()?)?;
    assert_eq!(intent.guest_ip.to_string(), "10.50.0.2");
    assert_eq!(intent.guest_mac, "02:00:00:00:00:01");
    assert_eq!(intent.gateway_ip.to_string(), "10.50.0.1");
    assert_eq!(intent.gateway_mac, "02:00:00:00:00:02");
    assert_eq!(intent.controller_cidrs, vec!["10.50.0.4/32"]);
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    let calls_before = fs::read("/fixture-api/calls.log")?;
    command(
        "ip",
        &["-n", NS, "addr", "del", "10.50.0.2/32", "dev", "eth0"],
    )?;
    let second = run_cli(&binary, "retained-after-address-removal")?;
    ensure!(
        second.status.success(),
        "retained intent CLI failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        calls_before,
        fs::read("/fixture-api/calls.log")?,
        "retained intent must not query API or acquire new authority"
    );
    command(
        "ip",
        &["-n", NS, "addr", "add", "10.50.0.2/32", "dev", "eth0"],
    )?;
    // Removing the final IPv4 address also removes its routes and neighbors.
    // Recreate the complete CNI attachment before testing new launch failures.
    command(
        "ip",
        &["-n", NS, "route", "replace", "10.50.0.1/32", "dev", "eth0"],
    )?;
    command(
        "ip",
        &[
            "-n",
            NS,
            "route",
            "replace",
            "default",
            "via",
            "10.50.0.1",
            "dev",
            "eth0",
        ],
    )?;
    command(
        "ip",
        &[
            "-n",
            NS,
            "neigh",
            "replace",
            "10.50.0.1",
            "lladdr",
            "02:00:00:00:00:02",
            "nud",
            "permanent",
            "dev",
            "eth0",
        ],
    )?;
    qualify_tampering(&binary, &guest, &launch, &bundle)?;
    fs::write(
        "/coverage/node-intent-result.json",
        serde_json::to_vec_pretty(
            &json!({"production_cli":true,"mocked_kubernetes_api":true,"real_netns":true,"guest_pod_ip_initially_missing":true,"immutable_private_intent":true,"retained_after_outer_address_removal":true,"tamper_cases":7,"intent":intent}),
        )?,
    )?;
    Ok(())
}

fn qualify_tampering(
    binary: &str,
    guest: &Value,
    launch: &admission::Launch,
    bundle: &Value,
) -> Result<()> {
    let trusted_node_config = fs::read("/etc/openshell-kata/node-intent.json")?;
    let name = admission::name(guest)?;
    let namespace = guest["metadata"]["namespace"]
        .as_str()
        .context("fixture namespace")?;
    for (index, case) in [
        "broker-hook",
        "namespace-uid",
        "controller-not-ready",
        "new-pod-uid",
        "broker-namespace-uid",
        "missing-neighbor",
        "global-config",
    ]
    .iter()
    .enumerate()
    {
        let uid = format!("{:08}-9999-4999-8999-999999999999", index + 10);
        let mut candidate = guest.clone();
        candidate["metadata"]["uid"] = json!(uid);
        let mut candidate_bundle = bundle.clone();
        candidate_bundle["annotations"]["io.kubernetes.cri.sandbox-uid"] = json!(uid);
        write(Path::new(BUNDLE).join("config.json"), &candidate_bundle)?;
        snapshot("pod", namespace, name, &candidate)?;
        snapshot("namespace", "cluster", namespace, &launch.source_namespace)?;
        snapshot(
            "namespace",
            "cluster",
            "openshell-network",
            &launch.broker_namespace,
        )?;
        snapshot("pods", "openshell-system", "list", &launch.controllers)?;
        snapshot(
            "pods",
            "openshell-network",
            "list",
            &json!({"items":[launch.broker]}),
        )?;
        match *case {
            "broker-hook" => {
                let mut wrong = launch.broker.clone();
                wrong["spec"]["containers"][0]["lifecycle"] =
                    json!({"postStart":{"exec":{"command":["false"]}}});
                snapshot(
                    "pods",
                    "openshell-network",
                    "list",
                    &json!({"items":[wrong]}),
                )?;
            }
            "namespace-uid" => {
                let mut wrong = launch.source_namespace.clone();
                wrong["metadata"]["uid"] = json!(uid);
                snapshot("namespace", "cluster", namespace, &wrong)?;
            }
            "controller-not-ready" => {
                let mut wrong = launch.controllers.clone();
                wrong["items"][0]["status"]["initContainerStatuses"][1]["ready"] = json!(false);
                snapshot("pods", "openshell-system", "list", &wrong)?;
            }
            "new-pod-uid" => {
                candidate["metadata"]["uid"] = json!("88888888-8888-4888-8888-888888888888");
                snapshot("pod", namespace, name, &candidate)?;
            }
            "broker-namespace-uid" => {
                let mut wrong = launch.broker_namespace.clone();
                wrong["metadata"]["uid"] = json!(uid);
                snapshot("namespace", "cluster", "openshell-network", &wrong)?;
            }
            "missing-neighbor" => {
                command(
                    "ip",
                    &[
                        "-n",
                        NS,
                        "neigh",
                        "flush",
                        "to",
                        "10.50.0.1",
                        "dev",
                        "eth0",
                        "nud",
                        "all",
                    ],
                )?;
            }
            "global-config" => {
                let config_path = "/etc/openshell-kata/node-intent.json";
                let mut wrong: Value = serde_json::from_slice(&fs::read(config_path)?)?;
                wrong["kubectl_sha256"] = json!("0".repeat(64));
                write(config_path, &wrong)?;
            }
            _ => unreachable!("bounded qualification case"),
        }
        let output = run_cli(binary, case)?;
        fs::write(
            format!("/coverage/node-negative-{case}.log"),
            &output.stderr,
        )?;
        ensure!(
            !output.status.success(),
            "tampered production CLI unexpectedly succeeded: {case}"
        );
        ensure!(
            !Path::new(&format!("/run/openshell-kata/intents/{uid}.json")).exists(),
            "tampered launch wrote intent: {case}"
        );
        let reason = match *case {
            "broker-hook" => "unrendered broker container field: lifecycle",
            "namespace-uid" | "broker-namespace-uid" => "namespace generation differs",
            "controller-not-ready" => "controller process is not running and ready",
            "new-pod-uid" => "CRI and live Pod UID differ",
            "missing-neighbor" => "exact prepopulated gateway neighbor required",
            "global-config" => "kubectl digest differs from operator pin",
            _ => unreachable!("bounded qualification reason"),
        };
        ensure!(
            String::from_utf8_lossy(&output.stderr).contains(reason),
            "wrong rejection for {case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if *case == "missing-neighbor" {
            command(
                "ip",
                &[
                    "-n",
                    NS,
                    "neigh",
                    "replace",
                    "10.50.0.1",
                    "lladdr",
                    "02:00:00:00:00:02",
                    "nud",
                    "permanent",
                    "dev",
                    "eth0",
                ],
            )?;
        }
    }
    write(Path::new(BUNDLE).join("config.json"), bundle)?;
    fs::write("/etc/openshell-kata/node-intent.json", trusted_node_config)?;
    snapshot("pod", namespace, name, guest)?;
    snapshot("namespace", "cluster", namespace, &launch.source_namespace)?;
    snapshot(
        "namespace",
        "cluster",
        "openshell-network",
        &launch.broker_namespace,
    )?;
    snapshot("pods", "openshell-system", "list", &launch.controllers)?;
    snapshot(
        "pods",
        "openshell-network",
        "list",
        &json!({"items":[launch.broker]}),
    )?;
    Ok(())
}
