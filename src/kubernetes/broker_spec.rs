//! Closed trusted Pod projection permitting only explicit Kubernetes defaults.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub(super) fn validate(actual: &Value, expected: &Value) -> Result<()> {
    let fields = actual.as_object().context("broker Pod spec missing")?;
    for (key, value) in fields {
        if matches!(key.as_str(), "containers" | "initContainers") {
            let containers = value
                .as_array()
                .context("broker container inventory missing")?;
            ensure!(containers.len() == 1, "unexpected broker sidecar");
            container(&containers[0], &expected[key][0])?;
        } else if key == "dnsConfig" {
            validate_dns(value, &expected[key])?;
        } else if key == "activeDeadlineSeconds" {
            ensure!(
                value
                    .as_u64()
                    .is_some_and(|seconds| (1..=86400).contains(&seconds)),
                "broker deadline missing or excessive"
            );
        } else if key == "securityContext" {
            let mut required = expected[key].clone();
            if value.get("supplementalGroupsPolicy").is_some()
                && required.get("supplementalGroupsPolicy").is_none()
            {
                required["supplementalGroupsPolicy"] = json!("Merge");
            }
            ensure!(*value == required, "broker security context changed");
        } else if let Some(required) = expected.get(key) {
            ensure!(value == required, "broker Pod specification changed");
        } else {
            ensure!(
                pod_default(key, value),
                "unrendered broker Pod field: {key}"
            );
        }
    }
    ensure!(
        expected
            .as_object()
            .context("expected broker Pod spec missing")?
            .keys()
            .all(|key| actual.get(key).is_some()),
        "required broker Pod field missing"
    );
    Ok(())
}
fn container(actual: &Value, expected: &Value) -> Result<()> {
    for (key, value) in actual
        .as_object()
        .context("broker container spec missing")?
    {
        if let Some(required) = expected.get(key) {
            ensure!(value == required, "broker container specification changed");
        } else {
            let valid = match key.as_str() {
                "imagePullPolicy" => value == "IfNotPresent",
                "terminationMessagePath" => value == "/dev/termination-log",
                "terminationMessagePolicy" => value == "File",
                "stdin" | "stdinOnce" | "tty" => value == false,
                _ => false,
            };
            ensure!(valid, "unrendered broker container field: {key}");
        }
    }
    ensure!(
        expected
            .as_object()
            .context("expected container missing")?
            .keys()
            .all(|key| actual.get(key).is_some()),
        "required broker container field missing"
    );
    Ok(())
}
fn pod_default(key: &str, value: &Value) -> bool {
    match key {
        "dnsPolicy"=>value=="ClusterFirst",
        "schedulerName"=>value=="default-scheduler",
        "serviceAccountName"|"serviceAccount"=>value=="default",
        "preemptionPolicy"=>value=="PreemptLowerPriority",
        "priority"=>value==0,
        "hostNetwork"|"hostPID"|"hostIPC"=>value==false,
        "hostUsers"=>value==true,
        "nodeName"=>value.as_str().is_some_and(|v|!v.is_empty()&&v.len()<=253&&v.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b".-".contains(&b))),
        "imagePullSecrets"=>value.as_array().is_some_and(Vec::is_empty),
        "os"=>*value==json!({"name":"linux"}),
        "tolerations"=>value.as_array().is_some_and(|v|v.iter().all(|t|["node.kubernetes.io/not-ready","node.kubernetes.io/unreachable"].iter().any(|key|*t==json!({"key":key,"operator":"Exists","effect":"NoExecute","tolerationSeconds":300})))),
        _=>false,
    }
}

fn validate_dns(actual: &Value, expected: &Value) -> Result<()> {
    ensure!(
        actual.as_object().is_some_and(|o| o
            .keys()
            .all(|key| matches!(key.as_str(), "nameservers" | "searches" | "options")))
            && actual["nameservers"] == expected["nameservers"]
            && actual["options"] == expected["options"]
            && actual
                .get("searches")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "broker DNS authority changed"
    );
    Ok(())
}
