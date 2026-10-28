//! Original lease admission and Kubelet-relative deadline validation.

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes epoch")?
        .as_secs())
}

pub(super) fn expires_at(existing: Option<Option<u64>>, lifetime: u64, now: u64) -> Result<u64> {
    ensure!(
        (60..=86400).contains(&lifetime),
        "VM lifetime must be between 60 and 86400 seconds"
    );
    let expires = match existing {
        Some(expires) => {
            expires.context("retained runtime has no verified lease; explicit cleanup required")?
        }
        None => now.checked_add(lifetime).context("VM lifetime overflow")?,
    };
    ensure!(expires > now, "sandbox lease expired");
    ensure!(
        expires - now <= 86400,
        "retained VM lease exceeds supported maximum"
    );
    Ok(expires)
}

pub(super) fn allowed_seconds(expires: u64, start: &str) -> Result<u64> {
    let start =
        chrono::DateTime::parse_from_rfc3339(start).context("invalid Kubelet start time")?;
    let seconds = u64::try_from(start.timestamp()).context("Kubelet start precedes epoch")?;
    // Round the start up: a fractional second must not extend the original lease.
    let start = seconds
        .checked_add(u64::from(start.timestamp_subsec_nanos() != 0))
        .context("Kubelet start overflow")?;
    let allowed = expires
        .checked_sub(start)
        .filter(|seconds| *seconds > 0)
        .context("sandbox lease expired before Kubelet start")?;
    Ok(allowed)
}

pub(super) fn patch(pod: &Value, nonce: &str, expires: u64) -> Result<Option<Value>> {
    ensure!(
        pod["metadata"]["annotations"]["openshell-kata.io/launch-nonce"] == nonce,
        "runtime launch generation changed"
    );
    let uid = pod["metadata"]["uid"]
        .as_str()
        .context("runtime UID missing")?;
    let revision = pod["metadata"]["resourceVersion"]
        .as_str()
        .context("runtime revision missing")?;
    let start = pod["status"]["startTime"]
        .as_str()
        .context("Kubelet start time missing")?;
    let allowed = allowed_seconds(expires, start)?;
    let current = pod["spec"]["activeDeadlineSeconds"]
        .as_u64()
        .filter(|seconds| *seconds > 0)
        .context("Kubelet deadline missing")?;
    if current <= allowed {
        return Ok(None);
    }
    Ok(Some(json!([
        {"op":"test","path":"/metadata/uid","value":uid},
        {"op":"test","path":"/metadata/resourceVersion","value":revision},
        {"op":"test","path":"/metadata/annotations/openshell-kata.io~1launch-nonce","value":nonce},
        {"op":"replace","path":"/spec/activeDeadlineSeconds","value":allowed}
    ])))
}
