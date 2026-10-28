//! Read-only authenticated evidence transport outside privileged Pod execution.

mod client;
mod config;
mod server;

pub use client::verify_remote;
pub use config::{GuardClientConfig, GuardServerConfig};
pub use server::serve;

use anyhow::{Result, ensure};
use std::net::SocketAddr;

const MAX_PROOF: usize = 64 * 1024;
const MAX_REQUEST: usize = 512;
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
const SERVER_NAME: &str = "runtime-guard.kata-system.internal";

#[allow(clippy::all)]
mod wire {
    tonic::include_proto!("openshell_kata.guard.v1");
}

fn canonical_uuid(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value)?;
    ensure!(
        !parsed.is_nil() && parsed.to_string() == value,
        "noncanonical proof identity"
    );
    Ok(())
}
fn server_name(node_uid: &str) -> Result<String> {
    canonical_uuid(node_uid)?;
    Ok(SERVER_NAME.into())
}
fn validate_endpoint(endpoint: SocketAddr) -> Result<()> {
    ensure!(
        matches!(endpoint,SocketAddr::V4(address) if address.ip().is_private() && address.port()==9443),
        "guard proof requires private IPv4 port 9443"
    );
    Ok(())
}

#[cfg(test)]
use config::{FileKind, read_file};
#[cfg(all(test, target_os = "linux"))]
mod linux_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_tests;
