use anyhow::{Result, bail};
use clap::Parser;
use std::{fmt, path::PathBuf};

/// Validated immutable target identifier used at runtime boundaries.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SandboxId(String);

impl SandboxId {
    /// Validate a gateway identifier before using it in lifecycle commands.
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > 128
            || !value.as_bytes()[0].is_ascii_alphanumeric()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("invalid sandbox identifier");
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Operator configuration; no workload input can select host commands.
#[derive(Clone, Debug, Parser)]
pub struct Config {
    #[arg(long)]
    pub socket: PathBuf,
    #[arg(long, default_value = "https://127.0.0.1:28670")]
    pub gateway: String,
    #[arg(long)]
    pub gateway_ca: PathBuf,
    #[arg(long)]
    pub lifecycle: PathBuf,
    #[arg(long)]
    pub lifecycle_arg: Vec<String>,
    #[arg(long, default_value = "/usr/bin/ssh")]
    pub ssh: PathBuf,
    /// Explicit local experiment: policies are inspected but not fully enforced.
    #[arg(long)]
    pub prototype_policy_mode: bool,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        for path in [&self.socket, &self.gateway_ca, &self.lifecycle, &self.ssh] {
            if !path.is_absolute() {
                bail!("operator paths must be absolute");
            }
        }
        let endpoint = tonic::transport::Endpoint::from_shared(self.gateway.clone())?;
        let uri = endpoint.uri();
        if uri.scheme_str() != Some("https")
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'))
        {
            bail!("gateway requires TLS");
        }
        if self.prototype_policy_mode
            && !uri.host().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            })
        {
            bail!("prototype policy mode is limited to a loopback gateway");
        }
        Ok(())
    }
}

/// Quote one shell argument for the remote guest's POSIX shell.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
