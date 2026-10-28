use crate::config::{Config, SandboxId};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{net::IpAddr, path::PathBuf, process::Stdio};
use tokio::process::{Child, Command};

/// Trusted lifecycle output describing a pinned SSH route to one guest.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guest {
    pub sandbox_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub private_key_path: PathBuf,
    pub known_hosts_path: PathBuf,
}
impl Guest {
    pub fn validate(&self, id: &SandboxId) -> Result<()> {
        if self.sandbox_id != id.as_str()
            || !self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            || self.port == 0
        {
            bail!("lifecycle returned an invalid guest route");
        }
        if self.username.is_empty()
            || !self
                .username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            bail!("invalid guest user");
        }
        if !self.private_key_path.is_absolute() || !self.known_hosts_path.is_absolute() {
            bail!("guest authentication paths must be absolute");
        }
        Ok(())
    }

    fn command(&self, config: &Config) -> Command {
        let mut command = Command::new(&config.ssh);
        command
            .args([
                "-F",
                "/dev/null",
                "-T",
                "-oBatchMode=yes",
                "-oIdentitiesOnly=yes",
                "-oStrictHostKeyChecking=yes",
                "-oForwardAgent=no",
                "-oControlMaster=no",
                "-oLogLevel=ERROR",
            ])
            .arg(format!(
                "-oUserKnownHostsFile={}",
                self.known_hosts_path.display()
            ))
            .arg("-i")
            .arg(&self.private_key_path)
            .arg("-p")
            .arg(self.port.to_string())
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_ASKPASS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }

    pub fn exec(&self, config: &Config, command: &str) -> Result<Child> {
        self.command(config)
            .arg("--")
            .arg(format!("{}@{}", self.username, self.host))
            .arg(command)
            .spawn()
            .context("starting isolated guest SSH execution")
    }
    pub fn sftp(&self, config: &Config) -> Result<Child> {
        self.command(config)
            .arg("-s")
            .arg("--")
            .arg(format!("{}@{}", self.username, self.host))
            .arg("sftp")
            .spawn()
            .context("starting isolated guest SFTP")
    }
    pub fn tcp(&self, config: &Config, host: &str, port: u32) -> Result<Child> {
        if !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) && host != "localhost" {
            bail!("preview target must be loopback");
        }
        if port == 0 || port > u16::MAX.into() {
            bail!("invalid preview port");
        }
        let target = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        self.command(config)
            .arg("-W")
            .arg(target)
            .arg("--")
            .arg(format!("{}@{}", self.username, self.host))
            .spawn()
            .context("starting guest TCP relay")
    }
}

pub async fn lifecycle(config: &Config, action: &str, id: &SandboxId) -> Result<Option<Guest>> {
    let output = Command::new(&config.lifecycle)
        .args(&config.lifecycle_arg)
        .arg(action)
        .arg(id.as_str())
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .context("running guest lifecycle")?;
    if !output.status.success() {
        let diagnostic: String = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(4096)
            .collect();
        tracing::error!(action, sandbox=%id, stderr=%diagnostic, "guest lifecycle failed");
        bail!(
            "guest lifecycle {action} failed with status {}",
            output.status
        );
    }
    if action == "create" || action == "start" {
        let guest: Guest =
            serde_json::from_slice(&output.stdout).context("decoding guest lifecycle metadata")?;
        guest.validate(id)?;
        Ok(Some(guest))
    } else {
        Ok(None)
    }
}
