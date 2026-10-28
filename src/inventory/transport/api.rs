//! Exact-object API operations with bounded output and no ambient credentials.
use super::{CourierConfig, InventoryConfig, Target};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

pub(super) struct Api {
    program: PathBuf,
    kubeconfig: PathBuf,
    timeout: Duration,
}
impl Api {
    pub(super) fn publisher(config: &InventoryConfig) -> Self {
        Self {
            program: config.kubectl_path.clone(),
            kubeconfig: config.kubeconfig_path.clone(),
            timeout: Duration::from_secs(config.api_timeout_secs.min(3)),
        }
    }
    pub(super) fn courier(config: &CourierConfig) -> Self {
        Self {
            program: config.kubectl_path.clone(),
            kubeconfig: config.kubeconfig_path.clone(),
            timeout: Duration::from_secs(config.api_timeout_secs),
        }
    }
    pub(super) async fn get(&self, target: &Target) -> Result<Value> {
        self.request(&["get", "--raw", &target.path()], None).await
    }
    pub(super) async fn put(&self, target: &Target, value: &Value) -> Result<Value> {
        let bytes = serde_json::to_vec(value)?;
        ensure!(
            bytes.len() <= 2 * 1024 * 1024,
            "inventory replacement exceeds bound"
        );
        self.request(
            &["replace", "--raw", &target.path(), "-f", "-"],
            Some(bytes),
        )
        .await
    }
    async fn request(&self, args: &[&str], input: Option<Vec<u8>>) -> Result<Value> {
        let mut child = Command::new(&self.program)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .arg("--kubeconfig")
            .arg(&self.kubeconfig)
            .arg(format!("--request-timeout={}s", self.timeout.as_secs()))
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut output = child
            .stdout
            .take()
            .context("inventory API output missing")?;
        let mut writer = child.stdin.take();
        let work = async {
            let write = async {
                if let Some(bytes) = input {
                    let mut stream = writer.take().context("inventory API input missing")?;
                    stream.write_all(&bytes).await?;
                    stream.shutdown().await?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let read = async {
                let mut bytes = Vec::new();
                (&mut output)
                    .take(2 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .await?;
                ensure!(
                    bytes.len() <= 2 * 1024 * 1024,
                    "inventory API response exceeds bound"
                );
                Ok::<_, anyhow::Error>(bytes)
            };
            let (_, bytes) = tokio::try_join!(write, read)?;
            ensure!(
                child.wait().await?.success(),
                "inventory API request failed"
            );
            Ok::<_, anyhow::Error>(serde_json::from_slice(&bytes)?)
        };
        tokio::time::timeout(self.timeout, work)
            .await
            .context("inventory API deadline exceeded")?
    }
}
