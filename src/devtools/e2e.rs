use super::{
    local::{Local, require_success},
    tools::digest,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NAME: &str = "rust-upload-check";
const REMOTE: &str = "/sandbox/project/upload";
const SHORT: Duration = Duration::from_secs(120);

fn fixture(local: &Local) -> Result<PathBuf> {
    let root = local.state.join("fixtures/upload");
    std::fs::create_dir_all(root.join("nested"))?;
    for (name, content) in [
        ("nested/text.txt", "Rust adapter round trip\n"),
        (
            "probe.sh",
            "#!/bin/sh\nprintf 'executable mode preserved\\n'\n",
        ),
        ("index.html", "Rust OpenShell + Kata + Docker Compose: OK\n"),
        (
            "Dockerfile",
            "FROM busybox:1.37\nWORKDIR /www\nRUN printf 'Docker build RUN works\\n' > /build-proof\nCOPY index.html .\nCMD [\"httpd\", \"-f\", \"-p\", \"8080\", \"-h\", \"/www\"]\n",
        ),
        (
            "compose.yaml",
            "services:\n  web:\n    build: .\n    ports: [\"127.0.0.1:18080:8080\"]\n  worker:\n    image: busybox:1.37\n    command: [\"sleep\", \"1800\"]\n",
        ),
    ] {
        std::fs::write(root.join(name), content)?;
    }
    std::fs::set_permissions(
        root.join("probe.sh"),
        std::fs::Permissions::from_mode(0o755),
    )?;
    std::fs::write(
        root.join("binary.dat"),
        (0..65536)
            .map(|index| (index % 256) as u8)
            .collect::<Vec<_>>(),
    )?;
    let mut large = std::fs::File::create(root.join("large.bin"))?;
    for index in 0u64..(16 * 1024 * 1024 / 32) {
        large.write_all(&Sha256::digest(index.to_le_bytes()))?;
    }
    Ok(root)
}
async fn shell(local: &Local, label: &str, command: &str, timeout: Duration) -> Result<()> {
    local
        .checked_cli(
            &[
                "sandbox", "exec", NAME, "--no-tty", "--", "sh", "-ec", command,
            ],
            timeout,
            Some(label),
        )
        .await?;
    Ok(())
}
async fn upload(local: &Local, directory: &Path, iteration: usize) -> Result<()> {
    local
        .checked_cli(
            &[
                "sandbox",
                "upload",
                "--no-git-ignore",
                NAME,
                &directory.to_string_lossy(),
                "/sandbox/project",
            ],
            Duration::from_secs(180),
            Some(&format!("upload-{iteration}")),
        )
        .await?;
    Ok(())
}
fn hashes(directory: &Path) -> Result<BTreeMap<String, String>> {
    fn walk(root: &Path, directory: &Path, results: &mut BTreeMap<String, String>) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                walk(root, &path, results)?;
            } else if entry.file_type()?.is_file() {
                results.insert(
                    path.strip_prefix(root)?.to_string_lossy().into_owned(),
                    digest(&path)?,
                );
            } else {
                bail!("unexpected non-regular object in qualification fixture");
            }
        }
        Ok(())
    }
    let mut results = BTreeMap::new();
    walk(directory, directory, &mut results)?;
    Ok(results)
}
async fn round_trip(local: &Local, directory: &Path, iteration: &str) -> Result<()> {
    let destination = local.state.join("downloads").join(iteration);
    if destination.exists() {
        std::fs::remove_dir_all(&destination)?;
    }
    std::fs::create_dir_all(&destination)?;
    local
        .checked_cli(
            &[
                "sandbox",
                "download",
                NAME,
                REMOTE,
                &destination.to_string_lossy(),
            ],
            Duration::from_secs(180),
            Some(&format!("download-{iteration}")),
        )
        .await?;
    let expected = hashes(directory)?;
    let actual = hashes(&destination)?;
    let actual = if actual == expected {
        actual
    } else if destination.join("upload").is_dir() {
        hashes(&destination.join("upload"))?
    } else {
        actual
    };
    ensure!(
        expected == actual,
        "download hashes differ from uploaded fixture"
    );
    std::fs::write(
        local.evidence.join(format!("hashes-{iteration}.json")),
        serde_json::to_vec_pretty(&actual)?,
    )?;
    Ok(())
}
async fn preview() -> Result<String> {
    let mut connection = tokio::net::TcpStream::connect("127.0.0.1:29680").await?;
    connection
        .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut bytes = Vec::new();
    connection.take(65536).read_to_end(&mut bytes).await?;
    let response = String::from_utf8(bytes)?;
    ensure!(
        response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200"),
        "preview HTTP status was not 200"
    );
    ensure!(
        response.contains("Compose: OK"),
        "preview body did not match fixture"
    );
    Ok(response)
}
async fn preview_and_transfers(local: &Local, directory: &Path) -> Result<()> {
    let mut forward = local
        .command(local.state.join("bin/openshell"))?
        .args([
            "forward",
            "service",
            NAME,
            "--target-port",
            "18080",
            "--local",
            "127.0.0.1:29680",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let outcome = async {
        let mut response = None;
        for _ in 0..40 {
            ensure!(
                forward.try_wait()?.is_none(),
                "preview forward exited early"
            );
            if let Ok(Ok(value)) = tokio::time::timeout(Duration::from_secs(2), preview()).await {
                response = Some(value);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let response = response.context("preview did not become ready")?;
        std::fs::write(
            local.evidence.join("preview.json"),
            serde_json::to_vec_pretty(&json!({"status": 200, "response": response}))?,
        )?;
        for iteration in 1..4 {
            let label = format!("concurrent-{iteration}");
            tokio::try_join!(
                upload(local, directory, iteration),
                shell(
                    local,
                    &label,
                    "printf 'concurrent exec works\\n'; docker ps --format '{{.Names}}'",
                    SHORT
                )
            )?;
            round_trip(local, directory, &iteration.to_string()).await?;
        }
        Ok(())
    }
    .await;
    let _ = forward.kill().await;
    let _ = forward.wait().await;
    outcome
}
pub async fn execute(local: &Local, resume: bool, policy: &Path) -> Result<()> {
    let directory = fixture(local)?;
    local
        .checked_cli(
            &["gateway", "info", "--output", "json"],
            SHORT,
            Some("gateway-info"),
        )
        .await?;
    if !resume {
        local
            .checked_cli(
                &[
                    "policy",
                    "set",
                    "--global",
                    "--yes",
                    "--policy",
                    &policy.to_string_lossy(),
                ],
                SHORT,
                Some("protocol-fixture"),
            )
            .await?;
        local
            .checked_cli(
                &[
                    "sandbox",
                    "create",
                    "--name",
                    NAME,
                    "--from",
                    "docker:29-dind",
                    "--detach",
                    "--no-auto-providers",
                    "--",
                    "sh",
                    "-c",
                    "sleep 3600",
                ],
                Duration::from_secs(300),
                Some("create"),
            )
            .await?;
    }
    let listing: serde_json::Value = serde_json::from_slice(
        &local
            .checked_cli(
                &["sandbox", "list", "--output", "json"],
                SHORT,
                Some("sandbox-ready"),
            )
            .await?
            .stdout,
    )?;
    let sandbox_id = listing["sandboxes"]
        .as_array()
        .context("missing sandbox list")?
        .iter()
        .find(|item| item["name"] == NAME)
        .and_then(|item| item["id"].as_str())
        .context("qualification sandbox not found")?
        .to_owned();
    shell(
        local,
        "identity",
        "id; uname -r; docker version --format '{{.Server.Version}}'",
        SHORT,
    )
    .await?;
    upload(local, &directory, 0).await?;
    shell(
        local,
        "executable-mode",
        &format!("{REMOTE}/probe.sh"),
        SHORT,
    )
    .await?;
    round_trip(local, &directory, "0").await?;
    shell(local, "compose", &format!("cd {REMOTE}; docker compose up -d --build; docker compose ps; curl --noproxy '*' --fail --silent http://127.0.0.1:18080"), Duration::from_secs(240)).await?;
    preview_and_transfers(local, &directory).await?;
    let restart_marker = uuid::Uuid::new_v4().to_string();
    shell(
        local,
        "fresh-restart-marker",
        &format!("printf '%s' '{restart_marker}' > /sandbox/restart-marker"),
        SHORT,
    )
    .await?;
    local
        .checked_cli(&["sandbox", "stop", NAME], SHORT, Some("stop"))
        .await?;
    local
        .checked_cli(
            &["sandbox", "start", NAME],
            Duration::from_secs(300),
            Some("start"),
        )
        .await?;
    shell(
        local,
        "after-restart",
        &format!("test \"$(cat /sandbox/restart-marker)\" = '{restart_marker}'; sha256sum {REMOTE}/large.bin; docker info >/dev/null"),
        SHORT,
    )
    .await?;
    round_trip(local, &directory, "restart").await?;
    local
        .checked_cli(&["sandbox", "delete", NAME], SHORT, Some("delete"))
        .await?;
    for _ in 0..60 {
        let output = local
            .cli(&["sandbox", "list", "--output", "json"], SHORT, None)
            .await?;
        let listing: serde_json::Value = serde_json::from_slice(&require_success(output)?.stdout)?;
        let absent = !listing["sandboxes"]
            .as_array()
            .context("missing sandbox list")?
            .iter()
            .any(|sandbox| sandbox["id"] == sandbox_id);
        if absent && !local.state.join("runtime").join(&sandbox_id).exists() {
            std::fs::write(
                local.evidence.join("runtime-deleted.json"),
                serde_json::to_vec_pretty(&json!({"sandbox_id": sandbox_id, "deleted": true}))?,
            )?;
            println!(
                "PASS: transfer hashes, concurrent exec, Docker build/Compose, preview, restart, delete"
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("sandbox deletion did not reconcile runtime and gateway state")
}
