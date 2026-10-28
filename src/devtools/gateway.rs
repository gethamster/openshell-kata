use super::local::{GATEWAY, Local, PORT, private_directory, require_success, run};
use anyhow::Result;
use std::{os::unix::fs::PermissionsExt, time::Duration};

pub async fn setup(local: &Local) -> Result<()> {
    let registration = local
        .state
        .join("config/openshell/gateways")
        .join(GATEWAY)
        .join("metadata.json");
    let registered = if registration.exists() {
        let metadata: serde_json::Value = serde_json::from_slice(&std::fs::read(&registration)?)?;
        if metadata["name"] != GATEWAY
            || metadata["gateway_endpoint"] != format!("https://127.0.0.1:{PORT}")
            || metadata["is_remote"] != false
            || metadata["auth_mode"] != "mtls"
        {
            anyhow::bail!("existing local gateway registration differs; refusing to replace it");
        }
        true
    } else {
        false
    };
    let tls = local.state.join("tls");
    if !tls.join("server/tls.crt").exists() {
        require_success(
            run(
                local
                    .command(local.state.join("bin/openshell-gateway"))?
                    .args(["generate-certs", "--output-dir"])
                    .arg(&tls)
                    .args(["--server-san", "127.0.0.1", "--server-san", "localhost"]),
                Duration::from_secs(30),
            )
            .await?,
        )?;
    }
    let trust = local
        .state
        .join("config/openshell/gateways")
        .join(GATEWAY)
        .join("mtls");
    private_directory(&trust)?;
    for (source, target) in [
        (tls.join("ca.crt"), "ca.crt"),
        (tls.join("client/tls.crt"), "tls.crt"),
        (tls.join("client/tls.key"), "tls.key"),
    ] {
        let destination = trust.join(target);
        if destination
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            anyhow::bail!("refusing a symlink in local trust directory");
        }
        std::fs::copy(source, &destination)?;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o600))?;
    }
    let quote = |relative: &str| {
        serde_json::to_string(&tls.join(relative).to_string_lossy())
            .expect("path string serializes")
    };
    let socket = serde_json::to_string(&local.state.join("driver.sock").to_string_lossy())?;
    let config = format!(
        r#"[openshell]
version = 2
[openshell.gateway]
name = "{GATEWAY}"
bind_address = "127.0.0.1:{PORT}"
log_level = "info"
compute_driver = "openshell-kata"
[openshell.gateway.tls]
cert_path = {}
key_path = {}
client_ca_path = {}
[openshell.gateway.mtls_auth]
enabled = true
operator_enabled = false
[openshell.gateway.auth]
allow_unauthenticated_users = false
[openshell.gateway.gateway_jwt]
signing_key_path = {}
public_key_path = {}
kid_path = {}
gateway_id = "openshell-kata-local"
ttl_secs = 900
[openshell.drivers.openshell-kata]
socket_path = {socket}
"#,
        quote("server/tls.crt"),
        quote("server/tls.key"),
        quote("ca.crt"),
        quote("jwt/signing.pem"),
        quote("jwt/public.pem"),
        quote("jwt/kid")
    );
    std::fs::write(local.state.join("gateway.toml"), config)?;
    if !registered {
        local
            .checked_cli(
                &[
                    "gateway",
                    "add",
                    &format!("https://127.0.0.1:{PORT}"),
                    "--local",
                    "--name",
                    GATEWAY,
                ],
                Duration::from_secs(30),
                None,
            )
            .await?;
    }
    println!("Local gateway PKI and registration ready");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn existing_pki_is_preserved_and_only_local_state_is_registered() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let local = Local::new(directory.path())?;
        for name in [
            "server/tls.crt",
            "server/tls.key",
            "client/tls.crt",
            "client/tls.key",
            "ca.crt",
        ] {
            let path = local.state.join("tls").join(name);
            std::fs::create_dir_all(path.parent().expect("TLS path has parent"))?;
            std::fs::write(path, format!("original-{name}"))?;
        }
        let binary = local.state.join("bin/openshell");
        std::fs::create_dir_all(binary.parent().expect("binary has parent"))?;
        std::fs::write(
            &binary,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$XDG_STATE_HOME/registration\"\n",
        )?;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))?;
        setup(&local).await?;
        assert_eq!(
            std::fs::read_to_string(local.state.join("tls/server/tls.key"))?,
            "original-server/tls.key"
        );
        let registration = std::fs::read_to_string(local.state.join("state/registration"))?;
        assert!(registration.contains("https://127.0.0.1:29670"));
        assert!(registration.contains("--local"));
        let key = local
            .state
            .join("config/openshell/gateways/kata-rust/mtls/tls.key");
        assert_eq!(std::fs::read_to_string(&key)?, "original-client/tls.key");
        assert_eq!(std::fs::metadata(key)?.permissions().mode() & 0o777, 0o600);
        let registration = local
            .state
            .join("config/openshell/gateways/kata-rust/metadata.json");
        std::fs::write(
            &registration,
            serde_json::to_vec(
                &serde_json::json!({"name":GATEWAY,"gateway_endpoint":format!("https://127.0.0.1:{PORT}"),"is_remote":false,"auth_mode":"mtls"}),
            )?,
        )?;
        std::fs::write(&binary, "#!/bin/sh\nexit 99\n")?;
        setup(&local).await?;
        std::fs::write(&registration, b"{}")?;
        assert!(setup(&local).await.is_err());
        Ok(())
    }
}
