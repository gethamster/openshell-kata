"""Generate disposable local PKI and register the pinned official gateway."""

from pathlib import Path
import shutil
import subprocess

from local import GATEWAY, LOCAL, PORT, cli, environment


def main():
    tls = LOCAL / "tls"
    env = environment()
    if not (tls / "server/tls.crt").exists():
        subprocess.run([str(LOCAL / "bin/openshell-gateway"), "generate-certs",
                        "--output-dir", str(tls), "--server-san", "127.0.0.1",
                        "--server-san", "localhost"], env=env, check=True,
                       capture_output=True, timeout=30)
    trust = LOCAL / "config/openshell/gateways" / GATEWAY / "mtls"
    trust.mkdir(mode=0o700, parents=True, exist_ok=True)
    for source, target in ((tls / "ca.crt", "ca.crt"),
                           (tls / "client/tls.crt", "tls.crt"),
                           (tls / "client/tls.key", "tls.key")):
        shutil.copyfile(source, trust / target)
        (trust / target).chmod(0o600)
    config = f'''[openshell]
version = 2
[openshell.gateway]
name = "{GATEWAY}"
bind_address = "127.0.0.1:{PORT}"
log_level = "info"
compute_driver = "openshell-kata"
[openshell.gateway.tls]
cert_path = "{tls / 'server/tls.crt'}"
key_path = "{tls / 'server/tls.key'}"
client_ca_path = "{tls / 'ca.crt'}"
[openshell.gateway.mtls_auth]
enabled = true
operator_enabled = false
[openshell.gateway.auth]
allow_unauthenticated_users = false
[openshell.gateway.gateway_jwt]
signing_key_path = "{tls / 'jwt/signing.pem'}"
public_key_path = "{tls / 'jwt/public.pem'}"
kid_path = "{tls / 'jwt/kid'}"
gateway_id = "openshell-kata-local"
ttl_secs = 900
[openshell.drivers.openshell-kata]
socket_path = "{LOCAL / 'driver.sock'}"
'''
    (LOCAL / "gateway.toml").write_text(config)
    cli("gateway", "add", f"https://127.0.0.1:{PORT}", "--local", "--name", GATEWAY)
    print("Local gateway PKI and registration ready")


if __name__ == "__main__":
    main()
