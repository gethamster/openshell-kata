# Read-only node fence proof service

The privileged node guard runs in `kata-system`, separate from the restricted
`openshell-network` broker namespace. The adapter must not receive `pods/exec`
permission in the guard namespace. It reads the actual guard Pod and Node
identity through the Kubernetes API, then requests evidence over mTLS.

The guard Pod contains the two explicitly admitted containers `node-intent` and
`proof-server`, both using the pinned guard image. The collector alone receives
the projected read-only Kubernetes service-account credential. The proof server
receives its own node leaf key, public trust roots and client fingerprint list.
Automatic token mounting is disabled, and no process supervisor is required.

The only RPC is
`openshell_kata.guard.v1.NodeFenceProof/Verify`. Its request contains canonical
non-nil UUID strings `pod_uid` and `nonce`. Its response contains a bounded
`HostedFenceResponse` JSON value. The server performs the same live namespace,
interface, pinned TCX link and program readback as the local guard verifier.
It does not accept commands, filesystem paths, mutations or installation requests.
Reading an old proof file alone does not satisfy this RPC.

## Server configuration

Run the immutable guard image with a Downward API `POD_IP` environment value:

```text
kata-runtime-guard serve --config /etc/openshell-kata/proof-server.json --bind $(POD_IP):9443
```

Kubernetes expands the argument directly; no shell or JSON rewriting is needed.
The bind address must be a specific private IPv4 address on port 9443. The
configuration may instead supply `bind`; an explicit command argument overrides
it. An absent address fails closed, and there is no wildcard-listener fallback.

```json
{
  "version": 1,
  "certificate_file": "/run/guard-tls/private/server.crt",
  "private_key_file": "/run/guard-tls/private/server.key",
  "client_ca_file": "/run/guard-tls/private/client-ca.crt",
  "allowed_client_certificate_sha256": ["<SHA-256 of the authorized client leaf certificate DER>"]
}
```

All files must be bounded regular files owned by root or the running operator
UID, without group or other write permission. Private keys must have no group
or other permissions. Use private owned copies when a projected Secret's final
entries are symlinks. Do not mount a CA signing key in the guard Pod.

The server requires a valid client chain under its dedicated client CA **and**
an exact allowed client leaf fingerprint. Fingerprints use lowercase hexadecimal
SHA-256 of DER certificate bytes, not PEM text. At most sixteen fingerprints are
accepted. Updating the authorization set requires restarting the server with
the reviewed configuration.

The existing fixed `/etc/openshell-kata/runtime-guard.json` must also validate
before the listener starts. It pins the node UID, official shim, BPF object and
trusted local tools. The proof service has at most sixteen host verifications
in flight. A disconnected or timed-out request retains its capacity reservation
until the underlying host readback finishes.

## Adapter configuration

The client configuration is separate from the network operator profile so that
the node observer need not receive gateway private credentials:

```json
{
  "version": 1,
  "server_ca_file": "/run/guard-client/private/server-ca.crt",
  "certificate_file": "/run/guard-client/private/client.crt",
  "private_key_file": "/run/guard-client/private/client.key"
}
```

The adapter connects to the observed guard Pod IP on port 9443. It verifies the
fixed server role name `runtime-guard.kata-system.internal`. The operator issues
that exact SAN, without a wildcard. The client exposes no arbitrary server-name
or system-trust-root override. This is a TLS identity,
and no DNS record is required.
The client supplies only its dedicated identity and CA; it does not discover
ambient cloud credentials, system CAs or authentication plugins.

The deployment operator issues the dedicated guard service-role leaf and mounts
its key only in proof-server Pods. Keep its CA signing key outside those Pods.
The shared role certificate does not cryptographically identify an individual
node. The trust model treats node and host root as trusted outside the guest VM
boundary; exact node identity comes from the independently observed Kubernetes
Node/Pod binding and the live host proof. New nodes therefore need no separate
leaf issuance or online issuer.

The adapter checks the response challenge, Pod UID, Node UID, original expiry
and complete launch binding, and rechecks the guard Pod generation and Node
boot identity through the Kubernetes API. Request messages are limited to
512 bytes, proof JSON to 64 KiB, and the client operation to ten seconds.
There is no fallback to privileged Pod execution.
