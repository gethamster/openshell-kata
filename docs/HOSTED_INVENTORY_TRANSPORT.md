# Hosted inventory transport

The publisher and courier run under separate service accounts. The publisher
observes Nodes, Services and configured DNS names, then updates one precreated
ConfigMap. The gateway's courier can only read that exact ConfigMap. Neither
process requires Secrets, TokenRequest, cloud credentials or ConfigMap creation.

The ConfigMap must have exactly one data key, `inventory.json`, and the annotation
`openshell-kata.io/inventory-run` must equal the configured run UUID. Its namespace,
name and UID are fixed in both configurations. Kubernetes admission must prevent
changing the run annotation and broadening the corresponding roles. The initial
data string may be empty; the courier rejects it until fresh observations arrive.

Run the publisher with:

```sh
kata-network-inventory publish --config /etc/openshell-kata/publisher.json
```

The publisher configuration is version one with these fields:

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `inventory_config_file` | Absolute path to the existing file-generator configuration |
| `namespace`, `name` | Exact precreated ConfigMap |
| `uid` | Observed ConfigMap UID |
| `run_uuid` | Canonical non-nil UUID matching the immutable annotation |

The source configuration retains the existing authentication, DNS, baseline,
refresh and private scratch-file contract. Each cycle makes fresh observations.
The publisher replaces the ConfigMap with its observed UID and resource version.
If a response is lost or uncertain, it makes one bounded GET and accepts success
only when the expected generation and canonical digest were committed under the
same UID and run. It does not blindly retry the write or extend the source expiry.

Run the courier with:

```sh
kata-network-inventory courier --config /etc/openshell-kata/courier.json
```

The courier configuration is version one with `kubectl_path`, `kubectl_sha256`,
`kubeconfig_path`, `namespace`, `name`, `uid`, `run_uuid`, `output_path`,
`poll_millis` and `api_timeout_secs`. Paths are absolute. Polling is between one
and 1000 milliseconds; each API operation times out within one to five seconds.
The explicit kubeconfig must use HTTPS, an explicit CA and a projected token file.
Exec helpers, inline credentials, proxy configuration and ambient environment are
rejected. Configurations and binaries must be trusted-owner regular files that
other users cannot modify.

The courier reads the API directly, rather than waiting for projected ConfigMap
updates. It accepts only fresh version-one inventories with at most 4096 CIDRs.
Generations cannot regress, and a generation cannot change its canonical digest.
Repeated reads never reset that generation's in-process monotonic deadline or
rewrite its timestamps. A private existing file retains the generation floor
across process restart. Failed API calls or malformed observations leave the
previous file untouched so its original expiry closes authority.

`output_path` should select a private child such as
`/run/openshell-kata-inventory/private/current.json`. The child directory is owned
by the process UID with mode `0700`; atomic output files use mode `0600`. The
gateway's `HostedNetworkConfig.inventory_file` must select that same file.
`--once` performs one bounded reconciliation and returns failure when it cannot
establish the required state. The original `--config PATH [--once]` file-generator
mode remains available.
