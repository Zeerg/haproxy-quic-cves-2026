# Isolated reproduction lab

## Scope

This lab compares official HAProxy 3.2.11 and 3.2.12 images for two QUIC
denial-of-service vulnerabilities. It sends one packet per control, waits for a
bounded observation period, checks exact evidence, and removes all target
containers.

The packet builders only send to `127.0.0.1`. The sender joins the target's
Docker network namespace, which has no external interface.

## Requirements

- Docker with Linux containers.
- Python 3.10 or later.
- Network access to pull the three digest-pinned base images and Python packages.

## Run

Run from the repository root:

```sh
python3 lab/verify.py
```

The verifier runs the vulnerable and fixed controls sequentially for each CVE.
It does not expose a QUIC port on the host.

## Evidence gates

| Case | Required evidence |
| --- | --- |
| CVE-2026-26080 vulnerable | Exit 134, at least 20 `qc_parse_frm()` enter events, at least 20 leave events, and the master exit report |
| CVE-2026-26080 fixed | Process remains live and logs `malformed frame type` |
| CVE-2026-26081 vulnerable | Exit 139 plus `quic_token_check`, `Segmentation fault`, and the master exit report |
| CVE-2026-26081 fixed | Process remains live and logs `invalid token length` |

A timeout, unrelated exit, missing marker, or cleanup failure fails the run.
See [`../docs/EVIDENCE.md`](../docs/EVIDENCE.md) for the dated observations.

## Topology

```text
PoC container
  `--network container:<fixed target name>`
                 |
                 | UDP 127.0.0.1:8443
                 v
HAProxy target container
  `--network none`
  no published ports
  bounded CPU, memory, and process count
```

## Files

| Path | Purpose |
| --- | --- |
| `verify.py` | Builds the sender, runs all four controls, checks evidence, and confirms cleanup |
| `poc_cve_2026_26080.py` | Builds and protects the truncated-frame-type QUIC Initial |
| `poc_cve_2026_26081.py` | Builds the short-token QUIC Initial |
| `haproxy.cfg` | Minimal QUIC listener with developer-level QUIC tracing |
| `start-haproxy-lab.sh` | Creates a one-day self-signed certificate and starts HAProxy |
| `Dockerfile.poc` | Builds the digest-pinned Python sender image |
| `Dockerfile.source` | Builds a selected vendored HAProxy release with OpenSSL QUIC compatibility |

## Local source builds

The local builds are secondary controls. The official AWS-LC images in
`verify.py` are authoritative for runtime comparison.

```sh
docker build -f lab/Dockerfile.source \
  --build-arg VERSION=3.2.11 \
  -t haproxy-quic-local:3.2.11 .

docker build -f lab/Dockerfile.source \
  --build-arg VERSION=3.2.12 \
  -t haproxy-quic-local:3.2.12 .
```

The Dockerfile verifies the selected source archive against its tracked
SHA-256 sidecar before extraction.

## Standalone packet options

Both packet builders accept `--port` and `--receive`. The token PoC also accepts
`--token-length` and `--sweep`. The destination address is fixed to loopback.

```sh
python3 lab/poc_cve_2026_26080.py --port 18443 --receive
python3 lab/poc_cve_2026_26081.py --port 18443 --token-length 1 --receive
```

These commands require a local authorized QUIC listener. The full verifier is
the supported release test.
