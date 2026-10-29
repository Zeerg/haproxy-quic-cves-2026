# Agent Guide

## Purpose

This repository documents and reproduces two HAProxy QUIC denial-of-service
vulnerabilities. Use it for authorized security research, controlled release
comparison, and static-analysis development.

## What This Is

- An isolated network-level reproduction for CVE-2026-26080 and CVE-2026-26081.
- A vulnerable HAProxy 3.2.11 versus fixed 3.2.12 comparison.
- A pair of generalized CodeQL C/C++ review queries with synthetic tests.
- A record of exact image digests, source checksums, and observed evidence.

## What This Is Not

- It is not a scanner or target-discovery tool.
- It is not a general remote exploit framework.
- It does not prove confidentiality, integrity, or code-execution impact.
- It does not prove identical CVE-2026-26081 behavior across all crypto builds.
- It does not classify a timeout or unrelated process exit as reproduction.

## Repository Map

| Path | Purpose |
| --- | --- |
| `README.md` | Main findings, mechanism, tested results, scope, and limits |
| `lab/` | Runtime verifier, PoCs, configuration, startup script, and Dockerfiles |
| `lab/README.md` | Lab topology, evidence gates, commands, and file guide |
| `codeql/` | Generalized queries, locks, tests, and query documentation |
| `docs/EVIDENCE.md` | Dated runtime evidence and exact artifact identities |
| `vendor/` | Unmodified HAProxy release archives, checksums, and license notes |

## Safety Rules

- Keep both PoCs locked to `127.0.0.1`.
- Keep target containers on `--network none`.
- Do not publish container ports to the host.
- Do not add caller-controlled hosts, addresses, image names, scripts, or container names.
- Keep CPU, memory, process counts, requests, and command duration bounded.
- Keep vulnerable and fixed runs sequential.
- Always run cleanup and confirm that each target container is absent.
- Limit testing to availability and parser behavior.

## Evidence Rules

Do not classify a result from exit status alone.

| Case | Required evidence |
| --- | --- |
| CVE-2026-26080 vulnerable | Exit 134, repeated parser enter/leave events, and the master exit report |
| CVE-2026-26080 fixed | Live process and `malformed frame type` |
| CVE-2026-26081 vulnerable | Exit 139, `quic_token_check`, `Segmentation fault`, and the master exit report |
| CVE-2026-26081 fixed | Live process and `invalid token length` |

Treat missing markers, response differences, timeouts, unrelated exits, and
cleanup failures as failed or inconclusive runs.

## Change Rules

- Keep `README.md`, `lab/README.md`, and `docs/EVIDENCE.md` synchronized with behavior changes.
- Preserve official image digests and exact HAProxy version checks.
- Preserve SHA-256 verification before extracting vendored source.
- Keep supplemental trace observations separate from automated evidence gates.
- Keep the OpenSSL compatibility result separate from the official AWS-LC result.
- Do not overstate CodeQL findings as confirmed vulnerabilities.
- Keep the query logic independent of HAProxy function names and protocol names.
- Preserve upstream licensing for files and archives under `vendor/`.

## Validation

Run the public entry point after runtime changes:

```sh
python3 lab/verify.py
```

Run syntax and shell checks after changing lab scripts:

```sh
python3 -m py_compile \
  lab/verify.py \
  lab/poc_cve_2026_26080.py \
  lab/poc_cve_2026_26081.py
shellcheck lab/start-haproxy-lab.sh
git diff --check
```

Run the CodeQL suite after query, metadata, lock, or test changes:

```sh
codeql pack install codeql
codeql pack install --additional-packs=codeql codeql/tests
codeql test run --additional-packs=codeql codeql/tests
```

Validate both documented source builds after Dockerfile or archive changes:

```sh
docker build -f lab/Dockerfile.source --build-arg VERSION=3.2.11 -t haproxy-quic-local:3.2.11 .
docker build -f lab/Dockerfile.source --build-arg VERSION=3.2.12 -t haproxy-quic-local:3.2.12 .
```

After Docker tests, confirm that no target container remains:

```sh
docker ps -a --filter name=haproxy-cve-2026-
```
