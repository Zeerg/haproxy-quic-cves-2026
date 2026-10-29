# Reproduction Evidence

Test date: 2026-10-27

Host architecture: Apple arm64 with Docker 29.2.1 through Colima.

## Targets

| Role | Image | Digest | Crypto build |
| --- | --- | --- | --- |
| Vulnerable | `haproxytech/haproxy-ubuntu:3.2.11` | `sha256:269ba21df24a31963ea7d01a774c881de3dff0f1663f3b2c28f58b13bfe34363` | AWS-LC 1.65.1, `USE_QUIC=1` |
| Fixed | `haproxytech/haproxy-ubuntu:3.2.12` | `sha256:8f1b9b64695390081372c1e5801bd1a1315a5862fcbe1212c626507e676bd197` | AWS-LC 1.65.1, `USE_QUIC=1` |

The exact HAProxy release archives are in `../vendor/`. Their SHA-256 values match HAProxy's published checksum files:

- 3.2.11: `1ded04101274ae686d11f55fb3874638e79bae4211e3e8caff95ef8b1b96a54b`
- 3.2.12: `310b424e60db2f3990206ca7c81293586842cb628e7dfad572c7146ae9e95a91`

The PoC helper image uses the multi-platform `python:3.12-slim` manifest at
`sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f`.

## CVE-2026-26080

`../lab/poc_cve_2026_26080.py` builds a validly protected QUIC v1 Initial packet. The decrypted payload is three PADDING frames followed by `0x40`. That final byte declares a two-byte frame-type varint, but no second byte exists inside the packet.

Observed on the official 3.2.11 image:

- The trace confirmed successful header protection removal and payload decryption.
- `qc_parse_frm()` repeatedly reported `PADDING` without input progress.
- The watchdog backtrace contained `qc_parse_frm` and `wdt_handler`.
- The worker aborted. The container exited with status 134.

The verifier gates this result on exit 134, at least 20 repeated `qc_parse_frm()` enter/leave pairs, and the master exit report.
The other trace details above are supplemental observations from the dated test run.

Observed on the official 3.2.12 image with the same PoC:

- The trace reported `malformed frame type`.
- HAProxy set transport error `0x7`, `FRAME_ENCODING_ERROR`.
- HAProxy sent `CONNECTION_CLOSE` and released the connection.
- The container remained running throughout the three-second control observation.

The verifier gates the fixed control on continued liveness and the `malformed frame type` rejection marker.

This is a confirmed remote denial of service against a QUIC listener. It is not a source-only or timeout-based result.

## CVE-2026-26081

`../lab/poc_cve_2026_26081.py` sends a 1200-byte QUIC Initial containing a one-byte NEW_TOKEN value. Token validation occurs before payload decryption.

Observed on the official AWS-LC-based 3.2.11 image:

- The trace reached `quic_token_check()`.
- The worker received SIGSEGV and exited with status 139.
- The master reported `Current worker ... exited with code 139 (Segmentation fault)`.
- The container exited with status 139.

The verifier gates this result on exit 139 plus `quic_token_check`, `Segmentation fault`, and the master exit report.

Observed on the official AWS-LC-based 3.2.12 image with the same PoC:

- The trace reported `invalid token length`.
- HAProxy rejected the token and sent Retry.
- The container remained running throughout the three-second control observation.

The verifier gates the fixed control on continued liveness and the `invalid token length` rejection marker.
The observed Retry is supplemental and is not part of the automated gate.

A self-built OpenSSL 3.0 compatibility build rejected the malformed token without crashing. The official AWS-LC image reproduced the vendor-described impact. The vulnerable behavior therefore depends on the crypto API and build, but it exists in an official production-style image.

This is a confirmed remote denial of service against affected QUIC builds. It is not a source-only result.

## Lab classification

Both PoCs are confirmed network-level reproducers. They are not unverified lab-only scaffolds.

The supplied configuration and verifier are intentionally lab-only. They bind inside isolated container network namespaces, and both PoCs are locked to loopback.

## Re-verification 2026-10-29

`lab/verify.py` re-run end to end on the same digest-pinned images; all four
gates held (vulnerable exits 134/139 with required markers; fixed stayed live
with `malformed frame type` and `invalid token length`).

A supplemental manual run against a fresh 3.2.11 container captured the full
kill chain for each packet: for CVE-2026-26081 the trace reached
`quic_token_check(): entering` immediately before `exited with code 139
(Segmentation fault)` and the master's `killing every processes with SIGTERM`;
for CVE-2026-26080 the worker logged 897,219 `qc_parse_frm()` enter/leave
events in one run before `exited with code 134 (Aborted)` and the same
master-side teardown. Both runs ended with the container exited and the
QUIC listener dead — a full-instance outage from one unauthenticated packet
each, not a per-connection failure.
