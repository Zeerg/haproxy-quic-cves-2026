# HAProxy QUIC denial-of-service research

Reproducible network PoCs, vulnerable and fixed controls, and CodeQL queries for
CVE-2026-26080 and CVE-2026-26081.

Both issues were reproduced against the official AWS-LC-based
`haproxytech/haproxy-ubuntu:3.2.11` image. HAProxy 3.2.12 rejected the same
packets and remained available.

> **Scope:** both vulnerabilities require a configured QUIC listener. They
> affect availability, not confidentiality or integrity. This repository tests
> one exact vulnerable image and one fixed image. It does not claim that every
> crypto build has identical crash behavior. The PoCs are locked to loopback
> and the verifier runs them inside isolated container network namespaces.

## Findings

| CVE | Defect | HAProxy 3.2.11 | HAProxy 3.2.12 |
| --- | --- | --- | --- |
| CVE-2026-26080 | Ignored failure while decoding a truncated QUIC frame-type varint | Repeated parser loop; watchdog abort; exit 134 | `malformed frame type`; connection rejected; process remains live |
| CVE-2026-26081 | Unsigned length underflow while validating a short NEW_TOKEN | AWS-LC path reaches `quic_token_check()`; SIGSEGV; exit 139 | `invalid token length`; Retry path; process remains live |

## Mechanism

### CVE-2026-26080: truncated frame-type varint

HAProxy 3.2.11 calls `quic_dec_int()` for a frame type without checking its
0/1 result. A payload that ends with `0x40` declares a two-byte QUIC varint but
provides no second byte. Decode failure leaves the input position unchanged.
The packet loop calls `qc_parse_frm()` repeatedly until the watchdog aborts the
worker.

HAProxy 3.2.12 checks the return value, reports `malformed frame type`, and sets
`FRAME_ENCODING_ERROR`.

### CVE-2026-26081: short token length

HAProxy 3.2.11 accepts a non-empty NEW_TOKEN before it proves the exact token
length. `quic_token_check()` then subtracts fixed random and format lengths from
the attacker-supplied length. A one-byte token underflows those calculations.
The official AWS-LC build crashes in token validation.

HAProxy 3.2.12 requires `tokenlen == QUIC_TOKEN_LEN` before the pointer and
length arithmetic.

## Confirmed reproduction

Tested on October 27, 2026 on Apple arm64 with Docker 29.2.1 through Colima.
The verifier uses digest-pinned official HAProxy images and a digest-pinned PoC
base image.

```sh
python3 lab/verify.py
```

Expected summary:

```text
cve-2026-26080: vulnerable exit=134; fixed status=running; control marker='malformed frame type'
cve-2026-26081: vulnerable exit=139; fixed status=running; control marker='invalid token length'
```

The verifier does not classify results from exit status alone. It also requires
path-specific vulnerable markers, fixed-version liveness, and fixed rejection
markers. It removes each target and confirms cleanup before continuing.

See [`docs/EVIDENCE.md`](docs/EVIDENCE.md) for exact digests, checksums,
evidence gates, and observed behavior.

## Layout

| Path | Purpose |
| --- | --- |
| `lab/` | Isolated runtime verifier, packet builders, HAProxy configuration, and Dockerfiles |
| `lab/README.md` | Lab topology, commands, evidence gates, and source-build instructions |
| `codeql/` | Generalized C/C++ review queries and synthetic tests |
| `docs/EVIDENCE.md` | Dated runtime evidence and exact artifact identities |
| `vendor/` | Unmodified HAProxy 3.2.11 and 3.2.12 source archives, checksums, and license notes |
| `AGENTS.md` | Scope, safety, evidence, and validation guidance for automated analysis |

## Safety model

- The PoCs send only to `127.0.0.1`.
- Each target uses Docker `--network none`; the sender joins that exact network namespace.
- No container port is published to the host.
- CPU, memory, process counts, and Docker command duration are bounded.
- The verifier uses fixed container names, fixed image digests, and fixed scripts.
- Cleanup runs in `finally` blocks and confirms that target containers are absent.

The PoCs terminate vulnerable HAProxy workers. Use this repository only for
authorized research in the supplied local lab.

## CodeQL research

The query pack models two related C/C++ review patterns:

- Ignored 0/1 failure results from functions that can update indirect output.
- Range-unproven subtraction that reaches a size argument or pointer offset.

These are medium-precision review queries, not CVE signatures. Treat each
result as a request for contract and range analysis. See
[`codeql/README.md`](codeql/README.md) for test and analysis commands.

## Limits

- CVE-2026-26081 reproduced on the official AWS-LC image but not on the local
  OpenSSL 3.0 compatibility build.
- The repository proves remote denial of service against the tested QUIC
  listener configurations. It does not test other security impacts.
- The repository does not include Internet scanning, target discovery, or a
  caller-controlled remote destination.
- Supplemental trace observations in `docs/EVIDENCE.md` are labeled separately
  from the automated release gates.

## Primary references

- [HAProxy Technologies security advisory](https://www.haproxy.com/blog/cves-2026-quic-denial-of-service)
- [HAProxy 3.3.3 release announcement](https://www.mail-archive.com/haproxy@formilux.org/msg46589.html)
- [HAProxy 3.2 source releases](https://www.haproxy.org/download/3.2/src/)

## Acknowledgments

Shoutout to [TurenOS](https://turen.io/turenos) and
[Daybreak Blue](https://openai.com/daybreak/) for supporting the research,
review, and validation workflow behind this project.

## License

The original lab and query files are available under the MIT License. See
[`LICENSE`](LICENSE). The HAProxy source archives in `vendor/` retain their
upstream licenses. See [`vendor/README.md`](vendor/README.md).
