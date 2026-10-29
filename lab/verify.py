#!/usr/bin/env python3
"""Run vulnerable and fixed controls for both HAProxy QUIC CVEs."""

import json
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
CONFIG = ROOT / "haproxy.cfg"
ENTRYPOINT = ROOT / "start-haproxy-lab.sh"
POC_IMAGE = "haproxy-quic-poc:2026"
VULNERABLE_IMAGE = (
    "haproxytech/haproxy-ubuntu@"
    "sha256:269ba21df24a31963ea7d01a774c881de3dff0f1663f3b2c28f58b13bfe34363"
)
FIXED_IMAGE = (
    "haproxytech/haproxy-ubuntu@"
    "sha256:8f1b9b64695390081372c1e5801bd1a1315a5862fcbe1212c626507e676bd197"
)
COMMAND_TIMEOUT_SECONDS = 300


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        text=True,
        capture_output=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )


def remove(name: str) -> None:
    run("docker", "rm", "--force", name, check=False)


def start(name: str, image: str, version: str) -> None:
    remove(name)
    run(
        "docker",
        "run",
        "--detach",
        "--name",
        name,
        "--network",
        "none",
        "--cpus",
        "1",
        "--memory",
        "256m",
        "--pids-limit",
        "128",
        "--volume",
        f"{CONFIG}:/etc/haproxy.cfg:ro",
        "--volume",
        f"{ENTRYPOINT}:/usr/local/bin/start-haproxy-lab:ro",
        image,
        "sh",
        "/usr/local/bin/start-haproxy-lab",
    )
    time.sleep(1)
    state = inspect(name)
    if not state["Running"]:
        raise RuntimeError(f"{name} did not start: {logs(name, 80)}")
    version_output = run("docker", "exec", name, "haproxy", "-v").stdout
    if f"HAProxy version {version}-" not in version_output:
        raise RuntimeError(f"{name} did not report HAProxy {version}")


def inspect(name: str) -> dict:
    output = run("docker", "inspect", "--format", "{{json .State}}", name).stdout
    return json.loads(output)


def logs(name: str, lines: int) -> str:
    result = run("docker", "logs", "--tail", str(lines), name)
    return result.stdout + result.stderr


def send(name: str, script: str) -> None:
    run(
        "docker",
        "run",
        "--rm",
        "--network",
        f"container:{name}",
        "--cpus",
        "1",
        "--memory",
        "128m",
        "--pids-limit",
        "64",
        POC_IMAGE,
        "python",
        f"/lab/{script}",
        "--port",
        "8443",
    )


def verify_case(
    cve: str,
    script: str,
    vulnerable_exit: int,
    vulnerable_markers: tuple[tuple[str, int], ...],
    fixed_marker: str,
) -> None:
    vulnerable = f"haproxy-{cve}-vulnerable"
    fixed = f"haproxy-{cve}-fixed"

    try:
        start(vulnerable, VULNERABLE_IMAGE, "3.2.11")
        send(vulnerable, script)
        time.sleep(3)
        vulnerable_state = inspect(vulnerable)
        vulnerable_logs = logs(vulnerable, 120)
        if vulnerable_state["Running"] or vulnerable_state["ExitCode"] != vulnerable_exit:
            raise AssertionError(
                f"{cve}: expected vulnerable exit {vulnerable_exit}, got {vulnerable_state}"
            )
        for marker, minimum_count in vulnerable_markers:
            marker_count = vulnerable_logs.count(marker)
            if marker_count < minimum_count:
                raise AssertionError(
                    f"{cve}: vulnerable log marker {marker!r} appeared "
                    f"{marker_count} times; expected at least {minimum_count}"
                )

        start(fixed, FIXED_IMAGE, "3.2.12")
        send(fixed, script)
        time.sleep(3)
        fixed_state = inspect(fixed)
        fixed_logs = logs(fixed, 120)
        if not fixed_state["Running"]:
            raise AssertionError(f"{cve}: fixed target terminated with {fixed_state['ExitCode']}")
        if fixed_marker not in fixed_logs:
            raise AssertionError(f"{cve}: expected fixed rejection marker was absent")

        print(
            f"{cve}: vulnerable exit={vulnerable_state['ExitCode']}; "
            f"fixed status={fixed_state['Status']}; control marker={fixed_marker!r}"
        )
    finally:
        remove(vulnerable)
        remove(fixed)
        for name in (vulnerable, fixed):
            if run("docker", "inspect", name, check=False).returncode == 0:
                raise RuntimeError(f"cleanup failed for {name}")


def main() -> None:
    run("docker", "pull", VULNERABLE_IMAGE)
    run("docker", "pull", FIXED_IMAGE)
    run(
        "docker",
        "build",
        "--file",
        str(ROOT / "Dockerfile.poc"),
        "--tag",
        POC_IMAGE,
        str(REPO_ROOT),
    )

    verify_case(
        "cve-2026-26080",
        "poc_cve_2026_26080.py",
        134,
        (
            ("qc_parse_frm(): entering", 20),
            ("qc_parse_frm(): leaving", 20),
            ("exited with code 134", 1),
        ),
        "malformed frame type",
    )
    verify_case(
        "cve-2026-26081",
        "poc_cve_2026_26081.py",
        139,
        (
            ("quic_token_check", 1),
            ("Segmentation fault", 1),
            ("exited with code 139", 1),
        ),
        "invalid token length",
    )


if __name__ == "__main__":
    main()
