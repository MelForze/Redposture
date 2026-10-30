"""Genuine PVE API/ACL/TLS controls; this fixture cannot validate VM/CT/kernel."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from scripts.qa_owned_volumes import guarded_command
from scripts.qa_tls_prefix_proxy import proxy

pytestmark = pytest.mark.skipif(os.environ.get("REDPOSTURE_REAL_QA") != "1", reason="serial real PVE API QA")
ROOT = Path(__file__).resolve().parents[1]


def _totp_code(secret: str, counter: int) -> str:
    digest = hmac.new(
        base64.b32decode(secret + "=" * ((-len(secret)) % 8)), counter.to_bytes(8, "big"), hashlib.sha1
    ).digest()
    offset = digest[-1] & 15
    return f"{(int.from_bytes(digest[offset : offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


def test_local_pve_api_roles_token_tls_and_discover(tmp_path: Path, mtls_material: dict[str, Path]) -> None:
    # Reuse the tested loopback TLS/prefix transport; the upstream is genuine PVE.
    project = "rp-pve-api-" + uuid.uuid4().hex[:10]
    password = "QA-pve-api-2026-only!"
    env = {**os.environ, "PVE_ROOT_PASSWORD": password}
    compose = ["docker", "compose", "-p", project, "-f", str(ROOT / "tests/fixtures/proxmox_api/docker-compose.yml")]

    def run(command: list[str], *, timeout: int = 180, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=timeout)
        with (tmp_path / "commands.log").open("a") as log:
            log.write(
                subprocess.list2cmdline(command)
                + "\n"
                + result.stdout
                + result.stderr
                + f"\nexit={result.returncode}\n"
            )
        if check:
            assert result.returncode == 0, result.stderr
        return result

    def execute(*command: str) -> str:
        return run([*compose, "exec", "-T", "proxmox", *command]).stdout

    try:
        run(
            guarded_command(
                [*compose, "up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "240"], tmp_path
            ),
            timeout=280,
        )
        target = "https://" + run([*compose, "port", "proxmox", "8006"]).stdout.strip()

        def audit(name: str, *flags: str, address: str = target) -> dict:
            output = tmp_path / (name + ".json")
            result = run(
                [
                    sys.executable,
                    str(ROOT / "redposture.py"),
                    "proxmox",
                    "-t",
                    address,
                    *flags,
                    "--timeout",
                    "12",
                    "--workers",
                    "2",
                    "--no-color",
                    "-f",
                    "json",
                    "-o",
                    str(output),
                ]
            )
            raw = output.read_text()
            assert "\x1b" not in raw + result.stdout
            value = json.loads(raw)
            return value[0] if isinstance(value, list) else value

        root = ("-u", "root@pam", "-p", password)
        detected = audit("detect")
        assert detected["is_proxmox"] is True, detected
        valid = audit("root-inventory", *root, "--nodes", "--users", "--enum-cve")
        assert valid["status"] == "token_ok" and "pve-lab" in valid["nodes"] and "root@pam" in valid["users"], valid
        wrong = audit("wrong-password", "-u", "root@pam", "-p", "wrong-qa-password")
        assert wrong["status"] == "auth_failed", wrong
        execute("pveum", "user", "add", "qa-reader@pve", "--password", "qa-reader-pass")
        limited = audit("no-acl", "-u", "qa-reader@pve", "-p", "qa-reader-pass", "--nodes", "--users")
        assert limited["auth_username"] == "qa-reader@pve" and limited["cap_modify"] is False, limited
        execute("pveum", "acl", "modify", "/", "--users", "qa-reader@pve", "--roles", "PVEAuditor")
        auditor = audit("auditor", "-u", "qa-reader@pve", "-p", "qa-reader-pass", "--nodes")
        assert "pve-lab" in auditor["nodes"] and auditor["cap_modify"] is False, auditor
        token = json.loads(
            execute("pveum", "user", "token", "add", "root@pam", "qa", "--privsep", "0", "--output-format", "json")
        )
        token_value = "root@pam!qa=" + token["value"]
        accepted = audit("valid-token", "--pveapitoken", token_value, "--nodes")
        assert accepted["status"] == "token_ok", accepted
        rejected = audit("invalid-token", "--pveapitoken", token_value + "wrong")
        assert rejected["status"] == "auth_failed", rejected
        with proxy(target, mtls_material) as base:
            proxied = audit("tls-prefix", *root, "--nodes", address=base)
            assert proxied["status"] == "token_ok" and "pve-lab" in proxied["nodes"], proxied
        execute(
            "sh",
            "-c",
            "printf 'name:qa-api-fixture\nmemory:128\ndescription: api_token=glpat-abcdefghijklmnopqrstuv\n' > /etc/pve/qemu-server/990001.conf",
        )
        discovery = audit("discover", *root, "--discover", "--discover-time", "60")
        assert "glpat-abcdefghijklmnopqrstuv" in json.dumps(discovery.get("findings")), discovery
        # Save the vendor's schema for a separately verifiable 2FA setup.
        execute("pvesh", "usage", "/access/tfa/qa-reader@pve", "-v")
        secret = base64.b32encode(os.urandom(20)).decode().rstrip("=")
        uri = f"otpauth://totp/RedpostureQA:qa-reader@pve?secret={secret}&issuer=RedpostureQA"
        # Generate the code at submit time and retry only if the 30-second
        # period changed while Docker/PVE processed the first request.
        for attempt in range(2):
            remaining = 30 - time.time() % 30
            if remaining < 5:
                time.sleep(remaining + 0.1)
            counter = int(time.time() // 30)
            try:
                execute(
                    "pvesh",
                    "create",
                    "/access/tfa/qa-reader@pve",
                    "--type",
                    "totp",
                    "--description",
                    "qa-local",
                    "--totp",
                    uri,
                    "--value",
                    _totp_code(secret, counter),
                )
                break
            except AssertionError:
                if attempt or int(time.time() // 30) == counter:
                    raise
        two_factor = audit("second-factor", "-u", "qa-reader@pve", "-p", "qa-reader-pass", "--nodes")
        assert two_factor.get("provided_credentials_ok") is not True, two_factor
        assert two_factor["status"] != "auth_failed" and "second factor required" in json.dumps(two_factor).lower(), (
            two_factor
        )
    finally:
        run([*compose, "logs", "--no-color", "--tail", "80"], check=False)
        run(guarded_command([*compose, "down", "--volumes", "--remove-orphans"], tmp_path))
