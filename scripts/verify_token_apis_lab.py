#!/usr/bin/env python3
"""Verify one running token API fixture; compose profiles run independently."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", choices=("vault", "nomad", "jupyter"))
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("--token", default=None)
    parser.add_argument("--token-file", type=Path, default=None)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    module = args.module
    port = {"vault": 28200, "nomad": 24646, "jupyter": 28888}[module]
    target = f"http://127.0.0.1:{port}"
    token = args.token or {"vault": "root", "jupyter": "qa-jupyter-token"}.get(module)
    if args.token_file:
        value = args.token_file.read_text().strip()
        try:
            payload = json.loads(value)
        except ValueError:
            payload = value
        token = payload.get("SecretID") if isinstance(payload, dict) else payload
    if token is None:
        parser.error("Nomad verification requires the fixture's bootstrap --token")
    inventory = {
        "vault": ["--show-mounts", "--show-auth"],
        "nomad": ["--show-jobs", "--show-nodes", "--show-members"],
        "jupyter": ["--show-contents", "--show-sessions", "--show-kernels"],
    }[module]

    def run(name: str, flags: list[str], *, address: str = target) -> dict:
        output = args.artifacts / (name + ".json")
        command = [
            sys.executable,
            str(ROOT / "redposture.py"),
            module,
            "-t",
            address,
            "--no-color",
            "--timeout",
            "3",
            "-f",
            "json",
            "-o",
            str(output),
            *flags,
        ]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=45)
        (args.artifacts / (name + ".log")).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, name
        assert "\x1b" not in output.read_text(), name
        value = json.loads(output.read_text())
        record = value[0] if isinstance(value, list) else value
        assert record.get("is_" + module), (name, record)

        def exposed(value: object) -> bool:
            if isinstance(value, dict):
                return any(exposed(v) for k, v in value.items() if k != "token_policies")
            if isinstance(value, list):
                return any(exposed(v) for v in value)
            return isinstance(value, str) and value == token

        assert not exposed(record), name
        return record

    anon = run("anonymous", [])
    assert anon.get("auth_required") is True, anon
    valid = run("valid-inventory", ["--token", token, *inventory, "--enum-cve"])
    assert valid.get("provided_credentials_ok") is True, valid
    invalid = run("invalid", ["--token", "qa-invalid-token"])
    assert invalid.get("provided_credentials_ok") is False, invalid
    discovery = run("discover", ["--token", token, "--discover"])
    assert discovery.get("content_discovery", {}).get("status") in {"complete", "partial"}, discovery
    if module != "nomad":
        assert discovery.get("content_discovery", {}).get("findings"), discovery
    # Real output uses the same command but TXT, without ANSI in stdout or file.
    txt = args.artifacts / "inventory.txt"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "redposture.py"),
            module,
            "-t",
            target,
            "--token",
            token,
            *inventory,
            "--no-color",
            "-o",
            str(txt),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0 and "\x1b" not in result.stdout + txt.read_text()
    assert result.stdout.index("token accepted" if module == "vault" else "Token accepted") < result.stdout.index(
        {"vault": "Secret Engines", "nomad": "Jobs Enumeration", "jupyter": "Contents Enumeration"}[module]
    )
    tokens = args.artifacts / "tokens.txt"
    tokens.write_text("qa-invalid-token\n" + token + "\n")
    spray_file = args.artifacts / "spray.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "redposture.py"),
            "spray",
            "-t",
            target,
            "--modules",
            module,
            "--tokens",
            str(tokens),
            "--account-interval",
            "0.01",
            "--origin-rate",
            "100",
            "--no-color",
            "-f",
            "json",
            "-o",
            str(spray_file),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=45,
    )
    (args.artifacts / "spray.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr
    sprayed = [json.loads(line) for line in spray_file.read_text().splitlines() if line.strip()]
    statuses = {row["status"] for row in sprayed}
    assert {"valid", "invalid"} <= statuses, sprayed
    if module != "vault":
        open_port = 24647 if module == "nomad" else 28889
        opened = run("open-server", [], address=f"http://127.0.0.1:{open_port}")
        assert opened.get("auth_required") is False and opened.get("rce_potential") is True, opened
        unverified = run("open-server-token", ["--token", "arbitrary"], address=f"http://127.0.0.1:{open_port}")
        assert unverified.get("provided_credentials_ok") is not True, unverified
    print(f"{module}: anonymous, valid/invalid token, inventory, discovery, TXT/JSON and spray passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
