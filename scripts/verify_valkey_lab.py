"""Read-only scanner contracts against an already running real Valkey lab."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_extended_version_matrix import _record  # noqa: E402


def validate_valkey_record(record: dict[str, Any], *, version_known: bool, credentials: bool | None) -> None:
    assert record.get("is_redis") is True, "RESP product was not confirmed"
    if credentials is not None:
        assert record.get("provided_credentials_ok") is credentials, "credential result mismatch"
    enumeration = record.get("cve_enumeration")
    assert isinstance(enumeration, dict), "enumeration missing"
    if version_known:
        assert record.get("implementation") == "valkey", "Valkey misidentified as Redis"
        assert record.get("redis_version") is None, "Redis compatibility version must not replace Valkey version"
        assert record.get("valkey_version") == record.get("server_version")
        assert len(enumeration.get("products", [])) == 1
        assert enumeration["products"][0]["product_key"] == "valkey"
        assert enumeration["status"] in {"matched", "no_matches"}
    else:
        assert record.get("server_version") is None
        assert enumeration["status"] == "version_unknown"
        assert not enumeration.get("findings"), "unknown version produced a CVE"
    assert all(item["product"] == "valkey" for item in enumeration.get("findings", [])), "Redis CVE leakage"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--project", default="redposture-versions-valkey")
    args = parser.parse_args()
    output = args.artifact_dir / "valkey-contracts"
    output.mkdir(parents=True)
    compose = ["docker", "compose", "-p", args.project, "-f", str(ROOT / "lab/services/valkey/docker-compose.yml")]
    for service, password in (("valkey-open", None), ("valkey-auth", "ValkeyAdmin!2026")):
        command = [*compose, "exec", "-T", service, "valkey-cli"]
        if password:
            command += ["-a", password]
        seeded = subprocess.run(
            [
                *command,
                "MSET",
                "redposture:password",
                "ValkeyFixtureSecret!2026",
                "redposture:api_key",
                "vk-fixture-api-key",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        assert seeded.stdout.strip() == "OK", "seed did not reach the real server"
    cases = [
        ("anonymous", 16379, [], True, None),
        ("auth-required", 16380, [], False, None),
        ("valid", 16380, ["-u", "default", "-p", "ValkeyAdmin!2026"], True, True),
        ("invalid", 16380, ["-u", "default", "-p", "incorrect"], False, False),
        ("observer", 16380, ["-u", "observer", "-p", "V13w-Only!2026"], True, True),
        ("no-info", 16380, ["-u", "noinfo", "-p", "N0-Info!2026"], False, True),
        ("defcreds", 16380, ["--defcreds"], False, None),
        ("tls-insecure", 16381, ["--tls", "--insecure", "-u", "default", "-p", "ValkeyAdmin!2026"], True, True),
        (
            "tls-ca",
            16381,
            [
                "--tls",
                "--tls-ca",
                str(ROOT / "lab/services/valkey/certs/server.crt"),
                "-u",
                "default",
                "-p",
                "ValkeyAdmin!2026",
            ],
            True,
            True,
        ),
        ("keys", 16380, ["-u", "observer", "-p", "V13w-Only!2026", "--show-keys", "10", "--dump", "10"], True, True),
    ]
    results = []
    for name, port, extra, known, credentials in cases:
        command = [
            sys.executable,
            str(ROOT / "redposture.py"),
            "redis",
            "-t",
            f"127.0.0.1:{port}",
            *extra,
            "--enum-cve",
        ]
        json_command = [*command, "--format", "json"]
        (output / f"{name}.command.txt").write_text(shlex.join(json_command) + "\n", encoding="utf-8")
        result = subprocess.run(json_command, capture_output=True, text=True, check=True, timeout=90)
        (output / f"{name}.jsonl").write_text(result.stdout + result.stderr, encoding="utf-8")
        record = _record(result.stdout)
        validate_valkey_record(record, version_known=known, credentials=credentials)
        if name == "keys":
            assert set(record.get("keys") or []) == {"redposture:password", "redposture:api_key"}
            assert "ValkeyFixtureSecret!2026" in json.dumps(record.get("key_values"))
        for mode, options in (("txt", []), ("debug", ["--debug"])):
            tsv = output / f"{name}-{mode}.tsv"
            txt_command = [*command, *options, "--no-color", "-o", str(tsv)]
            (output / f"{name}-{mode}.command.txt").write_text(shlex.join(txt_command) + "\n", encoding="utf-8")
            result = subprocess.run(
                txt_command,
                capture_output=True,
                text=True,
                check=True,
                timeout=90,
            )
            (output / f"{name}-{mode}.log").write_text(result.stdout + result.stderr, encoding="utf-8")
            assert "\x1b" not in tsv.read_text(), "ANSI leaked into TSV"
            assert all(len(line.split("\t")) == 4 for line in tsv.read_text().splitlines()), "invalid TSV fields"
            assert "CVE's Enumeration" not in result.stdout or "potentially affected" in result.stdout
        results.append(
            {
                "case": name,
                "status": "passed",
                "version": record.get("server_version"),
                "cve_status": record["cve_enumeration"]["status"],
            }
        )
        print(f"[passed] Valkey {name}", flush=True)
    (output / "report.json").write_text(json.dumps({"results": results}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
