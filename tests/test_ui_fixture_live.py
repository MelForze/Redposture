"""Verify versioned UI fixtures, known data and honest unsupported discovery."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core import web_panels
from redposture_core.cli_args import parse_args
from redposture_core.clients.async_http_detect import AsyncDetectionHttp, AsyncHttpFallback
from redposture_core.stage_runtime import AuditCommandRunner
from redposture_core.targeting import ScanTargetSpec
from scripts.bootstrap_ui_lab import onboard_redisinsight, wait_api
from scripts.qa_owned_volumes import guarded_command

pytestmark = pytest.mark.skipif(os.environ.get("REDPOSTURE_REAL_QA") != "1", reason="serial real UI fixture QA")
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("product", ["mongo", "redis", "pgadmin"])
def test_standard_fixture_inventory_dump_and_discovery_status(
    tmp_path: Path, product: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = "rp-ui-fixture-" + uuid.uuid4().hex[:10]
    compose = [
        "docker",
        "compose",
        "-p",
        project,
        "-f",
        str(ROOT / "tests/fixtures/web_panels/docker-compose.yml"),
        "--profile",
        product,
    ]

    def run(command: list[str], *, timeout: int = 90, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=timeout)
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

    service, port, module, count = {
        "mongo": ("mongo-express", 8081, "mongodb", 4),
        "redis": ("redisinsight", 5540, "redis", 3),
        "pgadmin": ("pgadmin", 80, "postgres", 7),
    }[product]
    auth = ["-u", "qa@example.com", "-p", "admin-password-22"] if product == "pgadmin" else []
    flags = {
        "mongo": ["--database", "qa"],
        "redis": ["--show-keys"],
        "pgadmin": [
            "--pgadmin-server-password",
            "reader-pass-22",
            "--database",
            "qa",
            "--table",
            "public.known",
            "--show-columns",
        ],
    }[product]
    try:
        run(guarded_command([*compose, "up", "-d", "--pull", "never"], tmp_path), timeout=150)
        target = "http://" + run([*compose, "port", service, str(port)]).stdout.strip()
        wait_api(target, "/api/info" if product == "redis" else "/" if product == "mongo" else "/misc/ping")
        if product == "redis":
            onboard_redisinsight(target)
            assert onboard_redisinsight(target)  # Idempotent on the real API, not just mocks.

        parsed = urlsplit(target)
        assert parsed.hostname is not None and parsed.port is not None
        ctx = SimpleNamespace(
            host=parsed.hostname,
            port=parsed.port,
            args=SimpleNamespace(timeout=8, retries=0),
            target=ScanTargetSpec(host=parsed.hostname, explicit_port=parsed.port, scheme=parsed.scheme),
        )
        sync_proof = web_panels.detect_panel(module, ctx)

        async def native_proof() -> dict | None:
            monkeypatch.setattr(
                asyncio.get_running_loop(),
                "run_in_executor",
                lambda *args, **kwargs: pytest.fail("native panel detection used an executor"),
            )
            async with AsyncDetectionHttp(timeout=8, retries=0, max_bytes=128 * 1024) as http:
                return await web_panels.detect_panel_async(module, ctx, http)

        fallback_reason = None
        try:
            async_proof = asyncio.run(native_proof())
        except AsyncHttpFallback as exc:
            # pgAdmin's browser access check redirects to login. Native HTTP
            # deliberately delegates redirects to the original sync client.
            # Verify the real runtime boundary rather than treating the
            # unsupported transport shape as a negative product fingerprint.
            fallback_reason = str(exc)
            assert fallback_reason == "redirect or ambiguous framing"
            args = parse_args([module, "-t", target, "--timeout", "8", "--retries", "0"])
            stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
            runner = AuditCommandRunner(
                args=args, spec=getattr(stage, f"build_{module}_spec")(args), emit_line=lambda _: None
            )
            try:
                assert asyncio.run(runner._run_async_detect_with_state(ctx.host, ctx.port, ctx.target, None)) is None
                outcome = runner._run_detect_with_state(ctx.host, ctx.port, ctx.target, None)
                record = outcome.record.to_dict()
                assert sync_proof is not None
                async_proof = {key: record.get(key) for key in sync_proof}
            finally:
                runner._close_all_lifecycle_states()
        expected_product = {"mongo": "mongo_express", "redis": "redis_insight", "pgadmin": "pgadmin"}[product]
        assert sync_proof is not None and async_proof is not None
        for proof in (sync_proof, async_proof):
            assert proof["ui_product"] == expected_product and proof["detection_status"] == "confirmed", proof
        assert async_proof == sync_proof
        (tmp_path / "fingerprint-parity.json").write_text(
            json.dumps({"proof": async_proof, "sync_fallback_reason": fallback_reason}, ensure_ascii=False)
        )

        def audit(name: str, *action: str) -> dict:
            output = tmp_path / (name + ".json")
            result = run(
                [
                    sys.executable,
                    str(ROOT / "redposture.py"),
                    module,
                    "-t",
                    target,
                    *auth,
                    *flags,
                    *action,
                    "--timeout",
                    "8",
                    "--workers",
                    "2",
                    "--no-color",
                    "-f",
                    "json",
                    "-o",
                    str(output),
                ],
                timeout=180,
            )
            raw = output.read_text()
            assert "\x1b" not in raw + result.stdout
            value = json.loads(raw)
            return value[0] if isinstance(value, list) else value

        record = audit("dump", "--dump")
        assert record["surface"] == "ui", record
        exported = record["ui"]["inventory"]["export"]
        assert exported["partial"] is False and exported["count"] == count, exported
        path = Path(exported["path"])
        raw = (path if path.is_absolute() else tmp_path / path).read_text()
        assert "seeded-" in raw and "\x1b" not in raw
        assert len(raw.splitlines()) == len(set(raw.splitlines())) == count
        discover = audit("discover", "--discover")
        assert discover["ui"]["inventory"]["discover"]["status"] == "unsupported_by_ui", discover
        # Unsupported read paths must not masquerade as an empty successful scan.
        assert discover.get("content_discovery", {}).get("status") != "complete", discover
    finally:
        run([*compose, "logs", "--no-color", "--tail", "80"], check=False)
        run(guarded_command([*compose, "down", "--volumes", "--remove-orphans"], tmp_path))
