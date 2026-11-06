"""Full default catalogs survive mixed detection and multiple accepted users."""

import asyncio
import importlib
import threading
from collections import Counter
from dataclasses import replace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner
from redposture_core.targeting import ScanTargetSpec


@pytest.mark.parametrize("module", ["postgres", "kafka"])
@pytest.mark.parametrize("positive_percent", [0, 5, 50, 100])
def test_real_module_credential_catalog_is_complete_after_async_detection(module, positive_percent, tmp_path):
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    inputs = [f"198.18.0.{i + 1}:5432" for i in range(100)]
    source = tmp_path / "targets.txt"
    source.write_text("\n".join(inputs + inputs[::7]) + "\n")
    args = parse_args([module, "-t", str(source), "--defcreds", "--workers", "2", "--no-color"])
    if module == "postgres":
        # PostgreSQL's command entrypoint installs the catalog before plan
        # construction; exercise that same preparation without network hooks.
        args._audit_credential_runs = stage.sort_default_audit_credential_runs(
            stage.AuditCredentialRun(username=user, password=password, source="default")
            for user, password in stage.actions._POSTGRES_DEFAULT_CREDENTIALS
        )
    original = getattr(stage, f"build_{module}_plan")(args)
    credentials = original.credential_runs
    assert len(credentials) > 2
    calls = []
    lock = threading.Lock()
    main = threading.get_ident()

    def record(ctx):
        positive = int(ctx.host.rsplit(".", 1)[1]) % 100 < positive_percent
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module=module,
            service=module,
            status="auth_required" if positive else "not_service",
            auth_required=True if positive else None,
            extra={"is_" + module: positive},
        )

    def sync(ctx):
        pytest.fail("sync detection unexpectedly repeated")

    async def native(ctx, http):
        if int(ctx.host.rsplit(".", 1)[1]) % 7 == 0:
            await asyncio.sleep(0.001)
        return record(ctx)

    accepted = {credentials[0].label, credentials[-1].label}

    def auth(ctx, detected):
        with lock:
            calls.append((ctx.host, ctx.credential.label, threading.get_ident()))
        ok = ctx.credential.label in accepted
        return replace(
            detected,
            status="valid_credentials" if ok else "auth_required",
            extra={
                **detected.extra,
                "provided_credentials": True,
                "provided_credentials_ok": ok,
                "provided_username": ctx.credential.username,
                "provided_password": ctx.credential.password,
            },
        )

    spec = replace(
        getattr(stage, f"build_{module}_spec")(args),
        detect=sync,
        detect_async=native,
        async_detect_sync_hook=sync,
        auth=auth,
        capabilities=lambda ctx, r: r,
        data=lambda ctx, r: r,
        lifecycle_state_factory=None,
        lifecycle_state_close=None,
        rce_probe=None,
        render=lambda r: [],
        render_module=None,
    )
    targets = []
    for _, _, _, target in original.iter_target_specs():
        assert isinstance(target, ScanTargetSpec)
        targets.append(replace(target, surface_hint="backend"))
    assert original.target_count == len(targets) == 100
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None).run_plan(
        AuditCommandPlan(
            target_specs_by_port={5432: tuple(targets)}, workers=2, output_format="json", credential_runs=credentials
        )
    )
    expected = Counter(
        (t.host, c.label)
        for t in targets
        if int(t.host.rsplit(".", 1)[1]) % 100 < positive_percent
        for c in credentials
    )
    assert Counter((host, pair) for host, pair, _ in calls) == expected
    assert all(worker != main for _, _, worker in calls)
    positives = [row for row in result.records if row.get("is_" + module)]
    assert len(positives) == positive_percent
    for row in positives:
        attempts = row["attempted_credentials"]
        assert len(attempts) == len(credentials)
        assert len({(a["username"], a["password"]) for a in attempts}) == len(credentials)
        assert sum(a["status"] == "valid_credentials" for a in attempts) == 2
        assert not any(a.get("skipped") or a.get("status") == "skipped" for a in attempts)
