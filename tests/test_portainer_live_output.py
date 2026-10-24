"""Authentication is printed before a slow Portainer inventory completes."""

from __future__ import annotations

import threading
from dataclasses import replace

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.portainer.stage import build_portainer_plan, build_portainer_spec
from redposture_core.stage_runtime import AuditCommandRunner


def test_portainer_intro_and_pair_precede_slow_inventory():
    args = parse_args(["portainer", "-t", "http://localhost:9000", "-u", "admin", "-p", "secret", "--discover"])
    entered = threading.Event()
    release = threading.Event()
    lines = []
    errors = []

    def detect(ctx):
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "is_portainer": True,
                "status": "auth_required",
                "surface": "ui",
                "ui_product": "portainer",
                "credential_verification_status": "available",
                "ui": {"version": "2.39.7", "auth_required": True, "inventory": {}},
            },
            module="portainer",
            service="portainer",
        )

    def auth(ctx, prior):
        return AuditRecord.from_mapping(
            {
                **prior.to_dict(),
                "status": "valid_credentials",
                "credential_state": "valid",
                "provided_credentials_ok": True,
                "provided_username": "admin",
                "provided_password": "secret",
            },
            module="portainer",
            service="portainer",
        )

    def data(ctx, prior):
        entered.set()
        assert release.wait(3)
        return AuditRecord.from_mapping(
            {**prior.to_dict(), "portainer_metadata": {"password": "warehouse-test-secret-827341"}},
            module="portainer",
            service="portainer",
        )

    spec = replace(build_portainer_spec(args), detect=detect, auth=auth, data=data, lifecycle_state_factory=None)

    def scan():
        try:
            AuditCommandRunner(args=args, spec=spec, emit_line=lines.append).run_plan(build_portainer_plan(args))
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=scan)
    worker.start()
    try:
        assert entered.wait(2)
        assert len(lines) >= 2
        assert "Portainer" in lines[0] and lines[1].endswith("[+] admin:secret")
    finally:
        release.set()
        worker.join(4)
    assert not worker.is_alive() and not errors
    assert sum("admin:secret" in line for line in lines) == 1
    assert any("Discover Secrets" in line for line in lines)
