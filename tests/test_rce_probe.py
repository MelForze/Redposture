from __future__ import annotations

from types import SimpleNamespace

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.consul.actions import _detect_line as consul_detect
from redposture_core.modules.jenkins.render import _format_detect_record as jenkins_detect
from redposture_core.modules.jupyter.render import _format_detect_record as jupyter_detect
from redposture_core.modules.kafka.render import _format_detect_record as kafka_detect
from redposture_core.modules.nomad.render import _format_detect_record as nomad_detect
from redposture_core.modules.portainer.render import _format_detect_record as portainer_detect
from redposture_core.modules.rce_probe import probe_execution
from redposture_core.modules.registry.product_render import _format_detect_record as nexus_detect


def _context() -> SimpleNamespace:
    return SimpleNamespace(
        args=SimpleNamespace(execute=None, execute_timeout=12.0, execute_max_bytes=1024),
        host="127.0.0.1",
        port=1234,
        credential=SimpleNamespace(username="user", password="pass", token=None),
        target=None,
        lifecycle_state=SimpleNamespace(execution={"old": True}),
    )


def test_probe_requires_successful_exit_and_correlated_marker() -> None:
    ctx = _context()
    prior = AuditRecord(host=ctx.host, port=ctx.port, module="demo", service="demo", status="valid_credentials")
    observed: dict[str, object] = {}

    def execute(probe_ctx, _record, state):
        observed["command"] = probe_ctx.args.execute
        observed["timeout"] = probe_ctx.args.execute_timeout
        observed["state_cache"] = state.execution
        return {
            "execution": {
                "executed": True,
                "exit_code": 0,
                "stdout": probe_ctx.args.execute.removeprefix("echo ") + "\n",
                "status": "complete",
            }
        }

    result = probe_execution(ctx, prior, ctx.lifecycle_state, execute)

    assert result.extra["rce"] is True
    assert result.extra["rce_probe_performed"] is True
    assert str(observed["command"]).startswith("echo REDPOSTURE_RCE_")
    assert observed["timeout"] == 5.0
    assert observed["state_cache"] is None
    assert ctx.args.execute is None
    assert ctx.lifecycle_state.execution == {"old": True}


def test_probe_denial_is_false_but_transport_failure_is_unknown() -> None:
    ctx = _context()
    prior = AuditRecord(host=ctx.host, port=ctx.port, module="demo", service="demo", status="auth_required")

    denied = probe_execution(
        ctx,
        prior,
        ctx.lifecycle_state,
        lambda *_: {"execution": {"executed": False, "status": "unverified", "error": "HTTP 403"}},
    )
    timed_out = probe_execution(
        ctx,
        prior,
        ctx.lifecycle_state,
        lambda *_: {"execution": {"executed": False, "status": "timeout", "error": "request timed out"}},
    )

    assert denied.extra["rce"] is False
    assert timed_out.extra["rce"] is None


def test_known_disabled_execution_surface_is_false_without_sending_command() -> None:
    ctx = _context()
    prior = AuditRecord.from_mapping(
        {"host": ctx.host, "port": ctx.port, "status": "open_no_auth", "rce": False},
        module="consul",
        service="consul",
    )

    def unexpected(*_args):
        raise AssertionError("disabled Consul script checks must not execute a command")

    result = probe_execution(ctx, prior, ctx.lifecycle_state, unexpected)
    assert result.extra["rce"] is False
    assert result.extra["rce_probe_performed"] is False


def test_all_seven_execution_module_detection_lines_show_rce_boolean() -> None:
    base = {"host": "127.0.0.1", "port": 1234, "status": "open_no_auth", "rce": False}
    cases = (
        (consul_detect, {**base, "is_consul": True, "anonymous_scopes": {}, "version": "1.0"}),
        (jenkins_detect, {**base, "is_jenkins": True, "version": "2.0"}),
        (jupyter_detect, {**base, "is_jupyter": True, "version": "3.0"}),
        (kafka_detect, {**base, "is_kafka": True, "auth_required": False}),
        (nomad_detect, {**base, "is_nomad": True, "version": "1.0", "auth_required": False}),
        (
            portainer_detect,
            {**base, "is_portainer": True, "ui_product": "portainer", "ui": {"version": "2.0"}},
        ),
        (
            nexus_detect,
            {**base, "module": "nexus", "service": "nexus", "is_nexus": True, "nexus_info": {"version": "3.0"}},
        ),
    )

    for render, record in cases:
        line = render(record, "txt")
        assert "(rce:False)" in line, (render.__module__, line)


def test_all_seven_execute_modules_register_detection_probe() -> None:
    from redposture_core.modules.consul.stage import build_consul_spec
    from redposture_core.modules.jenkins.stage import build_jenkins_spec
    from redposture_core.modules.jupyter.stage import build_jupyter_spec
    from redposture_core.modules.kafka.stage import build_kafka_spec
    from redposture_core.modules.nexus.stage import build_nexus_spec
    from redposture_core.modules.nomad.stage import build_nomad_spec
    from redposture_core.modules.portainer.stage import build_portainer_spec

    builders = (
        ("consul", build_consul_spec),
        ("jenkins", build_jenkins_spec),
        ("jupyter", build_jupyter_spec),
        ("kafka", build_kafka_spec),
        ("nexus", build_nexus_spec),
        ("nomad", build_nomad_spec),
        ("portainer", build_portainer_spec),
    )
    for module, build in builders:
        args = parse_args([module, "-t", "127.0.0.1"])
        spec = build(args)
        assert callable(spec.rce_probe), module
