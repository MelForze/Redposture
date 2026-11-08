"""Completion follows all debug locations; normal reports keep one value line."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.discovery_rendering import format_discovery_finding_line
from redposture_core.discovery_spool import SpoolingFindings
from redposture_core.discovery_values import DiskBackedText
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditRecord, ModuleAuditSpec


def run_report(tmp_path, *, module, disk, live, debug, output_format="txt", secret=None, sources=False):
    secret = secret or "inactive-order-password" + ("Ab0_" * 20000 if disk else "")
    value = DiskBackedText()
    value.append_text(secret)
    value.finish()
    value_or_text = value if disk else secret
    finding = {
        "type": "password",
        "secret_type": "password",
        "value": value_or_text,
        "confidence": "high",
        "score": 85,
        "fingerprint": hashlib.sha256(secret.encode()).hexdigest(),
        "occurrence_count": 3,
        "object_path": "$.password",
        "locations": [{"object": f"config/{i}", "path": "/password"} for i in range(3)],
    }
    findings = [finding]
    if disk:
        findings = SpoolingFindings()
        findings.add(finding)

    def detect(ctx):
        return AuditRecord(host=ctx.host, port=ctx.port, module=module, service=module, status="open_no_auth")

    def data(ctx, record):
        emitted = live and callable(ctx.live_emit)
        if emitted:
            if disk:
                ctx.live_discovery_value(
                    module.upper(), ctx.host, ctx.port, finding_type="password", value=value, place="$.password"
                )
                assert isinstance(findings, SpoolingFindings)
                findings.mark_emitted("password", finding["fingerprint"])
            else:
                ctx.live_emit(
                    [
                        format_discovery_finding_line(
                            module.upper(),
                            ctx.host,
                            ctx.port,
                            severity="high",
                            finding_type="password",
                            value=secret,
                            place="$.password",
                        )
                    ]
                )
        if isinstance(findings, SpoolingFindings):
            findings.finish()
        extra: dict[str, Any] = {
            "_discover_findings_streamed": bool(emitted),
            "_elastic_disk_live_emitted": bool(emitted and disk),
        }
        if module == "elastic":
            extra["discover_findings"] = findings
        elif module == "minio":
            extra["secret_findings"] = findings
        else:
            extra["content_discovery"] = {"status": "complete", "findings": findings, "live_emitted": bool(emitted)}
        if sources:
            rows = [
                {
                    "id": module + ".files",
                    "implemented": True,
                    "requested": 2,
                    "read": 1,
                    "denied": 1,
                    "unsupported": False,
                    "complete": False,
                }
            ]
            if "content_discovery" in extra:
                extra["content_discovery"]["sources"] = rows
            else:
                extra["discover_sources"] = rows
        return AuditRecord.from_mapping({**record.to_dict(), **extra}, module=module)

    def render(record):
        lines = [f"{module.upper()}\tqa\t80\t [*] Service"]
        if module == "gitlab":
            return lines  # Common-module discovery is appended by the runtime.
        if not any(key in record.extra for key in ("discover_findings", "secret_findings", "content_discovery")):
            return lines
        if not record.extra.get("_discover_findings_streamed") and not disk:
            lines.append(
                format_discovery_finding_line(
                    module.upper(), "qa", 80, severity="high", finding_type="password", value=secret, place="$.password"
                )
            )
        label = "Discover Complete" if module == "elastic" else "Discover Secrets"
        lines.append(f"{module.upper()}\tqa\t80\t [*] {label} (status:complete) (findings:1)")
        return lines

    path = tmp_path / ("report.json" if output_format == "json" else "report.txt")
    spec = ModuleAuditSpec(
        module=module,
        label=module.upper(),
        default_port=80,
        detect=detect,
        data=data,
        render=render,
        is_detected=lambda _record: True,
    )
    runner = AuditCommandRunner(
        args=SimpleNamespace(discover=live, debug=debug, no_color=True), spec=spec, emit_line=print
    )
    result = runner.run_plan(
        AuditCommandPlan(targets_by_port={80: ("qa",)}, output_path=str(path), output_format=output_format, workers=1)
    )
    return path.read_text(), secret, result


@pytest.mark.parametrize("module", ["gitlab", "minio", "elastic"])
@pytest.mark.parametrize("debug", [False, True])
def test_source_evidence_is_debug_only_before_final_summary(tmp_path, capsys, module, debug):
    saved, secret, _ = run_report(tmp_path, module=module, disk=False, live=True, debug=debug, sources=True)
    terminal = capsys.readouterr().out
    for text in (saved, terminal):
        assert text.count("[debug] Discover Source") == int(debug)
        if debug:
            assert text.index("[debug] Discover Source") < max(
                text.rfind("Discover Complete"), text.rfind("Discover Secrets")
            )
            for field in (
                "implemented:True",
                "requested:2",
                "read:1",
                "denied:1",
                "unsupported:False",
                "complete:False",
            ):
                assert field in text
        assert "\x1b" not in text and "object at 0x" not in text


def test_source_debug_colors_follow_shared_palette():
    from redposture_core.discovery_rendering import discovery_color_spans

    payload = "[debug] Discover Source (requested:2) (read:0) (denied:1) (complete:False)"
    spans = {payload[start:end]: color for start, end, color in discovery_color_spans("*", payload)}
    assert spans["[debug] Discover Source"] == "white"
    assert spans["(requested:2)"] == "true_red"
    assert spans["(read:0)"] == spans["(denied:1)"] == "bright_green"
    assert spans["(complete:False)"] == "orange"


@pytest.mark.parametrize(
    "module,disk", [("elastic", False), ("elastic", True), ("gitlab", False), ("gitlab", True), ("minio", False)]
)
@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize("debug", [False, True])
def test_locations_are_debug_only_and_completion_is_last(tmp_path, capsys, module, disk, live, debug):
    saved, secret, result = run_report(tmp_path, module=module, disk=disk, live=live, debug=debug)
    terminal = capsys.readouterr().out
    for output in [saved, terminal]:
        lines = [line for line in output.splitlines() if line.startswith(module.upper())]
        assert "(status:complete)" in lines[-1] and "(findings:1)" in lines[-1], lines[-4:]
        assert sum("(status:complete)" in line for line in lines) == 1
        assert output.count(secret) == 1
        assert output.count("ValueSHA256=") == (3 if debug else 0)
        assert "\x1b" not in output
    if not live:
        assert result.emitted_lines == len(saved.splitlines())
    assert "_discovery_summary_lines" not in result.records[0]


@pytest.mark.parametrize("debug", [False, True])
def test_json_keeps_all_locations_independently_of_debug(tmp_path, capsys, debug):
    saved, secret, result = run_report(
        tmp_path, module="elastic", disk=False, live=True, debug=debug, output_format="json"
    )
    row = json.loads(saved)
    assert row["discover_findings"][0]["value"] == secret
    assert len(row["discover_findings"][0]["locations"]) == 3
    assert "_discovery_summary_lines" not in row
    assert result.emitted_lines == 1
    capsys.readouterr()


def test_summary_words_inside_value_do_not_delay_a_finding(tmp_path, capsys):
    secret = "prefix [*] Discover Complete (status:complete) literal"
    saved, _, _ = run_report(tmp_path, module="elastic", disk=False, live=False, debug=True, secret=secret)
    lines = saved.splitlines()
    value_index = next(i for i, line in enumerate(lines) if "[!] Pass Value=" in line)
    location_index = next(i for i, line in enumerate(lines) if "ValueSHA256=" in line)
    assert value_index < location_index < len(lines) - 1
    assert lines[-1].endswith("(status:complete) (findings:1)")
    capsys.readouterr()


def test_debug_location_read_error_does_not_print_false_completion(tmp_path, capsys, monkeypatch):
    from redposture_core import stage_runtime

    def fail(*args):
        raise OSError("location read failed")

    monkeypatch.setattr(stage_runtime, "iter_discovery_location_lines", fail)
    with pytest.raises(OSError, match="location read failed"):
        run_report(tmp_path, module="elastic", disk=False, live=True, debug=True)
    assert "Discover Complete" not in (tmp_path / "report.txt").read_text()
    capsys.readouterr()


def test_cancelled_record_keeps_debug_locations_before_summary(tmp_path, capsys, monkeypatch):
    from redposture_core import stage_runtime

    finding = {
        "type": "password",
        "value": "cancelled-test-password",
        "fingerprint": "test-digest",
        "locations": [{"object": "first"}, {"object": "last"}],
    }
    record = AuditRecord(
        host="qa",
        port=80,
        module="elastic",
        service="elastic",
        status="open_no_auth",
        extra={"is_elastic": True, "discover_findings": [finding]},
    )
    spec = ModuleAuditSpec(
        module="elastic",
        label="ELASTIC",
        default_port=80,
        detect=lambda ctx: record,
        is_detected=lambda _: True,
        record_skipped_credential_attempts=True,
        render=lambda _: ["ELASTIC\tqa\t80\t [*] Discover Complete (status:partial) (findings:1)"],
    )
    runner = AuditCommandRunner(args=SimpleNamespace(debug=True), spec=spec, emit_line=print)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt
        yield  # Make interruption happen while consuming outcomes.

    monkeypatch.setattr(stage_runtime.BoundedScheduler, "iter_completed", interrupted)
    monkeypatch.setattr(runner, "_cancelled_credential_records", lambda: [(record, Counter(), 0)])
    output = tmp_path / "cancelled.txt"
    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(AuditCommandPlan(targets_by_port={80: ("qa",)}, output_path=str(output), workers=1))
    lines = output.read_text().splitlines()
    assert sum("ValueSHA256=" in line for line in lines) == 2
    assert lines[-1].endswith("(status:partial) (findings:1)")
    capsys.readouterr()
