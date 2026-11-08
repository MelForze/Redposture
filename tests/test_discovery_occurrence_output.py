"""Every retained place reaches bounded TXT output, including after live values."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from redposture_core import storage_discovery as storage
from redposture_core.discovery_occurrences import OccurrenceRegistry
from redposture_core.discovery_rendering import discovery_color_spans, iter_discovery_location_lines
from redposture_core.discovery_values import DiskBackedText
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditRecord, ModuleAuditSpec


@pytest.mark.parametrize("field", ["content_discovery", "discover_report", "discover_findings", "secret_findings"])
def test_each_catalog_outputs_all_structured_places_without_repeating_secret(field):
    registry = OccurrenceRegistry()
    secret = "inactive-output-password"
    fp = hashlib.sha256(secret.encode()).hexdigest()
    for n in range(150):
        registry.add(
            {"type": "password", "value": secret, "fingerprint": fp},
            identity=("value", fp),
            location={"object": f"object/{n}", "row_ordinal": n},
        )
    registry.finish()
    report = registry if field.endswith("findings") else {"findings": registry}
    lines = ["".join(chunks) for chunks in iter_discovery_location_lines("demo", "qa", 80, {field: report})]
    assert len(lines) == 150
    assert all(secret not in line and fp in line and "\x1b" not in line for line in lines)
    assert [json.loads(line.split(" Place=", 1)[1])["row_ordinal"] for line in lines] == list(range(150))
    payload = lines[0].split("[!] ", 1)[1]
    assert discovery_color_spans("[!]", payload) == [(0, len(payload), "orange")]


def test_long_locator_is_never_materialized(monkeypatch):
    with DiskBackedText() as path:
        path.append_text("long/object/" * 10000)
        path.finish()
        registry = OccurrenceRegistry()
        for n in range(2):
            registry.add(
                {"type": "password", "value": "inactive-secret", "fingerprint": "digest"},
                location={"object": path, "row_ordinal": n},
            )
        registry.finish()
        monkeypatch.setattr(DiskBackedText, "__str__", lambda _self: pytest.fail("materialized locator"))
        lines = [
            "".join(chunks)
            for chunks in iter_discovery_location_lines("demo", "qa", 80, {"content_discovery": {"findings": registry}})
        ]
        assert len(lines) == 2
        assert json.loads(lines[-1].split(" Place=", 1)[1])["object"] == "long/object/" * 10000


@pytest.mark.parametrize("ordinal", ["row_ordinal", "document_ordinal"])
def test_single_value_retains_ordinal_needed_to_select_its_source(ordinal):
    registry = OccurrenceRegistry()
    registry.add(
        {"type": "password", "value": "inactive-secret", "fingerprint": "digest"},
        location={"object_path": "$.password", ordinal: 7},
    )
    registry.finish()
    lines = [
        "".join(chunks)
        for chunks in iter_discovery_location_lines("demo", "qa", 80, {"content_discovery": {"findings": registry}})
    ]
    assert len(lines) == 1
    assert json.loads(lines[0].split(" Place=", 1)[1])[ordinal] == 7


@pytest.mark.parametrize("debug", [False, True])
def test_runtime_outputs_later_places_after_live_value_once(tmp_path, capsys, debug):
    password = "inactive-live-location-password"

    def detect(ctx):
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            service="gitlab",
            module="gitlab",
            status="open_no_auth",
            extra={"is_gitlab": True, "detection_status": "confirmed", "detection_signals": ["gitlab.probe"]},
        )

    def data(ctx, record):
        collector = storage.DiscoveryCollector("gitlab", ctx, record.to_dict())
        for index in range(3):
            collector.add(f"object/{index}", {"password": password})
        return AuditRecord.from_mapping({**record.to_dict(), "content_discovery": collector.result()}, module="gitlab")

    spec = ModuleAuditSpec(
        module="gitlab",
        label="GITLAB",
        default_port=80,
        detect=detect,
        data=data,
        render=lambda _record: ["GITLAB\tqa\t80\t [*] GitLab"],
    )
    output = tmp_path / "findings.txt"
    runner = AuditCommandRunner(
        args=SimpleNamespace(discover=True, debug=debug), spec=spec, emit_line=lambda _line: None
    )
    runner.run_plan(
        AuditCommandPlan(targets_by_port={80: ("qa",)}, output_path=str(output), output_format="txt", workers=1)
    )
    saved = output.read_text()
    assert saved.count(password) == 1
    assert saved.count("ValueSHA256=") == (3 if debug else 0)
    places = [json.loads(line.split(" Place=", 1)[1]) for line in saved.splitlines() if "ValueSHA256=" in line]
    assert [place["object"] for place in places] == ([f"object/{i}" for i in range(3)] if debug else [])
    assert "\x1b" not in saved and "OccurrenceLocations(" not in saved
    capsys.readouterr()
