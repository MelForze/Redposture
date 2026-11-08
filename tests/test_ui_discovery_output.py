"""Companion UIs retain full values, with additional TXT places only in debug."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from redposture_core import web_panels
from redposture_core.discovery_occurrences import OccurrenceRegistry
from redposture_core.discovery_rendering import discovery_color_spans
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditRecord, ModuleAuditSpec


def test_panel_renderer_does_not_clip_values_or_stop_at_200_findings():
    secret = "inactive-" + "Ab0λ" * 1000
    rows = [
        {"value": secret + str(i), "secret_type": "password", "locations": [{"object": "qa", "path": f"/{i}"}]}
        for i in range(250)
    ]
    record = {
        "host": "qa",
        "port": 5601,
        "ui_product": "kibana",
        "ui": {"inventory": {"discover": {"count": 250, "records": rows, "items": [r["value"] for r in rows]}}},
    }
    lines = web_panels.render_panel(record, "ELASTIC")
    values = [line for line in lines if "Value=" in line]
    assert len(values) == 250
    assert secret + "249" in values[-1]
    assert "Place=" in values[-1] and "\x1b" not in values[-1]
    payload = values[-1].split("[!] ", 1)[1]
    assert discovery_color_spans("[!]", payload) == [(0, len(payload), "orange")]


@pytest.mark.parametrize("debug", [False, True])
def test_ui_runtime_streams_full_disk_values_and_all_places(tmp_path, capsys, monkeypatch, debug):
    secret = "inactive-" + "Ab0λ" * 20000
    with DiskBackedText() as disk:
        disk.append_text(secret)
        disk.finish()
        catalog = OccurrenceRegistry()
        for path in ("/first", "/last"):
            catalog.add(
                {"value": disk, "secret_type": "password", "fingerprint": disk.digest},
                identity=("value", disk.digest),
                location={"object": "qa/source", "path": path},
            )
        catalog.finish()
        monkeypatch.setattr(DiskBackedText, "__str__", lambda _self: pytest.fail("disk value was materialized"))
        items = web_panels._panel_discovery_items(catalog)
        encoded = json.loads("".join(iter_json_chunks({"items": items})))
        assert encoded["items"] == [secret]

        def detect(ctx):
            return AuditRecord(
                host=ctx.host,
                port=ctx.port,
                module="demo",
                service="demo",
                status="open_no_auth",
                extra={"is_demo": True, "detection_status": "confirmed", "detection_signals": ["qa.ui"]},
            )

        def data(ctx, record):
            return AuditRecord.from_mapping(
                {
                    **record.to_dict(),
                    "surface": "ui",
                    "ui_product": "kibana",
                    "ui": {"inventory": {"discover": {"count": 1, "records": catalog, "items": items}}},
                },
                module="demo",
            )

        spec = ModuleAuditSpec(
            module="demo", label="DEMO", default_port=80, detect=detect, data=data, render=lambda _: []
        )
        output = tmp_path / "ui.txt"
        runner = AuditCommandRunner(
            args=SimpleNamespace(discover=True, debug=debug), spec=spec, emit_line=lambda _: None
        )
        runner.run_plan(
            AuditCommandPlan(targets_by_port={80: ("qa",)}, output_path=str(output), output_format="txt", workers=1)
        )
        saved = output.read_text()
        assert saved.count(secret) == 1 and saved.count("ValueSHA256=") == (2 if debug else 0)
        assert (hashlib.sha256(secret.encode()).hexdigest() in saved) is debug
        assert "\x1b" not in saved and "DiskBacked" not in saved and "OccurrenceLocations(" not in saved
        capsys.readouterr()
