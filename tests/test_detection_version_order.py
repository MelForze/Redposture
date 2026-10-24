"""Version placement through the shared output path, including streaming and UI."""

from __future__ import annotations

import json

import pytest

from redposture_core import web_panels
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.rendering import order_detection_fields
from redposture_core.stage_runtime import LineOutputSink
from tests.test_audit_output_contracts_extended import _build_real_spec, _detected_payload, _service_lines


@pytest.mark.parametrize("suffix", ["(UI)", "(ACL enabled:True)", "(surface:master_ui)", "(state:STARTED) (HA:ACTIVE)"])
@pytest.mark.parametrize("version", ["1.2.3", "unknown"])
def test_detection_version_is_last_in_console_and_saved_txt(tmp_path, suffix, version):
    lines = []
    path = tmp_path / "output.txt"
    sink = LineOutputSink(str(path), emit_line=lines.append)
    sink.emit_many([f"DEMO\thost\t80\t [*] Service (auth required:True) (version:{version}) {suffix}"])
    sink.close()
    assert lines == [f"DEMO\thost\t80\t [*] Service (auth required:True) {suffix} (version:{version})"]
    assert path.read_text() == lines[0] + "\n"


def test_version_order_does_not_rewrite_credentials_or_json(tmp_path):
    lines = [
        "DEMO\thost\t80\t [+] u:p(version:1.2.3) (UI)",
        json.dumps({"version": "1.2.3", "value": "(version:2) (UI)"}),
    ]
    got = []
    sink = LineOutputSink(str(tmp_path / "out.txt"), emit_line=got.append)
    sink.emit_many(lines)
    sink.close()
    assert got == lines


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_all_real_module_headers_keep_version_at_the_right_edge(module, tmp_path):
    spec = _build_real_spec(module)
    lines = _service_lines(spec, _detected_payload(module, spec))
    assert len(lines) == 1
    got = []
    sink = LineOutputSink(str(tmp_path / "out.txt"), got.append)
    sink.emit_many(lines)
    sink.close()
    if "(version:" in got[0]:
        assert got[0].rstrip().split("(version:", 1)[1].count(")") == 1, got[0]
    assert order_detection_fields(got[0]) == got[0]
    assert "\x1b" not in (tmp_path / "out.txt").read_text()


@pytest.mark.parametrize("module,product", [(m, p) for m, ps in web_panels.MODULE_PRODUCTS.items() for p in ps])
def test_each_associated_ui_header_places_ui_before_version(module, product, tmp_path):
    lines = web_panels.render_panel(
        {"host": "qa", "port": 80, "ui_product": product, "ui": {"version": "1.2.3", "auth_required": False}},
        module.upper(),
    )
    got = []
    sink = LineOutputSink(None, got.append)
    sink.emit_many(lines)
    sink.close()
    assert got[0].endswith("(UI) (version:1.2.3)")
