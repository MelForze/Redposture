"""New source adapters keep the established Airflow discovery palette."""

import importlib
import json

import pytest

from redposture_core.data_discovery import render_discovery
from redposture_core.stage_runtime import _build_colored_emit


@pytest.mark.parametrize("module", ["docker", "rabbitmq", "grafana", "keycloak", "kafka", "vault", "portainer"])
def test_new_discovery_adapter_palette_and_plain_serialization(module):
    class Console:
        def __init__(self):
            self.calls = []
            self.lines = []

        def _paint(self, value, color, _stream):
            self.calls.append((value, color))
            return value

        def plain(self, value):
            self.lines.append(value)

    record = {
        "host": "qa",
        "port": 80,
        "content_discovery": {
            "status": "complete",
            "source": "authenticated",
            "findings": [
                {"type": "password", "confidence": "high", "value": "inactive!42", "object_path": "$.qa.password"}
            ],
        },
    }
    renderer = importlib.import_module(f"redposture_core.modules.{module}.render")
    colorize = getattr(renderer, f"_render_colored_{module}_line")
    console = Console()
    emit = _build_colored_emit(console, colorize)
    lines = render_discovery(module, record)
    for line in lines:
        emit(line)
    assert any("findings:1" in value and color == "true_red" for value, color in console.calls)
    assert any("status:complete" in value and color == "bright_green" for value, color in console.calls)
    assert any("Pass Value=" in value and color == "orange" for value, color in console.calls)
    assert "\x1b" not in "\n".join(lines) + json.dumps(record)
