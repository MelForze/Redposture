from __future__ import annotations

import pytest

from redposture_core import exporters


def test_exporters_lazy_facade_resolves_public_functions() -> None:
    assert callable(exporters.collect_exporter_debug_data)
    assert callable(exporters.scan_exporter_presence)
    assert callable(exporters.scan_exporters_and_trigger)
    missing_name = "missing"
    with pytest.raises(AttributeError, match="missing"):
        getattr(exporters, missing_name)
