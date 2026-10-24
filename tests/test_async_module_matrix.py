"""Every registered audit command keeps its native/sync detector pairing."""

from __future__ import annotations

import importlib

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.module_registry import _STAGE_RUNNER_MODULES, AUDIT_MODULE_NAMES


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_all_audit_commands_register_native_detection(module):
    args = parse_args([module, "-t", "127.0.0.1"])
    stage = importlib.import_module(_STAGE_RUNNER_MODULES[module])
    spec = getattr(stage, "build_" + module.replace("-", "_") + "_spec")(args)
    assert spec.detect_async is not None, module
    assert spec.detect is spec.async_detect_sync_hook, module
    if module in {"mongodb", "oracle", "docker", "etcd"}:
        assert spec.detect is None, "preserve monolithic credential batching"
