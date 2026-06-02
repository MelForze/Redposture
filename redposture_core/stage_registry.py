"""Compatibility facade for :mod:`redposture_core.modules.registry`."""

from __future__ import annotations

import sys as _sys
import types as _types

from . import stage_runtime as _stage_runtime
from .modules.registry import actions as _actions
from .modules.registry import policy as _policy
from .modules.registry import render as _render
from .modules.registry import stage as _stage

_ENTRYPOINT_NAME = "run_registry_stage"


for _module in (_actions, _policy, _render, _stage):
    for _name in dir(_module):
        if _name.startswith("__") or _name.startswith("audit_"):
            continue
        globals().setdefault(_name, getattr(_module, _name))


_RUNTIME_COMPAT_NAMES = {
    "start_" + "command_progress": (_stage_runtime, "start_" + "command_progress"),
    "filter_open_tcp_hosts_for_" + "credential_file": (
        _stage_runtime,
        "filter_open_tcp_hosts_for_" + "credential_file",
    ),
    "collect_scan_ports": (_stage_runtime, "collect_scan_ports"),
    "collect_scan_targets": (_stage_runtime, "collect_scan_targets"),
    "collect_scan_target_specs": (_stage_runtime, "collect_scan_target_specs"),
    "build_scan_execution_groups": (_stage_runtime, "build_scan_execution_groups"),
}


def __getattr__(name: str):
    runtime_target = _RUNTIME_COMPAT_NAMES.get(name)
    if runtime_target is not None:
        module_obj, attr_name = runtime_target
        return getattr(module_obj, attr_name)
    raise AttributeError(name)


class _StageFacadeModule(_types.ModuleType):
    def __setattr__(self, name: str, value):
        super().__setattr__(name, value)
        runtime_target = _RUNTIME_COMPAT_NAMES.get(name)
        if runtime_target is not None:
            module_obj, attr_name = runtime_target
            setattr(module_obj, attr_name, value)
        for module_obj in (_actions, _policy, _render, _stage):
            if hasattr(module_obj, name):
                setattr(module_obj, name, value)


_sys.modules[__name__].__class__ = _StageFacadeModule

__all__ = [
    _name
    for _name in globals()
    if not _name.startswith("__") and _name not in {"_actions", "_policy", "_render", "_stage"}
]
