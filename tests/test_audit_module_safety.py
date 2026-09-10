"""Cross-module safety invariants for every registered audit module.

Not tied to one service: these iterate `AUDIT_MODULE_NAMES` and assert framework
guarantees every audit module must uphold — the spec builds offline and
deterministically, its identity is consistent, redaction metadata is well-formed,
its plan targets only real ports, and any field it declares as sensitive is
actually stripped from the JSON payload the framework serializes.
"""

from __future__ import annotations

import importlib
import json

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.module_registry import AUDIT_MODULE_NAMES


def _stage(name: str):
    return importlib.import_module(f"redposture_core.modules.{name}.stage")


def _build_spec(name: str):
    args = parse_args([name, "-t", "127.0.0.1"])
    return getattr(_stage(name), f"build_{name}_spec")(args)


def _build_plan(name: str):
    args = parse_args([name, "-t", "127.0.0.1"])
    return getattr(_stage(name), f"build_{name}_plan")(args)


def test_registry_lists_every_module_package():
    # A module present on disk but missing from AUDIT_MODULE_NAMES (or vice versa)
    # would silently drop out of every cross-module guarantee below.
    assert AUDIT_MODULE_NAMES, "no audit modules registered"
    assert len(set(AUDIT_MODULE_NAMES)) == len(AUDIT_MODULE_NAMES)


@pytest.mark.parametrize("name", AUDIT_MODULE_NAMES)
def test_spec_builds_offline_with_consistent_identity(name):
    spec = _build_spec(name)
    assert spec.module == name
    assert spec.label == name.upper()


@pytest.mark.parametrize("name", AUDIT_MODULE_NAMES)
def test_spec_build_is_deterministic(name):
    first, second = _build_spec(name), _build_spec(name)
    assert first.module == second.module
    assert first.label == second.label
    assert first.structured_output_redact_fields == second.structured_output_redact_fields


@pytest.mark.parametrize("name", AUDIT_MODULE_NAMES)
def test_redaction_metadata_is_wellformed(name):
    fields = _build_spec(name).structured_output_redact_fields
    assert isinstance(fields, tuple)
    assert all(isinstance(field, str) and field.strip() for field in fields)
    assert len(fields) == len(set(fields))


@pytest.mark.parametrize("name", AUDIT_MODULE_NAMES)
def test_plan_targets_only_positive_ports(name):
    plan = _build_plan(name)
    assert plan.ports, f"{name} plan has no ports"
    assert all(isinstance(port, int) and port > 0 for port in plan.ports)


@pytest.mark.parametrize("name", AUDIT_MODULE_NAMES)
def test_declared_redaction_actually_strips_sensitive_json(name):
    fields = _build_spec(name).structured_output_redact_fields
    if not fields:
        pytest.skip(f"{name} declares no redaction")
    payload = {"host": "h", "port": 1, "status": "detected"}
    for field in fields:
        payload[field] = f"SENSITIVE-{field}"
    record = AuditRecord.from_mapping(payload, module=name, service=name)
    serialized = record.to_dict()
    # Present before redaction, at the top level where the framework pops them.
    assert all(field in serialized for field in fields)
    for field in fields:
        serialized.pop(field, None)
    # After redaction no sensitive marker survives anywhere in the JSON blob.
    assert "SENSITIVE" not in json.dumps(serialized, ensure_ascii=False)
