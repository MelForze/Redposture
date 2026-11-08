from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.performance_contracts import token_inventory_errors


def inventory(module):
    field = {"vault": "mounts", "nomad": "jobs", "jupyter": "kernels"}[module]
    rows = {
        "vault": [
            {"path": "secret/", "type": "kv", "description": "Platform configuration", "options": {"version": "2"}},
            {"path": "database/", "type": "database", "description": "Database roles", "options": {}},
            {"path": "transit/", "type": "transit", "description": "Application signing", "options": {}},
        ],
        "nomad": [
            {"ID": name, "Name": name, "Namespace": "default", "Status": "running"}
            for name in ("platform-api", "billing-batch", "nightly-backup")
        ],
        "jupyter": [
            {"id": "analysis", "name": "python3", "execution_state": "idle"},
            {"id": "reporting", "name": "python3", "execution_state": "busy"},
        ],
    }[module]
    return field, {
        "status": "valid_credentials",
        "token_valid": True,
        "inventory_requested": [field],
        field + "_access": "allowed",
        field + "_partial": False,
        field: rows,
        "mounts_count": 3,
    }


@pytest.mark.parametrize("module", ["vault", "nomad", "jupyter"])
def test_seeded_inventory_requires_exact_objects_not_just_counts(module):
    field, row = inventory(module)
    assert token_inventory_errors(module, row, limited=False) == []
    for variant in ["changed", "missing", "duplicate", "unrequested", "partial"]:
        bad = deepcopy(row)
        if variant == "changed":
            key = {"vault": "type", "nomad": "Status", "jupyter": "execution_state"}[module]
            bad[field][0][key] = "changed"
        elif variant == "missing":
            bad[field].pop()
        elif variant == "duplicate":
            bad[field].append(deepcopy(bad[field][0]))
        elif variant == "unrequested":
            bad["inventory_requested"] = []
        else:
            bad[field + "_partial"] = True
        assert token_inventory_errors(module, bad, limited=False), variant


@pytest.mark.parametrize("module", ["vault", "nomad", "jupyter"])
def test_limited_inventory_preserves_verified_identity_and_explicit_denial(module):
    field, row = inventory(module)
    del row[field]
    row[field + "_access"] = "denied"
    assert token_inventory_errors(module, row, limited=True) == []
    row[field + "_access"] = "allowed"
    row[field] = []
    assert token_inventory_errors(module, row, limited=True)
    row["token_valid"] = False
    assert token_inventory_errors(module, row, limited=True)
