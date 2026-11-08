"""Action gates validate full seeded objects/selectors, not merely a nonempty list."""

from __future__ import annotations

import copy
import json

import pytest

from scripts.performance_contracts import platform_inventory_errors


def valid_row(module, limited):
    row = {"host": "127.0.0.1", "port": 8888, "is_" + module: True}
    if module == "consul":
        return {
            **row,
            "auth_valid": True,
            "services_list_requested": True,
            "services_list": None
            if limited
            else [
                {"name": n, "tags": t}
                for n, t in [
                    ("platform-api", ["prod", "http"]),
                    ("billing-worker", ["prod", "batch"]),
                    ("metrics", ["infra"]),
                ]
            ],
            "services_list_error": "Forbidden" if limited else None,
        }
    if module == "kubeapi":
        return {
            **row,
            "auth_valid": True,
            "show_namespaces": True,
            "can_list_namespaces": not limited,
            "namespaces": [] if limited else ["platform", "billing", "observability"],
            "namespaces_error": "Forbidden" if limited else None,
            "namespaces_partial": False,
        }
    if module == "qdrant":
        return {
            **row,
            "provided_credentials_ok": True,
            "dump": True,
            "collection_name": "restricted-ml",
            "collections_count": 2 if limited else 3,
            "collections": ["platform-events", "billing-events"] + ([] if limited else ["restricted-ml"]),
            "collection_dump_items": [
                {
                    "name": "restricted-ml",
                    "ok": not limited,
                    "status": 403 if limited else 200,
                    "error": "Access denied" if limited else None,
                    "info_raw": None
                    if limited
                    else json.dumps(
                        {
                            "result": {
                                "points_count": 128,
                                "config": {"params": {"vectors": {"size": 8, "distance": "Cosine"}}},
                            }
                        }
                    ),
                }
            ],
        }
    project = {
        "id": 103,
        "path_with_namespace": "platform/reporting",
        "http_url_to_repo": "http://127.0.0.1:8888/platform/reporting.git",
        "web_url": "http://127.0.0.1:8888/platform/reporting",
    }
    access = {
        **project,
        "repo_read": True,
        "issues_read": True,
        "members_read": True,
        "repo_error": None,
        "issues_error": None,
        "members_error": None,
    }
    return {
        **row,
        "token_valid": True,
        "gitlab_surface": "web",
        "project_filters": ["platform/reporting"],
        "token_projects": [] if limited else [project],
        "token_access": [] if limited else [access],
        "token_projects_error": "authentication required" if limited else None,
    }


@pytest.mark.parametrize("module", ["consul", "kubeapi", "qdrant", "gitlab"])
@pytest.mark.parametrize("limited", [False, True])
def test_seeded_read_and_explicit_denial_are_both_observed_behaviors(module, limited):
    assert platform_inventory_errors(module, valid_row(module, limited), limited=limited) == []


@pytest.mark.parametrize("module", ["consul", "kubeapi", "qdrant", "gitlab"])
def test_empty_inventory_is_not_a_success_or_a_confirmed_denial(module):
    row = valid_row(module, False)
    for key in (
        "services_list",
        "namespaces",
        "collections",
        "collection_dump_items",
        "token_projects",
        "token_access",
    ):
        if key in row:
            row[key] = []
    assert platform_inventory_errors(module, row, limited=False)
    assert platform_inventory_errors(module, row, limited=True)


@pytest.mark.parametrize("module", ["consul", "kubeapi", "qdrant", "gitlab"])
def test_identity_cannot_be_inferred_from_the_known_data_objects(module):
    row = valid_row(module, False)
    for key in ("auth_valid", "provided_credentials_ok", "token_valid"):
        if key in row:
            row[key] = None
    assert platform_inventory_errors(module, row, limited=False)


@pytest.mark.parametrize("module", ["consul", "kubeapi", "qdrant", "gitlab"])
def test_duplicate_objects_wrong_path_or_modified_values_fail(module):
    row = copy.deepcopy(valid_row(module, False))
    if module == "consul":
        row["services_list"][0]["tags"] = ["wrong"]
    elif module == "kubeapi":
        row["namespaces"] = ["platform"] * 3
    elif module == "qdrant":
        row["collection_dump_items"][0]["info_raw"] = "{}"
    else:
        row["token_projects"][0]["path_with_namespace"] = "platform/api"
    assert platform_inventory_errors(module, row, limited=False)


@pytest.mark.parametrize("limited", [False, True])
def test_qdrant_public_record_uses_dump_and_collection_name_not_internal_options(limited):
    row = valid_row("qdrant", limited)
    row.pop("dump_requested", None)
    row["dump"] = True
    row["collection_name"] = "restricted-ml"
    assert platform_inventory_errors("qdrant", row, limited=limited) == []


def test_internal_option_or_an_unselected_collection_is_not_enough():
    row = valid_row("qdrant", False)
    row.pop("dump")
    row["dump_requested"] = True
    assert platform_inventory_errors("qdrant", row, limited=False)
    row["dump"] = True
    row["collection_name"] = "platform-events"
    assert platform_inventory_errors("qdrant", row, limited=False)
