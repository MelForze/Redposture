"""Received compute API evidence, surface isolation and real action parity."""

from __future__ import annotations

import importlib
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from scripts.performance_compute import compute_inventory_errors, compute_reply
from scripts.performance_readonly import ReadOnlyWireLedger
from scripts.profile_module_performance import module_options, unsupported_auth_reason


def actual_audit(module, access, categories):
    ledger = ReadOnlyWireLedger()

    class Pool:
        def request(self, method, url, **kwargs):
            parsed = urlsplit(url)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            raw = compute_reply(module, method, path, access=access)
            ledger.record_response(0, method, path, {}, kwargs.get("body", b""), raw)
            head, body = raw.split(b"\r\n\r\n", 1)
            headers = {
                k.decode(): v.strip().decode() for k, v in (line.split(b":", 1) for line in head.split(b"\r\n")[1:])
            }
            return HttpResponse(int(head.split(b" ", 2)[1]), body, headers)

    options = parse_args([module, "-t", "http://127.0.0.1:43123", *["--show-" + name for name in categories]])
    context = SimpleNamespace(
        host="127.0.0.1", port=43123, args=options, credential=None, lifecycle_state=SimpleNamespace(http=Pool())
    )
    actions = importlib.import_module("redposture_core.modules." + module + ".actions")
    record = actions.data_record(context, actions.detect_record(context))
    return record, ledger.pop(0)


@pytest.mark.parametrize("access", ["open", "limited"])
@pytest.mark.parametrize("categories", [[], ["workers"], ["apps"], ["workers", "apps"]])
def test_spark_master_and_rest_have_independent_inventory(access, categories):
    record, wire = actual_audit("spark", access, categories)
    assert not compute_inventory_errors("spark", record, wire, access=access, categories=categories)
    assert not record.get("provided_credentials_ok") and not record.get("credential_attempts")
    assert all(c["method"] == "GET" for c in wire["calls"])


@pytest.mark.parametrize("access", ["open", "limited", "denied"])
@pytest.mark.parametrize("categories", [[], ["apps"], ["nodes"], ["metrics"], ["apps", "nodes", "metrics"]])
def test_yarn_public_cluster_info_does_not_grant_apps_nodes_or_metrics(access, categories):
    record, wire = actual_audit("yarn", access, categories)
    assert not compute_inventory_errors("yarn", record, wire, access=access, categories=categories)
    assert not record.get("provided_credentials_ok") and not record.get("credential_attempts")


@pytest.mark.parametrize("module,categories", [("spark", ["workers", "apps"]), ("yarn", ["apps", "nodes", "metrics"])])
@pytest.mark.parametrize(
    "fault",
    ["missing-wire", "corrupt-reply", "missing-object", "changed-object", "completion", "credential", "mutation"],
)
def test_false_inventory_and_corrupt_received_evidence_fail(module, categories, fault):
    record, wire = actual_audit(module, "open", categories)
    record, wire = deepcopy(record), deepcopy(wire)
    if fault == "missing-wire":
        wire["calls"] = []
    elif fault == "corrupt-reply":
        wire["calls"][-1]["response_body"] += "corrupt"
    elif fault == "missing-object":
        record["apps"] = record["apps"][:-1]
    elif fault == "changed-object":
        record["apps"][0]["name"] = "other"
    elif fault == "completion":
        record["inventory_status"] = "partial"
    elif fault == "credential":
        wire["calls"][0]["headers"]["authorization"] = "Basic fixture"
    else:
        wire["calls"][0]["method"] = "POST"
    assert compute_inventory_errors(module, record, wire, access="open", categories=categories)


@pytest.mark.parametrize("module", ["spark", "yarn"])
@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_compute_profile_never_registers_submits_or_executes(module, method):
    for path in ["/v1/submissions/create", "/ws/v1/cluster/apps/new-application", "/ws/v1/cluster/apps"]:
        assert compute_reply(module, method, path, access="open").startswith(b"HTTP/1.1 405")


@pytest.mark.parametrize("module", ["spark", "yarn"])
@pytest.mark.parametrize("mode", ["credentials", "defcreds"])
def test_compute_pair_flags_are_not_fabricated_into_valid_authentication(module, mode):
    assert unsupported_auth_reason(module, mode)
    assert "-u" not in module_options(module, "run", "http://127.0.0.1:43123", 1)


def test_denied_spark_cannot_masquerade_as_positive_product_proof():
    with pytest.raises(ValueError, match="cannot prove"):
        compute_reply("spark", "GET", "/json/", access="denied")
