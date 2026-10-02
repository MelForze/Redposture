"""Property tests for product fingerprints and offline CVE enumeration."""

from __future__ import annotations

import importlib
import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.clients.mongodb import is_mongodb_hello_response
from redposture_core.cve import (
    CveCatalogError,
    _validate_entry,
    load_catalog,
    normalize_version,
    render_finding_lines,
    version_in_range,
)
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.modules.airflow import actions as airflow
from redposture_core.modules.airflow.stage import build_airflow_spec
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun

_JSON_SCALARS = st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=128)
_JSON = st.recursive(
    _JSON_SCALARS,
    lambda children: st.lists(children, max_size=6) | st.dictionaries(st.text(max_size=40), children, max_size=6),
    max_leaves=20,
)


class _AirflowPayloadClient:
    base_url = "http://property.invalid:8080"

    def __init__(self, payload: Any, *, status: int = 200) -> None:
        self.body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.status = status

    def get(self, _path: str, *, authed: bool = True) -> AirflowResponse:
        del authed
        return AirflowResponse(http_status=self.status, headers={}, body=self.body)

    @classmethod
    def from_raw(cls, body: str, *, status: int = 200) -> _AirflowPayloadClient:
        client = cls(None, status=status)
        client.body = body.encode("utf-8")
        return client


@given(_JSON)
def test_airflow_arbitrary_json_confirms_only_a_strict_fingerprint(payload: Any) -> None:
    detection = airflow.detect_airflow(_AirflowPayloadClient(payload))
    if detection.status != "confirmed":
        return

    assert isinstance(payload, dict)
    version = airflow._airflow_version(payload)
    assert version is not None
    assert (
        (isinstance(payload.get("git_version"), str) and bool(payload["git_version"].strip()))
        or airflow._looks_like_health(AirflowResponse(200, {}, json.dumps(payload).encode()))
        or airflow._looks_like_dag_collection(AirflowResponse(200, {}, json.dumps(payload).encode()))
    )


@given(st.text(max_size=2048))
def test_airflow_html_login_sso_and_proxy_text_never_confirms(body: str) -> None:
    decorated = f"<html><title>Airflow Login SSO</title>{body}</html>"
    detection = airflow.detect_airflow(_AirflowPayloadClient.from_raw(decorated))
    assert detection.status == "not_airflow"


@given(_JSON)
def test_mongodb_hello_validator_never_accepts_generic_shapes(payload: Any) -> None:
    accepted = is_mongodb_hello_response(payload)
    if not accepted:
        return

    assert isinstance(payload, dict)
    assert not isinstance(payload.get("ok"), bool) and payload.get("ok") == 1
    assert isinstance(payload.get("minWireVersion"), int)
    assert isinstance(payload.get("maxWireVersion"), int)
    assert payload["minWireVersion"] <= payload["maxWireVersion"]
    assert any(
        key in payload
        for key in ("isWritablePrimary", "ismaster", "secondary", "arbiterOnly", "setName", "msg", "topologyVersion")
    )


@given(st.text(max_size=512), st.sampled_from(("numeric", "oracle", "minio_release")))
def test_version_normalization_is_total_and_deterministic(raw: str, scheme: str) -> None:
    first = normalize_version(raw, scheme)
    second = normalize_version(raw, scheme)
    assert first == second
    assert first is None or all(isinstance(part, int) and part >= 0 for part in first)


@given(
    st.integers(min_value=0, max_value=99),
    st.integers(min_value=0, max_value=99),
    st.integers(min_value=0, max_value=99),
)
def test_numeric_fixed_boundary_is_exclusive(major: int, minor: int, patch: int) -> None:
    fixed = f"{major}.{minor}.{patch}"
    affected = {"introduced": "0.0.0", "fixed": fixed, "scheme": "numeric"}
    assert version_in_range(fixed, affected) is False


@given(
    st.sampled_from(load_catalog().entries),
    st.sampled_from(("id", "severity", "score", "vector", "impact", "references", "affected")),
)
def test_catalog_validator_rejects_policy_mutations(entry: dict[str, Any], field: str) -> None:
    mutated = deepcopy(entry)
    invalid_values: dict[str, Any] = {
        "id": "not-a-cve",
        "severity": "LOW",
        "score": 6.9,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "impact": "dos",
        "references": ["http://insecure.invalid/advisory"],
        "affected": [],
    }
    mutated[field] = invalid_values[field]
    with pytest.raises(CveCatalogError):
        _validate_entry(mutated, set())


@given(st.sampled_from(("no_matches", "version_unknown", "unsupported")), st.lists(_JSON, max_size=3))
def test_empty_cve_enumeration_never_renders_a_heading(status: str, products: list[Any]) -> None:
    payload = {"cve_enumeration": {"status": status, "products": products, "findings": []}}
    assert render_finding_lines(payload, label="DEMO", host="127.0.0.1", port=1) == []


def _real_specs() -> dict[str, Any]:
    specs: dict[str, Any] = {}
    for module in AUDIT_MODULE_NAMES:
        args = parse_args([module, "-t", "127.0.0.1"])
        package = module.replace("-", "_")
        stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
        specs[module] = getattr(stage, f"build_{package}_spec")(args)
    return specs


def _fingerprint_payload(module: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": 1,
        "service": module,
        "status": "detected",
        f"is_{module}": True,
    }
    if module == "keeper":
        payload.update({"is_zookeeper": True, "is_keeper": True})
    elif module == "zookeeper":
        payload.update({"is_zookeeper": True, "is_keeper": False})
    elif module in {"harbor", "nexus", "docker-registry"}:
        payload["is_registry"] = True
    return payload


def test_pairwise_product_markers_do_not_cross_confirm_other_modules() -> None:
    specs = _real_specs()
    for source_module in AUDIT_MODULE_NAMES:
        record = AuditRecord.from_mapping(
            _fingerprint_payload(source_module), module=source_module, service=source_module
        )
        for detector_module, spec in specs.items():
            assert spec.is_detected is not None
            assert bool(spec.is_detected(record)) is (source_module == detector_module), (
                source_module,
                detector_module,
                record.to_dict(),
            )


def test_probable_service_stays_in_json_and_skips_auth_data_and_cve_matching() -> None:
    calls = {"auth": 0, "data": 0}
    args = SimpleNamespace(enum_cve=True, debug=False)

    def detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "status": "probable",
                "is_airflow": False,
                "detection_status": "probable",
                "version": "2.9.2",
            },
            module="airflow",
            service="airflow",
        )

    def auth(_ctx: Any, record: AuditRecord) -> AuditRecord:
        calls["auth"] += 1
        return record

    def data(_ctx: Any, record: AuditRecord) -> AuditRecord:
        calls["data"] += 1
        return record

    spec = replace(build_airflow_spec(args), detect=detect, auth=auth, data=data)
    emitted: list[str] = []
    result = AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append).run_plan(
        AuditCommandPlan(
            targets_by_port={8080: ("127.0.0.1",)},
            credential_runs=(AuditCredentialRun(username="user", password="pass"),),
            output_format="json",
        )
    )

    assert calls == {"auth": 0, "data": 0}
    assert result.detected_count == 0
    assert result.records[0]["detection_status"] == "probable"
    assert result.records[0]["cve_enumeration"]["status"] == "unsupported"
    assert result.records[0]["cve_enumeration"]["reason"] == "service_not_confirmed"
    assert len(emitted) == 1


@given(st.datetimes(min_value=datetime(2000, 1, 1), max_value=datetime(2035, 12, 31)))
def test_minio_admin_and_release_tag_preserve_exact_instant_and_fixed_boundary(moment: datetime) -> None:
    iso = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    tag = "RELEASE." + moment.strftime("%Y-%m-%dT%H-%M-%SZ")
    assert normalize_version(iso, "minio_release") == normalize_version(tag, "minio_release")
    assert normalize_version(iso, "minio_release") == (
        moment.year,
        moment.month,
        moment.day,
        moment.hour,
        moment.minute,
        moment.second,
    )
    assert version_in_range(iso, {"fixed": tag, "scheme": "minio_release"}) is False
