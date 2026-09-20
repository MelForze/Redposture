from __future__ import annotations

import json
import socket
import urllib.request
from collections import Counter
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.cve import (
    CveCatalogError,
    DetectedProduct,
    enumerate_record,
    load_catalog,
    normalize_version,
    resolve_products,
    version_in_range,
)
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec


def test_bundled_catalog_is_valid_and_policy_constrained() -> None:
    catalog = load_catalog()
    assert catalog.version == "2026-09-20"
    assert catalog.entries
    keys: set[tuple[str, str]] = set()
    for entry in catalog.entries:
        key = (entry["id"], entry["product"])
        assert key not in keys
        keys.add(key)
        assert entry["severity"] in {"HIGH", "CRITICAL"}
        assert entry["score"] >= 7.0
        vector_parts = entry["vector"].split("/")
        assert all(metric in vector_parts for metric in ("AV:N", "UI:N"))
        assert entry["privileges_required"] in {"N", "L"}
        assert f"PR:{entry['privileges_required']}" in vector_parts
        assert entry["impact"] in {
            "rce",
            "command_execution",
            "auth_bypass",
            "account_takeover",
            "file_read",
            "file_write",
            "ssrf",
        }
        assert entry["affected"]
        assert all(str(ref).startswith("https://") for ref in entry["references"])
        assert len(entry["references"]) >= 2
        assert any("nvd.nist.gov" in ref for ref in entry["references"])
        assert any("nvd.nist.gov" not in ref for ref in entry["references"])


def test_bundled_catalog_has_reviewed_coverage_per_product() -> None:
    counts = Counter(entry["product"] for entry in load_catalog().entries)
    assert len(load_catalog().entries) == 186
    assert counts == {
        "apache_airflow": 11,
        "apache_zookeeper": 2,
        "clickhouse": 3,
        "docker_engine": 1,
        "elasticsearch": 6,
        "etcd": 1,
        "gitlab": 72,
        "grafana": 10,
        "harbor": 2,
        "hashicorp_consul": 1,
        "kubernetes": 1,
        "minio": 4,
        "mongodb": 6,
        "nexus_repository": 5,
        "opensearch": 1,
        "oracle_database": 2,
        "postgresql": 22,
        "proxmox_ve": 1,
        "qdrant": 5,
        "rabbitmq": 4,
        "redis": 23,
        "valkey": 3,
    }
    assert Counter(entry["impact"] for entry in load_catalog().entries)["ssrf"] == 31
    assert Counter(entry["privileges_required"] for entry in load_catalog().entries) == {"N": 88, "L": 98}


@pytest.mark.parametrize(
    ("raw", "scheme", "expected"),
    [
        ("v1.27.5", "numeric", (1, 27, 5)),
        ("13.10.2-ee", "numeric", (13, 10, 2)),
        ("19.0.0.0.0", "numeric", (19, 0, 0, 0, 0)),
        ("9.6.24 (Ubuntu)", "numeric", (9, 6, 24)),
        ("8.2.7-rc1", "numeric", (8, 2, 7)),
        ("1.9.0-dev", "numeric", (1, 9, 0)),
        ("8.2.7+vendor.1", "numeric", (8, 2, 7)),
        ("18c", "oracle", (18, 0, 0, 0, 0)),
        ("RELEASE.2024-01-31T20-20-33Z", "minio_release", (2024, 1, 31, 20, 20, 33)),
        ("8", "numeric", None),
        ("8.x", "numeric", None),
        ("unknown", "numeric", None),
    ],
)
def test_version_normalizers(raw: str, scheme: str, expected: tuple[int, ...] | None) -> None:
    assert normalize_version(raw, scheme) == expected


@pytest.mark.parametrize(
    ("version", "affected", "expected"),
    [
        ("8.2.0", {"introduced": "8.2.0", "fixed": "8.2.7"}, True),
        ("8.2.6", {"introduced": "8.2.0", "fixed": "8.2.7"}, True),
        ("8.2.7", {"introduced": "8.2.0", "fixed": "8.2.7"}, False),
        ("8.2.7-rc1", {"introduced": "8.2.0", "fixed": "8.2.7"}, True),
        ("8.2.7+vendor.1", {"introduced": "8.2.0", "fixed": "8.2.7"}, False),
        ("8.1.9", {"introduced": "8.2.0", "fixed": "8.2.7"}, False),
        (
            "1.9.0-dev",
            {"introduced": "1.9.0-dev", "last_affected": "1.9.0-dev"},
            True,
        ),
        (
            "1.9.0-alpha",
            {"introduced": "1.9.0-dev", "last_affected": "1.9.0-dev"},
            False,
        ),
        ("v1.12.2", {"introduced": "1.12.0", "last_affected": "1.12.2"}, True),
        ("v1.12.3", {"introduced": "1.12.0", "last_affected": "1.12.2"}, False),
        ("garbage", {"introduced": "1.0", "fixed": "2.0"}, None),
    ],
)
def test_version_range_boundaries(version: str, affected: dict[str, str], expected: bool | None) -> None:
    assert version_in_range(version, affected) is expected


def test_multiple_ranges_and_stable_newest_first_order() -> None:
    catalog = load_catalog()
    gitlab = enumerate_record("gitlab", {"version": "13.9.5"}, catalog=catalog, confirmed=True)
    assert gitlab["status"] == "matched"
    assert [finding["id"] for finding in gitlab["findings"]] == [
        "CVE-2022-0249",
        "CVE-2021-22214",
        "CVE-2021-22205",
    ]
    fixed = enumerate_record("gitlab", {"version": "14.9.2"}, catalog=catalog, confirmed=True)
    assert fixed["status"] == "no_matches"


def test_ssrf_oracle_and_postgresql_boundaries() -> None:
    catalog = load_catalog()
    consul = enumerate_record("consul", {"version": "1.11.4"}, catalog=catalog, confirmed=True)
    assert [(finding["id"], finding["impact"]) for finding in consul["findings"]] == [("CVE-2022-29153", "ssrf")]
    assert enumerate_record("consul", {"version": "1.11.5"}, catalog=catalog, confirmed=True)["status"] == (
        "no_matches"
    )

    oracle = enumerate_record("oracle", {"server_version": "18c"}, catalog=catalog, confirmed=True)
    assert [finding["id"] for finding in oracle["findings"]] == ["CVE-2018-3259"]

    postgres = enumerate_record("postgres", {"server_version": "18.3"}, catalog=catalog, confirmed=True)
    assert [finding["id"] for finding in postgres["findings"]] == ["CVE-2026-6478"]
    assert enumerate_record("postgres", {"server_version": "18.4"}, catalog=catalog, confirmed=True)["status"] == (
        "no_matches"
    )


def test_minio_and_clickhouse_catalog_boundaries() -> None:
    catalog = load_catalog()
    minio_vulnerable = enumerate_record(
        "minio",
        {"version": "RELEASE.2023-03-13T19-46-17Z"},
        catalog=catalog,
        confirmed=True,
    )
    minio_fixed = enumerate_record(
        "minio",
        {"version": "RELEASE.2023-03-20T20-16-18Z"},
        catalog=catalog,
        confirmed=True,
    )
    clickhouse_vulnerable = enumerate_record(
        "clickhouse", {"server_version": "24.4.2.140"}, catalog=catalog, confirmed=True
    )
    clickhouse_fixed = enumerate_record("clickhouse", {"server_version": "24.4.2.141"}, catalog=catalog, confirmed=True)
    assert [finding["id"] for finding in minio_vulnerable["findings"]] == ["CVE-2023-28432"]
    assert minio_fixed["status"] == "no_matches"
    assert [finding["id"] for finding in clickhouse_vulnerable["findings"]] == ["CVE-2024-6873"]
    assert clickhouse_fixed["status"] == "no_matches"


@pytest.mark.parametrize(
    ("module", "payload", "cve_id", "fixed_payload"),
    [
        (
            "registry",
            {"is_nexus": True, "nexus_info": {"version": "3.68.0"}},
            "CVE-2024-4956",
            {"is_nexus": True, "nexus_info": {"version": "3.68.1"}},
        ),
        (
            "registry",
            {"is_nexus": True, "nexus_info": {"version": "3.14.0"}},
            "CVE-2019-7238",
            {"is_nexus": True, "nexus_info": {"version": "3.15.0"}},
        ),
        (
            "registry",
            {"is_nexus": True, "nexus_info": {"version": "3.90.2"}, "auth_required": False},
            "CVE-2026-3199",
            {"is_nexus": True, "nexus_info": {"version": "3.91.0"}, "auth_required": False},
        ),
        (
            "airflow",
            {"version": "2.9.2", "auth_required": False},
            "CVE-2024-39877",
            {"version": "2.9.3", "auth_required": False},
        ),
        (
            "clickhouse",
            {"server_version": "19.13.9"},
            "CVE-2019-16535",
            {"server_version": "19.14.0"},
        ),
        (
            "gitlab",
            {"version": "14.5.2"},
            "CVE-2022-0244",
            {"version": "14.5.3"},
        ),
        (
            "gitlab",
            {"version": "13.9.3", "auth_required": False},
            "CVE-2021-22192",
            {"version": "13.9.4", "auth_required": False},
        ),
        (
            "grafana",
            {"server_version": "9.5.16", "auth_required": False},
            "CVE-2024-1442",
            {"server_version": "9.5.17", "auth_required": False},
        ),
    ],
)
def test_new_catalog_entries_respect_fixed_boundaries(
    module: str,
    payload: dict[str, object],
    cve_id: str,
    fixed_payload: dict[str, object],
) -> None:
    catalog = load_catalog()
    vulnerable = enumerate_record(module, payload, catalog=catalog, confirmed=True)
    fixed = enumerate_record(module, fixed_payload, catalog=catalog, confirmed=True)
    assert cve_id in {finding["id"] for finding in vulnerable["findings"]}
    assert cve_id not in {finding["id"] for finding in fixed["findings"]}


def test_unknown_unsupported_and_unconfirmed_are_not_guessed() -> None:
    catalog = load_catalog()
    assert enumerate_record("grafana", {"server_version": None}, catalog=catalog, confirmed=True)["status"] == (
        "version_unknown"
    )
    assert enumerate_record("kafka", {}, catalog=catalog, confirmed=True)["reason"] == ("unsupported_version_detection")
    assert enumerate_record("grpc", {}, catalog=catalog, confirmed=True)["reason"] == ("unsupported_product_detection")
    assert enumerate_record("registry", {"is_registry": True}, catalog=catalog, confirmed=True)["status"] == (
        "unsupported"
    )
    assert enumerate_record("grafana", {"server_version": "8.2.6"}, catalog=catalog, confirmed=False)["findings"] == []


def test_qdrant_privileged_endpoint_check_remains_additional_evidence_without_access() -> None:
    result = enumerate_record(
        "qdrant",
        {
            "version": "1.15.5",
            "ghsa_f632_vm87_2m2f": {
                "id": "GHSA-f632-vm87-2m2f",
                "cve": "CVE-2026-25628",
                "endpoint": "/logger",
                "affected_range": ">=1.9.3,<1.15.6",
                "version": "1.15.5",
                "version_affected": True,
                "logger_reachable": True,
                "logger_blocked": False,
                "assessment": "potentially_vulnerable",
            },
        },
        catalog=load_catalog(),
        confirmed=True,
    )
    assert result["findings"] == []
    assert result["status"] == "no_matches"
    assert result["additional_evidence"] == [
        {
            "id": "CVE-2026-25628",
            "advisory_id": "GHSA-f632-vm87-2m2f",
            "title": "Arbitrary file write via /logger endpoint",
            "endpoint": "/logger",
            "detected_version": "1.15.5",
            "affected_range": ">=1.9.3,<1.15.6",
            "version_affected": True,
            "endpoint_reachable": True,
            "endpoint_blocked": False,
            "assessment": "potentially_vulnerable",
            "catalog_eligible": True,
            "catalog_access_condition": "requires_low_privileges",
        }
    ]


def test_low_privilege_cve_requires_credentials_or_anonymous_access() -> None:
    catalog = load_catalog()
    protected = enumerate_record(
        "grafana",
        {"server_version": "11.0.0", "auth_required": True},
        catalog=catalog,
        confirmed=True,
    )
    anonymous = enumerate_record(
        "grafana",
        {"server_version": "11.0.0", "auth_required": False},
        catalog=catalog,
        confirmed=True,
    )
    authenticated = enumerate_record(
        "grafana",
        {"server_version": "11.0.0", "auth_required": True},
        catalog=catalog,
        confirmed=True,
        credentials_provided=True,
    )

    assert "CVE-2024-9264" not in {finding["id"] for finding in protected["findings"]}
    anonymous_finding = next(finding for finding in anonymous["findings"] if finding["id"] == "CVE-2024-9264")
    authenticated_finding = next(finding for finding in authenticated["findings"] if finding["id"] == "CVE-2024-9264")
    assert anonymous_finding["privileges_required"] == "L"
    assert anonymous_finding["access_basis"] == "anonymous_access"
    assert authenticated_finding["privileges_required"] == "L"
    assert authenticated_finding["access_basis"] == "provided_credentials"


@pytest.mark.parametrize(
    ("module", "payload", "cve_id", "vulnerable_version", "fixed_version"),
    [
        ("airflow", {"version": "2.10.0"}, "CVE-2024-45498", "2.10.0", "2.10.1"),
        ("gitlab", {"version": "14.3.0"}, "CVE-2021-39867", "14.3.0", "14.3.1"),
        ("grafana", {"server_version": "11.2.0"}, "CVE-2024-9264", "11.2.0", "11.2.1"),
        (
            "minio",
            {"version": "RELEASE.2022-04-11T00-00-00Z"},
            "CVE-2022-24842",
            "RELEASE.2022-04-11T00-00-00Z",
            "RELEASE.2022-04-12T06-55-35Z",
        ),
        ("opensearch", {}, "CVE-2023-23612", "2.4.0", "2.5.0"),
        ("postgres", {"server_version": "16.0"}, "CVE-2023-5869", "16.0", "16.1"),
        ("proxmox", {"version": "8.0"}, "CVE-2023-43320", "8.0", "8.1"),
        ("qdrant", {"version": "1.15.5"}, "CVE-2026-25628", "1.15.5", "1.15.6"),
        ("redis", {"server_version": "7.0.3"}, "CVE-2022-31144", "7.0.3", "7.0.4"),
    ],
)
def test_low_privilege_catalog_boundaries(
    module: str,
    payload: dict[str, object],
    cve_id: str,
    vulnerable_version: str,
    fixed_version: str,
) -> None:
    version_field = next((field for field in ("version", "server_version") if field in payload), "server_version")
    vulnerable_payload = {**payload, version_field: vulnerable_version, "auth_required": False}
    fixed_payload = {**payload, version_field: fixed_version, "auth_required": False}
    if module == "opensearch":
        module = "elastic"
        vulnerable_payload["vendor"] = "opensearch"
        fixed_payload["vendor"] = "opensearch"

    vulnerable = enumerate_record(module, vulnerable_payload, catalog=load_catalog(), confirmed=True)
    fixed = enumerate_record(module, fixed_payload, catalog=load_catalog(), confirmed=True)

    assert cve_id in {finding["id"] for finding in vulnerable["findings"]}
    assert cve_id not in {finding["id"] for finding in fixed["findings"]}


def test_product_resolvers_distinguish_compatible_products() -> None:
    assert resolve_products("elastic", {"vendor": "elasticsearch", "server_version": "8.1.0"})[0].product_key == (
        "elasticsearch"
    )
    assert resolve_products("elastic", {"vendor": "opensearch", "server_version": "2.1.0"})[0].product_key == (
        "opensearch"
    )
    assert resolve_products("redis", {"implementation": "valkey", "server_version": "8.0.0"})[0].product_key == (
        "valkey"
    )
    assert resolve_products("keeper", {"version": "24.1.2"})[0].product_key == "clickhouse_keeper"
    assert resolve_products("zookeeper", {"is_keeper": False, "version": "3.8.4"})[0].product_key == (
        "apache_zookeeper"
    )
    assert resolve_products(
        "registry",
        {"is_harbor": True, "harbor_info": {"harbor_version": "v2.10.0"}},
    )[0] == DetectedProduct("harbor", "Harbor", "v2.10.0")


@pytest.mark.parametrize(
    ("module", "payload", "expected"),
    [
        ("airflow", {"version": "2.11.1"}, "apache_airflow"),
        ("clickhouse", {"server_version": "24.3.4.146"}, "clickhouse"),
        ("consul", {"version": "1.20.0"}, "hashicorp_consul"),
        ("docker", {"server_version": "27.1.0"}, "docker_engine"),
        ("elastic", {"vendor": "elasticsearch", "server_version": "8.15.0"}, "elasticsearch"),
        ("elastic", {"vendor": "opensearch", "server_version": "2.15.0"}, "opensearch"),
        ("etcd", {"server_version": "3.5.15"}, "etcd"),
        ("gitlab", {"version": "17.3.1-ee"}, "gitlab"),
        ("grafana", {"server_version": "11.2.0"}, "grafana"),
        ("kubeapi", {"version": "v1.31.0"}, "kubernetes"),
        ("minio", {"version": "RELEASE.2024-08-17T01-24-54Z"}, "minio"),
        ("mongodb", {"server_version": "7.0.14"}, "mongodb"),
        ("oracle", {"server_version": "19.0.0.0.0"}, "oracle_database"),
        ("postgres", {"server_version": "16.4"}, "postgresql"),
        ("proxmox", {"version": "8.2.4"}, "proxmox_ve"),
        ("qdrant", {"version": "1.15.6"}, "qdrant"),
        ("rabbitmq", {"version": "3.13.7"}, "rabbitmq"),
        ("redis", {"implementation": "redis", "server_version": "7.4.0"}, "redis"),
        ("redis", {"implementation": "valkey", "server_version": "8.0.0"}, "valkey"),
        ("zookeeper", {"version": "3.9.2"}, "apache_zookeeper"),
        ("keeper", {"version": "24.8.1.2684"}, "clickhouse_keeper"),
        ("registry", {"is_harbor": True, "harbor_info": {"harbor_version": "v2.11.1"}}, "harbor"),
        ("registry", {"is_nexus": True, "nexus_info": {"version": "3.72.0-04"}}, "nexus_repository"),
        ("registry", {"is_gitlab": True, "gitlab_info": {"version": "17.3.1-ee"}}, "gitlab"),
    ],
)
def test_all_supported_product_resolvers(module: str, payload: dict[str, object], expected: str) -> None:
    products = resolve_products(module, payload)
    assert [product.product_key for product in products] == [expected]
    assert products[0].version
    product_json = products[0].to_dict()
    assert product_json["normalized_version"]


def test_enumeration_performs_no_dns_or_external_http(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline CVE enumeration attempted network I/O")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    result = enumerate_record("grafana", {"server_version": "8.2.6"}, catalog=load_catalog(), confirmed=True)
    assert result["status"] == "matched"
    assert "CVE-2021-43798" in {finding["id"] for finding in result["findings"]}


def test_clickhouse_version_probe_is_read_only() -> None:
    from redposture_core.modules.clickhouse import actions

    queries: list[str] = []

    class Client:
        def execute(self, query: str) -> list[tuple[str]]:
            queries.append(query)
            return [("24.3.4.146",)]

    session = actions._ChSession("native", Client(), "default", "", "default")
    assert actions._read_clickhouse_version(session) == "24.3.4.146"
    assert queries == ["SELECT version()"]


def test_redis_version_probe_distinguishes_valkey() -> None:
    from redposture_core.modules.redis import actions

    assert actions._redis_server_identity("bulk", b"# Server\r\nredis_version:7.2.4\r\n") == ("redis", "7.2.4")
    assert actions._redis_server_identity("bulk", b"# Server\r\nvalkey_version:8.0.1\r\n") == ("valkey", "8.0.1")
    assert actions._redis_server_identity("error", b"NOAUTH") == (None, None)


def test_proxmox_version_probe_uses_resolved_read_only_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.proxmox import stage

    calls: list[tuple[str, dict[str, str]]] = []

    def request(_host: str, _port: int, path: str, *_args: object, auth_headers: dict[str, str], **_kwargs: object):
        calls.append((path, auth_headers))
        return 200, {"data": {"version": "8.2.4"}}, {}, None

    monkeypatch.setattr(stage.actions, "_proxmox_request", request)
    state = stage._ProxmoxLifecycleState(resolved_auth=({"Authorization": "PVE token"}, "token", None, None, []))
    ctx = SimpleNamespace(
        args=SimpleNamespace(enum_cve=True, timeout=1.0, retries=0, insecure=True, proxy=None, https=True),
        host="10.0.0.1",
        port=8006,
        target=None,
        lifecycle_state=state,
    )
    assert stage._proxmox_version_for_context(ctx, state) == "8.2.4"
    assert calls == [("/version", {"Authorization": "PVE token"})]


def test_registry_enum_cve_enables_vendor_fingerprints(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.registry import actions, stage

    seen: dict[str, object] = {}

    def detect(ctx: Any, options: dict[str, object]) -> dict[str, object]:
        seen.update(options)
        return {"host": ctx.host, "port": ctx.port, "status": "not_registry"}

    monkeypatch.setattr(actions, "detect_registry", detect)
    args = parse_args(["registry", "-t", "127.0.0.1", "--enum-cve"])
    spec = stage.build_registry_spec(args)
    assert spec.detect is not None
    spec.detect(SimpleNamespace(host="127.0.0.1", port=5000, target=None))
    assert seen["harbor"] is True
    assert seen["gitlab"] is True
    assert seen["nexus"] is True


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_enum_cve_flag_is_available_for_every_audit_module(module: str) -> None:
    args = parse_args([module, "-t", "127.0.0.1", "--enum-cve"])
    assert args.enum_cve is True


@pytest.mark.parametrize(
    "argv",
    [
        ["exporters", "scan", "-t", "127.0.0.1", "--enum-cve"],
        ["exporters", "collect", "-t", "127.0.0.1", "--enum-cve"],
        ["exporters", "trigger", "-t", "127.0.0.1", "--enum-cve"],
        ["--selfcert", "--enum-cve"],
    ],
)
def test_enum_cve_flag_is_rejected_outside_audit_modules(argv: list[str]) -> None:
    with pytest.raises(SystemExit):
        parse_args(argv)


def _grafana_spec(callbacks: list[dict[str, object]] | None = None) -> tuple[ModuleAuditSpec, SimpleNamespace]:
    def detect(ctx: object) -> AuditRecord:
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "service": "grafana",
                "status": "open_no_auth",
                "is_grafana": True,
                "server_version": "8.2.6",
            },
            module="grafana",
            service="grafana",
        )

    spec = ModuleAuditSpec(
        module="grafana",
        label="GRAFANA",
        default_port=3000,
        detect=detect,
        render=lambda record: [f"GRAFANA\t{record.host}\t{record.port}\t[*] Grafana Service"],
    )
    args = SimpleNamespace(
        enum_cve=True,
        debug=False,
        record_callback=(callbacks.append if callbacks is not None else None),
    )
    return spec, args


def test_runtime_inserts_cve_after_service_line_and_enriches_callbacks() -> None:
    emitted: list[str] = []
    callbacks: list[dict[str, object]] = []
    spec, args = _grafana_spec(callbacks)
    result = AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append).run_plan(
        AuditCommandPlan(targets_by_port={3000: ("10.0.0.1",)}, output_format="txt")
    )
    assert emitted[0].endswith("[*] Grafana Service")
    assert any("CVE-2021-43798 potentially affected (HIGH 7.5)" in line for line in emitted[1:])
    assert result.records[0]["cve_enumeration"]["status"] == "matched"
    assert "CVE-2021-43798" in {finding["id"] for finding in callbacks[0]["cve_enumeration"]["findings"]}


def test_runtime_json_contains_structured_result_and_no_extra_lines() -> None:
    emitted: list[str] = []
    spec, args = _grafana_spec()
    AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append).run_plan(
        AuditCommandPlan(targets_by_port={3000: ("10.0.0.1",)}, output_format="json")
    )
    assert len(emitted) == 1
    payload = json.loads(emitted[0])
    assert payload["cve_enumeration"]["status"] == "matched"
    assert payload["cve_enumeration"]["products"][0]["normalized_version"] == "8.2.6"
    findings = {finding["id"]: finding for finding in payload["cve_enumeration"]["findings"]}
    assert findings["CVE-2021-43798"]["fixed_version"] == "8.2.7"


def test_runtime_enables_low_privilege_findings_for_explicit_credentials() -> None:
    def detect(ctx: object) -> AuditRecord:
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "service": "grafana",
                "status": "auth_required",
                "auth_required": True,
                "is_grafana": True,
                "server_version": "11.0.0",
            },
            module="grafana",
            service="grafana",
        )

    spec = ModuleAuditSpec(
        module="grafana",
        label="GRAFANA",
        default_port=3000,
        detect=detect,
        render=lambda record: [f"GRAFANA\t{record.host}\t{record.port}\t[*] Grafana Service"],
    )
    args = SimpleNamespace(enum_cve=True, debug=False, username="user", password="pass")
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _line: None).run_plan(
        AuditCommandPlan(targets_by_port={3000: ("10.0.0.1",)}, output_format="json")
    )
    findings = {finding["id"]: finding for finding in result.records[0]["cve_enumeration"]["findings"]}
    assert findings["CVE-2024-9264"]["access_basis"] == "provided_credentials"


def test_default_credential_sweep_alone_does_not_enable_low_privilege_findings() -> None:
    spec = ModuleAuditSpec(
        module="grafana",
        label="GRAFANA",
        default_port=3000,
        detect=lambda ctx: AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "service": "grafana",
                "status": "auth_required",
                "auth_required": True,
                "is_grafana": True,
                "server_version": "11.0.0",
            },
            module="grafana",
            service="grafana",
        ),
        render=lambda record: [f"GRAFANA\t{record.host}\t{record.port}\t[*] Grafana Service"],
    )
    args = SimpleNamespace(enum_cve=True, debug=False, defcreds=True)
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _line: None).run_plan(
        AuditCommandPlan(targets_by_port={3000: ("10.0.0.1",)}, output_format="json")
    )
    findings = {finding["id"] for finding in result.records[0]["cve_enumeration"]["findings"]}
    assert "CVE-2024-9264" not in findings


def test_runtime_without_flag_preserves_record_and_text() -> None:
    emitted: list[str] = []
    spec, args = _grafana_spec()
    args.enum_cve = False
    result = AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append).run_plan(
        AuditCommandPlan(targets_by_port={3000: ("10.0.0.1",)}, output_format="txt")
    )
    assert emitted == ["GRAFANA\t10.0.0.1\t3000\t[*] Grafana Service"]
    assert "cve_enumeration" not in result.records[0]


def test_debug_reports_unknown_version_without_normal_txt_noise() -> None:
    emitted: list[str] = []
    debug: list[str] = []
    spec = ModuleAuditSpec(
        module="grafana",
        label="GRAFANA",
        default_port=3000,
        detect=lambda ctx: AuditRecord.from_mapping(
            {"host": ctx.host, "port": ctx.port, "status": "detected", "is_grafana": True},
            module="grafana",
            service="grafana",
        ),
        render=lambda _record: ["service"],
    )
    args = SimpleNamespace(enum_cve=True, debug=True, debug_emit=debug.append)
    AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append).run_plan(
        AuditCommandPlan(targets_by_port={3000: ("host",)}, output_format="txt")
    )
    assert emitted == ["service"]
    assert any("status=version_unknown" in line for line in debug)


def test_invalid_catalog_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text('{"schema_version": 1, "entries": []}', encoding="utf-8")
    import redposture_core.cve as cve

    cve.load_catalog.cache_clear()
    monkeypatch.setattr(cve, "_catalog_path", lambda: broken)
    with pytest.raises(CveCatalogError, match="catalog_version"):
        cve.load_catalog()
    cve.load_catalog.cache_clear()


def test_invalid_catalog_ranges_fail_closed(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    import redposture_core.cve as cve

    base_entry = {
        "id": "CVE-2099-10000",
        "product": "example",
        "title": "Example remote command execution",
        "severity": "CRITICAL",
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "rce",
        "affected": [
            {"introduced": "1.0.0", "fixed": "2.0.0"},
            {"introduced": "1.0.0", "fixed": "2.0.0"},
        ],
        "references": ["https://example.invalid/advisory"],
        "verified_at": "2026-09-20",
    }
    path = tmp_path / "duplicate.json"
    path.write_text(
        json.dumps({"schema_version": 1, "catalog_version": "test", "entries": [base_entry]}),
        encoding="utf-8",
    )
    cve.load_catalog.cache_clear()
    monkeypatch.setattr(cve, "_catalog_path", lambda: path)
    with pytest.raises(CveCatalogError, match="duplicate affected range"):
        cve.load_catalog()

    base_entry["affected"] = [{"introduced": "major-only", "fixed": "2.0.0"}]
    path.write_text(
        json.dumps({"schema_version": 1, "catalog_version": "test", "entries": [base_entry]}),
        encoding="utf-8",
    )
    cve.load_catalog.cache_clear()
    with pytest.raises(CveCatalogError, match="invalid introduced version"):
        cve.load_catalog()

    base_entry["affected"] = [
        {"introduced": "1.0.0", "fixed": "3.0.0"},
        {"introduced": "2.0.0", "fixed": "4.0.0"},
    ]
    path.write_text(
        json.dumps({"schema_version": 1, "catalog_version": "test", "entries": [base_entry]}),
        encoding="utf-8",
    )
    cve.load_catalog.cache_clear()
    with pytest.raises(CveCatalogError, match="affected ranges must not overlap"):
        cve.load_catalog()
    cve.load_catalog.cache_clear()


def test_catalog_rejects_high_privilege_entries(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    import redposture_core.cve as cve

    path = tmp_path / "high-privilege.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "catalog_version": "test",
                "entries": [
                    {
                        "id": "CVE-2099-10000",
                        "product": "example",
                        "title": "Example remote command execution",
                        "severity": "HIGH",
                        "score": 8.0,
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                        "impact": "rce",
                        "affected": [{"fixed": "2.0.0"}],
                        "references": ["https://example.invalid/advisory"],
                        "verified_at": "2026-09-20",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    cve.load_catalog.cache_clear()
    monkeypatch.setattr(cve, "_catalog_path", lambda: path)
    with pytest.raises(CveCatalogError, match="exactly one of PR:N or PR:L"):
        cve.load_catalog()
    cve.load_catalog.cache_clear()
