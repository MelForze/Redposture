from __future__ import annotations

import base64
import json
from hashlib import sha256
from typing import Any

import pytest

from redposture_core.modules.elastic import actions as elastic_actions
from redposture_core.modules.elastic import discover as elastic_discover
from redposture_core.modules.elastic.discover import (
    DetectedSecret,
    DiscoverCoverage,
    DiscoverEngine,
    DiscoverOptions,
    DiscoverRequest,
    DiscoverResponse,
    DiscoveryBudget,
    FindingAccumulator,
    FindingLocation,
    MappedField,
    analyze_value,
    build_signature_queries,
    build_signature_query,
    build_targeted_query,
    classify_field,
    extract_mapping_fields,
    normalize_field_name,
    run_discovery,
    scan_value_tree,
)


def _walk_strings(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            strings.append(str(key))
            strings.extend(_walk_strings(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            strings.extend(_walk_strings(item))
    return strings


@pytest.mark.parametrize(
    ("variant", "canonical"),
    [
        ("clientSecret", "client_secret"),
        ("client-secret", "client_secret"),
        ("client.secret", "client_secret"),
        ("Client Secret", "client_secret"),
        ("CLIENT_SECRET", "client_secret"),
    ],
)
def test_field_normalization_is_separator_and_case_independent(variant: str, canonical: str) -> None:
    assert normalize_field_name(variant) == normalize_field_name(canonical)


@pytest.mark.parametrize(
    "field_name",
    [
        "password",
        "database.passwd",
        "credentials.pwd",
        "oauth.clientSecret",
        "aws.secret-access-key",
        "request.authorization",
        "service.apiToken",
        "oauth.refresh_token",
        "connectionString",
        "database.dsn",
    ],
)
def test_sensitive_field_classification_covers_nested_and_camel_case_names(field_name: str) -> None:
    assert classify_field(field_name) == "strong"


@pytest.mark.parametrize(
    "field_name",
    [
        "public_key",
        "tls.certificate",
        "kms.key_id",
        "api_key_id",
        "oauth.token_id",
        "username",
        "email",
        "password_policy",
        "token_count",
        "content_checksum",
        "document_hash",
    ],
)
def test_identifier_and_public_material_fields_are_excluded(field_name: str) -> None:
    assert classify_field(field_name) == "excluded"


def test_extract_mapping_fields_finds_nested_index_false_runtime_and_metadata() -> None:
    mapping = {
        "logs": {
            "mappings": {
                "_meta": {"deployment": {"clientSecret": "meta-secret"}},
                "dynamic_templates": [
                    {
                        "credential_strings": {
                            "path_match": "*.password",
                            "mapping": {"type": "keyword"},
                        }
                    }
                ],
                "runtime": {
                    "derivedToken": {
                        "type": "keyword",
                        "script": {"source": "emit(params.apiToken)", "params": {"apiToken": "runtime-secret"}},
                    }
                },
                "properties": {
                    "service": {
                        "properties": {
                            "clientSecret": {"type": "keyword"},
                            "credentials": {
                                "type": "object",
                                "enabled": False,
                            },
                        }
                    },
                    "message": {"type": "text"},
                },
            }
        }
    }

    fields = extract_mapping_fields(mapping)
    serialized = json.dumps([field.to_dict() for field in fields], sort_keys=True)

    assert "service.clientSecret" in serialized
    assert "service.credentials" in serialized
    assert "derivedToken" in serialized
    assert "dynamic_templates" in serialized
    assert "_meta" in serialized


def test_targeted_query_is_structured_and_has_a_bounded_clause_count() -> None:
    fields = [f"service_{index}.password" for index in range(40)]
    query = build_targeted_query(fields)
    serialized = json.dumps(query, sort_keys=True)

    assert "simple_query_string" not in serialized
    assert '"query_string"' not in serialized
    assert "-----BEGIN" not in serialized
    assert " OR " not in serialized

    bool_nodes = [
        value for value in _walk_dict_values(query) if isinstance(value, dict) and isinstance(value.get("should"), list)
    ]
    assert bool_nodes
    assert max(len(node["should"]) for node in bool_nodes) <= 24


def test_signature_query_never_uses_parser_syntax_or_negative_begin_marker() -> None:
    query = build_signature_query(["message", "event.original", "payload"])
    strings = _walk_strings(query)
    serialized = json.dumps(query, sort_keys=True)

    assert "simple_query_string" not in serialized
    assert '"query_string"' not in serialized
    assert " OR " not in serialized
    assert all(not value.startswith("-") for value in strings)
    assert "-----BEGIN" not in serialized


def test_signature_queries_cover_all_mapped_blob_fields_with_bounded_clauses() -> None:
    fields = [MappedField("logs", f"payload.field_{offset}", "text", "neutral") for offset in range(130)]

    queries = build_signature_queries(fields)
    serialized = json.dumps(queries, sort_keys=True)
    requested = {value for query in queries for value in _walk_strings(query) if value.startswith("payload.field_")}
    should_nodes = [
        value
        for query in queries
        for value in _walk_dict_values(query)
        if isinstance(value, dict) and isinstance(value.get("should"), list)
    ]

    assert requested == {field.path for field in fields}
    assert should_nodes
    assert all(len(node["should"]) <= 24 for node in should_nodes)
    assert "simple_query_string" not in serialized


def _walk_dict_values(value: Any) -> list[Any]:
    values: list[Any] = []
    if isinstance(value, dict):
        for item in value.values():
            values.append(item)
            values.extend(_walk_dict_values(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            values.append(item)
            values.extend(_walk_dict_values(item))
    return values


@pytest.mark.parametrize(
    ("value", "secret_type", "expected_value"),
    [
        (
            "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----",
            "private_key",
            "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----",
        ),
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart",
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart",
        ),
        ("AIza" + "a" * 35, "google_api_key", "AIza" + "a" * 35),
        ("ghp_" + "a" * 36, "github_token", "ghp_" + "a" * 36),
        ("glpat-" + "a" * 20, "gitlab_token", "glpat-" + "a" * 20),
        ("xoxb-" + "1" * 12 + "-" + "a" * 24, "slack_token", "xoxb-" + "1" * 12 + "-" + "a" * 24),
        ("sk_live_" + "a" * 24, "stripe_key", "sk_live_" + "a" * 24),
        ("hvs." + "a" * 24, "vault_token", "hvs." + "a" * 24),
        ("npm_" + "a" * 32, "npm_token", "npm_" + "a" * 32),
        ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "password", "password"),
        ("postgresql://alice:p%40ssword@db.internal/app", "password", "p@ssword"),
        ("client_secret=opaque-secret-value", "secret", "opaque-secret-value"),
    ],
)
def test_strong_value_detectors_preserve_full_secret_values(
    value: str,
    secret_type: str,
    expected_value: str,
) -> None:
    detections = analyze_value(value, path="message")

    assert any(
        detection.secret_type == secret_type
        and detection.value == expected_value
        and detection.available
        and detection.score >= 55
        for detection in detections
    )


def test_jwe_detector_supports_direct_encryption_with_empty_key_segment() -> None:
    header = base64.urlsafe_b64encode(b'{"alg":"dir","enc":"A256GCM"}').rstrip(b"=").decode()
    token = f"{header}..aW5pdHZlY3Rvcg.Y2lwaGVydGV4dA.YXV0aHRhZw"

    detections = analyze_value(token, path="authorization")

    assert any(item.secret_type == "jwe" and item.value == token and item.score >= 90 for item in detections)
    assert all(item.secret_type != "jwt" for item in detections)


def test_exact_sensitive_field_accepts_weak_but_real_password() -> None:
    detections = analyze_value("changeme", path="database.password")

    assert [(item.secret_type, item.value) for item in detections] == [("password", "changeme")]
    assert detections[0].score >= 75


def test_aws_access_key_is_only_reported_with_its_secret_pair() -> None:
    access_key = "AKIA1234567890ABCDEF"
    standalone = analyze_value(access_key, path="message")
    pair = scan_value_tree(
        {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        source_kind="document",
        object_name="logs/aws",
    )

    assert standalone and all(not item.available for item in standalone)
    assert any(
        item.secret_type == "aws_secret_access_key"
        and item.value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        and item.score >= 90
        for item, _ in pair.detections
    )
    weak_pair = scan_value_tree(
        {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": "long-but-not-an-aws-secret",
        },
        source_kind="document",
        object_name="logs/aws-invalid",
    )
    assert all("aws_credential_pair" not in item.detectors for item, _ in weak_pair.detections)


@pytest.mark.parametrize("value", ["${PASSWORD}", "{{ vault.password }}", "<redacted>", "REDACTED", "********"])
def test_placeholders_are_counted_but_never_exported_as_findings(value: str) -> None:
    scalar = analyze_value(value, path="password")
    tree = scan_value_tree(
        {"password": value},
        source_kind="document",
        object_name="logs/doc-1",
        index="logs",
        document_id="doc-1",
    )

    assert scalar and all(not item.available and item.score < 55 for item in scalar)
    assert tree.detections == []
    assert tree.suppressed_indicators == 1


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("message", "authentication failed: invalid password"),
        ("public_key", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC"),
        ("certificate", "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"),
        ("api_key_id", "key-id-1234567890"),
        ("token_id", "4aa53929-1234-4567-9abc-aabbccddeeff"),
        ("checksum", "8f14e45fceea167a5a36dedd4bea2543"),
        ("finance.transaction_id", "550e8400-e29b-41d4-a716-446655440000"),
        ("service", "elastic"),
    ],
)
def test_common_logs_identifiers_and_public_material_are_not_secrets(path: str, value: str) -> None:
    assert analyze_value(value, path=path) == []


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("token", "expired"),
        ("auth", "required"),
        ("session", "complete"),
        ("key", "Escape"),
    ],
)
def test_medium_fields_suppress_common_state_and_keyboard_words(path: str, value: str) -> None:
    assert analyze_value(value, path=path) == []


def test_recursive_scanner_finds_nested_lists_embedded_json_and_base64_credentials() -> None:
    payload = {
        "services": [
            {
                "credentials": {
                    "apiKey": "opaque-service-api-key",
                    "dockerAuth": "dXNlcjpzdXBlci1zZWNyZXQ=",
                }
            }
        ],
        "embedded": json.dumps({"oauth": {"clientSecret": "embedded-client-secret"}}),
    }

    result = scan_value_tree(
        payload,
        source_kind="document",
        object_name="logs/doc-42",
        index="logs",
        document_id="doc-42",
    )
    detected = {(item.secret_type, item.value, location.path) for item, location in result.detections}

    assert ("secret", "opaque-service-api-key", "/services/0/credentials/apiKey") in detected
    assert ("secret", "embedded-client-secret", "/embedded/oauth/clientSecret") in detected
    assert all(location.index == "logs" and location.id == "doc-42" for _, location in result.detections)


def test_semantic_kind_value_pair_detects_generic_secret_documents() -> None:
    result = scan_value_tree(
        {"kind": "api_key", "value": "elastic-prod-api-key-2026"},
        source_kind="document",
        object_name="secrets/secret-1",
        index="secrets",
        document_id="secret-1",
    )

    assert any(
        detection.value == "elastic-prod-api-key-2026"
        and "sensitive_field" in detection.detectors
        and location.path == "/value"
        for detection, location in result.detections
    )


def test_base64_is_decoded_only_in_a_credential_context() -> None:
    encoded = "dXNlcjpzdXBlci1zZWNyZXQ="

    credential_context = scan_value_tree(
        {"auth": encoded},
        source_kind="document",
        object_name="logs/credential",
    )
    neutral_context = scan_value_tree(
        {"blob": encoded},
        source_kind="document",
        object_name="logs/blob",
    )

    assert any(
        item.value == "super-secret" and "base64_credential" in item.detectors
        for item, _ in credential_context.detections
    )
    assert all(item.value != "super-secret" for item, _ in neutral_context.detections)


def test_base64_password_leaf_exports_decoded_value_instead_of_encoded_wrapper() -> None:
    encoded = "U3VwZXItU2VjcmV0LTEyMw=="
    result = scan_value_tree(
        {"password": encoded},
        source_kind="document",
        object_name="logs/kubernetes-secret",
    )
    values = {item.value for item, _location in result.detections}

    assert "Super-Secret-123" in values
    assert encoded not in values


def test_base64_service_account_json_is_scanned_once_for_inner_credentials() -> None:
    private_key = "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----"
    encoded = base64.b64encode(
        json.dumps(
            {
                "type": "service_account",
                "client_secret": "google-client-secret",
                "private_key": private_key,
            }
        ).encode()
    ).decode()
    result = scan_value_tree(
        {"credentials": encoded},
        source_kind="document",
        object_name="logs/service-account",
    )
    values = {item.value for item, _location in result.detections}

    assert "google-client-secret" in values
    assert private_key in values
    assert encoded not in values
    assert all(item.secret_type != "encoded_credentials" for item, _location in result.detections)


def test_recursive_scanner_reports_each_traversal_limit() -> None:
    options = DiscoverOptions(
        max_depth=2,
        max_array_items=1,
        max_scalar_bytes=8,
        max_embedded_json_bytes=4,
    )
    result = scan_value_tree(
        {
            "nested": {"deeper": {"password": "must-not-be-reached"}},
            "items": [{"password": "first-secret"}, {"password": "second-secret"}],
            "password": "a-very-long-secret",
        },
        source_kind="document",
        object_name="logs/limited",
        options=options,
    )

    assert {"max_depth", "max_array_items", "max_scalar_bytes"} <= set(result.truncated_reasons)


def test_finding_accumulator_deduplicates_by_secret_and_merges_locations() -> None:
    detection = analyze_value("same-full-secret", path="password")[0]
    first = FindingLocation(
        source_kind="document",
        object="logs/doc-1",
        index="logs",
        id="doc-1",
        path="/password",
    )
    second = FindingLocation(
        source_kind="ingest_pipeline",
        object="pipeline-1",
        path="/processors/0/set/value",
    )
    accumulator = FindingAccumulator()

    assert accumulator.add(detection, first) is True
    assert accumulator.add(
        DetectedSecret(
            value=detection.value,
            secret_type=detection.secret_type,
            score=95,
            detectors=("strong_format",),
        ),
        second,
    )

    finding = accumulator.findings()[0]
    expected_digest = sha256(b"password\0same-full-secret").hexdigest()
    assert finding.fingerprint == f"sha256:{expected_digest}"
    assert finding.value == "same-full-secret"
    assert finding.score == 95
    assert finding.confidence == "very_high"
    assert finding.occurrence_count == 2
    assert {"sensitive_field", "strong_format"} <= set(finding.detectors)
    assert [location.to_dict() for location in finding.locations] == [first.to_dict(), second.to_dict()]


def test_finding_accumulator_does_not_count_same_location_twice() -> None:
    accumulator = FindingAccumulator()
    detection = DetectedSecret("same-secret", "password", 85, ("sensitive_field",))
    location = FindingLocation("document", "logs/doc-1", "/password", index="logs", id="doc-1")

    assert accumulator.add(detection, location)
    assert accumulator.add(detection, location)

    assert accumulator.findings()[0].occurrence_count == 1
    assert accumulator.findings()[0].locations == [location]


def test_finding_accumulator_enforces_finding_and_location_caps() -> None:
    accumulator = FindingAccumulator(max_findings=1, max_locations=2)
    first_secret = DetectedSecret("first-secret", "password", 85, ("sensitive_field",))
    second_secret = DetectedSecret("second-secret", "password", 85, ("sensitive_field",))

    for offset in range(3):
        assert accumulator.add(
            first_secret,
            FindingLocation("document", f"logs/{offset}", f"/password/{offset}"),
        )
    assert accumulator.add(second_secret, FindingLocation("document", "logs/other", "/password")) is False

    assert accumulator.limit_reached is True
    assert accumulator.locations_dropped == 1
    assert accumulator.findings()[0].occurrence_count == 3
    assert len(accumulator.findings()[0].locations) == 2


def test_discovery_budget_stops_before_exceeding_document_and_byte_limits() -> None:
    document_budget = DiscoveryBudget(DiscoverOptions(max_documents=2, max_source_bytes=100, max_seconds=300))

    assert document_budget.consume_document(4)
    assert document_budget.consume_document(6)
    assert document_budget.documents == 2
    assert document_budget.source_bytes == 10
    assert document_budget.consume_document(1) is False
    assert document_budget.stopped is True
    assert document_budget.reasons == ["max_documents"]

    byte_budget = DiscoveryBudget(DiscoverOptions(max_documents=10, max_source_bytes=10, max_seconds=300))
    assert byte_budget.consume_document(10)
    assert byte_budget.consume_document(1) is False
    assert byte_budget.documents == 1
    assert byte_budget.source_bytes == 10
    assert byte_budget.reasons == ["max_source_bytes"]


def test_discovery_budget_tracks_time_and_finding_limits() -> None:
    current = 0.0

    def monotonic() -> float:
        return current

    budget = DiscoveryBudget(
        DiscoverOptions(max_documents=10, max_source_bytes=100, max_seconds=3, max_findings=2),
        monotonic=monotonic,
    )
    assert budget.check(findings=1)
    current = 3.0
    assert budget.check(findings=3) is False
    assert budget.reasons == ["max_seconds", "max_findings"]


def test_documents_without_source_still_consume_unique_document_budget() -> None:
    engine = DiscoverEngine(
        lambda _request: DiscoverResponse(status=200, payload=b"{}"),
        options=DiscoverOptions(max_documents=1),
    )

    engine._process_hit("logs", {"_index": "logs", "_id": "missing-1"}, candidate=False, payload_complete=True)
    engine._process_hit("logs", {"_index": "logs", "_id": "missing-1"}, candidate=False, payload_complete=True)
    engine._process_hit("logs", {"_index": "logs", "_id": "missing-2"}, candidate=False, payload_complete=True)

    assert engine.budget.documents == 1
    assert engine.budget.reasons == ["max_documents"]
    assert engine.coverage.missing_source_documents == 1
    assert engine.coverage.duplicate_documents == 1


def test_engine_stops_after_an_additional_unique_finding_exceeds_cap() -> None:
    engine = DiscoverEngine(
        lambda _request: DiscoverResponse(status=200, payload=b"{}"),
        options=DiscoverOptions(max_findings=1),
    )

    engine._scan_configuration(
        "cluster_settings",
        {"password": "first-secret", "client_secret": "second-secret"},
        object_name="_cluster/settings",
        source_kind="cluster_settings",
    )

    assert len(engine.accumulator) == 1
    assert engine.accumulator.limit_reached is True
    assert engine.budget.reasons == ["max_findings"]


@pytest.mark.parametrize(
    ("source_kind", "object_name", "payload", "expected_value"),
    [
        (
            "ingest_pipeline",
            "redact-and-route",
            {
                "processors": [
                    {
                        "set": {
                            "field": "headers.Authorization",
                            "value": "Bearer pipeline-token-value",
                        }
                    }
                ]
            },
            "pipeline-token-value",
        ),
        (
            "component_template",
            "service-settings",
            {"template": {"mappings": {"_meta": {"clientSecret": "template-secret"}}}},
            "template-secret",
        ),
        (
            "node_settings",
            "node-a",
            {"settings": {"node": {"attr": {"lab_password": "node-setting-secret"}}}},
            "node-setting-secret",
        ),
        (
            "mapping",
            "logs",
            {
                "derived": {
                    "credential_hint": {
                        "type": "keyword",
                        "script": {"params": {"apiToken": "derived-secret"}},
                    }
                }
            },
            "derived-secret",
        ),
    ],
)
def test_configuration_response_shapes_are_scanned_read_only(
    source_kind: str,
    object_name: str,
    payload: dict[str, Any],
    expected_value: str,
) -> None:
    result = scan_value_tree(payload, source_kind=source_kind, object_name=object_name)

    matching = [(item, location) for item, location in result.detections if item.value == expected_value]
    assert matching
    assert all(location.source_kind == source_kind and location.object == object_name for _, location in matching)


def test_ingest_set_processor_uses_field_name_as_context_for_opaque_value() -> None:
    pipeline = {
        "processors": [
            {
                "set": {
                    "field": "database.password",
                    "value": "opaque-pipeline-password",
                }
            }
        ]
    }

    result = scan_value_tree(
        pipeline,
        source_kind="ingest_pipelines",
        object_name="credential-injector",
    )

    assert any(
        detection.value == "opaque-pipeline-password"
        and detection.secret_type == "password"
        and location.path == "/processors/0/set/value"
        for detection, location in result.detections
    )


def test_signature_query_wraps_nested_blob_fields_in_nested_query() -> None:
    field = MappedField(
        index="logs",
        path="events.payload",
        field_type="text",
        classification="neutral",
        nested_path="events",
    )

    query = build_signature_query([field])
    serialized = json.dumps(query, sort_keys=True)

    assert '"nested"' in serialized
    assert '"path": "events"' in serialized
    assert "events.payload" in serialized


def _response(
    payload: Any,
    *,
    status: int = 200,
    error: str | None = None,
    truncated: bool = False,
) -> tuple[int, bytes, dict[str, str], str | None, bool]:
    return (
        status,
        json.dumps(payload, separators=(",", ":")).encode(),
        {"Content-Type": "application/json"},
        error,
        truncated,
    )


def test_run_discovery_paginates_beyond_200_updates_and_closes_pit() -> None:
    requests: list[DiscoverRequest] = []
    search_bodies: list[dict[str, Any]] = []
    close_bodies: list[dict[str, Any]] = []
    pit_sequence = 0

    def request(item: DiscoverRequest) -> tuple[int, bytes, dict[str, str], str | None, bool]:
        nonlocal pit_sequence
        requests.append(item)
        body = json.loads(item.body) if item.body else {}

        if item.path == "/_resolve/index/*?expand_wildcards=all":
            return _response(
                {
                    "indices": [
                        {"name": "logs", "attributes": ["open"]},
                        {"name": "archive", "attributes": ["closed"]},
                    ]
                }
            )
        if item.path.startswith("/logs/_mapping"):
            return _response(
                {
                    "logs": {
                        "mappings": {
                            "properties": {
                                "message": {"type": "text"},
                                "database": {
                                    "properties": {
                                        "password": {"type": "keyword"},
                                    }
                                },
                            }
                        }
                    }
                }
            )
        if item.path.startswith("/logs/_settings"):
            return _response({"logs": {"settings": {"index": {"number_of_shards": "1"}}}})
        if item.path == "/_cluster/settings?flat_settings=false&include_defaults=false":
            return _response({"persistent": {}, "transient": {}}, truncated=True)
        if item.path.startswith("/_nodes/settings?"):
            return _response(
                {
                    "error": {
                        "type": "security_exception",
                        "reason": "missing privilege",
                    },
                    "status": 403,
                },
                status=403,
            )
        if item.path in {"/_index_template", "/_component_template", "/_template"}:
            return _response({})
        if item.path == "/_ingest/pipeline":
            return _response(
                {
                    "route-events": {
                        "processors": [
                            {
                                "set": {
                                    "field": "headers.Authorization",
                                    "value": "Bearer pipeline-token-value",
                                }
                            }
                        ]
                    }
                }
            )
        if item.method == "POST" and item.path.startswith("/logs/_pit?"):
            pit_sequence += 1
            return _response({"id": f"pit-open-{pit_sequence}"}, status=201)
        if item.method == "DELETE" and item.path == "/_pit":
            close_bodies.append(body)
            return _response({"succeeded": True})
        if item.method == "POST" and item.path == "/_search":
            search_bodies.append(body)
            query = body.get("query")
            if query != {"match_all": {}}:
                return _response(
                    {
                        "hits": {
                            "total": {"value": 0, "relation": "eq"},
                            "hits": [],
                        }
                    }
                )

            search_after = body.get("search_after")
            if search_after is None:
                benign_hits = [
                    {
                        "_index": "logs",
                        "_id": f"finance-{offset}",
                        "_source": {
                            "transaction_id": f"550e8400-e29b-41d4-a716-{offset:012d}",
                            "message": "token expired after invalid password",
                            "amount": offset,
                        },
                        "sort": [offset],
                    }
                    for offset in range(200)
                ]
                return _response(
                    {
                        "pit_id": "pit-sweep-page-1",
                        "_shards": {"total": 1, "successful": 1, "failed": 0},
                        "hits": {
                            "total": {"value": 203, "relation": "eq"},
                            "hits": benign_hits,
                        },
                    }
                )
            if search_after == [199]:
                return _response(
                    {
                        "pit_id": "pit-sweep-page-2",
                        "_shards": {
                            "total": 2,
                            "successful": 1,
                            "failed": 1,
                            "failures": [
                                {
                                    "index": "logs",
                                    "reason": {
                                        "type": "query_shard_exception",
                                        "reason": "one synthetic failed shard",
                                    },
                                }
                            ],
                        },
                        "hits": {
                            "total": {"value": 203, "relation": "eq"},
                            "hits": [
                                {
                                    "_index": "logs",
                                    "_id": "secret-after-page-200",
                                    "_source": {"database": {"password": "after-page-secret"}},
                                    "sort": [200],
                                },
                                {
                                    "_index": "logs",
                                    "_id": "fields-only",
                                    "fields": {"password": ["field-only-secret"]},
                                    "sort": [201],
                                },
                                {
                                    "_index": "logs",
                                    "_id": "stored-only",
                                    "stored_fields": {"clientSecret": ["stored-only-secret"]},
                                    "sort": [202],
                                },
                            ],
                        },
                    }
                )
            assert search_after == [202]
            assert body["pit"]["id"] == "pit-sweep-page-2"
            return _response(
                {
                    "hits": {
                        "total": {"value": 203, "relation": "eq"},
                        "hits": [],
                    }
                }
            )

        raise AssertionError(f"unexpected discover request: {item.method} {item.path}")

    report = run_discovery(
        request,
        vendor="elasticsearch",
        options=DiscoverOptions(page_size=200),
    )
    payload = report.to_dict()
    values = {finding["value"] for finding in payload["discover_findings"]}

    assert {
        "after-page-secret",
        "field-only-secret",
        "stored-only-secret",
        "pipeline-token-value",
    } <= values
    assert not any("550e8400" in value for value in values)
    assert report.schema_version == 2
    assert report.coverage.indices_enumerated == 2
    assert report.coverage.indices_closed == 1
    assert report.coverage.indices_scanned == 1
    assert report.coverage.documents_scanned == 203
    assert report.coverage.pages_scanned >= 4
    assert report.coverage.surfaces["node_settings"].status == "denied"
    assert report.coverage.shard_failures
    assert "cluster_settings:response_size_cap" in report.coverage.truncated_reasons
    assert payload["discover_coverage"]["complete"] is False
    assert any(
        body.get("search_after") == [199] and body.get("pit", {}).get("id") == "pit-sweep-page-1"
        for body in search_bodies
    )
    assert {"id": "pit-sweep-page-2"} in close_bodies
    assert not any("/archive/" in item.path for item in requests)
    assert payload["discover_results"][0]["index"] == "logs"


def test_source_disabled_mapping_requests_bounded_fields_without_executing_runtime_scripts() -> None:
    search_bodies: list[dict[str, Any]] = []
    pit_count = 0

    def request(item: DiscoverRequest) -> tuple[int, bytes, dict[str, str], str | None, bool]:
        nonlocal pit_count
        body = json.loads(item.body) if item.body else {}
        if item.path == "/_resolve/index/*?expand_wildcards=all":
            return _response({"indices": [{"name": "logs", "attributes": ["open"]}]})
        if item.path.startswith("/logs/_mapping"):
            return _response(
                {
                    "logs": {
                        "mappings": {
                            "_source": {"enabled": False},
                            "runtime": {
                                "runtimeSecret": {
                                    "type": "keyword",
                                    "script": {"source": "emit('constant')"},
                                }
                            },
                            "derived": {
                                "derivedSecret": {
                                    "type": "keyword",
                                    "script": {"source": "emit('constant')"},
                                }
                            },
                            "properties": {
                                "password": {
                                    "type": "keyword",
                                    "store": True,
                                },
                                "message": {"type": "text"},
                            },
                        }
                    }
                }
            )
        if item.path.startswith("/logs/_settings"):
            return _response({"logs": {"settings": {}}})
        if item.path in {
            "/_cluster/settings?flat_settings=false&include_defaults=false",
            "/_nodes/settings?flat_settings=false&include_defaults=false",
            "/_index_template",
            "/_component_template",
            "/_template",
            "/_ingest/pipeline",
        }:
            return _response({})
        if item.method == "POST" and item.path.startswith("/logs/_pit?"):
            pit_count += 1
            return _response({"id": f"pit-{pit_count}"}, status=201)
        if item.method == "DELETE" and item.path == "/_pit":
            return _response({"succeeded": True})
        if item.method == "POST" and item.path == "/_search":
            search_bodies.append(body)
            if "search_after" in body:
                return _response(
                    {
                        "hits": {
                            "total": {"value": 1, "relation": "eq"},
                            "hits": [],
                        }
                    }
                )
            field_names = set(_walk_strings(body.get("fields", [])))
            stored_field_names = set(_walk_strings(body.get("stored_fields", [])))
            can_return_value = "password" in field_names or "password" in stored_field_names
            return _response(
                {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_index": "logs",
                                "_id": f"source-disabled-{len(search_bodies)}",
                                **({"fields": {"password": ["source-disabled-secret"]}} if can_return_value else {}),
                                "sort": [1],
                            }
                        ],
                    }
                }
            )
        raise AssertionError(f"unexpected source-disabled request: {item.method} {item.path}")

    report = run_discovery(request, vendor="elasticsearch")
    serialized_bodies = [json.dumps(body, sort_keys=True) for body in search_bodies]
    requested_fields = [item for body in search_bodies for item in _walk_strings(body.get("fields", []))]
    requested_stored_fields = [item for body in search_bodies for item in _walk_strings(body.get("stored_fields", []))]

    assert "source-disabled-secret" in {finding.value for finding in report.findings}
    assert "password" in requested_fields
    assert "password" in requested_stored_fields
    assert "*" not in requested_fields
    assert "*" not in requested_stored_fields
    assert all("runtimeSecret" not in body and "derivedSecret" not in body for body in serialized_bodies)
    coverage = report.coverage.to_dict()
    assert coverage["complete"] is False
    assert coverage["source_disabled_indices"] == ["logs"]
    assert "document:logs:source_disabled" in coverage["truncated_reasons"]


def test_mapping_source_policy_detects_disabled_and_filtered_sources() -> None:
    disabled = {"logs": {"mappings": {"_source": {"enabled": False}}}}
    filtered = {"logs": {"mappings": {"_source": {"includes": ["public.*"], "excludes": ["credentials.*"]}}}}

    assert elastic_discover._mapping_source_policy(disabled, "logs") == (True, False)
    assert elastic_discover._mapping_source_policy(filtered, "logs") == (False, True)


def test_truncated_mapping_batch_is_split_without_poisoning_recovered_coverage() -> None:
    requests: list[str] = []

    def request(item: DiscoverRequest) -> tuple[int, bytes, dict[str, str], str | None, bool]:
        requests.append(item.path)
        encoded_batch = item.path.removeprefix("/").split("/", 1)[0]
        indices = encoded_batch.split(",")
        if len(indices) == 4:
            return _response({indices[0]: {"mappings": {}}}, truncated=True)
        return _response({index: {"mappings": {}} for index in indices})

    engine = DiscoverEngine(request, options=DiscoverOptions(mapping_batch_size=20))
    mappings = engine._fetch_index_resource(
        ["a", "b", "c", "d"],
        suffix="_mapping?expand_wildcards=open,hidden",
        surface_name="mappings",
    )
    surface = engine.coverage.surfaces["mappings"]

    assert set(mappings) == {"a", "b", "c", "d"}
    assert len(requests) == 3
    assert surface.status == "complete"
    assert surface.objects_attempted == 4
    assert surface.objects_scanned == 4
    assert engine.coverage.truncated is False


def test_pit_is_closed_when_a_search_request_fails() -> None:
    requests: list[DiscoverRequest] = []

    def request(item: DiscoverRequest) -> DiscoverResponse:
        requests.append(item)
        if item.method == "POST" and item.path == "/_search":
            raise OSError("synthetic search failure")
        return DiscoverResponse(status=200, payload=b'{"succeeded":true}')

    engine = DiscoverEngine(request, vendor="elasticsearch")
    completed = engine._paginate_pit(
        "logs",
        {"query": {"match_all": {}}},
        candidate=False,
        pit_id="pit-error",
        payload_complete=True,
    )

    assert completed is False
    cleanup = [item for item in requests if item.method == "DELETE" and item.path == "/_pit"]
    assert len(cleanup) == 1
    assert json.loads(cleanup[0].body or b"{}") == {"id": "pit-error"}


def test_opensearch_run_uses_vendor_pit_search_after_and_cleanup_shapes() -> None:
    requests: list[DiscoverRequest] = []

    def request(item: DiscoverRequest) -> tuple[int, bytes, dict[str, str], str | None, bool]:
        requests.append(item)
        body = json.loads(item.body) if item.body else {}
        if item.path == "/_resolve/index/*?expand_wildcards=all":
            return _response({"indices": [{"name": "logs", "attributes": ["open"]}]})
        if item.path.startswith("/logs/_mapping"):
            return _response(
                {
                    "logs": {
                        "mappings": {
                            "properties": {
                                "message": {"type": "text"},
                            }
                        }
                    }
                }
            )
        if item.path.startswith("/logs/_settings"):
            return _response({"logs": {"settings": {}}})
        if item.path in {
            "/_cluster/settings?flat_settings=false&include_defaults=false",
            "/_index_template",
            "/_component_template",
            "/_template",
            "/_ingest/pipeline",
        } or item.path.startswith("/_nodes/settings?"):
            return _response({})
        if item.method == "POST" and item.path.startswith("/logs/_search/point_in_time?"):
            return _response({"pit_id": "os-pit-open"}, status=201)
        if item.method == "POST" and item.path == "/_search":
            if "search_after" not in body:
                assert body["pit"]["id"] == "os-pit-open"
                return _response(
                    {
                        "pit_id": "os-pit-updated",
                        "hits": {
                            "total": {"value": 1, "relation": "eq"},
                            "hits": [
                                {
                                    "_index": "logs",
                                    "_id": "os-secret",
                                    "_source": {"password": "opensearch-full-secret"},
                                    "sort": [1],
                                }
                            ],
                        },
                    }
                )
            assert body["search_after"] == [1]
            assert body["pit"]["id"] == "os-pit-updated"
            return _response(
                {
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [],
                    }
                }
            )
        if item.method == "DELETE" and item.path == "/_search/point_in_time":
            assert body == {"pit_id": ["os-pit-updated"]}
            return _response({"succeeded": True})
        raise AssertionError(f"unexpected OpenSearch request: {item.method} {item.path}")

    report = run_discovery(request, vendor="opensearch", options=DiscoverOptions(page_size=1))
    serialized = report.to_dict()

    assert [finding["value"] for finding in serialized["discover_findings"]] == ["opensearch-full-secret"]
    assert serialized["discover_schema_version"] == 2
    assert serialized["discover_coverage"]["complete"] is True
    assert any(item.path.startswith("/logs/_search/point_in_time?") for item in requests)
    assert any(item.method == "DELETE" and item.path == "/_search/point_in_time" for item in requests)


def test_scroll_fallback_is_cleared_and_preserves_full_values() -> None:
    requests: list[DiscoverRequest] = []
    scroll_page = 0

    def request(item: DiscoverRequest) -> tuple[int, bytes, dict[str, str], str | None]:
        nonlocal scroll_page
        requests.append(item)
        if item.path.startswith("/logs/_pit?"):
            response = _response({}, status=404)
        elif item.method == "POST" and item.path.startswith("/logs/_search?scroll="):
            response = _response(
                {
                    "_scroll_id": "scroll-1",
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_index": "logs",
                                "_id": "scroll-secret",
                                "_source": {"password": "scroll-full-secret"},
                            }
                        ],
                    },
                }
            )
        elif item.method == "POST" and item.path == "/_search/scroll":
            scroll_page += 1
            response = _response(
                {
                    "_scroll_id": "scroll-2",
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [],
                    },
                }
            )
        elif item.method == "DELETE" and item.path == "/_search/scroll":
            response = _response({"succeeded": True})
        else:
            raise AssertionError(f"unexpected fallback request: {item.method} {item.path}")
        status, body, headers, error, _truncated = response
        return status, body, headers, error

    engine = DiscoverEngine(request, vendor="elasticsearch", options=DiscoverOptions(page_size=1))
    engine._search_query("logs", {"query": {"match_all": {}}}, candidate=False)

    assert scroll_page == 1
    assert [finding.value for finding in engine.accumulator.findings()] == ["scroll-full-secret"]
    clear = [item for item in requests if item.method == "DELETE" and item.path == "/_search/scroll"]
    assert len(clear) == 1
    assert json.loads(clear[0].body or b"{}") == {"scroll_id": ["scroll-2"]}


def test_scroll_hits_without_scroll_id_mark_coverage_partial() -> None:
    def request(item: DiscoverRequest) -> tuple[int, bytes, dict[str, str], str | None, bool]:
        if item.path.startswith("/logs/_pit?"):
            return _response({}, status=404)
        if item.method == "POST" and "scroll=" in item.path:
            return _response(
                {
                    "hits": {
                        "total": {"value": 2, "relation": "gte"},
                        "hits": [
                            {
                                "_index": "logs",
                                "_id": "orphaned-scroll-page",
                                "_source": {"password": "scroll-page-secret"},
                            }
                        ],
                    }
                }
            )
        raise AssertionError(f"unexpected no-scroll-id request: {item.method} {item.path}")

    engine = DiscoverEngine(request, vendor="elasticsearch")
    engine._search_query("logs", {"query": {"match_all": {}}}, candidate=False)

    assert [finding.value for finding in engine.accumulator.findings()] == ["scroll-page-secret"]
    assert engine.coverage.truncated is True
    assert any("scroll" in reason for reason in engine.coverage.truncated_reasons)


def test_single_page_fallback_marks_coverage_partial() -> None:
    requests: list[DiscoverRequest] = []

    def request(item: DiscoverRequest) -> tuple[int, bytes, dict[str, str], str | None, bool]:
        requests.append(item)
        if item.path.startswith("/logs/_pit?"):
            return _response({}, status=404)
        if "scroll=" in item.path:
            return _response({}, status=405)
        if item.path == "/logs/_search?expand_wildcards=open":
            return _response(
                {
                    "hits": {
                        "total": {"value": 2, "relation": "gte"},
                        "hits": [
                            {
                                "_index": "logs",
                                "_id": "first-page",
                                "_source": {"clientSecret": "single-page-secret"},
                            }
                        ],
                    }
                }
            )
        raise AssertionError(f"unexpected single-page request: {item.method} {item.path}")

    engine = DiscoverEngine(request, vendor="elasticsearch")
    engine._search_query("logs", {"query": {"match_all": {}}}, candidate=False)

    assert [finding.value for finding in engine.accumulator.findings()] == ["single-page-secret"]
    assert engine.coverage.truncated is True
    assert engine.coverage.truncated_reasons == ["search:logs:pagination_unavailable"]


def test_closed_indices_make_coverage_explicitly_incomplete() -> None:
    payload = DiscoverCoverage(
        indices_enumerated=2,
        indices_scanned=1,
        indices_closed=1,
    ).to_dict()

    assert payload["complete"] is False
    assert payload["status"] == "partial"


def test_truncated_resolve_with_complete_cat_fallback_does_not_poison_inventory_coverage() -> None:
    requests: list[DiscoverRequest] = []

    def request(item: DiscoverRequest) -> tuple[int, bytes, dict[str, str], str | None, bool]:
        requests.append(item)
        if item.path == "/_resolve/index/*?expand_wildcards=all":
            return _response(
                {"indices": [{"name": "incomplete-index", "attributes": ["open"]}]},
                truncated=True,
            )
        if item.path == "/_cat/indices?format=json&expand_wildcards=all&h=index,status":
            return _response(
                [
                    {"index": "logs", "status": "open"},
                    {"index": "archive", "status": "close"},
                ]
            )
        raise AssertionError(f"unexpected inventory request: {item.method} {item.path}")

    engine = DiscoverEngine(request)
    inventory, error, detail = engine._inventory()

    assert error is None
    assert detail is None
    assert [(item.name, item.status) for item in inventory] == [
        ("archive", "closed"),
        ("logs", "open"),
    ]
    assert engine.coverage.truncated is False
    assert engine.coverage.surfaces["index_inventory"].status == "complete"


def test_normal_text_exports_full_findings_but_hides_raw_candidate_documents() -> None:
    finding = FindingAccumulator()
    finding.add(
        DetectedSecret("full-exported-secret", "password", 90, ("sensitive_field",)),
        FindingLocation("document", "logs/doc-1", "/password", index="logs", id="doc-1"),
    )
    record = {
        "host": "127.0.0.1",
        "port": 9200,
        "status": "open_no_auth",
        "discover": True,
        "discover_schema_version": 2,
        "discover_findings": [item.to_dict() for item in finding.findings()],
        "discover_coverage": {
            "complete": True,
            "status": "complete",
            "indices_enumerated": 1,
            "indices_scanned": 1,
            "pages_scanned": 1,
            "documents_scanned": 1,
            "source_bytes_scanned": 42,
            "truncated_reasons": [],
        },
        "discover_results": [
            {
                "index": "logs",
                "total_hits": 1,
                "shown_hits": 1,
                "hits": [
                    {
                        "source": {
                            "message": "raw-candidate-document",
                        }
                    }
                ],
            }
        ],
        "discover_error": None,
    }

    normal_lines = elastic_actions._format_detail_records(record, "txt", debug=False)
    debug_lines = elastic_actions._format_detail_records(record, "txt", debug=True)
    normal = "\n".join(normal_lines)
    debug = "\n".join(debug_lines)

    assert "1 Secret Findings" in normal
    assert 'value="full-exported-secret"' in normal
    assert "Discover coverage status=complete" in normal
    assert "raw-candidate-document" not in normal
    assert "raw-candidate-document" in debug


def test_incomplete_empty_scan_does_not_claim_that_no_secrets_exist() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9200,
        "status": "open_no_auth",
        "discover": True,
        "discover_schema_version": 2,
        "discover_findings": [],
        "discover_coverage": {
            "complete": False,
            "status": "partial",
            "indices_enumerated": 2,
            "indices_scanned": 1,
            "pages_scanned": 1,
            "documents_scanned": 10,
            "source_bytes_scanned": 100,
            "truncated_reasons": ["max_documents"],
        },
        "discover_results": [],
        "discover_error": None,
    }

    lines = elastic_actions._format_detail_records(record, "txt", debug=False)
    rendered = "\n".join(lines)

    assert "0 Secret Findings in scanned scope" in rendered
    assert "status=partial" in rendered
    assert "reasons=max_documents" in rendered
