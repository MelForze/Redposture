#!/usr/bin/env python3
"""Run a small deterministic mutation suite over critical security decisions."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    name: str
    source: str
    original: str
    replacement: str
    tests: tuple[str, ...]


MUTATIONS = (
    Mutation(
        name="CVE fixed-version boundary becomes inclusive",
        source="redposture_core/cve.py",
        original="if fixed is not None and _compare_versions(parsed, fixed) >= 0:",
        replacement="if fixed is not None and _compare_versions(parsed, fixed) > 0:",
        tests=("tests/test_cve_catalog_properties.py",),
    ),
    Mutation(
        name="large scan threshold moves above 1000",
        source="redposture_core/stage_runtime.py",
        original="_LARGE_AUDIT_PLAN_ENDPOINTS = 1_000",
        replacement="_LARGE_AUDIT_PLAN_ENDPOINTS = 1_001",
        tests=("tests/test_stage_runtime.py::test_cli_audit_worker_profile_uses_expanded_endpoint_count",),
    ),
    Mutation(
        name="HTTPS-required classifier accepts the wrong status",
        source="redposture_core/clients/http_api.py",
        original="if int(status) != 400:",
        replacement="if int(status) != 401:",
        tests=("tests/test_code_review_regressions.py::test_https_required_response_classifier_is_strict",),
    ),
    Mutation(
        name="Keycloak redirect loses its provider fingerprint",
        source="redposture_core/auth_detection.py",
        original='return "keycloak", "oidc"',
        replacement='return "generic_sso", "oidc"',
        tests=("tests/test_auth_detection.py::test_detects_keycloak_from_redirect_url_and_page",),
    ),
    Mutation(
        name="mutating POST becomes replay-safe after an ambiguous failure",
        source="redposture_core/clients/http_api.py",
        original='replay_safe = str(request.method or "GET").upper() in {"GET", "HEAD"}',
        replacement='replay_safe = str(request.method or "GET").upper() in {"GET", "HEAD", "POST"}',
        tests=(
            "tests/test_mutating_retry_safety.py::test_mutating_http_requests_are_never_replayed_after_ambiguous_transport_failure",
        ),
    ),
    Mutation(
        name="redirect hop ceiling silently increases",
        source="redposture_core/clients/http_redirects.py",
        original="MAX_REDIRECTS = 5",
        replacement="MAX_REDIRECTS = 6",
        tests=("tests/test_redirect_matrix_contract.py::test_redirect_limit_and_signature_preparer_cover_every_hop",),
    ),
    Mutation(
        name="MinIO discovery worker limit drifts",
        source="redposture_core/modules/minio/discover.py",
        original="DISCOVER_WORKERS = 8",
        replacement="DISCOVER_WORKERS = 7",
        tests=(
            "tests/test_discovery_parallel_invariants.py::test_fixed_discovery_limits_match_the_command_wide_contract",
        ),
    ),
    Mutation(
        name="ClickHouse discovery worker limit drifts",
        source="redposture_core/modules/clickhouse/discover/engine.py",
        original="DISCOVER_WORKERS = 4",
        replacement="DISCOVER_WORKERS = 3",
        tests=(
            "tests/test_discovery_parallel_invariants.py::test_fixed_discovery_limits_match_the_command_wide_contract",
        ),
    ),
    Mutation(
        name="normal text starts emitting unconfirmed services",
        source="redposture_core/stage_runtime.py",
        original="suppress_undetected_records_in_text: bool = True",
        replacement="suppress_undetected_records_in_text: bool = False",
        tests=(
            "tests/test_release_quality_contracts.py::test_every_audit_module_obeys_mixed_target_output_contract[airflow]",
        ),
    ),
    Mutation(
        name="CVE findings switch from newest-first to oldest-first",
        source="redposture_core/cve.py",
        original='return (-int(year), -int(sequence), str(item.get("product") or ""))',
        replacement='return (int(year), int(sequence), str(item.get("product") or ""))',
        tests=("tests/test_cve.py::test_multiple_ranges_and_stable_newest_first_order",),
    ),
    Mutation(
        name="discovery compact output leaks severity labels",
        source="redposture_core/discovery_rendering.py",
        original="return f\"{module}\\t{host or '?'}\\t{int(port or 0)}\\t [!] {kind} Value={encoded_value} Place={encoded_place}\"",
        replacement="return f\"{module}\\t{host or '?'}\\t{int(port or 0)}\\t [!] {severity} {kind} Value={encoded_value} Place={encoded_place}\"",
        tests=("tests/test_discovery_rendering.py::test_common_discovery_line_escapes_value_and_place",),
    ),
    Mutation(
        name="completed discovery headings lose semantic status colors",
        source="redposture_core/discovery_rendering.py",
        original='if payload.startswith(("Discover Secrets", "Discover Complete")):',
        replacement='if payload.startswith(("Discover Secrets",)):',
        tests=(
            "tests/test_discovery_rendering.py::test_discovery_section_keeps_title_white_and_colors_status_and_findings",
        ),
    ),
    Mutation(
        name="MinIO accepts an embedded release inside an arbitrary banner",
        source="redposture_core/cve.py",
        original="match = _MINIO_RELEASE_RE.fullmatch(value.strip())",
        replacement="match = _MINIO_RELEASE_RE.search(value.strip())",
        tests=("tests/test_cve.py::test_minio_cve_version_requires_complete_valid_release_timestamp",),
    ),
    Mutation(
        name="MinIO discards release seconds when comparing CVE boundaries",
        source="redposture_core/cve.py",
        original="    return parts\n",
        replacement="    return (*parts[:3], 0, 0, 0)\n",
        tests=("tests/test_cve.py::test_minio_admin_iso_timestamp_keeps_time_and_excludes_fixed_release",),
    ),
    Mutation(
        name="Oracle loses the authenticated exact Database version",
        source="redposture_core/clients/oracle.py",
        original='driver_version = getattr(self.connection, "version", None)',
        replacement="driver_version = None",
        tests=(
            "tests/test_clients_oracle.py::test_database_version_uses_authenticated_handshake_even_without_banner_permission",
        ),
    ),
    Mutation(
        name="GitLab tries private version retrieval only after token rejection",
        source="redposture_core/modules/gitlab/actions.py",
        original='if state.token_valid is True and bool(getattr(ctx.args, "enum_cve", False)) and not record.get("version"):',
        replacement='if state.token_valid is False and bool(getattr(ctx.args, "enum_cve", False)) and not record.get("version"):',
        tests=("tests/test_gitlab_version_cve.py",),
    ),
    Mutation(
        name="Airflow treats a foreign service as confirmed",
        source="redposture_core/modules/airflow/stage.py",
        original='is_detected=lambda record: record.extra.get("is_airflow") is True,',
        replacement="is_detected=lambda record: True,",
        tests=(
            "tests/test_network_fingerprint_matrix.py::test_actual_detector_rejects_other_products_over_the_network[airflow-grafana]",
        ),
    ),
    # Registry: identity proof, architecture choice and bounded pagination.
    Mutation(
        name="OCI catalog stops after its first page",
        source="redposture_core/modules/registry/actions.py",
        original='next_path = _parse_link_next(resp_headers.get("link")) or ""',
        replacement='next_path = ""',
        tests=(
            "tests/test_quality_registry_matrix.py::test_oci_catalog_pagination_preserves_unique_sorted_repositories",
        ),
    ),
    Mutation(
        name="Harbor accepts a non-numeric identity",
        source="redposture_core/modules/registry/actions.py",
        original=" or not isinstance(user_id, int)",
        replacement="",
        tests=("tests/test_quality_registry_matrix.py::test_harbor_identity_requires_numeric_user_id",),
    ),
    Mutation(
        name="Nexus accepts an anonymous user list as credential proof",
        source="redposture_core/modules/registry/actions.py",
        original="if anonymous_status == 200:",
        replacement="if anonymous_status == 401:",
        tests=(
            "tests/test_quality_registry_matrix.py::test_registry_credential_requires_product_specific_protected_identity[anonymous-nexus]",
        ),
    ),
    Mutation(
        name="Nexus component pagination ignores a repeated token",
        source="redposture_core/modules/registry/actions.py",
        original="if continuation in seen_tokens:",
        replacement="if False and continuation in seen_tokens:",
        tests=("tests/test_quality_registry_matrix.py::test_nexus_component_pagination_keeps_partial_evidence[loop]",),
    ),
    Mutation(
        name="OCI manifest chooses ARM before Linux AMD64",
        source="redposture_core/modules/registry/actions.py",
        original='if os_name == "linux" and arch in {"amd64", "x86_64"}:',
        replacement='if os_name == "linux" and arch in {"arm64"}:',
        tests=(
            "tests/test_quality_registry_deep.py::test_manifest_index_selects_linux_amd64_then_reads_suspicious_config",
        ),
    ),
    # Discovery: independent byte/document models and malformed catalog rows.
    Mutation(
        name="Elastic rejects the document at the exact count limit",
        source="redposture_core/modules/elastic/discover.py",
        original="if self.documents + 1 > self.options.max_documents:",
        replacement="if self.documents + 1 >= self.options.max_documents:",
        tests=(
            "tests/test_quality_discovery_stateful.py::test_elastic_budget_accepts_exact_document_and_byte_boundaries",
        ),
    ),
    Mutation(
        name="Elastic rejects source bytes exactly at the limit",
        source="redposture_core/modules/elastic/discover.py",
        original="if proposed_bytes > self.options.max_source_bytes:",
        replacement="if proposed_bytes >= self.options.max_source_bytes:",
        tests=(
            "tests/test_quality_discovery_stateful.py::test_elastic_budget_accepts_exact_document_and_byte_boundaries",
        ),
    ),
    Mutation(
        name="MinIO byte reservation exceeds the target budget",
        source="redposture_core/modules/minio/discover.py",
        original="allowed = min(length, max(0, self.max_total_bytes - self._claimed_bytes))",
        replacement="allowed = max(length, max(0, self.max_total_bytes - self._claimed_bytes))",
        tests=("tests/test_quality_discovery_stateful.py::TestMinioClaimMachine",),
    ),
    Mutation(
        name="Airflow log truncation reports the wrong budget boundary",
        source="redposture_core/modules/airflow/discover.py",
        original="if len(encoded) > remaining:",
        replacement="if len(encoded) < remaining:",
        tests=("tests/test_quality_discovery_properties.py::test_airflow_log_stream_never_exceeds_either_byte_budget",),
    ),
    Mutation(
        name="ClickHouse reads a malformed one-column table row",
        source="redposture_core/modules/clickhouse/discover/inventory.py",
        original="if len(row) < 2:",
        replacement="if len(row) < 1:",
        tests=(
            "tests/test_quality_discovery_properties.py::test_clickhouse_catalog_ignores_short_foreign_rows_and_invalid_size_fields",
        ),
    ),
    # Exporters: bounded connection pool and callback success classification.
    Mutation(
        name="Exporter pool accepts one idle connection beyond per-host cap",
        source="redposture_core/exporters/http_pool.py",
        original="if len(bucket) >= self._max_idle_per_host:",
        replacement="if len(bucket) > self._max_idle_per_host:",
        tests=("tests/test_quality_exporter_pool.py::test_pool_per_origin_cap_and_context_cleanup",),
    ),
    Mutation(
        name="Exporter pool accepts one idle connection beyond total cap",
        source="redposture_core/exporters/http_pool.py",
        original="while self._idle_total >= self._max_idle_total:",
        replacement="while self._idle_total > self._max_idle_total:",
        tests=(
            "tests/test_quality_exporter_pool.py::test_pool_evicts_oldest_origin_and_never_reuses_dropped_connection",
        ),
    ),
    Mutation(
        name="Trigger waits for a fourth exporter error before stopping",
        source="redposture_core/exporters/trigger.py",
        original="if consecutive_exporter_failures >= 3:",
        replacement="if consecutive_exporter_failures >= 4:",
        tests=(
            "tests/test_quality_exporters_matrix.py::test_all_trigger_exporters_stop_after_repeated_server_errors[mysqld_exporter]",
        ),
    ),
    Mutation(
        name="Trigger incorrectly accepts HTTP 300 as callback evidence",
        source="redposture_core/exporters/trigger.py",
        original="request_accepted = 200 <= trigger_status < 300",
        replacement="request_accepted = 200 <= trigger_status <= 300",
        tests=("tests/test_quality_exporters_matrix.py::test_trigger_acceptance_is_distinct_from_callback_proof[300]",),
    ),
    Mutation(
        name="Trigger reverses probe_success evidence",
        source="redposture_core/exporters/trigger.py",
        original="trigger_ok = request_accepted and probe_success is True",
        replacement="trigger_ok = request_accepted and probe_success is False",
        tests=("tests/test_quality_exporters_matrix.py::test_trigger_acceptance_is_distinct_from_callback_proof[200]",),
    ),
    # Kafka: framing, codecs, SASL negotiation and ACL interpretations.
    Mutation(
        name="Kafka accepts a zero-length frame",
        source="redposture_core/clients/kafka.py",
        original="if frame_size <= 0 or frame_size > KAFKA_MAX_FRAME:",
        replacement="if frame_size < 0 or frame_size > KAFKA_MAX_FRAME:",
        tests=("tests/test_quality_kafka_fuzz.py::test_kafka_framed_socket_rejects_foreign_and_invalid_prefixes",),
    ),
    Mutation(
        name="Kafka xerial Snappy accepts a truncated header",
        source="redposture_core/clients/kafka.py",
        original="if len(payload) < 16:",
        replacement="if len(payload) < 15:",
        tests=("tests/test_quality_kafka_fuzz.py::test_kafka_snappy_xerial_chunks_and_optional_codecs",),
    ),
    Mutation(
        name="Kafka gzip decoder uses the wrong codec",
        source="redposture_core/clients/kafka.py",
        original="if codec == 1:",
        replacement="if codec == 2:",
        tests=("tests/test_quality_kafka_fuzz.py::test_kafka_snappy_xerial_chunks_and_optional_codecs",),
    ),
    Mutation(
        name="Kafka SASL handshake treats unsupported version as success",
        source="redposture_core/clients/kafka.py",
        original="if error_code == 35:",
        replacement="if error_code == 0:",
        tests=("tests/test_quality_kafka_fuzz.py::test_kafka_sasl_handshake_parses_success_rejection_and_unsupported",),
    ),
    Mutation(
        name="Kafka ACL treats cluster authorization failure as inconclusive",
        source="redposture_core/clients/kafka.py",
        original="if error_code in (29, 31):",
        replacement="if error_code in (29,):",
        tests=("tests/test_quality_kafka_fuzz.py::test_kafka_acl_probe_response_tristate_without_mutating_a_broker",),
    ),
)


def _mutated_source(mutation: Mutation) -> str:
    source = (ROOT / mutation.source).read_text(encoding="utf-8")
    occurrences = source.count(mutation.original)
    if occurrences < 1:
        raise RuntimeError(f"mutation anchor is missing: {mutation.name}")
    return source.replace(mutation.original, mutation.replacement, 1)


def run_mutation(mutation: Mutation) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="redposture-mutation-") as raw_temp:
        temp = Path(raw_temp)
        shutil.copytree(ROOT / "redposture_core", temp / "redposture_core")
        mutated_path = temp / mutation.source
        mutated_path.write_text(_mutated_source(mutation), encoding="utf-8")
        (temp / "pytest.ini").write_text("[pytest]\naddopts = -q\n", encoding="utf-8")

        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(temp)
        command = [
            sys.executable,
            "-m",
            "pytest",
            "--rootdir",
            str(temp),
            *(str(ROOT / test) for test in mutation.tests),
        ]
        completed = subprocess.run(
            command,
            cwd=temp,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        output = (completed.stdout + completed.stderr).strip()
        # Collection/import/configuration failures are broken QA, not a killed
        # mutation. A kill requires an actual failed assertion/test (pytest 1).
        return completed.returncode == 1 and "FAILED " in output and "FAILURES" in output, output


def main() -> int:
    survivors: list[str] = []
    for mutation in MUTATIONS:
        killed, output = run_mutation(mutation)
        if killed:
            print(f"[killed] {mutation.name}")
            continue
        survivors.append(mutation.name)
        print(f"[survived] {mutation.name}")
        if output:
            print(output)
    if survivors:
        print(f"mutation smoke failed: {len(survivors)} mutation(s) survived", file=sys.stderr)
        return 1
    print(f"mutation smoke passed: {len(MUTATIONS)} mutation(s) killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
