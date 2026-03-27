"""Adapter registry for DB ingest."""

from __future__ import annotations

import json
from typing import Any

from ...stage_validate import scan_validation_hits
from ..dto.ingest import (
    ArtifactCreate,
    EvidenceCreate,
    ExtensionRecord,
    FindingCreate,
    IngestEnvelope,
    ObservationCreate,
)
from ..security.sanitizer import sanitize_payload
from .base import BaseModuleIngestor

_GENERIC_PROTOCOLS = {
    "registry": "registry",
    "grafana": "grafana",
    "proxmox": "proxmox",
    "gitlab": "gitlab",
    "consul": "consul",
    "kubeapi": "kubeapi",
    "postgres": "postgres",
    "clickhouse": "clickhouse",
    "redis": "redis",
    "etcd": "etcd",
    "qdrant": "qdrant",
    "kafka": "kafka",
    "zookeeper": "zookeeper",
}


class GenericModuleIngestor(BaseModuleIngestor):
    def __init__(self, module_name: str, protocol: str) -> None:
        self.module_name = module_name
        self.protocol = protocol

    def ingest_record(self, record: dict[str, Any]) -> IngestEnvelope:
        sanitized = sanitize_payload(record)
        host = str(record.get("host") or record.get("target") or "").strip() or None
        port_raw = record.get("port")
        try:
            port = int(port_raw) if port_raw is not None else None
        except (TypeError, ValueError):
            port = None
        endpoint_host = host if host and "://" not in host else None
        service_name = str(record.get("service") or self.protocol)
        normalized_status = str(record.get("status") or record.get("type") or "observed")
        severity = _guess_severity(record)
        confidence = "high" if normalized_status not in {"detect", "observed"} else "medium"
        observation = ObservationCreate(
            target_text=host,
            canonical_host_key=host,
            hostname=host,
            host=endpoint_host,
            port=port,
            protocol=self.protocol,
            service_name=service_name,
            service_status=normalized_status,
            service_version=str(record.get("version") or record.get("server_version") or "").strip() or None,
            auth_required=record.get("auth_required") if isinstance(record.get("auth_required"), bool) else None,
            normalized_status=normalized_status,
            severity=severity,
            confidence=confidence,
            raw_json_result_sanitized=sanitized.data
            if isinstance(sanitized.data, dict | list)
            else {"value": sanitized.data},
            normalized_result_json={"status": normalized_status, "module": self.module_name},
            fingerprint_subject=str(record.get("type") or normalized_status),
        )
        findings: list[FindingCreate] = []
        if normalized_status in {
            "open_no_auth",
            "weak_default_creds",
            "valid_credentials",
            "invalid_credentials_anonymous",
        }:
            findings.append(
                FindingCreate(
                    title=f"{self.module_name} exposure on {host or '-'}",
                    finding_type=normalized_status,
                    protocol=self.protocol,
                    module_name=self.module_name,
                    severity=severity,
                    confidence=confidence,
                    status="open",
                    description=sanitized.preview_text,
                    dedup_subject=str(host or normalized_status),
                )
            )
        artifacts = [
            ArtifactCreate(
                artifact_role="raw_payload",
                payload=json.dumps(sanitized.data, ensure_ascii=False, sort_keys=True).encode("utf-8"),
                sanitized_preview_text=sanitized.preview_text,
                content_encoding="gzip",
            )
        ]
        evidence = [
            EvidenceCreate(
                evidence_type="observation",
                title=f"{self.module_name} raw payload",
                preview_text=sanitized.preview_text,
                artifact_index=0,
            )
        ]
        return IngestEnvelope(
            module_run=self.build_run(record),
            observations=[observation],
            findings=findings,
            artifacts=artifacts,
            evidence=evidence,
        )


class ExportersIngestor(BaseModuleIngestor):
    module_name = "exporters"
    protocol = "exporters"

    def build_run(self, first_record: dict[str, Any]):
        base_run = super().build_run(first_record)
        return base_run.model_copy(update={"source_type": _exporter_phase(first_record) or "import"})

    def ingest_record(self, record: dict[str, Any]) -> IngestEnvelope:
        sanitized = sanitize_payload(record)
        host = str(record.get("host") or record.get("target") or "").strip() or None
        port = _safe_int(record.get("port"))
        endpoint_host = host if host and "://" not in host else None
        exporter_name = str(record.get("exporter") or record.get("service") or "exporter").strip() or "exporter"
        phase = _exporter_phase(record)
        body = str(record.get("body") or "")
        _, validation_hits = scan_validation_hits(body, input_format="auto") if body else (0, [])
        validation_reasons = _exporter_validation_reasons(validation_hits)
        normalized_status = _exporter_status(record, phase=phase, validation_reasons=validation_reasons)
        severity = _exporter_severity(record, validation_reasons=validation_reasons)
        confidence = "high" if validation_reasons or normalized_status not in {"detected", "observed"} else "medium"
        observation = ObservationCreate(
            target_text=host,
            canonical_host_key=host,
            hostname=host,
            host=endpoint_host,
            port=port,
            path=_as_optional_text(record.get("endpoint")),
            protocol=self.protocol,
            service_name=exporter_name,
            service_status=normalized_status,
            service_version=str(record.get("version") or record.get("tool_version") or "").strip() or None,
            normalized_status=normalized_status,
            severity=severity,
            confidence=confidence,
            raw_json_result_sanitized=sanitized.data
            if isinstance(sanitized.data, dict | list)
            else {"value": sanitized.data},
            normalized_result_json={
                "status": normalized_status,
                "module": self.module_name,
                "phase": phase,
                "exporter": exporter_name,
                "validation_reasons": validation_reasons,
            },
            fingerprint_subject=_exporter_fingerprint_subject(
                record, phase=phase, validation_reasons=validation_reasons
            ),
        )
        findings = _exporter_findings(
            record=record,
            exporter_name=exporter_name,
            host=host,
            port=port,
            phase=phase,
            severity=severity,
            confidence=confidence,
            validation_hits=validation_hits,
            validation_reasons=validation_reasons,
        )
        artifacts = [
            ArtifactCreate(
                artifact_role="raw_payload",
                payload=json.dumps(sanitized.data, ensure_ascii=False, sort_keys=True).encode("utf-8"),
                sanitized_preview_text=sanitized.preview_text,
                content_encoding="gzip",
            )
        ]
        evidence = [
            EvidenceCreate(
                evidence_type="observation",
                title=f"{exporter_name} raw payload",
                preview_text=sanitized.preview_text,
                artifact_index=0,
            )
        ]
        return IngestEnvelope(
            module_run=self.build_run(record),
            observations=[observation],
            findings=findings,
            artifacts=artifacts,
            evidence=evidence,
        )


class GrafanaIngestor(GenericModuleIngestor):
    def __init__(self) -> None:
        super().__init__("grafana", "grafana")

    def ingest_record(self, record: dict[str, Any]) -> IngestEnvelope:
        envelope = super().ingest_record(record)
        ext: list[ExtensionRecord] = []
        if record.get("type") == "datasources_dump":
            for item in record.get("datasources") or []:
                if not isinstance(item, dict):
                    continue
                ext.append(
                    ExtensionRecord(
                        table_name="grafana_datasources",
                        values={
                            "name": str(item.get("name") or "-"),
                            "datasource_type": str(item.get("type") or "-"),
                            "url": str(item.get("url") or "-"),
                            "access_mode": str(item.get("access") or "-"),
                            "details_json": item,
                        },
                    )
                )
        if record.get("status") == "open_no_auth":
            envelope.findings.append(
                FindingCreate(
                    title=f"Grafana anonymous access on {record.get('host')}",
                    finding_type="anonymous_access",
                    protocol="grafana",
                    module_name="grafana",
                    severity="high",
                    confidence="high",
                    description=str(record.get("host") or "grafana"),
                    dedup_subject=str(record.get("host") or "grafana"),
                )
            )
        envelope.extensions.extend(ext)
        return envelope


class KubeApiIngestor(GenericModuleIngestor):
    def __init__(self) -> None:
        super().__init__("kubeapi", "kubeapi")

    def ingest_record(self, record: dict[str, Any]) -> IngestEnvelope:
        envelope = super().ingest_record(record)
        extensions: list[ExtensionRecord] = []
        for namespace in record.get("namespaces") or []:
            extensions.append(
                ExtensionRecord(
                    table_name="kube_resources",
                    values={"kind": "Namespace", "name": str(namespace), "details_json": {"namespace": namespace}},
                )
            )
        for pod in record.get("pods") or []:
            if not isinstance(pod, dict):
                continue
            extensions.append(
                ExtensionRecord(
                    table_name="kube_resources",
                    values={
                        "kind": "Pod",
                        "namespace": str(pod.get("namespace") or "default"),
                        "name": str(pod.get("name") or "-"),
                        "details_json": pod,
                    },
                )
            )
        if record.get("auth_required") is False:
            envelope.findings.append(
                FindingCreate(
                    title=f"Kubernetes API anonymous access on {record.get('host')}",
                    finding_type="anonymous_access",
                    protocol="kubeapi",
                    module_name="kubeapi",
                    severity="critical",
                    confidence="high",
                    description=str(record.get("version") or "-"),
                    dedup_subject=str(record.get("host") or "kubeapi"),
                )
            )
        envelope.extensions.extend(extensions)
        return envelope


class PostgresIngestor(GenericModuleIngestor):
    def __init__(self) -> None:
        super().__init__("postgres", "postgres")

    def ingest_record(self, record: dict[str, Any]) -> IngestEnvelope:
        envelope = super().ingest_record(record)
        extensions: list[ExtensionRecord] = []
        if record.get("type") == "databases_dump":
            for database_name in record.get("databases") or []:
                extensions.append(
                    ExtensionRecord(
                        table_name="postgres_databases",
                        values={"database_name": str(database_name), "details_json": {"database": database_name}},
                    )
                )
        if record.get("type") == "tables_dump":
            for table_name in record.get("tables") or []:
                database_name, _, short_name = str(table_name).partition(".")
                extensions.append(
                    ExtensionRecord(
                        table_name="postgres_tables",
                        values={
                            "database_name": database_name or None,
                            "table_name": str(table_name),
                            "details_json": {"table": short_name or table_name},
                        },
                    )
                )
        if record.get("type") == "table_dump":
            extensions.append(
                ExtensionRecord(
                    table_name="postgres_tables",
                    values={
                        "database_name": str(record.get("database") or "").strip() or None,
                        "table_name": str(record.get("table") or "-"),
                        "columns_json": list(record.get("columns") or []),
                        "details_json": record,
                    },
                )
            )
        status = str(record.get("status") or "")
        if status in {"open_no_auth", "weak_default_creds", "valid_credentials"}:
            envelope.findings.append(
                FindingCreate(
                    title=f"Postgres exposure on {record.get('host')}",
                    finding_type=status,
                    protocol="postgres",
                    module_name="postgres",
                    severity="high" if status != "valid_credentials" else "medium",
                    confidence="high",
                    description=str(record.get("database") or "postgres"),
                    dedup_subject=f"{record.get('host')}:{record.get('port')}:{status}",
                )
            )
        envelope.extensions.extend(extensions)
        return envelope


class ModuleIngestRegistry:
    def __init__(self) -> None:
        self._items: dict[str, BaseModuleIngestor] = {}

    def register(self, adapter: BaseModuleIngestor) -> None:
        self._items[adapter.module_name] = adapter

    def get(self, module_name: str) -> BaseModuleIngestor:
        if module_name not in self._items:
            raise ValueError(f"unsupported ingest module: {module_name}")
        return self._items[module_name]


def _guess_severity(record: dict[str, Any]) -> str | None:
    status = str(record.get("status") or "")
    if status in {"open_no_auth", "weak_default_creds", "invalid_credentials_anonymous"}:
        return "high"
    if status in {"valid_credentials", "auth_required"}:
        return "medium"
    return None


def _safe_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_optional_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _exporter_phase(record: dict[str, Any]) -> str | None:
    explicit = str(record.get("source_type") or "").strip().lower()
    if explicit in {"scan", "collect", "trigger", "import"}:
        return explicit
    if any(key in record for key in ("callback_target", "trigger_url", "probe_success", "success")):
        return "trigger"
    if any(key in record for key in ("endpoint", "url", "ok", "body")):
        return "collect"
    if "detected" in record or "method" in record:
        return "scan"
    return None


def _exporter_validation_reasons(hits: list[dict[str, str | int]]) -> list[str]:
    reasons: list[str] = []
    for item in hits:
        raw_reason = str(item.get("reason") or "").strip()
        if not raw_reason:
            continue
        for token in raw_reason.split(","):
            reason = token.strip()
            if reason and reason not in reasons:
                reasons.append(reason)
    return reasons


def _exporter_status(record: dict[str, Any], *, phase: str | None, validation_reasons: list[str]) -> str:
    raw_status = record.get("status")
    if isinstance(raw_status, str):
        status_text = raw_status.strip()
        if status_text:
            return status_text
    if validation_reasons:
        return "credential_exposure"
    if phase == "collect":
        if record.get("ok") is True:
            return "collect_success"
        if record.get("error"):
            return "collect_error"
    if phase == "trigger":
        if record.get("probe_success") is True or record.get("success") is True:
            return "trigger_success"
        if record.get("error"):
            return "trigger_error"
    if record.get("detected") is True:
        return "detected"
    if record.get("error"):
        return "error"
    raw_type = str(record.get("type") or "").strip()
    return raw_type or "observed"


def _exporter_severity(record: dict[str, Any], *, validation_reasons: list[str]) -> str | None:
    if validation_reasons:
        if any(
            token in validation_reasons
            for token in (
                "default_creds_known_pair",
                "basic_auth_default_creds",
                "connection_string_auth",
                "cmd_connection_string_auth",
                "connection_string_query_secret",
                "cmd_connection_string_query_secret",
            )
        ):
            return "high"
        return "medium"
    return _guess_severity(record)


def _exporter_fingerprint_subject(
    record: dict[str, Any],
    *,
    phase: str | None,
    validation_reasons: list[str],
) -> str:
    if validation_reasons:
        endpoint = _as_optional_text(record.get("endpoint")) or _as_optional_text(record.get("trigger_url")) or "-"
        return f"{phase or 'exporters'}:{endpoint}:{','.join(validation_reasons)}"
    raw_status = str(record.get("status") or "").strip()
    if raw_status:
        return raw_status
    return str(record.get("type") or phase or "observed")


def _exporter_findings(
    *,
    record: dict[str, Any],
    exporter_name: str,
    host: str | None,
    port: int | None,
    phase: str | None,
    severity: str | None,
    confidence: str,
    validation_hits: list[dict[str, str | int]],
    validation_reasons: list[str],
) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    joined_reasons = ",".join(validation_reasons)
    if validation_reasons:
        endpoint = _as_optional_text(record.get("endpoint"))
        sample = str(validation_hits[0].get("sample") or "").strip() if validation_hits else ""
        sample_preview = sanitize_payload(sample).preview_text if sample else ""
        title_parts = [exporter_name]
        if phase:
            title_parts.append(phase)
        title = " ".join(title_parts) + f" credential exposure on {host or '-'}"
        description_parts = [f"reasons={joined_reasons}"]
        if endpoint:
            description_parts.append(f"endpoint={endpoint}")
        if sample_preview:
            description_parts.append(f"sample={sample_preview}")
        findings.append(
            FindingCreate(
                title=title,
                finding_type=joined_reasons if len(joined_reasons) <= 64 else validation_reasons[0],
                protocol="exporters",
                module_name="exporters",
                severity=severity or "medium",
                confidence=confidence,
                status="open",
                description=" ".join(description_parts),
                dedup_subject=f"{host or '-'}:{port or 0}:{phase or 'collect'}:{endpoint or '-'}:{joined_reasons}",
            )
        )

    raw_status = str(record.get("status") or "").strip()
    if raw_status in {
        "open_no_auth",
        "weak_default_creds",
        "valid_credentials",
        "invalid_credentials_anonymous",
    }:
        findings.append(
            FindingCreate(
                title=f"{exporter_name} exposure on {host or '-'}",
                finding_type=raw_status,
                protocol="exporters",
                module_name="exporters",
                severity=_guess_severity(record),
                confidence=confidence,
                status="open",
                description=_as_optional_text(record.get("trigger_url"))
                or _as_optional_text(record.get("url"))
                or _as_optional_text(record.get("endpoint")),
                dedup_subject=f"{host or '-'}:{port or 0}:{phase or 'exporters'}:{raw_status}",
            )
        )
    return findings


def build_ingest_registry() -> ModuleIngestRegistry:
    registry = ModuleIngestRegistry()
    registry.register(ExportersIngestor())
    registry.register(GrafanaIngestor())
    registry.register(KubeApiIngestor())
    registry.register(PostgresIngestor())
    for module_name, protocol in _GENERIC_PROTOCOLS.items():
        if module_name in {"exporters", "grafana", "kubeapi", "postgres"}:
            continue
        registry.register(GenericModuleIngestor(module_name, protocol))
    return registry
