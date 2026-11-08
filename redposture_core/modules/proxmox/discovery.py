"""PVE discovery fallback without materializing a large HTTP response."""

from __future__ import annotations

import codecs
import hashlib
import sqlite3
import tempfile
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

from ...discovery_context import JSONFieldContext
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_occurrences import OccurrenceRegistry
from ...discovery_paths import Text, concat_discovery_text, json_discovery_path
from ...discovery_rendering import iter_disk_discovery_finding_line_chunks
from ...discovery_spool import SpoolingStrings
from ...discovery_values import DiskBackedText, iter_json_chunks
from ...json_stream import JSONPath, JSONScalarStream
from ...rendering import sanitize_report_line
from ...secret_detection import fingerprint


class FindingIndex:
    """Bounded deduplication of legacy PVE endpoint/path/value identities."""

    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="redposture-pve-findings-")
        self.db = sqlite3.connect(Path(self.temporary.name) / "seen.sqlite")
        self.db.execute("CREATE TABLE seen (identity BLOB PRIMARY KEY)")

    @staticmethod
    def identity(value: object) -> bytes:
        hasher = hashlib.sha256()
        for chunk in iter_json_chunks(value):
            hasher.update(chunk.encode())
        return hasher.digest()

    def __contains__(self, value: object) -> bool:
        return self.db.execute("SELECT 1 FROM seen WHERE identity=?", (self.identity(value),)).fetchone() is not None

    def add(self, value: object) -> None:
        self.db.execute("INSERT OR IGNORE INTO seen(identity) VALUES (?)", (self.identity(value),))

    def close(self) -> None:
        self.db.close()
        self.temporary.cleanup()


def finding_type(reason: str) -> str:
    from ...discovery_rules import SCALAR_DETECTOR_TYPES

    name = reason.lower()
    if name in SCALAR_DETECTOR_TYPES or name in {"generic_secret", "high_entropy", "api_key"}:
        return name
    if "password" in name or "passwd" in name:
        return "password"
    if "token" in name:
        return "token"
    if "api" in name and "key" in name:
        return "api_key"
    if "key" in name:
        return "private_key"
    return "credential_pair"


class StreamedPayload(bytes):
    """Small bytes-compatible navigation view of an already inspected response."""

    def __new__(cls) -> StreamedPayload:
        return super().__new__(cls, b"{}")

    def __init__(self) -> None:
        self.findings = ProxmoxFindings()
        self.names: dict[str, SpoolingStrings] = {}
        self.permissions: dict[str, bool] = {}
        self.bytes_read = 0
        self.partial_reasons: list[str] = []

    def ids(self, name: str) -> list[str]:
        return self.names.get(name, [])

    @property
    def snapshot(self) -> dict[str, Any]:
        return {"data": self.permissions}

    def finish(self) -> None:
        self.findings.finish()
        for names in self.names.values():
            names.finish()


class ProxmoxFindings(OccurrenceRegistry):
    """Keep the PVE projection while sharing value/occurrence storage."""

    def append(self, finding: dict[str, Any]) -> None:
        value = finding["sample"]
        identity = fingerprint(value)
        payload = {
            **finding,
            "fingerprint": identity,
            "type": finding.get("type") or finding_type(finding.get("reason", "")),
        }
        original_place = {
            "source_kind": "pve_response",
            "object": finding["endpoint"],
            "endpoint": finding["endpoint"],
            "path": finding["path"],
        }
        for place in finding.get("locations") or (original_place,):
            self.add(payload, identity=("value", identity), location=place)

    def iter_appended(self, after: int):
        # Reading during collection must not call __getitem__/finish and close
        # the writer. Ordinals are contiguous insertion IDs (no row deletion).
        with closing(sqlite3.connect(self._path)) as db:
            for row in db.execute(
                "SELECT ordinal,payload,occurrence_count,locations_bytes FROM findings "
                "WHERE ordinal>? AND ordinal<=? ORDER BY ordinal",
                (after, len(self)),
            ):
                yield self._finding(row)


_CAPABILITIES = frozenset(
    {
        "User.Modify",
        "Permissions.Modify",
        "Realm.AllocateUser",
        "Sys.Audit",
        "Sys.Syslog",
        "VM.Audit",
        "Datastore.Audit",
        "Pool.Audit",
        "SDN.Audit",
        "VM.Config.Options",
        "VM.Config.CPU",
        "VM.Config.Disk",
        "VM.Config.Network",
        "VM.PowerMgmt",
        "Datastore.Allocate",
        "Datastore.AllocateSpace",
        "SDN.Use",
        "VM.Backup",
    }
)
_NAVIGATION = frozenset({"node", "vmid", "storage", "volid", "userid", "user"})


class _ResponseScanner:
    def __init__(self, endpoint: str, deadline: float, on_finding: Callable[[dict[str, Any]], None] | None) -> None:
        self.endpoint = endpoint
        self.deadline = deadline
        self.on_finding = on_finding
        self.payload = StreamedPayload()
        self.seen = DiscoveryFrontier()
        self.pending: list[str] = []
        self.pending_size = 0
        self.large: DiskBackedText | None = None
        self.contexts = JSONFieldContext(self.inspect, self.payload.partial_reasons.append, deadline=deadline)
        self.decoder = JSONScalarStream(
            self.string,
            on_primitive=self.primitive,
            deadline=deadline,
            on_container=self.contexts.container,
            on_container_end=self.contexts.end,
        )
        self.text_decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self.plain: DiskBackedText | None = None
        self.kind: str | None = None
        self.storage_failed = False

    def emit(self, finding: dict[str, Any]) -> None:
        value = finding["sample"]
        hasher = hashlib.sha256()
        for chunk in iter_json_chunks([finding["path"], fingerprint(value)]):
            hasher.update(chunk.encode())
        identity = hasher.hexdigest()
        if not self.seen.claim(identity):
            return
        before = len(self.payload.findings)
        self.payload.findings.append(finding)
        if self.on_finding is not None and len(self.payload.findings) > before:
            self.on_finding(finding)

    @staticmethod
    def path(path: JSONPath) -> Text:
        if path and path[0] == "data":
            path = path[1:]
        return json_discovery_path(path)

    def inspect(self, path: JSONPath, value: Any, field_name: str | None = None) -> None:
        from . import actions

        name = path[-1] if path and isinstance(path[-1], (str, DiskBackedText)) else None
        if actions._pve_auth_metadata_field(self.endpoint, name):
            return
        full_path = self.path(path)
        parent_path = self.path(path[:-1]) if name is not None else full_path
        if len(path) == 3 and path[0] == "data" and isinstance(path[1], int) and name in _NAVIGATION:
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                text = str(value).strip()
                if text and self.seen.claim("navigation:" + str(name) + ":" + text):
                    if str(name) not in self.payload.names:
                        self.payload.names[str(name)] = SpoolingStrings()
                    self.payload.names[str(name)].append(text)
            elif isinstance(value, DiskBackedText):
                self.payload.partial_reasons.append("invalid_navigation_identifier")
        if name in _CAPABILITIES and value not in (False, 0, None):
            self.payload.permissions[str(name)] = True
        if isinstance(value, str) and value in _CAPABILITIES:
            self.payload.permissions[value] = True
        if (
            name == "digest"
            and actions._PVE_VM_CONFIG_PATH_RE.fullmatch(self.endpoint)
            and isinstance(value, str)
            and actions._PVE_CONFIG_DIGEST_RE.fullmatch(value)
        ):
            return
        found: list[dict[str, Any]] = []
        complete = actions._collect_shared_findings(
            value if field_name is not None or name is None else {name: value},
            self.endpoint,
            found,
            set(),
            path=full_path if field_name is not None or name is None else parent_path,
            field_name=field_name,
            deadline=self.deadline,
        )
        if not complete:
            self.payload.partial_reasons.append("incomplete_payload")
        for finding in found:
            self.emit(finding)

    def string(self, path: JSONPath, text: str, final: bool) -> None:
        if self.large is None:
            self.pending.append(text)
            self.pending_size += len(text.encode("utf-8"))
            if self.pending_size > 65_536:
                self.large = DiskBackedText()
                for part in self.pending:
                    self.large.append_text(part)
                self.pending = []
        else:
            self.large.append_text(text)
        if final:
            if self.large is not None:
                self.large.finish()
                self.contexts.value(path, self.large)
                self.large = None
            else:
                self.contexts.value(path, "".join(self.pending))
            self.pending = []
            self.pending_size = 0

    def primitive(self, item: tuple[JSONPath, Any]) -> None:
        self.contexts.value(*item)

    def feed(self, data: bytes) -> None:
        self.payload.bytes_read += len(data)
        if self.kind is None:
            prefix = data.lstrip()
            if not prefix:
                return
            self.kind = "json" if prefix[:1] in {b"{", b"["} else "text"
            if self.kind == "text":
                self.plain = DiskBackedText()
        if self.kind == "json":
            self.decoder.feed(data)
        else:
            assert self.plain is not None
            self.plain.append_text(self.text_decoder.decode(data))

    def finish(self) -> None:
        if self.kind == "json":
            self.decoder.finish()
        elif self.plain is not None:
            self.plain.append_text(self.text_decoder.decode(b"", final=True))
            self.plain.finish()
            self.inspect((), self.plain)
            self.plain = None

    def close(self) -> None:
        try:
            self.contexts.close(flush=not self.storage_failed and time.monotonic() < self.deadline)
        finally:
            self.decoder.close()
            if self.large is not None:
                self.large.close()
            if self.plain is not None:
                self.plain.close()
            try:
                self.payload.finish()
            finally:
                self.seen.close()


def stream_proxmox_response(
    pool: Any,
    url: str,
    endpoint: str,
    *,
    headers: Mapping[str, str],
    timeout: float,
    deadline: float,
    on_finding: Callable[[dict[str, Any]], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> tuple[int, StreamedPayload, dict[str, str], str | None]:
    scanner = _ResponseScanner(endpoint, deadline, on_finding)
    status = 0
    failed = False

    def response_ready(code: int, _headers: Mapping[str, str]) -> None:
        nonlocal status
        status = code

    def chunk(data: bytes) -> None:
        if cancelled is not None and cancelled():
            from ...scheduler import NestedSchedulerCancelled

            raise NestedSchedulerCancelled("Proxmox discovery cancelled")
        nonlocal failed
        if status != 200 or failed:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("discover_time")
        try:
            scanner.feed(data)
        except (ValueError, UnicodeError):
            failed = True
            scanner.payload.partial_reasons.append("invalid_json_or_utf8")
        except OSError:
            failed = True
            scanner.storage_failed = True
            scanner.payload.partial_reasons.append("storage_failure")

    try:
        response = pool.request_stream(
            "GET",
            url,
            on_chunk=chunk,
            on_response=response_ready,
            chunk_size=65_536,
            headers={"Accept-Encoding": "identity", **headers},
            timeout=timeout,
            deadline=deadline,
            allow_cross_origin_redirects=False,
        )
        if response.status in {401, 403}:
            scanner.payload.partial_reasons.append("access_denied")
        elif response.error or response.status != 200:
            scanner.payload.partial_reasons.append(response.error or f"HTTP {response.status}")
        elif not failed:
            try:
                scanner.finish()
            except (ValueError, UnicodeError):
                scanner.payload.partial_reasons.append("invalid_json")
            except OSError:
                scanner.storage_failed = True
                scanner.payload.partial_reasons.append("storage_failure")
        try:
            scanner.contexts.close(flush=not scanner.storage_failed and time.monotonic() < deadline)
        except OSError:
            scanner.storage_failed = True
            scanner.payload.partial_reasons.append("storage_failure")
        result_headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
        if scanner.payload.partial_reasons:
            result_headers["x-redposture-discovery-error"] = "; ".join(scanner.payload.partial_reasons[:4])
        return response.status, scanner.payload, result_headers, None
    finally:
        scanner.close()


def write_proxmox_views(record: dict[str, Any]) -> str:
    """Render potentially large detail sections to disk, one row at a time."""
    from . import actions

    writer = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="redposture-pve-output-", delete=False)
    prefix = actions._nxc_prefix(record)

    def line(value: str) -> None:
        writer.write(sanitize_report_line(value) + "\n")

    try:
        for field, title in (("nodes", "Nodes"), ("users", "Users")):
            if not record.get("show_" + field):
                continue
            rows = record.get(field)
            count = len(rows) if isinstance(rows, list) else "unknown"
            line(f"{prefix} [*] {title} Enumeration (Count:{count})")
            if record.get(field + "_error"):
                line(f"{prefix} <error:{record[field + '_error']}>")
            elif rows:
                for value in rows:
                    line(f"{prefix} {value}")
            else:
                line(f"{prefix} <no {field}>")
        if record.get("discover_creds"):
            line(f"{prefix} [*] Discovered Credentials")
            line(f"{prefix} [*] Discovered URL")
            any_url = False
            scheme = "https" if record.get("use_https") else "http"
            with DiscoveryFrontier() as urls:
                for finding in record.get("findings") or ():
                    endpoint = str(finding.get("endpoint") or "")
                    for location in finding.get("locations") or ({"endpoint": endpoint},):
                        source_endpoint = location.get("endpoint") or endpoint
                        if urls.claim(source_endpoint):
                            any_url = True
                            line(
                                f"{prefix} [*] {scheme}://{record['host']}:{record['port']}/api2/json{source_endpoint}"
                            )
                    if record.get("_discover_findings_streamed"):
                        continue
                    value = finding.get("sample")
                    if isinstance(value, DiskBackedText):
                        for fragment in iter_disk_discovery_finding_line_chunks(
                            "PROXMOX",
                            record["host"],
                            record["port"],
                            finding_type=finding_type(str(finding.get("reason") or "")),
                            value=value,
                            place=concat_discovery_text(endpoint, finding.get("path") or ""),
                        ):
                            writer.write(fragment)
                        writer.write("\n")
                    else:
                        line(actions._format_single_finding_detail_line(record, finding))
            if not any_url:
                line(f"{prefix} [*] <none>")
        writer.close()
        return writer.name
    except BaseException:
        writer.close()
        Path(writer.name).unlink(missing_ok=True)
        raise
