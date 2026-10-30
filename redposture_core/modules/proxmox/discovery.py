"""PVE discovery fallback without materializing a large HTTP response."""

from __future__ import annotations

import codecs
import hashlib
import sqlite3
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ...discovery_frontier import DiscoveryFrontier
from ...discovery_paths import Text, concat_discovery_text, json_discovery_path, path_suffix
from ...discovery_rendering import iter_disk_discovery_finding_line_chunks
from ...discovery_spool import SpoolingRecords, SpoolingStrings
from ...discovery_values import DiskBackedText, iter_json_chunks
from ...json_stream import JSONPath, JSONScalarStream
from ...rendering import sanitize_report_line
from ...secret_detection import fingerprint, is_secret_field_name
from ...storage_discovery import DiscoveryCollector


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
    name = reason.lower()
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
        self.findings = SpoolingRecords()
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
        self.decoder = JSONScalarStream(self.string, on_primitive=self.primitive, deadline=deadline)
        self.text_decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self.plain: DiskBackedText | None = None
        self.kind: str | None = None

    def emit(self, finding: dict[str, Any]) -> None:
        value = finding["sample"]
        hasher = hashlib.sha256()
        for chunk in iter_json_chunks([finding["path"], fingerprint(value)]):
            hasher.update(chunk.encode())
        identity = hasher.hexdigest()
        if not self.seen.claim(identity):
            return
        self.payload.findings.append(finding)
        if self.on_finding is not None:
            self.on_finding(finding)

    @staticmethod
    def path(path: JSONPath) -> Text:
        if path and path[0] == "data":
            path = path[1:]
        return json_discovery_path(path)

    def inspect(self, path: JSONPath, value: Any) -> None:
        from . import actions

        name = path[-1] if path and isinstance(path[-1], (str, DiskBackedText)) else None
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
        if (
            isinstance(value, DiskBackedText)
            or isinstance(full_path, DiskBackedText)
            or isinstance(parent_path, DiskBackedText)
        ):
            if (
                name is None
                and isinstance(value, DiskBackedText)
                and value.byte_length <= 65_536
                and isinstance(full_path, str)
            ):
                # PVE reports and download metadata use product-specific key/value
                # syntax. Preserve those exact findings for small text responses.
                text_findings: list[dict[str, str]] = []
                actions._collect_text_findings(
                    "".join(value.iter_text_chunks()),
                    self.endpoint,
                    text_findings,
                    set(),
                    path=full_path,
                    limit=None,
                )
                for finding in text_findings:
                    self.emit(dict(finding))
                return
            now = time.monotonic()
            context = SimpleNamespace(
                args=SimpleNamespace(discover_time=max(0.000001, self.deadline - now)),
                discovery_started_at=now,
                host="",
                port=0,
                live_emit=None,
            )
            collector = DiscoveryCollector("proxmox", context, {})
            source = concat_discovery_text(self.endpoint, path_suffix(parent_path, "$"))
            if isinstance(value, DiskBackedText):
                collector.scan_disk_text(source, value, key=name)
            else:
                collector.add(source, {name: value} if name is not None else value, charge=False)
            report = collector.result()
            self.payload.partial_reasons.extend(report["partial_reasons"])
            for item in report["findings"]:
                place = item["object_path"]
                local = concat_discovery_text("$", path_suffix(place, "$." + self.endpoint))
                reason = item["type"]
                field = name if isinstance(name, str) else ""
                if reason == "generic_secret" and is_secret_field_name(field):
                    reason = "json_" + field.lower()
                self.emit({"endpoint": self.endpoint, "reason": reason, "path": local, "sample": item["value"]})
            return
        found: list[dict[str, str]] = []
        if name is not None:
            actions._collect_json_findings({name: value}, self.endpoint, found, set(), path=parent_path)
        elif isinstance(value, str):
            actions._collect_text_findings(value, self.endpoint, found, set(), path=full_path, limit=None)
        for finding in found:
            self.emit(dict(finding))

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
                self.inspect(path, self.large)
                self.large = None
            else:
                self.inspect(path, "".join(self.pending))
            self.pending = []
            self.pending_size = 0

    def primitive(self, item: tuple[JSONPath, Any]) -> None:
        self.inspect(*item)

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
        self.decoder.close()
        if self.large is not None:
            self.large.close()
        if self.plain is not None:
            self.plain.close()
        self.payload.finish()
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
) -> tuple[int, StreamedPayload, dict[str, str], str | None]:
    scanner = _ResponseScanner(endpoint, deadline, on_finding)
    status = 0
    failed = False

    def response_ready(code: int, _headers: Mapping[str, str]) -> None:
        nonlocal status
        status = code

    def chunk(data: bytes) -> None:
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
                    if urls.claim(endpoint):
                        any_url = True
                        line(f"{prefix} [*] {scheme}://{record['host']}:{record['port']}/api2/json{endpoint}")
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
