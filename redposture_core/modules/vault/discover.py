"""Allowlisted read-only Transit exports. Never generate dynamic credentials."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from ...discovery_base64 import decoded_base64_file
from ...discovery_engine import _scan_portioned_value
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_json import DiskJSONDocument
from ...discovery_sources import SourceManifest
from ...discovery_text import _Value
from ...discovery_values import DiskBackedText
from ...json_stream import JSONPath, JSONScalarStream
from ...secret_detection import SecretMatch
from ...storage_discovery import DiscoveryCollector
from ..token_api import ReadBudget
from .policy import safe_vault_path


def _document(
    client: Any, base: str, path: str, method: str, token: str | None, budget: ReadBudget, collector: DiscoveryCollector
) -> tuple[int, Any, bool]:
    # Vault exposes LIST through GET ?list=true. The shared streaming HTTP
    # transport deliberately supports only GET/HEAD/POST, so never pass LIST.
    if method == "LIST":
        path += ("&" if "?" in path else "?") + "list=true"
        method = "GET"
    parser = DiskJSONDocument(deadline=min(budget.deadline, collector.deadline))
    status = 0

    def response(code: int, _headers: Mapping[str, str]) -> None:
        nonlocal status
        status = code

    def chunk(data: bytes) -> None:
        if not collector.charge(len(data)) or not budget.allowed():
            raise TimeoutError("discover_time")
        if status in {200, 404}:
            parser.feed(data)

    try:
        budget.calls += 1
        result = client.pool.request_stream(
            method,
            base + path,
            on_response=response,
            on_chunk=chunk,
            headers={"Accept": "application/json", **({"X-Vault-Token": token} if token else {})},
            timeout=budget.timeout(),
            deadline=min(budget.deadline, collector.deadline),
            chunk_size=65536,
            allow_cross_origin_redirects=False,
            preserve_authorization_on_cross_origin=False,
        )
        if result.status not in {200, 404} or result.error or result.truncated:
            collector.partial(
                path, "access_denied" if result.status in {401, 403} else result.error or f"HTTP {result.status}"
            )
            return result.status, None, False
        value = parser.finish()
        return status, value, True
    except (OSError, ValueError) as exc:
        collector.partial(path, str(exc) or type(exc).__name__)
        return status, parser.partial_value(completed_arrays_only=True), False
    finally:
        parser.close()


def _export(
    client: Any,
    base: str,
    path: str,
    token: str | None,
    budget: ReadBudget,
    collector: DiscoveryCollector,
    location: Mapping[str, Any],
) -> tuple[int, bool]:
    status = 0
    builder: _Value | None = None
    keys_seen = False
    completed = 0
    initial = collector.partial_events

    def on_container(parts: JSONPath, kind: str) -> None:
        nonlocal keys_seen
        if parts == ("data", "keys"):
            keys_seen = kind == "object"
            if not keys_seen:
                collector.partial(path, "invalid_export_keys")
        elif len(parts) == 3 and parts[:2] == ("data", "keys"):
            collector.partial(path, "invalid_export_value")

    def string(parts: JSONPath, text: str, final: bool) -> None:
        nonlocal builder, completed
        if len(parts) != 3 or parts[:2] != ("data", "keys"):
            return
        version = parts[-1]
        if not isinstance(version, str) or not version.isascii() or not version.isdecimal() or not version.lstrip("0"):
            collector.partial(path, "invalid_export_version")
            return
        if builder is None:
            builder = _Value(65536)
        builder.append(text)
        if final:
            value = builder.finish()
            builder = None
            if value == "":
                collector.partial(path, "empty_export_value")
                return
            try:
                prefix = (
                    next(value.iter_text_chunks(max_chars=128), "")
                    if isinstance(value, DiskBackedText)
                    else value[:128]
                )
                if prefix.startswith("-----BEGIN") and location["export_type"] == "signing-key":
                    matches, _, covered = _scan_portioned_value(value, "$", 65536, _deadline=collector.deadline)
                    valid = covered and any(m.detector == "private_key" for m in matches)
                else:

                    def check() -> None:
                        if not collector.allowed() or not budget.allowed():
                            raise TimeoutError("discover_time")

                    with decoded_base64_file(value, check) as (_decoded, size):
                        valid = size >= 16
            except ValueError:
                valid = False
            if not valid:
                collector.partial(path, "invalid_private_export_encoding")
                if isinstance(value, DiskBackedText):
                    value.close()
                return
            collector.add(
                path + "/keys/" + version,
                SecretMatch("generic_secret", "high", "", value, ("vault_private_export",)),
                charge=False,
                location={**location, "version": version},
            )
            completed += 1

    def primitive(item: tuple[JSONPath, Any]) -> None:
        if len(item[0]) == 3 and item[0][:2] == ("data", "keys"):
            collector.partial(path, "invalid_export_value")

    parser = JSONScalarStream(
        string, on_primitive=primitive, on_container=on_container, deadline=min(budget.deadline, collector.deadline)
    )

    def response(code: int, _headers: Mapping[str, str]) -> None:
        nonlocal status
        status = code

    def chunk(data: bytes) -> None:
        if not collector.charge(len(data)) or not budget.allowed():
            raise TimeoutError("discover_time")
        if status == 200:
            parser.feed(data)

    try:
        budget.calls += 1
        result = client.pool.request_stream(
            "GET",
            base + path,
            on_response=response,
            on_chunk=chunk,
            headers={"Accept": "application/json", **({"X-Vault-Token": token} if token else {})},
            timeout=budget.timeout(),
            deadline=min(budget.deadline, collector.deadline),
            chunk_size=65536,
            allow_cross_origin_redirects=False,
            preserve_authorization_on_cross_origin=False,
        )
        if result.status != 200 or result.error or result.truncated:
            collector.partial(
                path, "access_denied" if result.status in {401, 403} else result.error or f"HTTP {result.status}"
            )
            return result.status, False
        parser.finish()
        if not keys_seen or not completed:
            collector.partial(path, "export_values_unavailable")
        if completed:
            collector.mark_accessible_source()
        return status, collector.partial_events == initial
    except (OSError, ValueError) as exc:
        collector.partial(path, str(exc) or type(exc).__name__)
        return status, False
    finally:
        if builder is not None:
            builder.close()
        parser.close()


def discover_transit_mount(
    client: Any,
    base: str,
    mount: str,
    token: str | None,
    budget: ReadBudget,
    collector: DiscoveryCollector,
    manifest: SourceManifest,
) -> None:
    kind = "vault.transit_exports"
    manifest.request(kind)
    with collector.source_guard(manifest, kind):
        if not safe_vault_path(mount) or mount.startswith("/"):
            collector.partial(kind, "invalid_mount_path")
            manifest.finish(kind, complete=False)
            return
        root = "/v1/" + quote(mount, safe="/")
        status, listing, complete = _document(client, base, root + "keys", "LIST", token, budget, collector)
        empty_errors = listing.get("errors") if isinstance(listing, Mapping) else None
        if status == 404 and isinstance(empty_errors, list) and len(empty_errors) == 0:
            collector.mark_accessible_source()
            return
        data = listing.get("data") if isinstance(listing, Mapping) else None
        keys = data.get("keys") if isinstance(data, Mapping) else None
        if status != 200 or not isinstance(keys, list):
            collector.partial(root + "keys", "access_denied" if status in {401, 403} else "key_list_unavailable")
            manifest.finish(kind, complete=False, denied=status in {401, 403})
            return
        manifest.finish(kind, complete=complete)
        collector.mark_accessible_source()
        with DiscoveryFrontier() as seen:
            for name in keys:
                if not collector.allowed() or not budget.allowed():
                    manifest.finish(kind, complete=False)
                    return
                if not isinstance(name, str) or not name or not safe_vault_path(name) or name.startswith("/"):
                    collector.partial(root + "keys", "invalid_key_name")
                    manifest.finish(kind, complete=False)
                    continue
                if not seen.claim(name):
                    continue
                encoded = quote(name, safe="")
                status, document, complete = _document(
                    client, base, root + "keys/" + encoded, "GET", token, budget, collector
                )
                data = document.get("data") if isinstance(document, Mapping) else None
                if status != 200 or not isinstance(data, Mapping):
                    collector.partial(root + "keys/" + name, "key_metadata_unavailable")
                    manifest.finish(kind, complete=False, denied=status in {401, 403})
                    continue
                if not complete:
                    manifest.finish(kind, complete=False)
                if data.get("exportable") is not True:
                    collector.partial(root + "keys/" + name, "private_values_not_exportable")
                    manifest.finish(kind, complete=False, unsupported=True)
                    continue
                key_type = data.get("type")
                exports = ["hmac-key"]
                if key_type in {"aes128-gcm96", "aes256-gcm96", "chacha20-poly1305"}:
                    exports.insert(0, "encryption-key")
                elif key_type in {
                    "ed25519",
                    "ecdsa-p256",
                    "ecdsa-p384",
                    "ecdsa-p521",
                    "rsa-2048",
                    "rsa-3072",
                    "rsa-4096",
                }:
                    exports.insert(0, "signing-key")
                elif key_type != "hmac":
                    collector.partial(root + "keys/" + name, "unsupported_transit_key_type")
                    manifest.finish(kind, complete=False, unsupported=True)
                    continue
                for export_type in exports:
                    if not collector.allowed() or not budget.allowed():
                        manifest.finish(kind, complete=False)
                        return
                    path = root + "export/" + export_type + "/" + encoded
                    status, ok = _export(
                        client,
                        base,
                        path,
                        token,
                        budget,
                        collector,
                        {
                            "source_kind": "vault_transit_export",
                            "object": name,
                            "mount": mount,
                            "export_type": export_type,
                        },
                    )
                    if ok:
                        manifest.read(kind)
                    manifest.finish(kind, complete=ok, denied=status in {401, 403})
