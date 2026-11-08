"""Read-only daemon API models and bounded received exchange evidence.

Protocol emulation only. No Docker socket is mounted and mutations never run.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit

from scripts.performance_contracts import HttpPairWireLedger
from scripts.performance_http_fixtures import response
from scripts.performance_portainer import inventory

DOCKER_VERSION = {"Version": "27.5.1", "ApiVersion": "1.47", "GitCommit": "qa-corpus", "Os": "linux"}
DOCKER_INFO = {
    **inventory("system", 11, limited=False),
    "ServerVersion": "27.5.1",
    "OSType": "linux",
    "ApiVersion": "1.47",
}
DOCKER_ROUTES = {
    "containers": "/containers/json?all=1",
    "images": "/images/json",
    "networks": "/networks",
    "volumes": "/volumes",
    "disk": "/system/df?verbose=1",
}


def docker_reply(method: str, path: str, *, access: str) -> bytes:
    if access not in {"open", "limited", "denied"}:
        raise ValueError("unknown daemon access model")
    route = re.sub(r"^/v1\.\d+(?=/)", "", urlsplit(path).path)
    headers = {"API-Version": "1.47", "Docker-Experimental": "false", "OSType": "linux"}
    if method != "GET":
        return response(405, {"message": "Mutation denied by read-only QA fixture"}, headers=headers)
    if route == "/_ping":
        return response(200, "OK", headers={**headers, "Content-Type": "text/plain"})
    if route == "/version":
        return response(200, DOCKER_VERSION, headers=headers)
    if route == "/info":
        return (
            response(403, {"message": "authorization denied by QA plugin"}, headers=headers)
            if access == "denied"
            else response(200, DOCKER_INFO, headers=headers)
        )
    categories = {urlsplit(v).path: k for k, v in DOCKER_ROUTES.items()}
    if route not in categories:
        return response(404, {"message": "page not found"}, headers=headers)
    category = categories[route]
    if access == "denied" or access == "limited" and category != "containers":
        return response(403, {"message": "authorization denied by QA plugin"}, headers=headers)
    return response(200, inventory(category, 11, limited=access == "limited"), headers=headers)


class ReadOnlyWireLedger(HttpPairWireLedger):
    """Complete received HTTP exchange, consumed after each logical root."""

    def record_response(
        self, index: int, method: str, path: str, headers: dict[bytes, bytes], body: bytes, raw: bytes
    ) -> None:
        if self._final is not None:
            raise RuntimeError("read-only wire ledger closed")
        try:
            head, payload = raw.split(b"\r\n\r\n", 1)
            status = int(head.split(b" ", 2)[1])
            if type(index) is not int or len(body) > 65536 or len(payload) > 65536:
                raise ValueError("read receipt bound exceeded")
            fields = {k.decode("ascii"): v.decode("utf-8") for k, v in headers.items()}
            if sum(len(k) + len(v.encode()) for k, v in fields.items()) > 16384:
                raise ValueError("header receipt bound exceeded")
            sent, received = body.decode("utf-8"), payload.decode("utf-8")
        except (ValueError, UnicodeError):
            self._malformed += 1
            return
        size = len(body) + len(payload) + sum(len(k) + len(v.encode()) for k, v in fields.items())
        if (
            self._pending >= self.total_limit
            or len(self._calls.get(index, [])) >= self.per_target_limit
            or index not in self._calls
            and len(self._calls) >= self.target_limit
            or self.pending_body_bytes + size > self.body_limit
        ):
            self._overflow += 1
            return
        call = {
            "kind": "readonly_exchange",
            "method": method,
            "path": path,
            "headers": fields,
            "status": status,
            "body": sent,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "response_body": received,
            "response_sha256": hashlib.sha256(payload).hexdigest(),
            "retained_bytes": size,
        }
        self._calls.setdefault(index, []).append(call)
        self._pending += 1
        self._recorded += 1
        self.pending_body_bytes += size

    def pop(self, index: int) -> dict[str, Any]:
        value = super().pop(index)
        self.pending_body_bytes -= sum(c["retained_bytes"] for c in value["calls"])
        return value


def readonly_wire_errors(wire: dict[str, Any] | None) -> list[str]:
    if not isinstance(wire, dict) or wire.get("complete") is not True or not isinstance(wire.get("calls"), list):
        return ["incomplete read-only exchange evidence"]
    for call in wire["calls"]:
        if (
            not isinstance(call, dict)
            or any(
                not isinstance(call.get(k), str)
                for k in ["kind", "method", "path", "body", "body_sha256", "response_body", "response_sha256"]
            )
            or type(call.get("status")) is not int
            or not isinstance(call.get("headers"), dict)
        ):
            return ["malformed read-only exchange"]
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in call["headers"].items()):
            return ["malformed received request headers"]
        if (
            call["kind"] != "readonly_exchange"
            or call["method"] != "GET"
            or call["body"]
            or any(k.lower() in {"authorization", "cookie"} for k in call["headers"])
        ):
            return ["unexpected credential or mutation in read-only daemon profile"]
        if (
            hashlib.sha256(call["body"].encode()).hexdigest() != call["body_sha256"]
            or hashlib.sha256(call["response_body"].encode()).hexdigest() != call["response_sha256"]
        ):
            return ["corrupt received read-only body"]
    return []


def docker_inventory_errors(
    record: dict[str, Any], wire: dict[str, Any] | None, *, access: str, categories: list[str]
) -> list[str]:
    errors = readonly_wire_errors(wire)
    if errors:
        return errors
    assert wire is not None
    calls = wire["calls"]
    by_path: dict[str, list[dict[str, Any]]] = {}
    for call in calls:
        by_path.setdefault(urlsplit(call["path"]).path, []).append(call)
    if (
        record.get("is_docker") is not True
        or record.get("server_version") != "27.5.1"
        or record.get("api_version") != "1.47"
    ):
        return ["Docker detection/version differs from seeded daemon"]
    if record.get("auth_required") is not (access == "denied"):
        return ["Docker authorization verdict differs from protected info API"]
    if record.get("status") != ("auth_required" if access == "denied" else "open_no_auth"):
        return ["Docker access is not backed by the protected info response"]
    for route, expected in [("/_ping", "OK"), ("/version", DOCKER_VERSION), ("/info", DOCKER_INFO)]:
        receipts = by_path.get(route, [])
        if not receipts:
            errors.append("missing Docker detection read: " + route)
        for receipt in receipts:
            status = 403 if route == "/info" and access == "denied" else 200
            try:
                body = receipt["response_body"] if route == "/_ping" else json.loads(receipt["response_body"])
            except ValueError:
                errors.append("invalid Docker detection JSON")
                continue
            if receipt["status"] != status or status == 200 and body != expected:
                errors.append("wrong Docker detection response")
    if access == "denied":
        if any(record.get(k) for k in ("containers", "images", "networks", "volumes", "system")) or any(
            urlsplit(c["path"]).path not in {"/_ping", "/version", "/info"} for c in calls
        ):
            errors.append("Docker inventory performed after protected info denied access")
        return errors
    capabilities = record.get("capabilities")
    if not isinstance(capabilities, dict):
        return [*errors, "missing Docker capability evidence"]
    for category in categories:
        names = [category] if category != "system" else ["info", "disk"]
        for name in names:
            route = "/info" if name == "info" else DOCKER_ROUTES[name]
            receipts = by_path.get(urlsplit(route).path, [])
            allowed = access == "open" or name in {"containers", "info"}
            cap = (
                "can_read_system_info"
                if name == "info"
                else "can_read_disk_usage"
                if name == "disk"
                else "can_list_" + name
            )
            if (
                capabilities.get(cap) is not allowed
                or not receipts
                or any(c["status"] != (200 if allowed else 403) for c in receipts)
            ):
                errors.append("Docker resource permission lacks matching response: " + name)
            raw_system = record.get("system")
            system = raw_system if isinstance(raw_system, dict) else {}
            value = system.get("info" if name == "info" else "df") if name in {"info", "disk"} else record.get(name)
            if not allowed:
                error = system.get("df_error") if name == "disk" else record.get(name + "_error")
                if not error or value:
                    errors.append("Docker denied resource was reported complete: " + name)
                continue
            expected = DOCKER_INFO if name == "info" else inventory(name, 11, limited=access == "limited")
            if name == "volumes":
                expected = expected["Volumes"]
            if value != expected:
                errors.append("Docker inventory differs from known objects: " + name)
    expected_partial = access == "limited" and bool(set(categories) - {"containers"})
    if (
        record.get("partial") is not expected_partial
        or categories
        and record.get("data_complete") is not (not expected_partial)
    ):
        errors.append("Docker inventory completion disagrees with requested permissions")
    return errors
