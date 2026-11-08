"""Bounded Elasticsearch 8 API fixture; never a real cluster or arbitrary writer.

Transient writes are restricted to the scanner's random probe namespace. Seeded
indices are immutable. Limited-role writes and document deletes are independent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import threading
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, urlsplit

from scripts.performance_contracts import HttpPairWireLedger, _ledgers, _malformed_attempts, _state
from scripts.performance_http_fixtures import response

VERSION = "8.19.0"
INDICES = ("billing-logs", "events-logs", "audit-events")
NODES = {
    name: {"name": name, "roles": ["data", "ingest", "master"], "ip": ip, "host": name + ".qa", "version": VERSION}
    for name, ip in [("billing-a", "192.0.2.11"), ("billing-b", "192.0.2.12")]
}
HEALTH = {
    "cluster_name": "billing-qa",
    "status": "green",
    "timed_out": False,
    "number_of_nodes": 2,
    "number_of_data_nodes": 2,
    "active_primary_shards": 3,
    "active_shards": 6,
    "relocating_shards": 0,
    "initializing_shards": 0,
    "unassigned_shards": 0,
}
PLUGINS = [
    {"name": "billing-a", "component": name, "version": VERSION, "description": description}
    for name, description in [("analysis-icu", "ICU Analysis"), ("ingest-attachment", "Ingest Attachment")]
]
PROBE_INDEX = re.compile(r"/redposture-access-probe-[0-9a-f]{32}(?:/_doc/redposture-probe)?")


def basic_pair(headers: dict[bytes, bytes]) -> tuple[str, str] | None:
    auth = headers.get(b"authorization", b"")
    if not auth.lower().startswith(b"basic "):
        return None
    try:
        value = base64.b64decode(auth[6:], validate=True).decode("utf-8")
    except (ValueError, UnicodeError, binascii.Error):
        return None
    username, separator, password = value.partition(":")
    return (username, password) if separator else None


class ElasticModel:
    def __init__(self, *, valid_pair: tuple[str, str] | None, limited: bool, max_active: int = 32):
        if max_active < 1:
            raise ValueError("positive transient index bound required")
        self.valid_pair, self.limited, self.max_active = valid_pair, limited, max_active
        self._indices: dict[tuple[str, str], bool] = {}
        self._counts: Counter[str] = Counter()
        self._lock = threading.Lock()

    def summary(self) -> dict[str, int]:
        with self._lock:
            return {
                "active_indices": len(self._indices),
                **{
                    name: self._counts[name]
                    for name in [
                        "created",
                        "documents_written",
                        "documents_deleted",
                        "indices_deleted",
                        "denied_document_deletes",
                        "unexpected_mutations",
                        "overflows",
                    ]
                },
            }

    def _reply(self, status: int, payload: Any, *, text: bool = False) -> bytes:
        headers = {"X-Elastic-Product": "Elasticsearch"}
        if status == 401:
            headers["WWW-Authenticate"] = 'Basic realm="security" charset="UTF-8"'
        if text:
            headers["Content-Type"] = "text/plain"
        return response(status, payload, headers=headers)

    def _denial(self, status: int, route: str) -> bytes:
        reason = (
            "missing or invalid authentication credentials for REST request [" + route + "]"
            if status == 401
            else "action is unauthorized for user with restricted role"
        )
        return self._reply(
            status,
            {
                "error": {
                    "root_cause": [{"type": "security_exception", "reason": reason}],
                    "type": "security_exception",
                    "reason": reason,
                },
                "status": status,
            },
        )

    def reply(self, method: str, path: str, headers: dict[bytes, bytes], body: bytes, host: str) -> bytes:
        parsed = urlsplit(path)
        route = parsed.path
        query = parse_qs(parsed.query)
        pair = basic_pair(headers)
        if self.valid_pair is None or pair != self.valid_pair:
            return self._denial(401, route)
        username = pair[0]
        if method in {"PUT", "DELETE"} and PROBE_INDEX.fullmatch(route):
            index = route.split("/")[1]
            key = (host, index)
            document = "/_doc/" in route
            with self._lock:
                if method == "PUT" and not document:
                    try:
                        valid = json.loads(body) == {}
                    except (ValueError, UnicodeError):
                        valid = False
                    if not valid:
                        return self._reply(400, {"error": "invalid probe creation body"})
                    if key in self._indices:
                        return self._reply(400, {"error": {"type": "resource_already_exists_exception"}})
                    if len(self._indices) >= self.max_active:
                        self._counts["overflows"] += 1
                        return self._reply(503, {"error": "bounded fixture capacity exceeded"})
                    self._indices[key] = False
                    self._counts["created"] += 1
                    return self._reply(200, {"acknowledged": True, "shards_acknowledged": True, "index": index})
                if key not in self._indices:
                    return self._reply(404, {"error": {"type": "index_not_found_exception"}, "status": 404})
                if method == "PUT":
                    try:
                        valid = json.loads(body) == {"redposture_probe": True}
                    except (ValueError, UnicodeError):
                        valid = False
                    if not valid:
                        return self._reply(400, {"error": "invalid probe document"})
                    self._indices[key] = True
                    self._counts["documents_written"] += 1
                    return self._reply(
                        201,
                        {
                            "_index": index,
                            "_id": "redposture-probe",
                            "result": "created",
                            "_version": 1,
                            "_shards": {"total": 1, "successful": 1, "failed": 0},
                        },
                    )
                if document:
                    if self.limited:
                        self._counts["denied_document_deletes"] += 1
                        return self._denial(403, route)
                    existed = self._indices[key]
                    self._indices[key] = False
                    self._counts["documents_deleted"] += int(existed)
                    return self._reply(
                        200 if existed else 404,
                        {"_index": index, "_id": "redposture-probe", "result": "deleted" if existed else "not_found"},
                    )
                del self._indices[key]
                self._counts["indices_deleted"] += 1
                return self._reply(200, {"acknowledged": True})
        if method == "POST" and route == "/_security/user/_has_privileges":
            try:
                value = json.loads(body)
            except (ValueError, UnicodeError):
                return self._reply(400, {"error": "invalid privilege request"})
            if not isinstance(value, dict):
                return self._reply(400, {"error": "invalid privilege request"})
            return self._reply(
                200,
                {
                    "username": username,
                    "has_all_requested": not self.limited,
                    "cluster": {"monitor": True, "manage": not self.limited, "manage_security": not self.limited},
                    "index": {
                        "*": {k: not self.limited for k in ["read", "view_index_metadata", "write", "create_index"]}
                    },
                    "application": {},
                },
            )
        if method != "GET":
            with self._lock:
                self._counts["unexpected_mutations"] += 1
            return self._reply(405, {"error": "mutation outside probe namespace denied"})
        if route == "/":
            return self._reply(
                200,
                {
                    "name": "billing-a",
                    "cluster_name": "billing-qa",
                    "cluster_uuid": "qa-cluster-id",
                    "version": {"number": VERSION, "build_flavor": "default", "build_type": "docker"},
                    "tagline": "You Know, for Search",
                },
            )
        if route == "/_security/_authenticate":
            return self._reply(
                200,
                {
                    "username": username,
                    "roles": ["billing_publisher"] if self.limited else ["superuser"],
                    "full_name": "QA Publisher",
                    "email": None,
                    "metadata": {},
                    "enabled": True,
                    "authentication_realm": {"name": "native", "type": "native"},
                    "lookup_realm": {"name": "native", "type": "native"},
                    "authentication_type": "realm",
                },
            )
        if route == "/_cluster/health":
            return self._reply(200, HEALTH)
        if route == "/_nodes":
            allowed = {field.rsplit(".", 1)[-1] for field in query.get("filter_path", [""])[0].split(",")} - {""}
            return self._reply(
                200,
                {
                    "nodes": {
                        key: {k: v for k, v in node.items() if not allowed or k in allowed}
                        for key, node in NODES.items()
                    }
                },
            )
        if route in {"/_resolve/index/*", "/_cat/indices", "/_search", *("/" + name + "/_search" for name in INDICES)}:
            if self.limited:
                return self._denial(403, route)
            if route == "/_resolve/index/*":
                return self._reply(
                    200,
                    {
                        "indices": [{"name": name, "attributes": ["open"]} for name in INDICES],
                        "aliases": [],
                        "data_streams": [],
                    },
                )
            if route == "/_cat/indices":
                return self._reply(200, [{"index": name, "status": "open"} for name in INDICES])
            return self._reply(
                200,
                {
                    "took": 1,
                    "timed_out": False,
                    "_shards": {"total": 1, "successful": 1, "failed": 0},
                    "hits": {"total": {"value": 3, "relation": "eq"}, "hits": []},
                },
            )
        if route == "/_security/user":
            if self.limited:
                return self._denial(403, route)
            return self._reply(
                200,
                {
                    user: {"roles": roles, "enabled": True, "full_name": full, "email": None, "metadata": {}}
                    for user, roles, full in [
                        (username, ["superuser"], "QA Publisher"),
                        ("billing-reader", ["billing_reader"], "Billing Reader"),
                        ("pipeline-writer", ["pipeline_writer"], "Pipeline Writer"),
                    ]
                },
            )
        if route in {"/_cat", "/_cat/"}:
            return self._reply(200, "/_cat/health\n/_cat/indices\n/_cat/nodes\n/_cat/plugins\n", text=True)
        if route == "/_cat/health":
            return self._reply(200, "billing-qa green 2 2 6 3 0 0 0\n", text=True)
        if route == "/_cat/nodes":
            return self._reply(200, [{"name": n["name"], "ip": n["ip"]} for n in NODES.values()])
        if route == "/_cat/plugins":
            return self._denial(403, route) if self.limited else self._reply(200, PLUGINS)
        if route in {"/_cat/aliases", "/_cat/templates", "/_cat/tasks"}:
            return self._denial(403, route) if self.limited else self._reply(200, [])
        if route in {"/_ingest/pipeline", "/_remote/info"}:
            return self._denial(403, route) if self.limited else self._reply(200, {})
        if route == "/_cluster/settings":
            return (
                self._denial(403, route)
                if self.limited
                else self._reply(
                    200, {"persistent": {"xpack.security.enabled": "true"}, "transient": {}, "defaults": {}}
                )
            )
        if route == "/_nodes/settings":
            return (
                self._denial(403, route)
                if self.limited
                else self._reply(
                    200,
                    {
                        "nodes": {
                            key: {"settings": {"http.cors.enabled": "false", "http.host": "127.0.0.1"}} for key in NODES
                        }
                    },
                )
            )
        return self._reply(
            404, {"error": {"type": "resource_not_found_exception", "reason": "unknown API endpoint"}, "status": 404}
        )


class ElasticWireLedger(HttpPairWireLedger):
    """All received Basic requests, complete bounded bodies and replies, by root."""

    def record_response(
        self, index: int, method: str, path: str, headers: dict[bytes, bytes], body: bytes, raw: bytes
    ) -> None:
        pair = basic_pair(headers)
        if pair is None:
            return
        if self._final is not None:
            raise RuntimeError("HTTP pair ledger closed")
        try:
            head, data = raw.split(b"\r\n\r\n", 1)
            status = int(head.split(b" ", 2)[1])
            if (
                type(index) is not int
                or len(body) > 65536
                or len(data) > 65536
                or sum(len(v.encode()) for v in pair) > 4096
            ):
                raise ValueError("receipt bound exceeded")
            sent = body.decode("utf-8", errors="strict")
            received = data.decode("utf-8", errors="strict")
        except (ValueError, UnicodeError):
            self._malformed += 1
            return
        size = len(body) + len(data)
        if (
            self._pending >= self.total_limit
            or len(self._calls.get(index, [])) >= self.per_target_limit
            or (index not in self._calls and len(self._calls) >= self.target_limit)
            or self.pending_body_bytes + size > self.body_limit
        ):
            self._overflow += 1
            return
        call = {
            "kind": "elastic_request",
            "method": method,
            "path": path,
            "username": pair[0],
            "password": pair[1],
            "status": status,
            "body": sent,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "response_body": received,
            "response_sha256": hashlib.sha256(data).hexdigest(),
        }
        self._calls.setdefault(index, []).append(call)
        self._pending += 1
        self._recorded += 1
        self.pending_body_bytes += size

    def pop(self, index: int) -> dict[str, Any]:
        value = super().pop(index)
        self.pending_body_bytes -= sum(
            len(c["body"].encode()) + len(c["response_body"].encode()) for c in value["calls"]
        )
        return value


def wire_elastic_record(record: dict[str, Any], wire: dict[str, Any] | None) -> tuple[dict[str, Any], str | None]:
    if not isinstance(wire, dict) or wire.get("complete") is not True or not isinstance(wire.get("calls"), list):
        return record, "incomplete Elastic wire receipts"
    calls = wire["calls"]
    if any(
        not isinstance(c, dict)
        or any(
            not isinstance(c.get(k), str)
            for k in [
                "kind",
                "method",
                "path",
                "username",
                "password",
                "body",
                "body_sha256",
                "response_body",
                "response_sha256",
            ]
        )
        or type(c.get("status")) is not int
        for c in calls
    ) or _malformed_attempts(record):
        return record, "malformed Elastic wire or client credential ledger"
    for c in calls:
        if (
            c["kind"] != "elastic_request"
            or hashlib.sha256(c["body"].encode()).hexdigest() != c["body_sha256"]
            or hashlib.sha256(c["response_body"].encode()).hexdigest() != c["response_sha256"]
        ):
            return record, "corrupt Elastic wire body"
    rows = max(_ledgers(record), key=len, default=[])
    observed = record
    if (
        not rows
        and isinstance(record.get("provided_username"), str)
        and isinstance(record.get("provided_password"), str)
        and type(record.get("auth_valid")) is bool
    ):
        # Some single-pair roots expose the actual attempted pair directly.
        # Preserve its verdict; the independent received pair must still match.
        rows = [{**record, "username": record["provided_username"], "password": record["provided_password"]}]
        observed = {**record, "attempted_credentials": rows}
    if not rows:
        return record, "missing Elastic client credential ledger"
    pairs = [(r.get("username"), r.get("password")) for r in rows]
    if any(not isinstance(u, str) or not isinstance(p, str) for u, p in pairs) or len(set(pairs)) != len(pairs):
        return record, "incomplete or duplicate Elastic client identities"
    identities = [c for c in calls if c["method"] == "GET" and c["path"] == "/_security/_authenticate"]
    if [(c["username"], c["password"]) for c in identities] != pairs:
        return record, "Elastic identity requests differ from client credential ledger"
    if {(c["username"], c["password"]) for c in calls} != set(pairs):
        return record, "unexpected credential on Elastic wire"
    for row, identity, pair in zip(rows, identities, pairs, strict=True):
        try:
            payload = json.loads(identity["response_body"])
        except ValueError:
            return record, "invalid Elastic identity response"
        state = _state(row)
        if state == "valid":
            if (
                identity["status"] != 200
                or not isinstance(payload, dict)
                or payload.get("username") != pair[0]
                or payload.get("enabled") is not True
            ):
                return record, "Elastic accepted credential lacks identity proof"
            own = [c for c in calls if (c["username"], c["password"]) == pair and c["method"] in {"PUT", "DELETE"}]
            if len(own) != 4 or [c["method"] for c in own] != ["PUT", "PUT", "DELETE", "DELETE"]:
                return record, "Elastic active write/delete/cleanup sequence incomplete"
            root = own[0]["path"]
            doc = root + "/_doc/redposture-probe"
            if not re.fullmatch(r"/redposture-access-probe-[0-9a-f]{32}", root) or [c["path"] for c in own] != [
                root,
                doc,
                doc,
                root,
            ]:
                return record, "Elastic write escaped correlated disposable index"
            if [c["status"] for c in own] not in [[200, 201, 200, 200], [200, 201, 403, 200]]:
                return record, "Elastic active write/delete status mismatch"
            try:
                results = [json.loads(c["response_body"]) for c in own]
            except ValueError:
                return record, "invalid Elastic write/delete response"
            if any(not isinstance(value, dict) for value in results):
                return record, "invalid Elastic write/delete response shape"
            if (
                results[0].get("acknowledged") is not True
                or results[1].get("result") != "created"
                or results[3].get("acknowledged") is not True
                or own[2]["status"] == 200
                and results[2].get("result") != "deleted"
            ):
                return record, "Elastic write/delete completion evidence missing"
            if (
                row.get("credential_write_access") != "allowed"
                or row.get("credential_delete_access") != ("allowed" if own[2]["status"] == 200 else "denied")
                or row.get("credential_probe_cleanup") != "complete"
                or row.get("credential_probe_index") != root[1:]
            ):
                return record, "Elastic capabilities contradict active write/delete proof"
        elif state == "invalid":
            if (
                identity["status"] != 401
                or row.get("auth_probe_status") != "rejected"
                or row.get("auth_probe_http_status") != 401
            ):
                return record, "Elastic rejection lacks explicit identity failure"
            if any(c["method"] in {"PUT", "DELETE"} for c in calls if (c["username"], c["password"]) == pair):
                return record, "Elastic mutation for rejected credential"
        else:
            return record, "Elastic client credential verdict unverified"
    return observed, None


def elastic_inventory_errors(record: dict[str, Any], *, limited: bool, categories: list[str]) -> list[str]:
    """Compare public inventory values to seeded data, not only row counts."""
    errors = []
    if record.get("server_version") != VERSION:
        errors.append("Elastic version differs from seeded cluster")
    for category in categories:
        if category == "endpoints":
            allowed = ["/_cat/health", "/_cat/nodes"]
            if not limited:
                allowed += [
                    "/_cat/indices",
                    "/_cat/plugins",
                    "/_cat/aliases",
                    "/_cat/templates",
                    "/_cat/tasks",
                    "/_ingest/pipeline",
                    "/_remote/info",
                ]
            if record.get("cat_endpoints") != sorted(allowed) or record.get("endpoints_error"):
                errors.append("Elastic endpoint inventory differs from seeded permissions")
        elif category == "plugins":
            expected = (
                None
                if limited
                else [
                    {"node": r["name"], **{k: r[k] for k in ("component", "version", "description")}} for r in PLUGINS
                ]
            )
            if record.get("cat_plugins") != expected or record.get("plugins_error") != (
                "Access Denied" if limited else None
            ):
                errors.append("Elastic plugin inventory differs from seeded permissions")
        elif category == "cluster":
            expected_nodes = sorted([{"id": key, **node} for key, node in NODES.items()], key=lambda n: str(n["name"]))
            if (
                record.get("cluster_health") != HEALTH
                or record.get("cluster_nodes") != expected_nodes
                or record.get("cluster_error")
            ):
                errors.append("Elastic cluster inventory differs from seeded objects")
        elif category == "users":
            username = record.get("effective_username")
            users = sorted(
                [
                    {"username": u, "roles": roles, "enabled": True, "full_name": full}
                    for u, roles, full in [
                        (username, ["superuser"], "QA Publisher"),
                        ("billing-reader", ["billing_reader"], "Billing Reader"),
                        ("pipeline-writer", ["pipeline_writer"], "Pipeline Writer"),
                    ]
                ],
                key=lambda r: str(r["username"]),
            )
            if record.get("users") != (None if limited else users) or record.get("users_error") != (
                "Access Denied" if limited else None
            ):
                errors.append("Elastic user inventory differs from seeded permissions")
        else:
            errors.append("unsupported Elastic inventory category")
    return errors
