"""Bounded etcd v3 gateway fixture and actual auth/session wire evidence.

This emulates a product API; it never creates an etcd cluster or writes keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any
from urllib.parse import urlsplit

from scripts.performance_contracts import HttpPairWireLedger, _ledgers, _malformed_attempts, _state
from scripts.performance_http_fixtures import response

VERSION = "3.5.14"
VALUES = {
    "/services/billing/config": '{"endpoint":"https://billing.qa/api","retries":3}',
    "/services/events/config": '{"endpoint":"https://events.qa/api","label":"события"}',
    "/secrets/pipeline-token": "pipeline-access-qa",
}
HEADER = {"cluster_id": "14841639068965178418", "member_id": "10276657743932975437", "revision": "7", "raft_term": "2"}


def token_for(pair: tuple[str, str], limited: bool) -> str:
    message = json.dumps([*pair, limited], ensure_ascii=False).encode()
    return "qa-etcd-" + hmac.digest(b"etcd-protocol-fixture-only", message, "sha256").hex()


def error(status: int, code: int, message: str) -> bytes:
    return response(status, {"error": message, "message": message, "code": code})


def etcd_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool,
) -> bytes:
    route = urlsplit(path).path
    if method == "GET" and route == "/version":
        return response(200, {"etcdserver": VERSION, "etcdcluster": "3.5.0"})
    if method == "GET" and route.startswith("/v2/"):
        return response(404, "404 page not found")
    if method != "POST" or route not in {"/v3/auth/status", "/v3/auth/authenticate", "/v3/kv/range"}:
        return response(404 if method == "GET" else 405, {"error": "unsupported fixture request"})
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError):
        return error(400, 3, "invalid JSON")
    if not isinstance(value, dict):
        return error(400, 3, "invalid request")
    if route == "/v3/auth/status":
        return response(200, {"header": HEADER, "enabled": True, "authRevision": "4"})
    if route == "/v3/auth/authenticate":
        if set(value) != {"name", "password"} or any(not isinstance(value[k], str) for k in value):
            return error(400, 3, "invalid authenticate request")
        if valid_pair is None or (value["name"], value["password"]) != valid_pair:
            return error(400, 3, "etcdserver: authentication failed, invalid user ID or password")
        return response(200, {"header": HEADER, "token": token_for(valid_pair, limited)})
    token = headers.get(b"authorization", b"")
    if valid_pair is None or token != token_for(valid_pair, limited).encode():
        return error(401, 16, "etcdserver: invalid auth token")
    if headers.get(b"grpc-metadata-authorization", token) != token:
        return error(401, 16, "etcdserver: invalid auth token")
    try:
        start = base64.b64decode(value["key"], validate=True)
        end = base64.b64decode(value.get("range_end", ""), validate=True)
        limit = int(value.get("limit", 0))
        if limit < 0 or not start:
            raise ValueError("invalid range")
    except (KeyError, ValueError, TypeError):
        return error(400, 3, "invalid range")
    selected = [
        (key, data)
        for key, data in sorted(VALUES.items())
        if (key.encode() == start if not end else key.encode() >= start and (end == b"\0" or key.encode() < end))
    ]
    if limited and (end or start != b"/services/billing/config"):
        return error(403, 7, "etcdserver: permission denied")
    result: dict[str, Any] = {"header": HEADER, "count": str(len(selected))}
    if value.get("count_only") is True:
        return response(200, result)
    page = selected[:limit] if limit else selected
    result["more"] = len(page) < len(selected)
    result["kvs"] = [
        {
            "key": base64.b64encode(key.encode()).decode(),
            "create_revision": "2",
            "mod_revision": "7",
            "version": "1",
            **({} if value.get("keys_only") is True else {"value": base64.b64encode(data.encode()).decode()}),
        }
        for key, data in page
    ]
    return response(200, result)


class EtcdWireLedger(HttpPairWireLedger):
    """Only actual login bodies and received token-bearing requests are kept."""

    def record_response(
        self, index: int, method: str, path: str, headers: dict[bytes, bytes], body: bytes, raw: bytes
    ) -> None:
        login = method == "POST" and urlsplit(path).path == "/v3/auth/authenticate"
        token = headers.get(b"authorization", b"")
        if not login and not token:
            return
        if self._final is not None:
            raise RuntimeError("HTTP pair ledger closed")
        try:
            head, payload = raw.split(b"\r\n\r\n", 1)
            status = int(head.split(b" ", 2)[1])
            if type(index) is not int or len(body) > 65536 or len(payload) > 65536 or len(token) > 4096:
                raise ValueError("etcd receipt bound")
            text, received = body.decode("utf-8"), payload.decode("utf-8")
            value = json.loads(text) if login else None
            if login and (
                not isinstance(value, dict)
                or set(value) != {"name", "password"}
                or any(not isinstance(value[k], str) for k in value)
            ):
                raise ValueError("malformed etcd login")
            call = {
                "kind": "etcd_login" if login else "etcd_read",
                "method": method,
                "path": path,
                "status": status,
                "body": text,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "response_body": received,
                "response_sha256": hashlib.sha256(payload).hexdigest(),
                "authorization": token.decode("utf-8"),
                "grpc_authorization": headers.get(b"grpc-metadata-authorization", b"").decode("utf-8"),
            }
            if login:
                assert isinstance(value, dict)
                call.update(username=value["name"], password=value["password"])
        except (ValueError, UnicodeError, TypeError):
            self._malformed += 1
            return
        size = len(body) + len(payload)
        if (
            self._pending >= self.total_limit
            or len(self._calls.get(index, [])) >= self.per_target_limit
            or index not in self._calls
            and len(self._calls) >= self.target_limit
            or self.pending_body_bytes + size > self.body_limit
        ):
            self._overflow += 1
            return
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


def wire_etcd_record(record: dict[str, Any], wire: dict[str, Any] | None) -> tuple[dict[str, Any], str | None]:
    if not isinstance(wire, dict) or wire.get("complete") is not True or not isinstance(wire.get("calls"), list):
        return record, "incomplete etcd wire proof"
    calls = wire["calls"]
    fields = [
        "kind",
        "method",
        "path",
        "body",
        "body_sha256",
        "response_body",
        "response_sha256",
        "authorization",
        "grpc_authorization",
    ]
    if _malformed_attempts(record) or any(
        not isinstance(c, dict)
        or any(not isinstance(c.get(k), str) for k in fields)
        or type(c.get("status")) is not int
        for c in calls
    ):
        return record, "malformed etcd receipt or client attempt"
    for c in calls:
        if (
            c["kind"] not in {"etcd_login", "etcd_read"}
            or hashlib.sha256(c["body"].encode()).hexdigest() != c["body_sha256"]
            or hashlib.sha256(c["response_body"].encode()).hexdigest() != c["response_sha256"]
        ):
            return record, "corrupt etcd body"
    rows = max(_ledgers(record), key=len, default=[])
    logins = [c for c in calls if c["kind"] == "etcd_login"]
    if not rows or len(rows) != len(logins):
        return record, "missing etcd credential attempts or login receipts"
    if any(
        not isinstance(row.get(k), str) or not isinstance(call.get(k), str)
        for row, call in zip(rows, logins, strict=True)
        for k in ("username", "password")
    ):
        return record, "malformed etcd credential identity"
    tokens = set()
    for row, call in zip(rows, logins, strict=True):
        if (
            call["method"] != "POST"
            or call["path"] != "/v3/auth/authenticate"
            or (row.get("username"), row.get("password")) != (call.get("username"), call.get("password"))
        ):
            return record, "etcd full credentials differ from received login"
        try:
            supplied, received = json.loads(call["body"]), json.loads(call["response_body"])
        except ValueError:
            return record, "invalid etcd auth JSON"
        if supplied != {"name": row.get("username"), "password": row.get("password")} or not isinstance(received, dict):
            return record, "invalid etcd auth body shape"
        if _state(row) == "valid":
            token = received.get("token")
            if call["status"] != 200 or not isinstance(token, str) or not token or token in tokens:
                return record, "etcd acceptance lacks distinct issued token"
            tokens.add(token)
        elif _state(row) == "invalid":
            if (
                call["status"] != 400
                or received.get("code") != 3
                or "authentication failed, invalid user id or password" not in str(received.get("message", "")).lower()
            ):
                return record, "etcd rejection lacks explicit auth failure"
        else:
            return record, "unverified etcd credential verdict"
    reads = [c for c in calls if c["kind"] == "etcd_read"]
    if {c["authorization"] for c in reads} != tokens:
        return record, "etcd issued session was lost or replaced before key read"
    received_values: dict[str, str] = {}
    absent_keys: set[str] = set()
    queried_keys: set[str] = set()
    for c in reads:
        if (
            c["method"] != "POST"
            or c["path"] != "/v3/kv/range"
            or c["grpc_authorization"] != c["authorization"]
            or c["status"] not in {200, 403}
        ):
            return record, "etcd key read lacks matching token or conclusive status"
        try:
            sent, result = json.loads(c["body"]), json.loads(c["response_body"])
            if not isinstance(sent, dict) or not isinstance(result, dict):
                raise ValueError("invalid range shape")
            if sent.get("count_only") is not True and not sent.get("range_end"):
                queried_keys.add(base64.b64decode(sent["key"], validate=True).decode())
            if c["status"] == 403:
                if result.get("code") != 7:
                    raise ValueError("missing permission denial")
                continue
            if sent.get("count_only") is not True:
                if not result.get("kvs") and not sent.get("range_end"):
                    absent_keys.add(base64.b64decode(sent["key"], validate=True).decode())
                for kv in result.get("kvs", []):
                    key = base64.b64decode(kv["key"], validate=True).decode()
                    value = base64.b64decode(kv.get("value", ""), validate=True).decode()
                    received_values[key] = value
        except (ValueError, TypeError, KeyError, UnicodeError):
            return record, "invalid etcd key response"
    selected_key = record.get("query_key")
    names = record.get("keys")
    if selected_key is not None and not isinstance(selected_key, str):
        return record, "malformed etcd selected key"
    if names is not None and (not isinstance(names, list) or any(not isinstance(name, str) for name in names)):
        return record, "malformed etcd key names"
    if selected_key and selected_key not in queried_keys:
        return record, "selected etcd key has no completed received request"
    if isinstance(names, list) and set(names) != set(received_values):
        return record, "etcd key names have no matching received range"
    selected_entry = record.get("query_key_entry")
    entries = record.get("key_value_entries") or ([selected_entry] if isinstance(selected_entry, dict) else [])
    if not isinstance(entries, list):
        return record, "malformed etcd key entries"
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("key"), str):
            return record, "malformed etcd key entry"
        if (
            isinstance(entry, dict)
            and entry.get("key") in absent_keys
            and entry.get("value") == "<not found>"
            and entry.get("error") is None
        ):
            continue
        if (
            not isinstance(entry, dict)
            or entry.get("key") not in received_values
            or entry.get("value") != received_values[entry["key"]]
        ):
            return record, "etcd value has no matching received range"
    return record, None


def etcd_inventory_errors(record: dict[str, Any], *, limited: bool, selected: str | None, dump: bool) -> list[str]:
    if (
        record.get("is_etcd") is not True
        or record.get("status") not in {"valid_credentials", "weak_default_creds"}
        or record.get("server_version") != VERSION
    ):
        return ["etcd inventory has no accepted product/account"]
    if selected:
        expected = {"key": selected, "value": VALUES.get(selected), "error": None, "api": "v3"}
        if limited and selected != "/services/billing/config":
            return (
                []
                if record.get("query_key_entry") is None and record.get("dump_error")
                else ["forbidden selected etcd key was reported as readable"]
            )
        if selected not in VALUES:
            expected["value"] = "<not found>"
        if record.get("query_key_entry") != expected or record.get("dump_error"):
            return ["selected etcd value/path differs from seed"]
    elif limited:
        if record.get("key_count") is not None or not record.get("dump_error") or record.get("key_value_entries"):
            return ["limited etcd global range was mistaken for a full inventory"]
    else:
        expected_entries = [
            {"key": key, "value": value, "error": None, "api": "v3"} for key, value in sorted(VALUES.items())
        ]
        if record.get("key_count") != len(VALUES) or record.get("keys") != sorted(VALUES) or record.get("dump_error"):
            return ["etcd key inventory differs from seed"]
        if dump and record.get("key_value_entries") != expected_entries:
            return ["etcd dump values differ from seed"]
    return []
