"""Seeded Kafka HTTP peers and complete form/session wire proof.

Protocol emulation, not a broker or real UI. Provectus and Kafbat login shapes
were checked separately on real v0.7.2/v1.5.0. No command or mutation runs here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import tempfile
import threading
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from scripts.performance_contracts import _ledgers, _malformed_attempts, _state, accepted_claim
from scripts.performance_http_fixtures import response

AUTH_SURFACES = frozenset({"provectus-ui", "kafbat-ui"})
SURFACES = AUTH_SURFACES
CLUSTER_NAMES = ("billing-production", "events-staging", "analytics-batch")
TOPIC_NAMES = tuple(f"billing.invoices.{number:03}" for number in range(201))
GROUP_NAMES = tuple(f"billing-consumer-{number:03}" for number in range(101))
BROKERS = tuple({"id": number, "host": f"broker-{number}.qa.internal"} for number in range(1, 4))
_KEY = b"redposture-kafka-ui-protocol-fixture-only"


def session_cookie(origin: str, pair: tuple[str, str]) -> str:
    user = base64.urlsafe_b64encode(pair[0].encode()).decode().rstrip("=")
    proof = hmac.new(_KEY, (origin + "\0" + "\0".join(pair)).encode(), "sha256").hexdigest()
    return "SESSION=qa-" + user + "." + proof


def _page(path: str, count: int, required_size: int) -> tuple[int, int] | None:
    try:
        fields = parse_qs(urlsplit(path).query, strict_parsing=True, max_num_fields=8)
        if set(fields) != {"page", "perPage"} or any(len(v) != 1 for v in fields.values()):
            return None
        number, size = int(fields["page"][0]), int(fields["perPage"][0])
        if size != required_size or not 1 <= number <= (count + size - 1) // size + 1:
            return None
        return (number - 1) * size, number * size
    except (ValueError, UnicodeError):
        return None


def kafka_ui_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    surface: str,
    origin: str,
    valid_pair: tuple[str, str] | None,
    limited: bool,
) -> bytes:
    if surface not in AUTH_SURFACES:
        raise ValueError("unsupported Kafka UI auth model")
    route = urlsplit(path).path
    provectus = surface == "provectus-ui"
    login = "/auth" if provectus else "/login"
    version = "v0.7.2" if provectus else "v1.5.0"
    cookie = headers.get(b"cookie", b"").decode("ascii", "replace")
    authenticated = valid_pair is not None and cookie == session_cookie(origin, valid_pair)
    if method == "POST" and route == login:
        try:
            fields = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True, max_num_fields=8)
            if set(fields) != {"username", "password"} or any(len(v) != 1 for v in fields.values()):
                raise ValueError("incomplete pair")
            pair = fields["username"][0], fields["password"][0]
        except (ValueError, UnicodeError):
            return response(400, {"error": "invalid form"})
        if not headers.get(b"content-type", b"").startswith(b"application/x-www-form-urlencoded"):
            return response(415, {"error": "unsupported media type"})
        if pair != valid_pair:
            return response(302, "", headers={"Location": login + "?error"})
        return response(
            302,
            "",
            headers={"Location": "/", "Set-Cookie": session_cookie(origin, pair) + "; Path=/; HttpOnly; SameSite=Lax"},
        )
    if method != "GET":
        return response(403, {"error": "QA policy forbids execution and mutations"})
    if body:
        return response(400, {"error": "unexpected GET body"})
    if route == "/actuator/info":
        return response(
            200,
            {
                "git": {"commit": {"id": "83b5a60"}},
                "build": {
                    "artifact": "kafka-ui-api",
                    "name": "kafka-ui-api",
                    "version": version,
                    "group": "com.provectus" if provectus else "io.kafbat",
                },
            },
        )
    if route == login:
        if provectus and headers.get(b"accept") == b"application/json":
            return response(406, {"code": 5000, "message": "Could not find acceptable representation"})
        page = (
            '<html><title>Please sign in</title><form method="post" action="/auth"><input name="username"><input name="password"></form></html>'
            if provectus
            else '<html><title>Kafbat UI</title><div id="root"></div></html>'
        )
        return response(200, page, headers={"Content-Type": "text/html"})
    if not provectus and route == "/api/config/authentication":
        return response(200, {"authType": "LOGIN_FORM", "oAuthProviders": []})
    if not provectus and route == "/api/authorization" and not authenticated:
        return response(200, {"rbacEnabled": False, "userInfo": None})
    if not authenticated and (route == "/" or route.startswith("/api/")):
        return response(302, "", headers={"Location": login})
    if authenticated and route == "/api/authorization":
        assert valid_pair is not None
        return response(200, {"rbacEnabled": limited, "userInfo": {"username": valid_pair[0], "permissions": []}})
    if authenticated and route == "/api/info":
        return response(
            200,
            {
                "enabledFeatures": [],
                "build": {"commitId": "83b5a60", "version": version, "buildTime": "2024-04-10T09:41:25Z"},
            },
        )
    if authenticated and route == "/api/clusters":
        return response(
            200,
            [
                {"name": name, "status": "online", "brokerCount": 3, "topicCount": len(TOPIC_NAMES), "readOnly": True}
                for name in CLUSTER_NAMES
            ],
        )
    parts = route.split("/")
    if authenticated and len(parts) >= 5 and parts[1:3] == ["api", "clusters"]:
        cluster, category = unquote(parts[3]), "/".join(parts[4:])
        if cluster not in CLUSTER_NAMES:
            return response(404, {"error": "unknown cluster"})
        if limited and cluster != CLUSTER_NAMES[0]:
            return response(403, {"code": 403, "message": "Forbidden by cluster ACL"})
        if category == "brokers":
            return response(200, list(BROKERS))
        if category in {"topics", "consumer-groups/paged"}:
            topics = category == "topics"
            values = TOPIC_NAMES if topics else GROUP_NAMES
            bounds = _page(path, len(values), 200 if topics else 100)
            if bounds is None:
                return response(400, {"error": "invalid pagination"})
            items = [
                {"name": name, "partitions": 3, "replicationFactor": 3}
                if topics
                else {"groupId": name, "state": "STABLE"}
                for name in values[slice(*bounds)]
            ]
            return response(200, {"topics" if topics else "consumerGroups": items, "totalPages": 2})
    return response(404, {"error": "unknown route"})


class KafkaUIWireLedger:
    """Bounded per-root evidence on disposable disk; no all-target payload RAM.

    Fixture calls are externally serialized, and the internal lock also guards
    consumers on another thread. The256MiB encoded disk budget is an explicit
    QA limit; exceeding it fails evidence rather than dropping receipts.
    """

    def __init__(
        self,
        *,
        per_target_limit: int = 130,
        total_limit: int = 262144,
        target_limit: int = 16384,
        body_limit: int = 256 * 1024 * 1024,
    ):
        if min(per_target_limit, total_limit, target_limit, body_limit) < 1:
            raise ValueError("positive Kafka UI receipt bounds required")
        self.per_target_limit, self.total_limit, self.target_limit, self.body_limit = (
            per_target_limit,
            total_limit,
            target_limit,
            body_limit,
        )
        self.pending_body_bytes = 0
        self._recorded = self._pending = self._targets = self._overflow = self._malformed = self._storage_errors = 0
        self._peak_pending = self._peak_bytes = 0
        self._final: dict[str, int] | None = None
        self._lock = threading.RLock()
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-kafka-ui-wire-")
        self.storage_path = Path(self._temporary.name) / "pending.sqlite"
        try:
            self._db = sqlite3.connect(self.storage_path, check_same_thread=False)
            self._db.execute("PRAGMA cache_size=-512")
            self._db.execute("PRAGMA mmap_size=0")
            self._db.execute("PRAGMA temp_store=FILE")
            self._db.execute("PRAGMA journal_mode=MEMORY")
            # Disposable QA evidence is never recovered after a process crash;
            # per-record durability fsync would distort network measurements.
            self._db.execute("PRAGMA synchronous=OFF")
            self._db.execute("PRAGMA max_page_count=131072")
            self._db.execute(
                "CREATE TABLE roots (root INTEGER PRIMARY KEY, calls INTEGER NOT NULL, bytes INTEGER NOT NULL)"
            )
            self._db.execute(
                "CREATE TABLE calls (root INTEGER NOT NULL, ordinal INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(root,ordinal))"
            )
            self._db.commit()
        except BaseException:
            if hasattr(self, "_db"):
                self._db.close()
            self._temporary.cleanup()
            raise

    def record_response(
        self, index: int, method: str, path: str, headers: dict[bytes, bytes], body: bytes, raw: bytes
    ) -> None:
        with self._lock:
            if self._final is not None:
                raise RuntimeError("Kafka UI wire ledger closed")
            try:
                head, payload = raw.split(b"\r\n\r\n", 1)
                if type(index) is not int or len(head) > 16384 or len(body) > 65536 or len(payload) > 65536:
                    raise ValueError("wire receipt bound exceeded")
                status = int(head.split(b" ", 2)[1])
                request_headers = {k.decode("ascii"): v.decode("utf-8") for k, v in headers.items()}
                if sum(len(k) + len(v.encode()) for k, v in request_headers.items()) > 16384:
                    raise ValueError("request headers exceed receipt bound")
                response_headers: dict[str, str] = {}
                for line in head.split(b"\r\n")[1:]:
                    key, value = line.decode("ascii").split(":", 1)
                    key = key.lower()
                    if not key or key in response_headers:
                        raise ValueError("duplicate response header")
                    response_headers[key] = value.strip()
                call = {
                    "kind": "kafka_ui_exchange",
                    "method": method,
                    "path": path,
                    "headers": request_headers,
                    "body": body.decode("utf-8"),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "status": status,
                    "response_headers": response_headers,
                    "response_body": payload.decode("utf-8"),
                    "response_sha256": hashlib.sha256(payload).hexdigest(),
                }
                encoded = json.dumps(call, separators=(",", ":"), ensure_ascii=True)
                size = len(encoded.encode("utf-8"))
            except (ValueError, UnicodeError, TypeError, AttributeError):
                self._malformed += 1
                return
            try:
                current = self._db.execute("SELECT calls,bytes FROM roots WHERE root=?", (index,)).fetchone()
                count, root_bytes = current if current is not None else (0, 0)
                if (
                    self._pending >= self.total_limit
                    or count >= self.per_target_limit
                    or current is None
                    and self._targets >= self.target_limit
                    or self.pending_body_bytes + size > self.body_limit
                    or root_bytes + size > 8 * 1024 * 1024
                ):
                    self._overflow += 1
                    return
                with self._db:
                    self._db.execute("INSERT INTO calls VALUES (?,?,?)", (index, count, encoded))
                    self._db.execute(
                        "INSERT INTO roots VALUES (?,?,?) ON CONFLICT(root) DO UPDATE SET calls=excluded.calls, bytes=excluded.bytes",
                        (index, count + 1, root_bytes + size),
                    )
                self._recorded += 1
                self._pending += 1
                self._targets += int(current is None)
                self.pending_body_bytes += size
                self._peak_pending = max(self._peak_pending, self._pending)
                self._peak_bytes = max(self._peak_bytes, self.pending_body_bytes)
            except sqlite3.Error:
                self._storage_errors += 1

    def pop(self, index: int) -> dict[str, Any]:
        with self._lock:
            if self._final is not None:
                raise RuntimeError("Kafka UI wire ledger closed")
            try:
                current = self._db.execute("SELECT calls,bytes FROM roots WHERE root=?", (index,)).fetchone()
                calls = [
                    json.loads(row[0])
                    for row in self._db.execute("SELECT payload FROM calls WHERE root=? ORDER BY ordinal", (index,))
                ]
                if current is not None:
                    with self._db:
                        self._db.execute("DELETE FROM calls WHERE root=?", (index,))
                        self._db.execute("DELETE FROM roots WHERE root=?", (index,))
                    self._pending -= current[0]
                    self.pending_body_bytes -= current[1]
                    self._targets -= 1
                return {"complete": not (self._overflow or self._malformed or self._storage_errors), "calls": calls}
            except (sqlite3.Error, ValueError, UnicodeError):
                self._storage_errors += 1
                return {"complete": False, "calls": []}

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            if self._final is not None:
                return dict(self._final)
            return {
                "recorded_calls": self._recorded,
                "pending_calls": self._pending,
                "pending_targets": self._targets,
                "overflow": self._overflow,
                "malformed": self._malformed,
                "storage_errors": self._storage_errors,
                "pending_bytes": self.pending_body_bytes,
                "peak_pending_calls": self._peak_pending,
                "peak_pending_bytes": self._peak_bytes,
                "sqlite_cache_kib": 512,
                "temporary_disk_bytes": self.storage_path.stat().st_size if self.storage_path.exists() else 0,
            }

    def close(self) -> None:
        with self._lock:
            if self._final is None:
                self._final = self.snapshot()
            try:
                self._db.close()
            finally:
                self.pending_body_bytes = 0
                self._temporary.cleanup()
                self._final["temporary_storage_removed"] = int(not self.storage_path.exists())


def exchange_errors(wire: dict[str, Any] | None) -> list[str]:
    if not isinstance(wire, dict) or wire.get("complete") is not True or not isinstance(wire.get("calls"), list):
        return ["incomplete Kafka UI exchange evidence"]
    for call in wire["calls"]:
        if not isinstance(call, dict) or type(call.get("status")) is not int or call.get("kind") != "kafka_ui_exchange":
            return ["malformed Kafka UI exchange"]
        for key in ["method", "path", "body", "body_sha256", "response_body", "response_sha256"]:
            if not isinstance(call.get(key), str):
                return ["malformed Kafka UI exchange text"]
        for key in ["headers", "response_headers"]:
            if not isinstance(call.get(key), dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in call[key].items()
            ):
                return ["malformed Kafka UI exchange headers"]
        try:
            corrupt = any(
                hashlib.sha256(call[key].encode()).hexdigest() != call[digest]
                for key, digest in [("body", "body_sha256"), ("response_body", "response_sha256")]
            )
        except UnicodeError:
            return ["malformed Kafka UI UTF-8 body"]
        if corrupt:
            return ["corrupt Kafka UI exchange body"]
        if call["method"] == "GET" and call["body"]:
            return ["unexpected Kafka UI GET body"]
        if "authorization" in call["headers"]:
            return ["unexpected HTTP Authorization in form-only model"]
        if call["method"] not in {"GET", "POST", "PUT"}:
            return ["unexpected Kafka UI mutation"]
        if call["method"] == "PUT" and (call["path"] != "/api/smartfilters/testexecutions" or call["status"] != 403):
            return ["unexpected or successful Kafka UI execution"]
    return []


def wire_kafka_ui_record(
    record: dict[str, Any],
    wire: dict[str, Any] | None,
    *,
    surface: str,
    origin: str,
    valid_pair: tuple[str, str] | None,
) -> tuple[dict[str, Any], list[str]]:
    errors = exchange_errors(wire)
    if errors:
        return record, errors
    assert wire is not None
    if surface not in AUTH_SURFACES or _malformed_attempts(record):
        return record, ["invalid Kafka UI surface or credential ledger"]
    login = "/auth" if surface == "provectus-ui" else "/login"
    observed: dict[tuple[str, str], str] = {}
    calls = wire["calls"]
    for call in calls:
        if call["method"] != "POST":
            continue
        if call["path"] != login:
            return record, ["credentials sent to unexpected Kafka UI endpoint"]
        try:
            fields = parse_qs(call["body"], keep_blank_values=True, strict_parsing=True, max_num_fields=8)
            if set(fields) != {"username", "password"} or any(len(v) != 1 for v in fields.values()):
                raise ValueError("incomplete pair")
            pair = fields["username"][0], fields["password"][0]
        except (ValueError, UnicodeError):
            return record, ["malformed received Kafka UI login pair"]
        if pair in observed:
            return record, ["duplicate Kafka UI login attempt"]
        response_headers = call["response_headers"]
        if pair == valid_pair:
            expected_cookie = session_cookie(origin, pair)
            issued = response_headers.get("set-cookie", "").split(";", 1)[0]
            if call["status"] != 302 or response_headers.get("location") != "/" or issued != expected_cookie:
                return record, ["successful form lacks matching issued session"]
            identity = False
            for reply in calls:
                if (
                    reply["method"] == "GET"
                    and reply["path"] == "/api/authorization"
                    and reply["headers"].get("cookie") == issued
                    and reply["status"] == 200
                ):
                    try:
                        payload = json.loads(reply["response_body"])
                        info = payload.get("userInfo") if isinstance(payload, dict) else None
                        identity |= isinstance(info, dict) and info.get("username") == pair[0]
                    except (ValueError, UnicodeError):
                        pass
            if not identity:
                return record, ["successful form lacks matching protected identity"]
            observed[pair] = "valid"
        else:
            if (
                call["status"] != 302
                or response_headers.get("location") != login + "?error"
                or response_headers.get("set-cookie")
            ):
                return record, ["invalid form lacks explicit rejection"]
            observed[pair] = "invalid"
    rows = max(_ledgers(record), key=len, default=[])
    if not rows and record.get("provided_username") is not None:
        rows = [
            {
                **record,
                "username": record.get("provided_username"),
                "password": record.get("provided_password"),
                "source": "provided",
            }
        ]
    pairs = [(r.get("username"), r.get("password")) for r in rows]
    if (
        any(not isinstance(u, str) or not isinstance(p, str) for u, p in pairs)
        or len(set(pairs)) != len(pairs)
        or set(pairs) != set(observed)
    ):
        return record, ["received full login pairs differ from client attempts"]
    validated = []
    for row, pair in zip(rows, pairs, strict=True):
        state = _state(row)
        if state in {"invalid_credentials", "rejected"}:
            state = "invalid"
        if (
            state == "unknown"
            and row.get("ok") is False
            and record.get("status") == "invalid_credentials"
            and record.get("provided_credentials_ok") is False
        ):
            # Kafka's typed runtime attempt has ok=False without a state key.
            # Require the corresponding explicit rejected root as well; never
            # turn a transport/unavailable result into a password rejection.
            state = "invalid"
        if (
            state != observed[pair]
            or (observed[pair] == "invalid" and accepted_claim(row))
            or (observed[pair] == "valid" and any(row.get(key) is False for key in ["ok", "provided_credentials_ok"]))
        ):
            return record, ["client credential verdict differs from form/session/identity proof"]
        validated.append({**row, "credential_state": state})
    issued = {session_cookie(origin, pair) for pair, state in observed.items() if state == "valid"}
    if any(call["headers"].get("cookie") and call["headers"]["cookie"] not in issued for call in calls):
        return record, ["unknown or cross-origin Kafka UI session received"]
    if record.get("provided_credentials_ok") is True and not any(v == "valid" for v in observed.values()):
        return record, ["root falsely accepts rejected Kafka UI login"]
    return {**record, "attempted_credentials": validated}, []


def inventory_errors(record: dict[str, Any], *, limited: bool, categories: list[str]) -> list[str]:
    errors = []
    clusters = [{"name": name, "broker_count": 3, "topic_count": 201, "read_only": True} for name in CLUSTER_NAMES]
    if record.get("ui_clusters") != clusters or record.get("cluster_count") != 3:
        errors.append("Kafka UI cluster inventory differs")
    accessible = CLUSTER_NAMES[:1] if limited else CLUSTER_NAMES
    for name, expected in [
        ("topics", [{"cluster": cluster, "name": name} for cluster in accessible for name in TOPIC_NAMES]),
        ("brokers", [{"cluster": cluster, **item} for cluster in accessible for item in BROKERS]),
        ("consumer_groups", [{"cluster": cluster, "name": name} for cluster in accessible for name in GROUP_NAMES]),
    ]:
        if name not in categories:
            continue
        if record.get("ui_" + name) != expected or record.get("ui_" + name + "_partial") is not limited:
            errors.append("Kafka UI paged inventory/ACL differs: " + name)
    return errors
