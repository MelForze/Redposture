"""Quality evidence for performance profiles; independent of product decisions.

The profiler must not call an incomplete credential observation successful.
These helpers describe claims made by a record, not whether credentials are
actually valid. Real validity comes from the controlled server scenario.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import statistics
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

ACCEPTED_STATES = frozenset(
    {"valid", "valid_credentials", "weak_default_creds", "auth_valid", "token_ok", "valid_token", "token_accepted"}
)


def public_summary_errors(path: Path, roles: dict[int, str]) -> list[str]:
    """Check the actual JSONL footer in bounded chunks, outside timed work.

    Ordinary records may contain large values; do not deserialize or retain
    them just to find the small terminal summary. The public footer contract
    starts with its type field and is bounded to64KiB by this QA observer.
    """
    footers: list[dict[str, Any]] = []
    start = True
    after_footer = False
    try:
        with path.open("rb") as handle:
            while chunk := handle.readline(65537):
                if after_footer and chunk.strip():
                    return ["public summary is not the last record"]
                if start and re.match(rb'\s*\{\s*"type"\s*:\s*"summary"(?:\s*[,}])', chunk):
                    if len(chunk) > 65536:
                        return ["public summary exceeds QA observer bound"]
                    try:
                        footer = json.loads(chunk)
                    except (ValueError, UnicodeError):
                        return ["malformed public JSON summary"]
                    if not isinstance(footer, dict):
                        return ["malformed public summary object"]
                    footers.append(footer)
                    after_footer = True
                start = chunk.endswith(b"\n")
    except OSError:
        return ["public JSON output is unavailable for summary verification"]
    expected = Counter(roles.values())
    if not expected["closed"]:
        return ["unexpected public operational summary"] if footers else []
    if len(footers) != 1:
        return ["missing public operational summary"]
    footer = footers[0]
    values = {
        "requested_targets": len(roles),
        "processed_targets": len(roles),
        "record_count": len(roles),
        "detected_count": expected["positive"],
        "operational_failure_count": expected["closed"],
        "conclusive_negative_count": expected["foreign"],
    }
    if any(type(footer.get(key)) is not int or footer[key] != value for key, value in values.items()):
        return ["public summary counts differ from known target partitions"]
    status, reason = (
        ("partial", "partial_operational_failure")
        if expected["positive"]
        else ("inconclusive", "operational_failures_before_detection")
    )
    if footer.get("status") != status or footer.get("reason") != reason:
        return ["public summary status/reason differs from known target partitions"]
    return []


_PROOF_FIELDS = (
    "provided_credentials_ok",
    "credential_verified",
    "auth_valid",
    "token_valid",
    "credentials_valid",
    "login_success",
)
_ATTEMPT_FIELDS = ("attempted_credentials", "credential_attempts", "credentials")


class SchedulerAdmissionProbe:
    """Observe constructed scheduler capacity without guessing or changing it."""

    def __init__(self, scheduler_type: type[Any], *, limit: int = 16):
        if limit < 1:
            raise ValueError("positive scheduler observation bound required")
        self.scheduler_type, self.limit = scheduler_type, limit
        self._original: Any = None
        self._wrapped: Any = None
        self._calls = self._overflow = 0
        self._configurations: list[dict[str, int]] = []
        self._restore_conflict = False

    def __enter__(self) -> SchedulerAdmissionProbe:
        self._original = self.scheduler_type.__init__

        def observed(owner: Any, *args: Any, **kwargs: Any) -> None:
            self._original(owner, *args, **kwargs)
            self._calls += 1
            detect, deep = getattr(owner, "detect_workers", None), getattr(owner, "deep_workers", None)
            if type(detect) is not int or type(deep) is not int or min(detect, deep) < 1:
                self._overflow += 1
                return
            item = {"detect_workers": detect, "deep_workers": deep}
            if item not in self._configurations:
                if len(self._configurations) < self.limit:
                    self._configurations.append(item)
                else:
                    self._overflow += 1

        self._wrapped = observed
        self.scheduler_type.__init__ = observed
        return self

    def __exit__(self, *_exc: Any) -> None:
        if self.scheduler_type.__init__ is self._wrapped:
            self.scheduler_type.__init__ = self._original
        else:
            self._restore_conflict = True

    def snapshot(self) -> dict[str, Any]:
        return {
            "constructor_calls": self._calls,
            "configurations": [dict(row) for row in self._configurations],
            "overflow": self._overflow,
            "restore_conflict": self._restore_conflict,
        }

    def selected_detect_workers(self) -> int | None:
        if self._overflow or self._restore_conflict:
            return None
        if not self._calls:
            return 0  # The native scheduler was not constructed (e.g. small batch/sync).
        limits = {row["detect_workers"] for row in self._configurations}
        return next(iter(limits)) if len(limits) == 1 else None


class CoordinationWireLedger:
    """Bounded actual digest/read receipts, consumed by destination."""

    def __init__(self, *, per_target_limit: int = 256, total_limit: int = 32768, target_limit: int = 8192):
        if min(per_target_limit, total_limit, target_limit) < 1:
            raise ValueError("positive coordination receipt bounds required")
        self.per_target_limit, self.total_limit, self.target_limit = per_target_limit, total_limit, target_limit
        self._calls: dict[int, list[dict[str, Any]]] = {}
        self._recorded = self._pending = self._overflow = self._malformed = 0
        self._final: dict[str, int] | None = None

    def record(
        self, index: int, kind: str, username: str | None, password: str | None, path: str | None, error: int
    ) -> None:
        if self._final is not None:
            raise RuntimeError("coordination ledger closed")
        paired = isinstance(username, str) and isinstance(password, str)
        anonymous = username is None and password is None
        if (
            type(index) is not int
            or type(error) is not int
            or not (paired or anonymous)
            or any(len(v.encode()) > 4096 for v in (username, password, path) if isinstance(v, str))
            or not (
                kind == "digest_ack"
                and paired
                and path is None
                or kind == "read"
                and isinstance(path, str)
                and path.startswith("/")
            )
        ):
            self._malformed += 1
            return
        if (
            index not in self._calls
            and len(self._calls) >= self.target_limit
            or len(self._calls.get(index, [])) >= self.per_target_limit
            or self._pending >= self.total_limit
        ):
            self._overflow += 1
            return
        self._calls.setdefault(index, []).append(
            {"kind": kind, "username": username, "password": password, "path": path, "error": error}
        )
        self._pending += 1
        self._recorded += 1

    def pop(self, index: int) -> dict[str, Any]:
        if self._final is not None:
            raise RuntimeError("coordination ledger closed")
        calls = self._calls.pop(index, [])
        self._pending -= len(calls)
        return {"complete": not (self._malformed or self._overflow), "calls": calls}

    def snapshot(self) -> dict[str, int]:
        return (
            dict(self._final)
            if self._final is not None
            else {
                "recorded_calls": self._recorded,
                "pending_calls": self._pending,
                "pending_targets": len(self._calls),
                "overflow": self._overflow,
                "malformed": self._malformed,
            }
        )

    def close(self) -> None:
        if self._final is None:
            self._final = self.snapshot()
            self._calls.clear()


def wire_coordination_record(
    record: dict[str, Any], wire: dict[str, Any] | None, *, module: str
) -> tuple[dict[str, Any], str | None]:
    """Exact expected-inconclusive control; never weakens explicit-invalid gates."""
    if (
        module not in {"zookeeper", "keeper"}
        or record.get("is_" + module) is not True
        or record.get("auth_required") is not True
        or record.get("credential_verification_status") != "available"
        or record.get("credential_verification_path") != "/"
        or not isinstance(record.get("anonymous_auth_probe_results"), dict)
        or record["anonymous_auth_probe_results"].get("/") != "noauth"
        or _malformed_attempts(record)
    ):
        return record, "missing confirmed coordination service/anonymous verifier"
    if not isinstance(wire, dict) or wire.get("complete") is not True or not isinstance(wire.get("calls"), list):
        return record, "incomplete coordination wire evidence"
    calls = wire["calls"]
    if any(
        not isinstance(c, dict)
        or not {"kind", "username", "password", "path", "error"}.issubset(c)
        or c.get("kind") not in {"digest_ack", "read"}
        or type(c.get("error")) is not int
        or not (
            isinstance(c.get("username"), str)
            and isinstance(c.get("password"), str)
            or c.get("username") is None
            and c.get("password") is None
            and c.get("kind") == "read"
        )
        or (c.get("kind") == "digest_ack" and c.get("path") is not None)
        or (c.get("kind") == "read" and (not isinstance(c.get("path"), str) or not c["path"].startswith("/")))
        for c in calls
    ):
        return record, "malformed coordination receipt"
    if sum(c["kind"] == "read" and c["username"] is None and c["path"] == "/" for c in calls) != 1:
        return record, "missing or duplicate received anonymous root probe"
    rows = max(_ledgers(record), key=len, default=[])
    if not rows and record.get("provided_credentials") is True:
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
        not pairs
        or any(not isinstance(u, str) or not isinstance(p, str) for u, p in pairs)
        or len(set(pairs)) != len(pairs)
    ):
        return record, "missing or duplicate complete client digest pairs"
    acks = [c for c in calls if c["kind"] == "digest_ack"]
    if [(c["username"], c["password"]) for c in acks] != pairs or any(c["error"] != 0 for c in acks):
        return record, "digest ACK pairs/order/count differ from client attempts"
    if any((c["username"], c["password"]) not in set(pairs) for c in calls if c["username"] is not None):
        return record, "unexpected received digest identity"
    if any(c["kind"] == "read" and c["error"] != -102 for c in calls):
        return record, "read differs from expected protected NOAUTH control"
    for row, pair in zip(rows, pairs, strict=True):
        own = row.get("credential_auth_probe_results")
        reads = [c for c in calls if c["kind"] == "read" and (c["username"], c["password"]) == pair]
        if (
            "provided_credentials_ok" not in row
            or row.get("provided_credentials_ok") is not None
            or row.get("status") != "auth_required"
            or row.get("credential_verdict") != "unverified"
            or not isinstance(own, dict)
            or own.get("/") != "noauth"
            or any(v != "noauth" for v in own.values())
            or any(row.get(k) is not None for k in ("credential_state", "credential_verification"))
            or not any(c["path"] == "/" for c in reads)
            or not set(own).issubset({c["path"] for c in reads})
        ):
            return record, "missing matching completed inconclusive digest read"
    return {**record, "attempted_credentials": rows}, None


class HttpPairWireLedger:
    """Consume bounded actual form/Basic requests by destination, never CLI values."""

    def __init__(
        self,
        *,
        per_target_limit: int = 130,
        total_limit: int = 32768,
        target_limit: int = 8192,
        body_limit: int = 8 * 1024 * 1024,
    ):
        if min(per_target_limit, total_limit, target_limit) < 1:
            raise ValueError("positive HTTP pair ledger bounds required")
        if body_limit < 1:
            raise ValueError("positive body ledger bound required")
        self.body_limit = body_limit
        self.pending_body_bytes = 0
        self.per_target_limit, self.total_limit, self.target_limit = per_target_limit, total_limit, target_limit
        self._calls: dict[int, list[dict[str, Any]]] = {}
        self._pending = self._recorded = self._overflow = self._malformed = 0
        self._final: dict[str, int] | None = None

    def record(
        self, index: int, module: str, method: str, path: str, headers: dict[bytes, bytes], body: bytes, status: int
    ) -> None:
        if self._final is not None:
            raise RuntimeError("HTTP pair ledger closed")
        route = urlsplit(path).path
        form = module == "gitlab" and method == "POST" and route == "/users/sign_in"
        basic = (
            module == "kubeapi"
            and route in {"/api/v1/namespaces", "/apis/authentication.k8s.io/v1/selfsubjectreviews"}
            or module == "rabbitmq"
            and route == "/api/whoami"
            or module == "harbor"
            and route == "/api/v2.0/users/current"
            or module == "nexus"
            and route in {"/service/rest/v1/security/users", "/service/rest/v1/status"}
        ) and headers.get(b"authorization", b"")[:6].lower() == b"basic "
        script = (
            module == "nexus"
            and method == "POST"
            and route == "/service/rest/v1/script"
            and headers.get(b"authorization", b"")[:6].lower() == b"basic "
        )
        if not (form or basic or script):
            return
        if type(index) is not int or type(status) is not int or len(body) > 65536:
            self._malformed += 1
            return
        try:
            if form:
                fields = parse_qs(
                    body.decode("utf-8"),
                    keep_blank_values=True,
                    strict_parsing=True,
                    errors="strict",
                    max_num_fields=16,
                )
                if any(
                    len(fields.get(key, [])) != 1 for key in ("user[login]", "user[password]", "authenticity_token")
                ):
                    raise ValueError("incomplete login form")
                username, password = fields["user[login]"][0], fields["user[password]"][0]
                cookie_text = headers.get(b"cookie", b"").decode("ascii", errors="strict")
                if len(cookie_text) + len(fields["authenticity_token"][0].encode()) > 4096:
                    raise ValueError("form proof exceeds measurement bound")
            else:
                value = base64.b64decode(headers[b"authorization"][6:], validate=True).decode("utf-8")
                username, separator, password = value.partition(":")
                if not separator:
                    raise ValueError("incomplete Basic pair")
            if len(username.encode()) + len(password.encode()) > 4096:
                raise ValueError("credential exceeds measurement ledger bound")
        except (KeyError, UnicodeError, ValueError):
            self._malformed += 1
            return
        if (
            self._pending >= self.total_limit
            or len(self._calls.get(index, [])) >= self.per_target_limit
            or (index not in self._calls and len(self._calls) >= self.target_limit)
        ):
            self._overflow += 1
            return
        if script and self.pending_body_bytes + len(body) > self.body_limit:
            self._overflow += 1
            return
        try:
            script_body = body.decode("utf-8", errors="strict") if script else None
        except UnicodeError:
            self._malformed += 1
            return
        call = {
            "kind": "form" if form else "nexus_probe" if script else "basic",
            "method": method,
            "path": path,
            "username": username,
            "password": password,
            "status": status,
        }
        if script:
            assert script_body is not None
            call.update(body=script_body, body_sha256=hashlib.sha256(body).hexdigest())
            self.pending_body_bytes += len(body)
        if form:
            call.update(
                csrf_token=fields["authenticity_token"][0],
                cookie=cookie_text,
                body_sha256=hashlib.sha256(body).hexdigest(),
            )
        self._calls.setdefault(index, []).append(call)
        self._recorded += 1
        self._pending += 1

    def pop(self, index: int) -> dict[str, Any]:
        if self._final is not None:
            raise RuntimeError("HTTP pair ledger closed")
        calls = self._calls.pop(index, [])
        self._pending -= len(calls)
        self.pending_body_bytes -= sum(len(c["body"].encode()) for c in calls if c["kind"] == "nexus_probe")
        return {"complete": not (self._overflow or self._malformed), "calls": calls}

    def snapshot(self) -> dict[str, int]:
        return (
            dict(self._final)
            if self._final is not None
            else {
                "recorded_calls": self._recorded,
                "pending_calls": self._pending,
                "pending_targets": len(self._calls),
                "overflow": self._overflow,
                "malformed": self._malformed,
            }
        )

    def close(self) -> None:
        if self._final is None:
            self._final = self.snapshot()
            self._calls.clear()
            self.pending_body_bytes = 0


def wire_http_pair_record(
    record: dict[str, Any], wire: dict[str, Any] | None, *, module: str
) -> tuple[dict[str, Any], str | None]:
    """Check matching full received identities; preserve the client's own verdict."""
    if module == "etcd":
        from scripts.performance_etcd import wire_etcd_record

        return wire_etcd_record(record, wire)
    if module == "elastic":
        from scripts.performance_elastic import wire_elastic_record

        return wire_elastic_record(record, wire)
    if module == "portainer":
        from scripts.performance_portainer import wire_portainer_record

        return wire_portainer_record(record, wire)
    if not isinstance(wire, dict) or wire.get("complete") is not True or not isinstance(wire.get("calls"), list):
        return record, "incomplete HTTP pair wire evidence"
    calls = wire["calls"]
    if any(
        not isinstance(r, dict)
        or any(not isinstance(r.get(k), str) for k in ("kind", "method", "path", "username", "password"))
        or type(r.get("status")) is not int
        for r in calls
    ):
        return record, "malformed HTTP credential receipt"
    ledgers = _ledgers(record)
    rows = max(ledgers, key=len, default=[])
    observation = record
    if _malformed_attempts(record):
        return record, "malformed client credential ledger"
    if (
        not rows
        and module in {"gitlab", "harbor", "nexus"}
        and record.get("is_" + module) is True
        and isinstance(record.get("provided_username"), str)
        and isinstance(record.get("provided_password"), str)
        and type(record.get("provided_credentials_ok")) is bool
        and record.get("status")
        in (
            {"valid_credentials", "auth_required"}
            if module in {"harbor", "nexus"}
            else {"valid_credentials", "invalid_credentials"}
        )
    ):
        rows = [
            {
                **record,
                "username": record["provided_username"],
                "password": record["provided_password"],
                "source": record.get("credentials_source"),
            }
        ]
        observation = {**record, "attempted_credentials": rows}
    if (
        not rows
        and module == "kubeapi"
        and record.get("is_kubeapi") is True
        and record.get("auth_mode") == "basic"
        and type(record.get("auth_valid")) is bool
        and record.get("auth_verification_method") in {"namespace_list", "self_subject_review"}
        and record.get("status") in {"auth_valid", "auth_failed", "invalid_credentials_anonymous"}
    ):
        # The single result omits its username/password. Attribute it only to
        # one unambiguous full pair actually received, never to CLI arguments.
        actual = {(r["username"], r["password"]) for r in calls}
        if len(actual) == 1:
            username, password = next(iter(actual))
            rows = [{**record, "username": username, "password": password, "source": record.get("credentials_source")}]
            observation = {**record, "attempted_credentials": rows}
    if not rows:
        return record, "missing client credential ledger"
    pairs = [(r.get("username"), r.get("password")) for r in rows]
    if any(not isinstance(u, str) or not isinstance(p, str) for u, p in pairs) or len(set(pairs)) != len(pairs):
        return record, "incomplete or duplicate client credential identities"
    if module == "nexus":
        return _wire_nexus_record(record, calls, rows, observation)
    received = {(r.get("username"), r.get("password")) for r in calls}
    if received != set(pairs):
        return record, "client pairs differ from received HTTP credentials"
    if module == "harbor":
        if (
            record.get("is_harbor") is not True
            or record.get("is_registry") is not True
            # Registry data records preserve the explicit boolean verdict,
            # but the optional auth-stage availability field is not emitted.
            # Missing is not a rejection: full identity receipts below must
            # still prove every decision. An explicit unavailable is invalid.
            or type(record.get("provided_credentials_ok")) is not bool
            or record.get("credential_verification_status") not in {None, "available"}
            or len(calls) != len(pairs)
            or any(
                r["kind"] != "basic" or r["method"] != "GET" or urlsplit(r["path"]).path != "/api/v2.0/users/current"
                for r in calls
            )
        ):
            return record, "Harbor identity verifier unavailable or repeated"
        for row, call in zip(rows, calls, strict=True):
            if (row["username"], row["password"]) != (call["username"], call["password"]) or not (
                _state(row) == "valid" and call["status"] == 200 or _state(row) == "invalid" and call["status"] == 401
            ):
                return record, "Harbor identity receipt contradicts client credential decision"
        return observation, None
    if module == "rabbitmq":
        if (
            record.get("is_rabbitmq") is not True
            or record.get("auth_required") is not True
            or record.get("credential_verification_status") != "available"
            or len(calls) != len(pairs)
            or any(
                r["kind"] != "basic" or r["method"] != "GET" or urlsplit(r["path"]).path != "/api/whoami" for r in calls
            )
        ):
            return record, "RabbitMQ identity verifier unavailable or repeated"
        for row in rows:
            same = [r for r in calls if (r["username"], r["password"]) == (row["username"], row["password"])]
            if (
                len(same) != 1
                or row.get("credential_http_status") != same[0]["status"]
                or (
                    not (_state(row) == "valid" and same[0]["status"] == 200)
                    and not (_state(row) == "invalid" and same[0]["status"] == 401)
                )
            ):
                return record, "RabbitMQ whoami receipt contradicts client credential decision"
        return observation, None
    if module == "gitlab":
        if any(
            r.get("kind") != "form" or r.get("method") != "POST" or urlsplit(r.get("path", "")).path != "/users/sign_in"
            for r in calls
        ) or len(calls) != len(pairs):
            return record, "GitLab login request count or surface differs"
        return observation, None
    if (
        module != "kubeapi"
        or record.get("auth_mode") != "basic"
        or (
            record.get("credentials_source") == "default"
            and record.get("credential_verification_status") != "available"
        )
    ):
        return record, "unavailable Basic proxy verifier"
    updated = []
    for row in rows:
        same = [
            r for r in calls if (r.get("username"), r.get("password")) == (row.get("username"), row.get("password"))
        ]
        if row.get("status") == "auth_valid" and not any(
            r.get("method") == "POST"
            and urlsplit(r.get("path", "")).path == "/apis/authentication.k8s.io/v1/selfsubjectreviews"
            and r.get("status") == 201
            for r in same
        ):
            return record, "missing verified Basic identity response"
        if (
            row.get("status") == "auth_failed"
            and not row.get("credential_state")
            and not row.get("credential_verification")
            and any(r.get("status") == 401 for r in same)
        ):
            updated.append({**row, "credential_state": "invalid"})
        else:
            updated.append(row)
    # Observer-only copy; the public output and its redaction rules stay intact.
    return {**record, "attempted_credentials": updated}, None


def nexus_probe_body_error(body: Any, digest: Any) -> str | None:
    """Check the actual denied request; this does not certify execution."""
    if not isinstance(body, str) or hashlib.sha256(body.encode()).hexdigest() != digest:
        return "missing or corrupt probe body"
    try:
        payload = json.loads(body)
        if (
            set(payload) != {"name", "type", "content"}
            or payload["type"] != "groovy"
            or not re.fullmatch(r"redposture-exec-[0-9a-f]{20}", payload["name"])
        ):
            return "unexpected Nexus probe envelope"
        content = payload["content"]
        commands = re.findall(r'java\.util\.Base64\.decoder\.decode\("([^"\n]+)"\)', content)
        if len(commands) != 1:
            return "missing or ambiguous probe command"
        command = base64.b64decode(commands[0], validate=True).decode("utf-8")
        if (
            not re.fullmatch(r"echo REDPOSTURE_RCE_[0-9a-f]{24}", command)
            or len(re.findall(r"RP_NEXUS_[0-9a-f]{24}:", content)) != 1
        ):
            return "unexpected automatic probe command or marker"
    except (ValueError, TypeError, KeyError, UnicodeError):
        return "malformed Nexus probe body"
    return None


def _wire_nexus_record(
    record: dict[str, Any], calls: list[dict[str, Any]], rows: list[dict[str, Any]], observation: dict[str, Any]
) -> tuple[dict[str, Any], str | None]:
    """Nexus admin identity or restricted differential proof, never bare 403."""
    if (
        record.get("is_nexus") is not True
        or record.get("is_registry") is not True
        or type(record.get("provided_credentials_ok")) is not bool
    ):
        return record, "Nexus product or explicit identity result missing"
    probes = [c for c in calls if c["kind"] == "nexus_probe"]
    calls = [c for c in calls if c["kind"] != "nexus_probe"]
    accepted = any(_state(r) == "valid" for r in rows)
    if len(probes) > 1 or (probes and not accepted):
        return record, "unexpected Nexus automatic probe count"
    for call in probes:
        if (
            call["method"] != "POST"
            or call["path"] != "/service/rest/v1/script"
            or call["status"] != 405
            or (call["username"], call["password"])
            != (record.get("provided_username"), record.get("provided_password"))
            or nexus_probe_body_error(call.get("body"), call.get("body_sha256"))
        ):
            return record, "invalid Nexus denied probe receipt"
    users = "/service/rest/v1/security/users"
    status = "/service/rest/v1/status"
    if any(c["kind"] != "basic" or c["method"] != "GET" or c["path"] not in {users, status} for c in calls):
        return record, "unexpected Nexus identity surface"
    identities = [c for c in calls if c["path"] == users]
    pairs = [(r["username"], r["password"]) for r in rows]
    if [(c["username"], c["password"]) for c in identities] != pairs:
        return record, "Nexus identity request count/order differs from client pairs"
    remaining = [c for c in calls if c["path"] == status]
    for row, identity in zip(rows, identities, strict=True):
        pair = (row["username"], row["password"])
        own = [c for c in remaining if (c["username"], c["password"]) == pair]
        controls = [
            c
            for c in remaining
            if c["username"] == pair[0]
            and (c["username"], c["password"]) not in pairs
            and re.fullmatch(r"rp-verification-[0-9a-f]{32}", c["password"])
        ]
        if _state(row) == "invalid":
            if identity["status"] != 401 or own:
                return record, "Nexus rejected identity not proven by 401"
            continue
        if _state(row) != "valid":
            return record, "Nexus fixture credential verdict unavailable"
        if identity["status"] == 200:
            if len(own) != 1 or own[0]["status"] != 200:
                return record, "Nexus authenticated metadata response missing or repeated"
        elif identity["status"] == 403:
            if (
                len(own) != 2
                or any(c["status"] != 200 for c in own)
                or len(controls) != 1
                or controls[0]["status"] != 401
            ):
                return record, "Nexus restricted identity lacks complete differential proof"
            remaining.remove(controls[0])
        else:
            return record, "Nexus accepted identity contradicts security users status"
        for call in own:
            remaining.remove(call)
    if remaining:
        return record, "unexpected Nexus status credentials or extra controls"
    return observation, None


def rabbitmq_inventory_errors(record: dict[str, Any], *, limited: bool, vhost: str | None = None) -> list[str]:
    """Exact read-only seeded queue/vhost ACL result, independent of client code."""
    queues = record.get("enumeration", {}).get("queues", {})
    expected = [
        ("billing", "billing.invoices", 12, 2),
        ("billing", "billing.retry", 3, 0),
    ] + ([] if limited else [("events", "events.audit", 7, 1)])
    if vhost is not None:
        expected = [r for r in expected if r[0] == vhost]
    rows = queues.get("items")
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        return ["missing RabbitMQ queue inventory"]
    actual = [(r.get("vhost"), r.get("name"), r.get("messages"), r.get("consumers")) for r in rows]
    errors = []
    expected_status = "denied" if limited and vhost == "events" else "ok"
    if actual != expected or queues.get("status") != expected_status or queues.get("truncated") is not False:
        errors.append("RabbitMQ queues missing/extra/duplicate/truncated")
    if record.get("admin") is not (not limited):
        errors.append("RabbitMQ admin capability differs from seeded permissions")
    expected_cluster_id = None if limited else "rabbitmq-cluster-id-qa-billing"
    if record.get("provided_credentials_ok") is not True or record.get("cluster_id") != expected_cluster_id:
        errors.append("RabbitMQ inventory lacks verified identity or cluster attribution")
    return errors


def minio_inventory_errors(record: dict[str, Any], *, limited: bool) -> list[str]:
    buckets = record.get("buckets")
    capability = record.get("credential_capabilities")
    if not isinstance(capability, dict):
        return ["missing MinIO bucket capability evidence"]
    if limited:
        return (
            []
            if (
                buckets == []
                and capability.get("bucket_count") is None
                and record.get("listing_errors") == ["ListBuckets: HTTP 403"]
                and record.get("inventory_coverage") == "partial"
            )
            else ["missing explicit MinIO bucket-list denial"]
        )
    expected = [
        {"name": name, "creation_date": "2026-01-01T00:00:00Z"}
        for name in ("analytics-reports", "pipeline-artifacts", "audit-backups")
    ]
    return (
        []
        if (
            isinstance(buckets, list)
            and len(buckets) == len(expected)
            and all(isinstance(item, dict) for item in buckets)
            and sorted(buckets, key=lambda item: str(item.get("name")))
            == sorted(expected, key=lambda item: item["name"])
            and type(capability.get("bucket_count")) is int
            and capability["bucket_count"] == 3
            and not capability.get("inventory_error")
            and not record.get("listing_errors")
            and record.get("inventory_coverage") != "partial"
        )
        else ["MinIO seeded bucket inventory or metadata differs"]
    )


class S3WireLedger:
    """Bounded complete signed root requests, consumed by destination root.

    The signature and canonical headers are retained, never the secret. A
    public credential row may be attributed only after independent HMAC proof.
    """

    def __init__(self, *, per_target_limit: int = 130, total_limit: int = 32768, target_limit: int = 8192):
        if min(per_target_limit, total_limit, target_limit) < 1:
            raise ValueError("positive S3 wire bounds required")
        self.per_target_limit, self.total_limit, self.target_limit = per_target_limit, total_limit, target_limit
        self._calls: dict[int, list[dict[str, Any]]] = {}
        self._pending = self._recorded = self._overflow = self._malformed = 0
        self._final: dict[str, int] | None = None

    def record(self, index: int, method: str, path: str, headers: dict[bytes, bytes], body: bytes) -> None:
        if self._final is not None:
            raise RuntimeError("S3 wire ledger closed")
        if method != "GET" or path != "/" or b"authorization" not in headers:
            return
        if type(index) is not int or body or len(headers) > 32:
            self._malformed += 1
            return
        try:
            if sum(len(k) + len(v) for k, v in headers.items()) > 8192:
                self._malformed += 1
                return
            fields = {k.decode("ascii"): v.decode("ascii") for k, v in headers.items()}
        except (AttributeError, UnicodeError, TypeError):
            self._malformed += 1
            return
        if (
            self._pending >= self.total_limit
            or len(self._calls.get(index, ())) >= self.per_target_limit
            or (index not in self._calls and len(self._calls) >= self.target_limit)
        ):
            self._overflow += 1
            return
        self._calls.setdefault(index, []).append({"method": method, "path": path, "headers": fields})
        self._pending += 1
        self._recorded += 1

    def pop(self, index: int) -> dict[str, Any]:
        if self._final is not None:
            raise RuntimeError("S3 wire ledger closed")
        calls = self._calls.pop(index, [])
        self._pending -= len(calls)
        return {"complete": not (self._overflow or self._malformed), "calls": calls}

    def snapshot(self) -> dict[str, int]:
        return (
            dict(self._final)
            if self._final is not None
            else {
                "recorded_calls": self._recorded,
                "pending_calls": self._pending,
                "pending_targets": len(self._calls),
                "overflow": self._overflow,
                "malformed": self._malformed,
            }
        )

    def close(self) -> None:
        if self._final is None:
            self._final = self.snapshot()
            self._calls.clear()


def wire_s3_record(
    record: dict[str, Any], wire: dict[str, Any] | None, *, single_pair: tuple[str, str] | None = None
) -> tuple[dict[str, Any], str | None]:
    """Verify received signatures; single_pair is a candidate, never evidence."""
    from scripts.performance_http_fixtures import verified_s3_access_key

    if not isinstance(wire, dict) or wire.get("complete") is not True:
        return record, "incomplete S3 wire ledger"
    calls = wire.get("calls")
    if not isinstance(calls, list) or not calls:
        return record, "missing signed S3 root requests"
    ledger = record.get("attempted_credentials")
    if isinstance(ledger, list) and ledger:
        pairs = [(r.get("username"), r.get("password")) for r in ledger if isinstance(r, dict)]
        if len(pairs) != len(ledger):
            return record, "malformed S3 credential ledger"
    elif single_pair is not None:
        identities = record.get("credential_results")
        if (
            not isinstance(identities, list)
            or len(identities) != 1
            or not isinstance(identities[0], dict)
            or identities[0].get("access_key") != single_pair[0]
            or identities[0].get("state") != record.get("credential_state")
            or record.get("is_minio") is not True
        ):
            return record, "missing S3 product identity verdict"
        pairs = [single_pair]
    else:
        return record, "missing S3 credential identity"
    if any(not isinstance(u, str) or not isinstance(p, str) for u, p in pairs):
        return record, "malformed S3 credential identity"
    if len(calls) < len(pairs) or len(set(pairs)) != len(pairs):
        return record, "S3 attempts differ from received root requests"
    proven: set[tuple[str, str]] = set()
    for call in calls:
        try:
            if call["method"] != "GET" or call["path"] != "/":
                return record, "unexpected S3 proof route"
            headers = {k.encode("ascii"): v.encode("ascii") for k, v in call["headers"].items()}
            matches = [
                (username, password)
                for username, password in pairs
                if isinstance(username, str)
                and isinstance(password, str)
                and verified_s3_access_key("GET", "/", headers, b"", secret_key=password) == username
            ]
        except (KeyError, AttributeError, UnicodeError, TypeError):
            return record, "malformed S3 wire request"
        if len(matches) != 1:
            return record, "S3 identity has no unique received signature proof"
        proven.add(matches[0])
    if proven != set(pairs):
        return record, "S3 credential has no received signature proof"
    if isinstance(ledger, list) and ledger:
        return record, None
    assert single_pair is not None
    return {
        **record,
        "attempted_credentials": [
            {**record, "username": single_pair[0], "password": single_pair[1], "source": "provided"}
        ],
    }, None


class GrpcWireLedger:
    """Bounded, consuming QA observations, indexed by actual destination.

    Only complete received RPCs enter here. This is not a statement that the
    client received the response: its independent product verdict is required.
    Store at most1KiB of authorization per call; overflow invalidates evidence.
    Call under the fixture lock. No expected catalogue is accepted as input.
    """

    def __init__(self, *, per_target_limit: int = 130, total_limit: int = 32768, target_limit: int = 8192):
        if min(per_target_limit, total_limit, target_limit) < 1:
            raise ValueError("positive wire ledger bounds required")
        self.per_target_limit, self.total_limit, self.target_limit = per_target_limit, total_limit, target_limit
        self._calls: dict[int, list[dict[str, Any]]] = {}
        self._pending = self._recorded = self._overflow = self._malformed = 0
        self._final: dict[str, int] | None = None

    def record(self, index: int, headers: list[tuple[bytes, bytes]] | None, status: int) -> None:
        if self._final is not None:
            raise RuntimeError("wire ledger closed")
        if type(index) is not int or type(status) is not int or not isinstance(headers, list) or len(headers) > 128:
            self._malformed += 1
            return
        fields: dict[bytes, bytes] = {}
        for item in headers:
            if not isinstance(item, (list, tuple)) or len(item) != 2 or not isinstance(item[0], bytes):
                self._malformed += 1
                return
            name, value = item
            if name not in {b":method", b":path", b"authorization"}:
                continue
            if name in fields or not isinstance(value, bytes) or len(value) > 1024:
                self._malformed += 1
                return
            fields[name] = value
        try:
            method, path = fields[b":method"].decode("ascii"), fields[b":path"].decode("ascii")
            auth = fields[b"authorization"].decode("ascii") if b"authorization" in fields else None
        except (KeyError, UnicodeError):
            self._malformed += 1
            return
        if len(path) > 256:
            self._malformed += 1
            return
        if (
            self._pending >= self.total_limit
            or len(self._calls.get(index, ())) >= self.per_target_limit
            or (index not in self._calls and len(self._calls) >= self.target_limit)
        ):
            self._overflow += 1
            return
        self._calls.setdefault(index, []).append(
            {"method": method, "path": path, "authorization": auth, "status": status}
        )
        self._recorded += 1
        self._pending += 1

    def pop(self, index: int) -> dict[str, Any]:
        if self._final is not None:
            raise RuntimeError("wire ledger closed")
        calls = self._calls.pop(index, [])
        self._pending -= len(calls)
        return {"complete": not (self._overflow or self._malformed), "calls": calls}

    def snapshot(self) -> dict[str, int]:
        return (
            dict(self._final)
            if self._final is not None
            else {
                "recorded_calls": self._recorded,
                "pending_calls": self._pending,
                "pending_targets": len(self._calls),
                "overflow": self._overflow,
                "malformed": self._malformed,
            }
        )

    def close(self) -> None:
        if self._final is None:
            self._final = self.snapshot()
            self._calls.clear()
            self._pending = 0


def wire_grpc_record(record: dict[str, Any], evidence: Any) -> tuple[dict[str, Any], str | None]:
    """Correlate known-denied gRPC sweeps, without changing product output.

    Each received credential must have its health/reflection calls, matching
    the independently rejected ledger row. Omitted token values come only from
    wire Authorization, never from a plan/catalogue or a generic count.
    """
    if (
        record.get("service") != "grpc"
        or record.get("status") != "invalid_credentials"
        or record.get("provided_credentials_ok") is not False
        or record.get("credential_verification_status") != "available"
        or record.get("health_access") != "auth_required"
        or record.get("reflection_access") != "auth_required"
    ):
        return record, "unconfirmed grpc rejection"
    rows = record.get("attempted_credentials")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
        return record, "missing or oversized grpc ledger"
    if any(record.get(field) for field in _ATTEMPT_FIELDS if field != "attempted_credentials"):
        return record, "conflicting grpc ledger alias"
    if any(
        not isinstance(row, dict)
        or row.get("status") != "invalid_credentials"
        or any(row.get(key) is not None and not isinstance(row[key], str) for key in ("username", "password", "token"))
        for row in rows
    ):
        return record, "unconfirmed grpc ledger row"
    if not isinstance(evidence, dict) or evidence.get("complete") is not True:
        return record, "missing or incomplete grpc wire evidence"
    calls = evidence.get("calls")
    if not isinstance(calls, list) or len(calls) != 2 * (len(rows) + 1):
        return record, "grpc wire call count differs"
    health = "/grpc.health.v1.Health/Check"
    reflection = {
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    }
    observed = []
    identities = set()
    for offset in range(0, len(calls), 2):
        pair = calls[offset : offset + 2]
        if any(
            not isinstance(call, dict)
            or call.get("method") != "POST"
            or type(call.get("status")) is not int
            or call["status"] != 16
            or not isinstance(call.get("path"), str)
            for call in pair
        ):
            return record, "grpc wire request or status differs"
        first, second = pair
        if first.get("path") != health or second.get("path") not in reflection:
            return record, "grpc verifier path differs"
        auth = first.get("authorization")
        if auth != second.get("authorization"):
            return record, "grpc verifier identities differ"
        if offset == 0:
            if auth is not None:
                return record, "grpc anonymous control carried credentials"
            continue
        if not isinstance(auth, str) or len(auth) > 1024:
            return record, "grpc credential not observed"
        row = dict(rows[offset // 2 - 1])
        if row.get("provided_credential_type") == "token":
            prefix, separator, token = auth.partition(" ")
            if prefix != "Bearer" or not separator or not token or any(c.isspace() for c in token):
                return record, "invalid grpc bearer header"
            if (
                row.get("username") is not None
                or row.get("password") is not None
                or row.get("token") not in {None, token}
            ):
                return record, "conflicting grpc token identity"
            row["token"] = token
        elif row.get("provided_credential_type") == "basic":
            try:
                if not auth.startswith("Basic "):
                    raise ValueError
                user, password = base64.b64decode(auth[6:], validate=True).decode("utf-8").split(":", 1)
            except ValueError:
                return record, "invalid grpc basic header"
            if row.get("username") != user or row.get("password") != password or row.get("token") is not None:
                return record, "conflicting grpc basic identity"
        else:
            return record, "unknown grpc credential kind"
        identity = (row.get("username"), row.get("password"), row.get("token"))
        if identity in identities:
            return record, "duplicate grpc wire identity"
        identities.add(identity)
        observed.append(row)
    return {**record, "attempted_credentials": observed}, None


class HttpRouteStats:
    """Bounded fixture-side counts, keeping different auth identities separate.

    Call under the fixture's lock. This is measurement metadata, not product
    output: full route/auth identities are hashed, display samples are bounded,
    and overflow remains visible rather than silently dropping requests.
    """

    def __init__(self, limit: int = 256) -> None:
        self.limit = max(1, int(limit))
        self.routes: dict[str, dict[str, Any]] = {}
        self.other = 0

    def record(
        self, method: str, path: str, headers: dict[bytes, bytes], body: bytes, *, body_group: str | None = None
    ) -> None:
        names = (
            b"authorization",
            b"private-token",
            b"x-vault-token",
            b"x-nomad-token",
            b"x-consul-token",
            b"api-key",
            b"cookie",
        )
        material = b"\0".join(name + b"=" + headers[name] for name in names if name in headers)
        mode = "header" if material else "body" if body else "anonymous"
        authorization = headers.get(b"authorization", b"")
        auth_body = body
        if authorization.startswith(b"AWS4-HMAC-SHA256 "):
            key = re.search(rb"\bCredential=([^/ ,]{1,256})/", authorization)
            if key is not None:
                # SigV4 signs the host and date, so opaque header hashing would
                # create one route row per destination. This grouping is only
                # the *claimed* access key; S3WireLedger retains every complete
                # signature and wire_s3_record independently verifies secrets.
                material = (
                    b"s3-claimed-access-key="
                    + key[1]
                    + b"\0"
                    + b"\0".join(
                        name + b"=" + headers[name] for name in names if name != b"authorization" and name in headers
                    )
                )
                mode = "s3_claimed_access_key"
        if method == "POST" and path.split("?", 1)[0] == "/users/sign_in":
            try:
                fields = parse_qs(
                    body.decode("utf-8"),
                    keep_blank_values=True,
                    strict_parsing=True,
                    errors="strict",
                    max_num_fields=16,
                )
            except (ValueError, UnicodeError):
                fields = {}
            if all(len(fields.get(key, [])) == 1 for key in ("authenticity_token", "user[login]", "user[password]")):
                # CSRF and session cookies vary per origin. Group stats by the
                # claimed pair, never mistake this for password/CSRF proof:
                # HttpPairWireLedger retains actual per-root form credentials.
                material = (
                    b"form-claimed-identity="
                    + json.dumps(
                        [fields["user[login]"][0], fields["user[password]"][0]], separators=(",", ":")
                    ).encode()
                    + b"\0"
                    + b"\0".join(name + b"=" + headers[name] for name in names if name != b"cookie" and name in headers)
                )
                auth_body = b""
                mode = "form_claimed_identity"
        if body_group == "gitlab-web-session" and method in {"GET", "HEAD"}:
            cookie = headers.get(b"cookie", b"")
            match = re.fullmatch(rb"_gitlab_session=profile-(anon-[0-9a-f]{24}|auth-[0-9a-f]{64})", cookie)
            if match:
                # Our fixture issues origin-bound HMAC sessions. Their opaque
                # values create one stats row per target, even for identical
                # read requests. This groups only the claimed fixture session
                # class, never verifies credentials or changes wire receipts.
                # Other headers, routes and body bytes keep their identities.
                state = match[1].split(b"-", 1)[0]
                material = (
                    b"gitlab-web-claimed-session="
                    + state
                    + b"\0"
                    + b"\0".join(name + b"=" + headers[name] for name in names if name != b"cookie" and name in headers)
                )
                mode = "gitlab_web_claimed_session_" + state.decode("ascii")
        if (
            body_group == "nexus-script-endpoint"
            and method == "POST"
            and urlsplit(path).path == "/service/rest/v1/script"
        ):
            # Only statistics grouping: full denied body/identity/status is
            # retained independently in HttpPairWireLedger for every root.
            auth_body = b"nexus-script-endpoint-claim"
            mode = "nexus_script_endpoint_claim"
        if body_group == "kafka-ui-auth":
            # Group only statistics, never authentication proof. Issued session
            # HMACs and complete form bodies remain in KafkaUIWireLedger.
            cookie = headers.get(b"cookie", b"")
            match = re.fullmatch(rb"SESSION=qa-([A-Za-z0-9_-]+)\.[0-9a-f]{64}", cookie)
            if match:
                material = b"kafka-ui-claimed-session=" + match[1]
                mode = "kafka_ui_claimed_session"
            if method == "PUT" and urlsplit(path).path == "/api/smartfilters/testexecutions":
                auth_body = b"kafka-ui-denied-exec-probe-claim"
            if method == "POST" and urlsplit(path).path in {"/auth", "/login"}:
                # The actual model has CSRF disabled, matching the real two
                # products. Pair form bytes therefore have no origin nonce.
                material = b"kafka-ui-claimed-form"
                mode = "kafka_ui_claimed_form"
        if (
            body_group == "portainer-exec-endpoint"
            and method == "POST"
            and re.fullmatch(r"/api/endpoints/\d+/docker/containers/[^/]+/exec", urlsplit(path).path)
        ):
            # Group only statistics; the complete denied request and actual
            # session token are retained by PortainerWireLedger per root.
            auth_body = b"portainer-exec-endpoint-claim"
            mode = "portainer_exec_endpoint_claim"
        auth = hashlib.sha256(material + b"\0body=" + auth_body).hexdigest()
        stats_path = path
        if body_group == "elastic-probe-index" and re.fullmatch(
            r"/redposture-access-probe-[0-9a-f]{32}(?:/_doc/redposture-probe)?", path
        ):
            stats_path = re.sub(r"(?<=/redposture-access-probe-)[0-9a-f]{32}", "<nonce>", path)
        route = method + " " + stats_path
        identity = hashlib.sha256((route + "\0" + auth).encode()).hexdigest()
        if identity not in self.routes:
            if len(self.routes) >= self.limit:
                self.other += 1
                return
            self.routes[identity] = {
                "method": method,
                "route": stats_path[:512],
                "display_truncated": len(path) > 512,
                "route_identity_sha256": identity,
                "auth_identity_sha256": auth,
                "auth_mode": mode,
                "requests": 0,
            }
        self.routes[identity]["requests"] += 1

    def snapshot(self) -> dict[str, Any]:
        return {"routes": list(self.routes.values()), "overflow_requests": self.other, "complete": self.other == 0}


def accepted_claim(row: dict[str, Any]) -> bool:
    """Include contradictory acceptance: a false proof is itself a failed gate."""
    return (
        row.get("ok") is True
        or any(row.get(field) is True for field in _PROOF_FIELDS)
        or str(row.get("status", "")).lower() in ACCEPTED_STATES
        or str(row.get("credential_state", "")).lower() == "valid"
    )


def _identity(row: dict[str, Any]) -> tuple[Any, ...]:
    # A profile retains only this record's tiny per-identity catalogue; full
    # credential values must not become global diagnostic keys.
    return tuple(row.get(key) for key in ("username", "password", "token", "source"))


def _state(row: dict[str, Any]) -> str:
    state = str(row.get("credential_state") or row.get("credential_verification") or row.get("status") or "").lower()
    if state == "rejected":
        return "invalid"
    if state in {
        "invalid",
        "invalid_credentials",
        "unknown",
        "unverified",
        "verification_unavailable",
        "inconclusive",
        "auth_unknown",
        "skipped",
        "cancelled",
    }:
        return state
    if accepted_claim(row):
        return "valid"
    if row.get("credential_verification_status") == "available" and row.get("provided_credentials_ok") is False:
        return "invalid"
    if (
        state == "invalid_credentials_anonymous"
        and row.get("auth_probe_status") == "rejected"
        and row.get("auth_probe_http_status") == 401
    ):
        return "invalid"
    if state == "auth_required" and str(row.get("error") or "").strip().lower() == "authentication rejected":
        return "invalid"
    if (
        state == "auth_failed"
        and row.get("auth_method") == "password"
        and str(row.get("error") or "").startswith("pve credential rejected:")
    ):
        return "invalid"
    if str(row.get("error") or "").strip().lower() in {"invalid credentials", "authentication failed"}:
        return "invalid"
    if str(row.get("error") or "").strip().upper().startswith("WRONGPASS "):
        return "invalid"
    return state or "unknown"


def _ledgers(record: dict[str, Any]) -> list[list[dict[str, Any]]]:
    return [
        [row for row in value if isinstance(row, dict)]
        for field in _ATTEMPT_FIELDS
        if isinstance(value := record.get(field), (list, tuple))
    ]


def _malformed_attempts(record: dict[str, Any]) -> int:
    # Aliases can be copies of one ledger. Report the largest malformed-row
    # count, not fictitious extra network attempts, and fail on any corruption.
    return max(
        (
            sum(not isinstance(row, dict) for row in values)
            for field in _ATTEMPT_FIELDS
            if isinstance(values := record.get(field), (list, tuple))
        ),
        default=0,
    )


def wire_token_record(
    record: dict[str, Any], *, received_token: str | None, source: str, module: str | None = None
) -> dict[str, Any]:
    """Observation-only adapter for token roots that omit credential identity.

    The caller supplies an unambiguous token actually received by the fixture's
    identity endpoint, never a token guessed from CLI arguments. The module's
    verdict is retained verbatim. Product output and existing ledgers are not
    changed, and an unavailable verifier still fails seeded-verdict checks.
    """
    if module in {"consul", "kubeapi", "qdrant", "gitlab", "keycloak"}:
        if not received_token or any(_ledgers(record)) or _malformed_attempts(record):
            return record
        verified: Any = None
        if module == "consul" and record.get("auth_mode") == "token":
            identity = record.get("auth_identity")
            if isinstance(identity, dict) and identity.get("ok") is record.get("auth_valid"):
                verified = record.get("auth_valid")
        elif (
            module == "kubeapi"
            and record.get("auth_mode") == "token"
            and record.get("auth_verification_method") in {"namespace_list", "self_subject_review"}
        ):
            verified = record.get("auth_valid")
        elif module == "gitlab" and record.get("token_provided") is True:
            verified = record.get("token_valid")
        elif module == "qdrant" and record.get("api_key_provided") is True:
            if record.get("credential_state") in {"valid", "invalid"}:
                verified = record.get("provided_credentials_ok")
        elif module == "keycloak" and record.get("credential_state") in {"valid", "invalid"}:
            candidate = record.get("provided_credentials_ok")
            if (
                type(candidate) is bool
                and record.get("credential_state") == ("valid" if candidate else "invalid")
                and record.get("token_access") == ("allowed" if candidate else "denied")
            ):
                verified = candidate
        if type(verified) is not bool:
            return record
        allowed_statuses = {
            "consul": {"valid_credentials"} if verified else {"auth_required", "invalid_credentials_anonymous"},
            "kubeapi": {"auth_valid"} if verified else {"auth_failed", "invalid_credentials_anonymous"},
            "gitlab": {"valid_credentials"} if verified else {"invalid_credentials"},
            "qdrant": {"open_auth"} if verified else {"auth_required", "open_no_auth"},
            "keycloak": {"valid_credentials"} if verified else {"auth_required"},
        }
        if record.get("status") not in allowed_statuses[module]:
            return record
        if module == "qdrant" and record.get("credential_state") != ("valid" if verified else "invalid"):
            return record
        proof: dict[str, Any] = {
            key: record[key]
            for key in ("status", "auth_valid", "token_valid", "provided_credentials_ok", "error", "auth_error")
            if key in record
        }
        return {
            **record,
            "attempted_credentials": [
                {
                    **proof,
                    "credential_state": "valid" if verified else "invalid",
                    "username": None,
                    "password": None,
                    "token": received_token,
                    "source": source,
                }
            ],
        }
    if (
        not received_token
        or any(_ledgers(record))
        or _malformed_attempts(record)
        or "token_valid" not in record
        or type(record["token_valid"]) not in {bool, type(None)}
        or record.get("credential_state") not in {"valid", "invalid", "unverified", "verification_unavailable"}
        or type(record.get("auth_http_status")) is not int
    ):
        return record
    proof = {
        key: record[key]
        for key in ("status", "credential_state", "token_valid", "provided_credentials_ok", "auth_http_status", "error")
        if key in record
    }
    return {
        **record,
        "attempted_credentials": [
            {**proof, "username": None, "password": None, "token": received_token, "source": source}
        ],
    }


def _observed_rows(record: dict[str, Any], ledgers: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows = max(ledgers, key=len, default=[])
    identities = record.get("credential_results")
    if (
        not rows
        and record.get("service") == "airflow"
        and record.get("is_airflow") is True
        and isinstance(identities, list)
        and len(identities) == 1
        and isinstance(identities[0], dict)
        and isinstance(identities[0].get("username"), str)
        and isinstance(record.get("credential_password"), str)
        and identities[0].get("state") == record.get("credential_state")
        and (
            (
                record.get("credential_state") in {"valid", "valid_but_restricted"}
                and record.get("provided_credentials_ok") is True
            )
            or (record.get("credential_state") == "invalid" and record.get("provided_credentials_ok") is False)
        )
    ):
        rows = [
            {
                **record,
                "username": identities[0]["username"],
                "password": record["credential_password"],
                "source": "provided",
            }
        ]
    # Proxmox's single password result exposes a legacy auth_attempts proof,
    # not the common credential ledger. Require the actual matching identity;
    # a generic proxy error remains an unverified observation, never invalid.
    if (
        not rows
        and record.get("service") == "proxmox"
        and record.get("auth_method") == "password"
        and isinstance(record.get("auth_username"), str)
        and isinstance(record.get("auth_password"), str)
        and isinstance(attempts := record.get("auth_attempts"), list)
        and attempts
        and all(isinstance(item, dict) for item in attempts)
        and any(
            item.get("username") == record["auth_username"]
            and item.get("password") == record["auth_password"]
            and item.get("ok") == ("True" if accepted_claim(record) else "False")
            for item in attempts
        )
    ):
        rows = [
            {**record, "username": record["auth_username"], "password": record["auth_password"], "source": "provided"}
        ]
    # The phase-aware Jenkins single-pair result has a separate identity and
    # verdict on the root, rather than a credential-attempt ledger. Require
    # actual auth evidence; a discovered identity alone is not an attempt.
    identities = record.get("credential_results")
    if (
        not rows
        and record.get("service") == "jenkins"
        and isinstance(identities, list)
        and len(identities) == 1
        and isinstance(identities[0], dict)
        and isinstance(identities[0].get("username"), str)
        and isinstance(record.get("credential_password"), str)
        and record.get("credential_state") in {"valid", "invalid", "unknown"}
        and type(record.get("auth_http_status")) is int
    ):
        rows = [
            {
                **record,
                "username": identities[0]["username"],
                "password": record["credential_password"],
                "source": record.get("credential_source"),
            }
        ]
    # Legacy single-pair Redis/PostgreSQL records expose authoritative proof
    # on the root instead of manufacturing a one-element attempt ledger.
    # Require an explicit supplied identity and a non-null verifier result;
    # a public endpoint or mere provided_credentials flag is not an attempt.
    if (
        not rows
        and record.get("provided_credentials") is True
        and record.get("provided_username") is not None
        and not record.get("defcreds_enabled")
        and any(isinstance(record.get(field), bool) for field in _PROOF_FIELDS)
    ):
        rows = [
            {
                **record,
                "username": record["provided_username"],
                "password": record.get("provided_password"),
                "source": "provided",
            }
        ]
    if (
        record.get("service") == "clickhouse"
        and record.get("is_clickhouse") is True
        and record.get("status") in {"auth_required", "valid_credentials", "weak_default_creds"}
        and (
            (
                record.get("status") == "auth_required"
                and (
                    record.get("provided_credentials_ok") is False
                    or (record.get("provided_credentials") is False and record.get("provided_credentials_ok") is None)
                )
            )
            or (
                record.get("status") in {"valid_credentials", "weak_default_creds"}
                and any(accepted_claim(row) for ledger in ledgers for row in ledger)
            )
        )
    ):
        # Its public ledger carries a native exception and ok=False, not the
        # generic credential_state. Only the explicit password rejection is
        # authoritative here; an EOF, permission error or unavailable verifier
        # must remain inconclusive. Adapt a copy, never the product result.
        def rejected(row: dict[str, Any]) -> bool:
            message = str(row.get("error") or "").replace("\\n", "\n")
            http_prefix = "Received ClickHouse exception, code: 516, server response: "
            if record.get("protocol") == "http" and message.startswith(http_prefix):
                message = message[len(http_prefix) :]
            code = re.match(r"^Code: 516\.\s*", message)
            detail = message[code.end() :] if code else ""
            explicit_rejection = code is not None and (
                detail.startswith("Authentication failed:")
                or detail.startswith(f"DB::Exception: {row.get('username')}: Authentication failed:")
            )
            return (
                row.get("ok") is False
                and not row.get("credential_state")
                and not row.get("credential_verification")
                and isinstance(row.get("username"), str)
                and isinstance(row.get("password"), str)
                and explicit_rejection
            )

        # The normalized alias omits ok. Its corresponding native alias must
        # prove rejection of the same full identity, including an empty password.
        proofs = {_identity(row) for ledger in ledgers for row in ledger if rejected(row)}
        rows = [
            {**row, "credential_state": "invalid"}
            if _identity(row) in proofs and not row.get("credential_state") and not row.get("credential_verification")
            else row
            for row in rows
        ]
    if (
        record.get("service") == "kafka"
        and record.get("is_kafka") is True
        and record.get("status") == "auth_required"
        and record.get("auth_flow") == "sasl_handshake"
        and record.get("transport_mode") in {"plaintext", "tls"}
    ):
        # The broker's native API36 verdict uses ok=False only for an explicit
        # password rejection. EOF/unsupported mechanism/timeout use ok=None.
        # Require that proof on a matching complete identity, not just text on
        # the root. Adapt the observer copy; keep public results untouched.
        proofs = {
            _identity(row)
            for ledger in ledgers
            for row in ledger
            if (row.get("ok") is False or ("ok" not in row and row.get("provided_credentials_ok") is False))
            and not row.get("credential_state")
            and not row.get("credential_verification")
            and isinstance(row.get("username"), str)
            and isinstance(row.get("password"), str)
            and str(row.get("error") or "").startswith("SASL auth failed:")
        }
        rows = [
            {**row, "credential_state": "invalid"}
            if _identity(row) in proofs and not row.get("credential_state") and not row.get("credential_verification")
            else row
            for row in rows
        ]
    return rows


def identity_digest(identities: list[tuple[Any, ...]]) -> str:
    """Order-independent full identities; preserve duplicates, not just length."""
    serial = sorted(json.dumps(values, ensure_ascii=True, separators=(",", ":")) for values in identities)
    return hashlib.sha256(json.dumps(serial, separators=(",", ":")).encode()).hexdigest()


def credential_digest(record: dict[str, Any]) -> str:
    rows = _observed_rows(record, _ledgers(record))
    return identity_digest([tuple(row.get(key) for key in ("username", "password", "token")) for row in rows])


def credential_summary(record: dict[str, Any]) -> dict[str, int]:
    """Summarize aliases without counting the same ledger two or three times.

    An empty/non-list legacy alias must not hide the real typed ledger. All
    aliases are inspected for erroneous positive claims; counts use the most
    detailed list. No attempts is distinct from verified zero acceptances.
    """
    ledgers = _ledgers(record)
    rows = _observed_rows(record, ledgers)
    states = Counter(_state(row) for row in rows)
    identities = Counter(_identity(row) for row in rows)
    positive = max((sum(accepted_claim(row) for row in ledger) for ledger in ledgers), default=0)
    return {
        "attempts_observed": len(rows),
        "accepted_claims": max(positive, int(accepted_claim(record))),
        "duplicate_attempts": sum(max(0, count - 1) for count in identities.values()),
        "invalid": sum(states[key] for key in ("invalid", "invalid_credentials")),
        "unverified": sum(
            count
            for state, count in states.items()
            if state not in {"valid", "invalid", "invalid_credentials", "skipped", "cancelled"}
        ),
        "skipped": sum(states[key] for key in ("skipped", "cancelled")),
        "malformed_attempts": _malformed_attempts(record),
    }


def credential_verdict_errors(record: dict[str, Any], *, accepted_identities: set[tuple[Any, Any, Any]]) -> list[str]:
    """Check seeded verifier decisions, not just catalogue size or one success.

    Use only when the fixture defines the verdict for every attempted identity.
    A real unavailable API is not an invalid password; in a seeded auth profile
    it is an incomplete scenario rather than a passing verification result.
    Fixed reason labels keep diagnostics bounded and exclude credential values.
    """
    ledgers = _ledgers(record)
    rows = _observed_rows(record, ledgers)
    malformed = _malformed_attempts(record)
    if not rows:
        return (["malformed credential rows"] if malformed else []) + ["no observed credential verdicts"]
    errors: set[str] = {"malformed credential rows"} if malformed else set()
    for row in rows:
        identity = tuple(row.get(key) for key in ("username", "password", "token"))
        expected = identity in accepted_identities
        state = _state(row)
        if state not in {"valid", "invalid", "invalid_credentials"}:
            errors.add("unverified or skipped seeded credential")
        if accepted_claim(row) != expected:
            errors.add("credential verdict differs from seeded identity")
        if state in {"invalid", "invalid_credentials"} and accepted_claim(row):
            errors.add("conflicting credential proof")
    # A shorter alias must not hide a false acceptance, even when the largest
    # ledger contains the right identities and decisions.
    for ledger in ledgers:
        for row in ledger:
            identity = tuple(row.get(key) for key in ("username", "password", "token"))
            if accepted_claim(row) and identity not in accepted_identities:
                errors.add("alias accepts an unseeded identity")
    return sorted(errors)


def airflow_inventory_errors(record: dict[str, Any], *, limited: bool) -> list[str]:
    """Three requested Airflow collections: exact objects or proven ACL denial."""
    errors = []
    if record.get("provided_credentials_ok") is not True:
        errors.append("identity not verified")
    if any(
        record.get(key) is not True
        for key in ("show_dags_requested", "show_keys_requested", "show_connections_requested")
    ):
        errors.append("inventory actions not applied")
    if (
        record.get("variable_keys") != ["deployment_region", "pipeline_pool"]
        or record.get("variable_keys_count") != 2
        or record.get("variable_keys_total") != 2
        or record.get("variable_keys_truncated") is not False
        or record.get("variable_keys_error")
    ):
        errors.append("variable inventory incomplete or incorrect")
    if limited:
        for prefix, access, error in (
            ("dag_ids", "dags", "dag_ids_error"),
            ("airflow_connections", "connections", "connections_error"),
        ):
            if (
                record.get(prefix) != []
                or not record.get(error)
                or record.get("authenticated_" + access + "_access") != "denied"
                or record.get("authenticated_" + access + "_http_status") != 403
            ):
                errors.append("known inventory denial not preserved")
        return errors
    dag_ids = record.get("dag_ids")
    if (
        not isinstance(dag_ids, list)
        or not all(isinstance(value, str) for value in dag_ids)
        or sorted(dag_ids) != ["events_ingest", "finance_daily", "warehouse_rollup"]
    ):
        errors.append("dag identities differ from seeded catalogue")
    expected = [
        (name, "postgres", "database.internal", 5432, "reader", "analytics")
        for name in ("warehouse_reporting", "events_archive")
    ]
    rows = record.get("airflow_connections")
    observed = (
        [
            tuple(row.get(k) for k in ("connection_id", "conn_type", "host", "port", "login", "schema"))
            for row in rows
            if isinstance(row, dict)
        ]
        if isinstance(rows, list)
        else []
    )
    if len(observed) != 2 or any(value not in observed for value in expected):
        errors.append("connection objects differ from seeded catalogue")
    for prefix, count, error in (("dag_ids", 3, "dag_ids_error"), ("airflow_connections", 2, "connections_error")):
        if (
            record.get(prefix + "_count") != count
            or record.get(prefix + "_total") != count
            or record.get(prefix + "_truncated") is not False
            or record.get(error)
        ):
            errors.append("inventory count or completeness incorrect")
    return errors


def grafana_inventory_errors(record: dict[str, Any], *, limited: bool) -> list[str]:
    """Check known seeded objects and an independent limited-access control."""
    errors = []
    if not accepted_claim(record):
        errors.append("identity not verified")
    if record.get("show_datasources") is not True:
        errors.append("inventory action not applied")
    if limited:
        if record.get("datasources") is not None or record.get("datasource_count") is not None:
            errors.append("denied inventory incorrectly reported as readable")
        ledgers = [record.get(field) for field in _ATTEMPT_FIELDS]
        proven_denial = any(
            isinstance(row, dict)
            and accepted_claim(row)
            and isinstance(caps := row.get("credential_capabilities"), dict)
            and caps.get("datasource_http_status") == 403
            for ledger in ledgers
            if isinstance(ledger, (list, tuple))
            for row in ledger
        )
        if not proven_denial:
            errors.append("known inventory denial not preserved in credential evidence")
        return errors
    expected = {
        ("Platform metrics", "prometheus", "http://metrics:9090", "proxy"),
        ("Application logs", "loki", "http://logs:3100", "proxy"),
    }
    rows = record.get("datasources")
    observed = (
        [tuple(row.get(key) for key in ("name", "type", "url", "access")) for row in rows if isinstance(row, dict)]
        if isinstance(rows, list)
        else []
    )
    if set(observed) != expected or len(observed) != 2 or record.get("datasource_count") != 2:
        errors.append("seeded inventory missing/extra/duplicated or changed")
    return errors


def jenkins_inventory_errors(record: dict[str, Any], *, limited: bool) -> list[str]:
    errors = []
    if not accepted_claim(record):
        errors.append("identity not verified")
    if record.get("jobs_requested") is not True:
        errors.append("jobs action not applied")
    if limited:
        if record.get("jobs_access") != "denied" or not record.get("jobs_partial") or record.get("jobs"):
            errors.append("known denied jobs incorrectly reported as complete/readable")
        return errors
    expected = {("platform-deploy", "blue"), ("billing-tests", "red"), ("nightly-backup", "blue")}
    rows = record.get("jobs")
    observed = (
        [(row.get("name"), row.get("color")) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    )
    if (
        set(observed) != expected
        or len(observed) != 3
        or record.get("jobs_count") != 3
        or record.get("jobs_access") != "allowed"
    ):
        errors.append("seeded jobs missing/extra/duplicated or changed")
    return errors


def token_inventory_errors(module: str, record: dict[str, Any], *, limited: bool) -> list[str]:
    """Independent expected objects for the three seeded token inventories."""
    field = {"vault": "mounts", "nomad": "jobs", "jupyter": "kernels"}[module]
    errors = []
    if not accepted_claim(record) or record.get("token_valid") is not True:
        errors.append("token identity not verified")
    if field not in (record.get("inventory_requested") or []):
        errors.append("inventory action not applied")
    if limited:
        if record.get(field + "_access") != "denied" or record.get(field) is not None:
            errors.append("known inventory denial not preserved")
        return errors
    expected: set[tuple[Any, ...]]
    keys: tuple[str, ...]
    if module == "vault":
        keys = ("path", "type", "description")
        expected = {
            ("secret/", "kv", "Platform configuration"),
            ("database/", "database", "Database roles"),
            ("transit/", "transit", "Application signing"),
        }
    elif module == "nomad":
        keys = ("ID", "Name", "Namespace", "Status")
        expected = {(name, name, "default", "running") for name in ("platform-api", "billing-batch", "nightly-backup")}
    else:
        keys = ("id", "name", "execution_state")
        expected = {("analysis", "python3", "idle"), ("reporting", "python3", "busy")}
    rows = record.get(field)
    observed = (
        [tuple(row.get(key) for key in keys) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    )
    if record.get(field + "_access") != "allowed" or record.get(field + "_partial") is True:
        errors.append("inventory is not completely readable")
    if (
        not isinstance(rows, list)
        or len(rows) != len(expected)
        or len(observed) != len(expected)
        or set(observed) != expected
    ):
        errors.append("seeded inventory objects missing/extra/duplicated or changed")
    if module == "vault" and isinstance(rows, list):
        options = {row.get("path"): row.get("options") for row in rows if isinstance(row, dict)}
        if record.get("mounts_count") != 3 or options.get("secret/") != {"version": "2"}:
            errors.append("mount metadata changed")
    return errors


def matching_case(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Reject incomparable before/after samples rather than inventing speedup."""
    keys: tuple[str, ...] = (
        "module",
        "mode",
        "model",
        "engine",
        "target_style",
        "auth_case",
        "auth_surface",
        "read_wire_storage_policy",
        "actions",
        "profile_sha256",
        "environment_sha256",
        "container_image_id",
        "seed",
        "targets",
        "timeout",
        "delay_ms",
        "retries",
        "detect_concurrency",
        "detect_policy",
        "http_peer",
        "deep_workers",
        "debug",
        "format",
        "save",
    )
    if before.get("mode") in {"credentials", "defcreds", "actions"}:
        keys += ("credential_expectation_per_positive", "credential_expected_sha256")
    for field in ("fixture_access_case", "credential_scenario_applicable"):
        if field in before or field in after:
            keys += (field,)
    return [key for key in keys if key not in before or key not in after or before[key] != after[key]]


def _readonly_kafka_evidence_ok(row: dict[str, Any]) -> bool:
    """N/A auth must describe the explicit read-only model, never form/SASL."""
    if (
        row.get("module") != "kafka"
        or row.get("auth_surface")
        not in {"akhq", "redpanda-console", "rest-proxy", "connect", "ksqldb", "schema-registry"}
        or row.get("auth_case") != "invalid"
        or row.get("credential_verdict_model") != "not_applicable_readonly_api"
        or row.get("read_wire_errors") != {}
    ):
        return False
    summary, evidence, counts = (
        row.get("read_wire_summary"),
        row.get("read_wire_evidence"),
        row.get("credential_observations"),
    )
    if not isinstance(summary, dict) or not isinstance(evidence, dict) or not isinstance(counts, dict):
        return False
    digest = evidence.get("sha256")
    return (
        type(row.get("targets")) is int
        and row["targets"] > 0
        and type(evidence.get("roots")) is int
        and evidence["roots"] == row["targets"]
        and isinstance(digest, str)
        and len(digest) == 64
        and all(c in "0123456789abcdef" for c in digest)
        and type(summary.get("recorded_calls")) is int
        and summary["recorded_calls"] >= 0
        and type(summary.get("temporary_storage_removed")) is int
        and summary["temporary_storage_removed"] == 1
        and all(
            type(summary.get(k)) is int and summary[k] == 0
            for k in ("overflow", "malformed", "storage_errors", "pending_calls", "pending_targets")
        )
        and all(
            type(counts.get(k)) is int
            for k in (
                "attempts_observed",
                "accepted_claims",
                "invalid",
                "unverified",
                "skipped",
                "duplicate_attempts",
                "malformed_attempts",
            )
        )
    )


def _credential_catalogue_evidence_ok(row: dict[str, Any]) -> bool:
    if row.get("mode") not in {"credentials", "defcreds", "actions"}:
        return True
    if row.get("credential_scenario_applicable") is False:
        counts = row.get("credential_observations")
        return (
            row.get("mode") == "actions"
            and (
                row.get("module") in ("docker", "spark", "yarn")
                and row.get("fixture_access_case") in ("open", "limited", "denied")
                or _readonly_kafka_evidence_ok(row)
            )
            and row.get("credential_quality") == "NOT_APPLICABLE"
            and row.get("credential_expectation_per_positive") is None
            and row.get("credential_expected_sha256") is None
            and row.get("credential_identity_digests") == {}
            and isinstance(counts, dict)
            and all(
                counts.get(key, 1) == 0
                for key in (
                    "attempts_observed",
                    "accepted_claims",
                    "invalid",
                    "unverified",
                    "skipped",
                    "duplicate_attempts",
                    "malformed_attempts",
                )
            )
        )
    expected, count = row.get("credential_expected_sha256"), row.get("credential_expectation_per_positive")
    observed, histogram = row.get("credential_identity_digests"), row.get("credential_count_histogram")
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(char not in "0123456789abcdef" for char in expected)
        or type(count) is not int
        or count < 1
        or not isinstance(observed, dict)
        or not isinstance(histogram, dict)
        or any(type(value) is not int or value < 1 for value in histogram.values())
        or any(key != str(count) for key in histogram)
    ):
        return False
    positives = sum(histogram.values())
    return observed == ({expected: positives} if positives else {}) and all(type(v) is int for v in observed.values())


def compare_profiles(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    """Repeated matched timings with an independent, non-negotiable quality gate.

    A broken baseline can show measured improvement after a bug fix. Its FAIL
    remains visible and is never retroactively converted to a passing sample.
    """
    if not before or len(before) != len(after):
        raise ValueError("equal nonempty measured sample sets required; exclude warmup")
    if any(matching_case(before[0], row) for row in before + after):
        raise ValueError("profile settings differ or are missing")
    for group in (before, after):
        if len({row.get("source_sha256") for row in group}) != 1 or not group[0].get("source_sha256"):
            raise ValueError("source snapshot missing or changed between samples")
    seconds = [[float(row["wall_seconds"]) for row in group] for group in (before, after)]
    if any(not 0 < value < float("inf") for group in seconds for value in group):
        raise ValueError("wall times must be finite and positive")
    medians = [statistics.median(group) for group in seconds]
    spread = max(max(group) - min(group) for group in seconds)
    threshold = max(0.25, medians[0] * 0.25, 3 * spread)
    repeated = len(before) >= 3
    delta = medians[1] - medians[0]
    timing = (
        "INSUFFICIENT_REPEATS"
        if not repeated
        else "REGRESSION"
        if delta > threshold
        else "IMPROVEMENT"
        if -delta > threshold
        else "WITHIN_NOISE"
    )
    results = {row.get("result_sha256") for row in before + after}
    same_results = len(results) == 1 and None not in results
    quality = {
        label: "PASS"
        if all(
            row.get("quality") == "PASS"
            and row.get("cleanup") == "PASS"
            and row.get("missing") == []
            and row.get("extra") == []
            and row.get("duplicates") == 0
            and row.get("invalid_credentials_accepted") == 0
            and row.get("negative_target_credential_verdicts", 0) == 0
            and row.get("malformed_credential_rows", 0) == 0
            and _credential_catalogue_evidence_ok(row)
            for row in group
        )
        else "FAIL"
        for label, group in (("before", before), ("after", after))
    }
    return {
        "repeats": len(before),
        "quality": quality,
        "same_results": same_results,
        "timing": timing,
        "timing_threshold_seconds": threshold,
        "before_median_seconds": medians[0],
        "after_median_seconds": medians[1],
        "speedup": medians[0] / medians[1],
        "wall_reduction_percent": (1 - medians[1] / medians[0]) * 100,
        "gate": "FAIL"
        if quality["after"] != "PASS" or not same_results or timing == "REGRESSION"
        else "INSUFFICIENT_REPEATS"
        if not repeated
        else "PASS",
    }


def proxmox_inventory_errors(record: dict[str, Any], *, limited: bool) -> list[str]:
    """Node/user read results do not prove guest execution or hypervisor state."""
    errors = []
    if record.get("is_proxmox") is not True or record.get("auth_method") != "password":
        errors.append("Proxmox identity unconfirmed")
    if record.get("status") not in {"token_ok", "weak_default_creds"}:
        errors.append("Proxmox password not accepted")
    actions = [
        ("nodes", ["pve-app", "pve-data", "pve-edge"]),
        ("users", ["backup@pve", "monitor@pve", "root@pam"]),
    ]
    if not any(record.get("show_" + name) is True for name, _ in actions):
        errors.append("Proxmox seeded read action missing")
    for name, expected in actions:
        if record.get("show_" + name) is not True:
            continue
        items, error = record.get(name), record.get(name + "_error")
        if limited:
            expected_error = (
                "unexpected HTTP 403 from /access/users" if name == "users" else "Permission check failed (Sys.Audit)"
            )
            if items not in (None, []) or error != expected_error:
                errors.append("Proxmox " + name + " ACL denial not explicit")
        elif (
            not isinstance(items, list)
            or any(not isinstance(item, str) for item in items)
            or sorted(items) != sorted(expected)
            or error
        ):
            errors.append("Proxmox " + name + " differs from seeded objects")
    return errors


def registry_inventory_errors(record: dict[str, Any], *, limited: bool) -> list[str]:
    """Observe seeded V2 objects/ACLs independently of protected-base identity."""
    errors = []
    if record.get("is_registry") is not True or record.get("provided_credentials_ok") is not True:
        errors.append("registry identity unconfirmed")
    if any(record.get("is_" + vendor) is True for vendor in ("harbor", "gitlab", "nexus")):
        errors.append("unexpected registry vendor")
    error = record.get("images_error")
    if record.get("show_tags") is True and record.get("repository") == "billing/worker":
        items = record.get("selected_repository_tags")
        expected = ["2026.11", "rollback", "stable"]
        denied = error == "billing/worker: authentication required"
    elif record.get("show_images") is True:
        items = record.get("images")
        expected = sorted(
            name + ":" + tag
            for name in ("billing/worker", "observability/collector", "platform/api")
            for tag in ("2026.11", "stable", "rollback")
        )
        denied = error == "authentication required"
        if not limited and record.get("image_count") != len(expected):
            errors.append("incorrect full image count")
    else:
        return errors + ["registry seeded action or selector missing"]
    if limited:
        if items not in (None, []) or not denied:
            errors.append("registry ACL denial not explicit")
    elif not isinstance(items, list) or any(not isinstance(item, str) for item in items):
        errors.append("registry inventory unavailable")
    elif sorted(items) != expected or error:
        errors.append("registry inventory differs from seeded objects")
    return errors


def vendor_transport_errors(record: dict[str, Any], *, role: str) -> list[str]:
    """A deliberately closed peer proves failure to inspect, not service absence."""
    if role != "closed":
        return []
    if (
        record.get("status") != "fail"
        or not isinstance(record.get("error"), str)
        or not record["error"].strip()
        or record.get("is_registry") is not False
        or any(record.get("is_" + vendor) is True for vendor in ["harbor", "nexus", "gitlab"])
        or record.get("provided_credentials_ok") is True
    ):
        return ["closed vendor target was not reported as a transport failure"]
    return []


def harbor_inventory_errors(record: dict[str, Any], *, limited: bool) -> list[str]:
    """Known API/registry reads; successful identity alone never proves inventory."""
    errors = []
    if record.get("is_harbor") is not True or record.get("provided_credentials_ok") is not True:
        errors.append("Harbor identity unconfirmed")
    if record.get("show_tags") is True and record.get("repository") == "billing/worker":
        values = record.get("selected_repository_tags")
        if limited:
            if values not in (None, []) or record.get("images_error") != "billing/worker: authentication required":
                errors.append("Harbor selected registry denial not explicit")
        elif values != ["2026.11", "rollback", "stable"] or record.get("images_error"):
            errors.append("Harbor selected tags differ from seeded values")
        return errors
    if record.get("show_images") is not True:
        return errors + ["Harbor seeded action missing"]
    projects = ["billing", "observability", "platform"]
    repos = ["billing/worker", "observability/collector", "platform/api"]
    images = sorted(repo + ":" + tag for repo in repos for tag in ["2026.11", "stable", "rollback"])
    artifacts = sorted(value + "@sha256:" + hashlib.sha256(value.encode()).hexdigest() for value in images)
    if limited:
        if (
            any(
                record.get(field) not in (None, [])
                for field in ["images", "harbor_projects", "harbor_repositories", "harbor_artifacts"]
            )
            or record.get("harbor_error") != "authentication required"
            or record.get("images_error") != "authentication required"
        ):
            errors.append("Harbor API/registry denials not explicit")
    elif (
        record.get("harbor_projects") != projects
        or record.get("harbor_repositories") != repos
        or record.get("harbor_artifacts") != artifacts
        or record.get("images") != images
        or record.get("image_count") != 9
        or record.get("images_error")
        or record.get("harbor_error")
    ):
        errors.append("Harbor full API/registry inventory differs from seeded data")
    return errors


def nexus_inventory_errors(record: dict[str, Any], *, limited: bool) -> list[str]:
    """Known Nexus REST repositories/components/assets, not a V2 connector."""
    errors = []
    if record.get("is_nexus") is not True or record.get("provided_credentials_ok") is not True:
        errors.append("Nexus identity unconfirmed")
    if not any(record.get(k) is True for k in ["show_repositories", "show_images", "assets"]):
        return errors + ["Nexus seeded action missing"]
    if limited:
        if record.get("nexus_error") != "authentication required" or any(
            record.get(k) not in (None, [])
            for k in ["nexus_repository_details", "nexus_repositories", "images", "nexus_assets"]
        ):
            errors.append("Nexus restricted read denial not preserved")
        return errors
    if record.get("nexus_error") or record.get("images_error"):
        errors.append("Nexus seeded reads returned error")
    details = record.get("nexus_repository_details")
    wanted = {
        ("billing-images", "docker", "hosted", True),
        ("platform-maven", "maven2", "hosted", True),
        ("release-assets", "raw", "hosted", True),
    }
    if (
        not isinstance(details, list)
        or len(details) != 3
        or any(not isinstance(r, dict) for r in details)
        or {(r.get("name"), r.get("format"), r.get("type"), r.get("online")) for r in details} != wanted
    ):
        return errors + ["Nexus repository metadata differs from seeded objects"]
    origin = f"http://{record.get('host')}:{record.get('port')}"
    if isinstance(details, list):
        expected_counts = {
            name: (
                3
                if (record.get("assets") is True and (not record.get("repository") or record.get("repository") == name))
                or (record.get("show_images") is True and name == "billing-images")
                else None
            )
            for name in ["billing-images", "platform-maven", "release-assets"]
        }
        if any(
            r.get("url") != origin + "/repository/" + r["name"] or r.get("components") != expected_counts[r["name"]]
            for r in details
        ):
            errors.append("Nexus repository URL or component counts differ from seed")
        if record.get("show_repositories") is True and record.get("nexus_repositories") != [
            f"{r['name']} (format={r['format']}, type=hosted, url={origin}/repository/{r['name']})" for r in details
        ]:
            errors.append("Nexus displayed repositories differ from seed")
    if record.get("show_images") is True:
        expected = sorted("billing-images/billing/worker:" + tag for tag in ["2026.11", "stable", "rollback"])
        if record.get("images") != expected or record.get("image_count") != 3:
            errors.append("Nexus paginated image references differ from seeded values")
    if record.get("assets") is True:
        selected = record.get("repository")
        repo_names = [selected] if selected else ["billing-images", "platform-maven", "release-assets"]
        expected_assets = []
        for name in repo_names:
            component = (
                "billing/worker"
                if name == "billing-images"
                else "platform-api"
                if name == "platform-maven"
                else "release-notes"
            )
            for tag in ["2026.11", "stable", "rollback"]:
                path = component + "/" + tag + ("/manifest.json" if name == "billing-images" else "/artifact.bin")
                expected_assets.append(
                    (
                        component,
                        tag,
                        path,
                        hashlib.sha256((name + ":" + path).encode()).hexdigest(),
                        origin + "/repository/" + name + "/" + path,
                    )
                )
        selector = record.get("asset")
        if selector:
            expected_assets = [v for v in expected_assets if v[2] == selector]
        assets = record.get("nexus_assets")
        if (
            not isinstance(assets, list)
            or len(assets) != len(expected_assets)
            or any(not isinstance(r, dict) or not isinstance(r.get("checksums"), dict) for r in assets)
            or [
                (
                    r.get("component_name"),
                    r.get("component_version"),
                    r.get("path"),
                    r.get("checksums", {}).get("sha256"),
                    r.get("download_url"),
                )
                for r in assets
            ]
            != expected_assets
            or record.get("asset_error")
        ):
            errors.append("Nexus full selected asset metadata differs from seed")
    return errors


def platform_inventory_errors(module: str, record: dict[str, Any], *, limited: bool) -> list[str]:
    """Independent seeded objects and selectors for platform token actions."""
    errors = []
    if not accepted_claim(record) or record.get("is_" + module) is not True:
        errors.append("identity/product not confirmed")

    def has_error(field: str) -> bool:
        return isinstance(record.get(field), str) and bool(record[field].strip())

    if module == "consul":
        if record.get("services_list_requested") is not True:
            errors.append("services action not requested")
        rows = record.get("services_list")
        if limited:
            if rows is not None or not has_error("services_list_error"):
                errors.append("services denial not preserved")
        else:
            expected = {
                ("platform-api", ("prod", "http")),
                ("billing-worker", ("prod", "batch")),
                ("metrics", ("infra",)),
            }
            well_formed = isinstance(rows, list) and all(
                isinstance(row, dict)
                and isinstance(row.get("name"), str)
                and isinstance(row.get("tags"), list)
                and all(isinstance(tag, str) for tag in row["tags"])
                for row in rows
            )
            observed = (
                {(row["name"], tuple(row["tags"])) for row in rows} if well_formed and isinstance(rows, list) else set()
            )
            if (
                not isinstance(rows, list)
                or not well_formed
                or len(rows) != 3
                or observed != expected
                or record.get("services_list_error")
            ):
                errors.append("seeded services/tags missing extra duplicated or changed")
    elif module == "kubeapi":
        if record.get("show_namespaces") is not True:
            errors.append("namespaces action not requested")
        rows = record.get("namespaces")
        if limited:
            if rows != [] or record.get("can_list_namespaces") is not False or not has_error("namespaces_error"):
                errors.append("namespace denial not preserved")
        elif (
            record.get("can_list_namespaces") is not True
            or record.get("namespaces_partial") is True
            or not isinstance(rows, list)
            or len(rows) != 3
            or not all(isinstance(name, str) for name in rows)
            or set(rows) != {"platform", "billing", "observability"}
            or record.get("namespaces_error")
        ):
            errors.append("seeded namespaces missing extra duplicated partial or changed")
    elif module == "qdrant":
        if record.get("dump") is not True or record.get("collection_name") != "restricted-ml":
            errors.append("selected collection action not requested")
        names = record.get("collections")
        expected_names = {"platform-events", "billing-events"} | (set() if limited else {"restricted-ml"})
        if (
            not isinstance(names, list)
            or len(names) != len(expected_names)
            or not all(isinstance(name, str) for name in names)
            or set(names) != expected_names
            or record.get("collections_count") != len(expected_names)
        ):
            errors.append("seeded collection catalogue missing extra duplicated or changed")
        rows = record.get("collection_dump_items")
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            return errors + ["selected collection result missing extra or duplicated"]
        entry = rows[0]
        if entry.get("name") != "restricted-ml":
            errors.append("collection selector not applied")
        if limited:
            if (
                entry.get("ok") is not False
                or entry.get("status") != 403
                or not entry.get("error")
                or entry.get("info_raw") is not None
            ):
                errors.append("collection ACL denial not preserved")
        else:
            try:
                payload = json.loads(entry.get("info_raw") or "null")
            except (ValueError, TypeError):
                payload = None
            result = payload.get("result") if isinstance(payload, dict) else None
            config = result.get("config") if isinstance(result, dict) else None
            params = config.get("params") if isinstance(config, dict) else None
            vectors = params.get("vectors") if isinstance(params, dict) else None
            if (
                entry.get("ok") is not True
                or entry.get("status") != 200
                or entry.get("error")
                or not isinstance(result, dict)
                or result.get("points_count") != 128
                or vectors != {"size": 8, "distance": "Cosine"}
            ):
                errors.append("full collection metadata changed or unavailable")
    elif module == "gitlab":
        if record.get("gitlab_surface") != "web" or record.get("project_filters") != ["platform/reporting"]:
            errors.append("web surface or project selector not applied")
        projects, access = record.get("token_projects"), record.get("token_access")
        if limited:
            if projects != [] or access != [] or not has_error("token_projects_error"):
                errors.append("project ACL denial not preserved")
        elif (
            not isinstance(projects, list)
            or len(projects) != 1
            or not isinstance(projects[0], dict)
            or not isinstance(access, list)
            or len(access) != 1
            or not isinstance(access[0], dict)
        ):
            errors.append("selected project missing extra or duplicated")
        else:
            project, rights = projects[0], access[0]
            origin = f"http://{record.get('host')}:{record.get('port')}"
            if (
                project.get("id") != 103
                or project.get("path_with_namespace") != "platform/reporting"
                or project.get("http_url_to_repo") != origin + "/platform/reporting.git"
                or project.get("web_url") != origin + "/platform/reporting"
                or record.get("token_projects_error")
            ):
                errors.append("selected page-two project metadata or origin changed")
            if (
                rights.get("id") != 103
                or rights.get("path_with_namespace") != "platform/reporting"
                or not all(rights.get(field) is True for field in ("repo_read", "issues_read", "members_read"))
                or any(rights.get(field) for field in ("repo_error", "issues_error", "members_error"))
            ):
                errors.append("project capabilities not completely verified")
    else:
        raise ValueError("unsupported platform inventory")
    return errors
