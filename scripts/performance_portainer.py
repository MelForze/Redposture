"""Seeded Portainer HTTP API model and full received login/session receipts.

This is a read-only protocol fixture, not a real Portainer or Docker engine.
Only authentication POST succeeds; all execution/mutation requests are denied.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from scripts.performance_contracts import HttpPairWireLedger, _ledgers, _malformed_attempts, _state
from scripts.performance_http_fixtures import response

ENVIRONMENTS: tuple[dict[str, Any], ...] = (
    {"Id": 11, "Name": "billing-production", "Type": 1, "Status": 1, "URL": "unix:///var/run/docker.sock"},
    {"Id": 22, "Name": "events-staging", "Type": 1, "Status": 1, "URL": "tcp://events-engine:2376"},
    {"Id": 33, "Name": "analytics-batch", "Type": 1, "Status": 1, "URL": "tcp://analytics-engine:2376"},
)
_KEY = b"redposture-portainer-protocol-fixture-only"


def issued_token(username: str, limited: bool) -> str:
    def encode(value: Any) -> bytes:
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()).rstrip(
            b"="
        )

    message = (
        encode({"alg": "HS256", "typ": "JWT"})
        + b"."
        + encode({"id": 2 if limited else 1, "username": username, "role": 2 if limited else 1, "exp": 4102444800})
    )
    signature = base64.urlsafe_b64encode(hmac.digest(_KEY, message, "sha256")).rstrip(b"=")
    return (message + b"." + signature).decode()


def inventory(category: str, environment: int, *, limited: bool) -> Any:
    count = 1 if limited else 3
    if category == "containers":
        return [
            {
                "Id": f"{environment:02x}{n:062x}",
                "Names": ["/" + name],
                "Image": "billing/" + name + ":2026.11",
                "State": "running",
                "Status": "Up 2 days",
                "Labels": {"com.docker.compose.project": "billing"},
            }
            for n, name in enumerate(("api", "worker", "scheduler")[:count], 1)
        ]
    if category == "images":
        return [
            {
                "Id": "sha256:" + f"{environment:02x}{n:062x}",
                "RepoTags": ["billing/" + name + ":2026.11"],
                "Size": n * 1000000,
            }
            for n, name in enumerate(("api", "worker", "scheduler"), 1)
        ]
    if category == "networks":
        return [
            {"Id": f"{environment:02x}{n:062x}", "Name": name, "Driver": "bridge", "Scope": "local"}
            for n, name in enumerate(("billing-frontend", "billing-backend"), 1)
        ]
    if category == "volumes":
        return {
            "Volumes": [
                {"Name": name, "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/" + name + "/_data"}
                for name in ("billing-data", "billing-logs")
            ],
            "Warnings": None,
        }
    if category == "system":
        return {
            "ID": "engine-" + str(environment),
            "Name": "billing-engine-" + str(environment),
            "ServerVersion": "28.4.0",
            "Containers": 3,
            "ContainersRunning": 3,
            "Images": 3,
            "OperatingSystem": "Debian GNU/Linux 12",
            "Architecture": "aarch64",
        }
    return {
        "LayersSize": 6000000,
        "Images": inventory("images", environment, limited=False),
        "Containers": inventory("containers", environment, limited=False),
        "Volumes": inventory("volumes", environment, limited=False)["Volumes"],
    }


def portainer_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool,
) -> bytes:
    route = urlsplit(path).path
    if method == "GET" and route == "/":
        return response(
            200, '<title>Portainer</title><main id="portainer"></main>', headers={"Content-Type": "text/html"}
        )
    if method == "GET" and route == "/api/system/status":
        return response(
            200, {"Version": "2.33.3", "InstanceID": "portainer-qa-instance", "Edition": "Community Edition"}
        )
    if method == "POST" and route == "/api/auth":
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            return response(400, {"message": "Invalid request payload"})
        if (
            not isinstance(value, dict)
            or set(value) != {"Username", "Password"}
            or any(not isinstance(value[k], str) for k in value)
        ):
            return response(400, {"message": "Invalid request payload"})
        if valid_pair is None or (value["Username"], value["Password"]) != valid_pair:
            return response(401, {"message": "Invalid credentials"})
        return response(200, {"jwt": issued_token(valid_pair[0], limited)})
    if method != "GET":
        return response(405, {"message": "Mutation denied by read-only QA fixture"})
    if not route.startswith("/api/"):
        return response(404, {"message": "Not found"})
    expected = ("Bearer " + issued_token(valid_pair[0], limited)).encode() if valid_pair else None
    if expected is None or headers.get(b"authorization") != expected:
        return response(401, {"message": "Unauthorized"})
    if route == "/api/users/me":
        assert valid_pair is not None
        return response(200, {"Id": 2 if limited else 1, "Username": valid_pair[0], "Role": 2 if limited else 1})
    if route == "/api/endpoints":
        query = parse_qs(urlsplit(path).query, strict_parsing=True)
        try:
            start, limit = int(query.get("start", ["0"])[0]), int(query.get("limit", ["100"])[0])
        except ValueError:
            return response(400, {"message": "Invalid pagination"})
        if start < 0 or not 1 <= limit <= 100:
            return response(400, {"message": "Invalid pagination"})
        endpoints = [r for r in ENVIRONMENTS if not limited or r["Id"] == 22]
        return response(200, endpoints[start : start + limit])
    match = re.fullmatch(
        r"/api/endpoints/(11|22|33)/docker/(containers/json|images/json|networks|volumes|info|system/df)", route
    )
    if match:
        environment = int(match[1])
        category = {
            "containers/json": "containers",
            "images/json": "images",
            "info": "system",
            "system/df": "disk",
        }.get(match[2], match[2])
        if limited and (environment != 22 or category != "containers"):
            return response(403, {"message": "Access denied to environment resource"})
        return response(200, inventory(category, environment, limited=limited))
    return response(404, {"message": "Not found"})


class PortainerWireLedger(HttpPairWireLedger):
    """Bounded actual request/response evidence; identity never invents a password."""

    def record_response(
        self, index: int, method: str, path: str, headers: dict[bytes, bytes], body: bytes, raw: bytes
    ) -> None:
        route = urlsplit(path).path
        kind = (
            "login"
            if method == "POST" and route == "/api/auth"
            else "identity"
            if method == "GET" and route == "/api/users/me"
            else "exec_probe"
            if method == "POST" and re.fullmatch(r"/api/endpoints/\d+/docker/containers/[^/]+/exec", route)
            else None
        )
        if kind is None:
            return
        if self._final is not None:
            raise RuntimeError("HTTP pair ledger closed")
        try:
            head, data = raw.split(b"\r\n\r\n", 1)
            status = int(head.split(b" ", 2)[1])
            if type(index) is not int or len(body) > 65536 or len(data) > 65536:
                raise ValueError("Portainer receipt exceeds measurement bound")
            call: dict[str, Any] = {"kind": "portainer_" + kind, "method": method, "path": path, "status": status}
            if kind == "login":
                value = json.loads(body)
                if set(value) != {"Username", "Password"} or any(not isinstance(value[k], str) for k in value):
                    raise ValueError("malformed login body")
                if sum(len(value[k].encode()) for k in value) > 4096:
                    raise ValueError("credential exceeds measurement bound")
                result = json.loads(data) if status == 200 else None
                token = result.get("jwt") if isinstance(result, dict) else None
                if status == 200 and (not isinstance(token, str) or not token or len(token) > 4096):
                    raise ValueError("missing issued token")
                call.update(
                    username=value["Username"],
                    password=value["Password"],
                    response_jwt=token,
                    body_sha256=hashlib.sha256(body).hexdigest(),
                )
            else:
                auth = headers.get(b"authorization", b"").decode("ascii", errors="strict")
                if not auth.startswith("Bearer ") or len(auth) > 4096:
                    raise ValueError("missing received session token")
                call["authorization"] = auth
                if kind == "identity":
                    call["response_identity"] = json.loads(data)
                else:
                    call.update(
                        body=body.decode("utf-8", errors="strict"), body_sha256=hashlib.sha256(body).hexdigest()
                    )
        except (ValueError, UnicodeError, AttributeError, TypeError):
            self._malformed += 1
            return
        body_bytes = len(body) if kind == "exec_probe" else 0
        if (
            self._pending >= self.total_limit
            or len(self._calls.get(index, [])) >= self.per_target_limit
            or (index not in self._calls and len(self._calls) >= self.target_limit)
            or self.pending_body_bytes + body_bytes > self.body_limit
        ):
            self._overflow += 1
            return
        self._calls.setdefault(index, []).append(call)
        self.pending_body_bytes += body_bytes
        self._recorded += 1
        self._pending += 1

    def pop(self, index: int) -> dict[str, Any]:
        result = super().pop(index)
        self.pending_body_bytes -= sum(
            len(r["body"].encode()) for r in result["calls"] if r["kind"] == "portainer_exec_probe"
        )
        return result


def wire_portainer_record(record: dict[str, Any], wire: dict[str, Any] | None) -> tuple[dict[str, Any], str | None]:
    if not isinstance(wire, dict) or wire.get("complete") is not True or not isinstance(wire.get("calls"), list):
        return record, "incomplete Portainer wire receipts"
    calls = wire["calls"]
    if any(
        not isinstance(r, dict)
        or any(not isinstance(r.get(k), str) for k in ("kind", "method", "path"))
        or r.get("kind") not in {"portainer_login", "portainer_identity", "portainer_exec_probe"}
        or type(r.get("status")) is not int
        for r in calls
    ) or _malformed_attempts(record):
        return record, "malformed Portainer credential receipts or client ledger"
    rows = max(_ledgers(record), key=len, default=[])
    if (
        not rows
        and record.get("is_portainer") is True
        and type(record.get("provided_credentials_ok")) is bool
        and all(isinstance(record.get(k), str) for k in ("provided_username", "provided_password"))
    ):
        rows = [
            {
                **record,
                "username": record["provided_username"],
                "password": record["provided_password"],
                "source": record.get("credentials_source"),
            }
        ]
    if not rows:
        return record, "missing Portainer client credential ledger"
    logins = [r for r in calls if r["kind"] == "portainer_login"]
    identities = [r for r in calls if r["kind"] == "portainer_identity"]
    probes = [r for r in calls if r["kind"] == "portainer_exec_probe"]
    pairs = [(r.get("username"), r.get("password")) for r in rows]
    if (
        any(not isinstance(u, str) or not isinstance(p, str) for u, p in pairs)
        or len(set(pairs)) != len(pairs)
        or len(logins) != len(rows)
        or [(r.get("username"), r.get("password")) for r in logins] != pairs
    ):
        return record, "Portainer login identities differ from client ledger"
    tokens = []
    for row, login in zip(rows, logins, strict=True):
        if login.get("method") != "POST" or login.get("path") != "/api/auth":
            return record, "incorrect Portainer login surface"
        if _state(row) == "invalid":
            if login["status"] != 401 or login.get("response_jwt") is not None:
                return record, "Portainer rejection contradicts actual login response"
        elif _state(row) == "valid":
            token = login.get("response_jwt")
            if login["status"] != 200 or not isinstance(token, str) or not token:
                return record, "Portainer acceptance has no issued JWT"
            same = [r for r in identities if r.get("authorization") == "Bearer " + token]
            if (
                len(same) != 1
                or same[0].get("method") != "GET"
                or same[0].get("path") != "/api/users/me"
                or same[0]["status"] != 200
            ):
                return record, "Portainer acceptance has no exact identity receipt"
            identity = same[0].get("response_identity")
            if (
                not isinstance(identity, dict)
                or identity.get("Username") != row["username"]
                or type(identity.get("Id")) is not int
                or identity["Id"] <= 0
                or type(identity.get("Role")) is not int
                or identity.get("Role") not in {1, 2}
            ):
                return record, "Portainer session identity differs from login"
            if token != issued_token(row["username"], identity["Role"] == 2):
                return record, "Portainer issued JWT signature or claims differ"
            tokens.append(token)
        else:
            return record, "Portainer client credential result is unverified"
    if len(identities) != len(tokens) or len(set(tokens)) != len(tokens):
        return record, "Portainer extra or ambiguous identity receipt"
    if len(probes) > 1:
        return record, "Portainer repeated automatic execution probe"
    for probe in probes:
        body = probe.get("body")
        if (
            probe.get("authorization") not in {"Bearer " + t for t in tokens}
            or probe.get("method") != "POST"
            or not re.fullmatch(r"/api/endpoints/\d+/docker/containers/[^/]+/exec", str(probe.get("path")))
            or probe["status"] != 405
            or not isinstance(body, str)
            or hashlib.sha256(body.encode()).hexdigest() != probe.get("body_sha256")
        ):
            return record, "Portainer denied execution receipt missing or corrupt"
        try:
            command = json.loads(body)["Cmd"]
        except (ValueError, KeyError, TypeError):
            return record, "Portainer probe command malformed"
        if (
            not isinstance(command, list)
            or len(command) != 3
            or command[:2] != ["/bin/sh", "-c"]
            or not isinstance(command[2], str)
            or len(re.findall(r"echo REDPOSTURE_RCE_[0-9a-f]{24}", command[2])) != 1
        ):
            return record, "Portainer automatic probe command differs"
    return {**record, "attempted_credentials": rows}, None


def portainer_inventory_errors(
    record: dict[str, Any], *, limited: bool, selected: str | None, categories: list[str]
) -> list[str]:
    ui = record.get("ui")
    inventory_data = ui.get("inventory") if isinstance(ui, dict) else None
    if not isinstance(inventory_data, dict):
        return ["missing Portainer inventory"]
    available = [r for r in ENVIRONMENTS if not limited or r["Id"] == 22]
    if selected:
        available = [r for r in available if str(r["Id"]) == selected or r["Name"] == selected]
    errors = []
    env = inventory_data.get("environments")
    if not available:
        if not isinstance(env, dict) or env.get("status") != "endpoint_not_found" or env.get("partial") is not True:
            return ["missing explicit selected environment denial"]
        return []
    if (
        not isinstance(env, dict)
        or env.get("records") != available
        or env.get("count") != len(available)
        or env.get("partial") is not False
    ):
        errors.append("Portainer environment inventory incomplete or wrong")
    for category in categories:
        section = inventory_data.get(category)
        if limited and category != "containers":
            if (
                not isinstance(section, dict)
                or section.get("status") != "unavailable"
                or section.get("partial") is not True
            ):
                errors.append("Portainer limited Docker resource denial missing: " + category)
            continue
        expected = []
        for environment in available:
            value = inventory(category, environment["Id"], limited=limited)
            if category == "system":
                expected.append(
                    {
                        "environment": environment["Id"],
                        "info": value,
                        "disk_usage": inventory("disk", environment["Id"], limited=limited),
                    }
                )
            else:
                values = value["Volumes"] if category == "volumes" else value
                expected.extend({"environment": environment["Id"], **r} for r in values)
        if (
            not isinstance(section, dict)
            or section.get("records") != expected
            or section.get("count") != len(expected)
            or section.get("partial") is not False
        ):
            errors.append("Portainer selected Docker inventory incomplete or wrong: " + category)
    return errors
