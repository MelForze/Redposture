"""Read-only Spark/YARN protocol corpora; never allocate or submit applications."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

from scripts.performance_http_fixtures import response
from scripts.performance_readonly import readonly_wire_errors

SPARK_WORKERS = [
    {
        "id": f"worker-20261107-{n}",
        "host": f"billing-worker-{n}.qa",
        "port": 7078,
        "state": "ALIVE" if n < 3 else "DEAD",
        "cores": 16,
        "coresused": n * 2,
        "memory": 32768,
        "memoryused": n * 1024,
    }
    for n in range(1, 4)
]
SPARK_APPS = [
    {"id": f"app-20261107093000-{n:04d}", "name": name, "user": "billing", "state": "RUNNING", "cores": n * 2}
    for n, name in enumerate(("billing-events", "invoice-rollup", "сверка-платежей"), 1)
]
SPARK_MASTER = {
    "url": "spark://billing-master.qa:7077",
    "cores": 48,
    "coresused": 12,
    "memory": 98304,
    "memoryused": 6144,
    "status": "ALIVE",
    "workers": SPARK_WORKERS,
    "activeapps": SPARK_APPS,
    "completedapps": [],
}
SPARK_STATUS = {
    "action": "SubmissionStatusResponse",
    "serverSparkVersion": "3.5.7",
    "submissionId": "redposture-probe",
    "success": False,
    "message": "Driver redposture-probe not found.",
}
YARN_INFO = {
    "id": 1794000000000,
    "startedOn": 1794000000000,
    "state": "STARTED",
    "haState": "ACTIVE",
    "resourceManagerVersion": "3.4.2",
    "hadoopVersion": "3.4.2",
}
YARN_APPS = [
    {
        "id": f"application_1794000000000_{n:04d}",
        "name": name,
        "user": "billing",
        "queue": "production",
        "state": "RUNNING" if n < 3 else "FINISHED",
        "finalStatus": "UNDEFINED" if n < 3 else "SUCCEEDED",
        "applicationType": "SPARK",
        "progress": 25.0 * n,
        "allocatedMB": n * 1024,
    }
    for n, name in enumerate(("billing-events", "invoice-rollup", "сверка-платежей"), 1)
]
YARN_NODES = [
    {"id": f"billing-node-{n}.qa:45454", "rack": "/billing", "state": "RUNNING", "usedMemoryMB": n * 1024}
    for n in range(1, 4)
]
YARN_METRICS = {"totalMB": 98304, "allocatedMB": 6144, "totalNodes": 3, "appsRunning": 2, "appsCompleted": 1}


def compute_reply(module: str, method: str, path: str, *, access: str) -> bytes:
    if module not in {"spark", "yarn"} or access not in {"open", "limited", "denied"}:
        raise ValueError("unknown compute profile")
    if module == "spark" and access == "denied":
        raise ValueError("a generic denied Spark API cannot prove the product; use a separate negative control")
    if method != "GET":
        return response(405, {"message": "Allocation, submission and execution disabled in read-only QA model"})
    parsed = urlsplit(path)
    if module == "spark":
        if access == "open" and parsed.path == "/json/":
            return response(200, SPARK_MASTER)
        if access == "open" and parsed.path == "/":
            return response(
                200,
                "<!doctype html><html><head><title>Spark Master at spark://billing-master.qa:7077</title></head>"
                '<body><span class="version">3.5.7</span></body></html>',
                headers={"Content-Type": "text/html; charset=utf-8"},
            )
        if access == "limited" and parsed.path == "/v1/submissions/status/redposture-probe":
            return response(200, SPARK_STATUS)
    else:
        if parsed.path == "/ws/v1/cluster/info":
            return response(200, {"clusterInfo": YARN_INFO})
        name = parsed.path.rsplit("/", 1)[-1]
        if parsed.path.startswith("/ws/v1/cluster/") and name in {"apps", "nodes", "metrics"}:
            if access == "denied" or access == "limited" and name != "metrics":
                return response(
                    403, {"RemoteException": {"exception": "AuthorizationException", "message": "Access denied"}}
                )
            if name == "apps":
                limit = parse_qs(parsed.query).get("limit", ["5000"])
                if limit not in (["1"], ["5000"]):
                    return response(400, {"message": "unexpected application limit"})
                return response(200, {"apps": {"app": YARN_APPS[: int(limit[0])]}})
            return response(
                200, {"nodes": {"node": YARN_NODES}} if name == "nodes" else {"clusterMetrics": YARN_METRICS}
            )
    return response(404, {"message": "Not found"})


def compute_inventory_errors(
    module: str, record: dict[str, Any], wire: dict[str, Any] | None, *, access: str, categories: list[str]
) -> list[str]:
    errors = readonly_wire_errors(wire)
    if errors:
        return errors
    assert wire is not None
    paths = [c["path"] for c in wire["calls"]]
    required = (
        {"/json/", "/"}
        if module == "spark" and access == "open"
        else {"/json/", "/v1/submissions/status/redposture-probe"}
        if module == "spark"
        else {"/ws/v1/cluster/info", "/ws/v1/cluster/apps?limit=1"}
    )
    if module == "yarn":
        required |= {"/ws/v1/cluster/" + name + ("?limit=5000" if name == "apps" else "") for name in categories}
    if not required.issubset(paths) or set(paths) - required:
        errors.append("missing or out-of-scope compute read receipts")
    if record.get("is_" + module) is not True or record.get("version") != ("3.5.7" if module == "spark" else "3.4.2"):
        errors.append("compute detection/version differs from seeded API")
    if record.get("inventory_requested", []) != categories:
        errors.append("compute selectors changed inventory scope")
    for c in wire["calls"]:
        expected = compute_reply(module, c["method"], c["path"], access=access)
        head, payload = expected.split(b"\r\n\r\n", 1)
        if c["response_body"].encode() != payload or c["status"] != int(head.split(b" ", 2)[1]):
            errors.append("compute exchange differs from actual model response")
    if module == "spark":
        if (
            record.get("surface") != ("master_ui" if access == "open" else "submission_rest")
            or record.get("auth_required") is not False
        ):
            errors.append("Spark surface/access is not backed by product proof")
        for name, expected_rows in (("workers", SPARK_WORKERS), ("apps", SPARK_APPS)):
            if name in categories:
                if record.get(name + "_access") != ("allowed" if access == "open" else "unavailable"):
                    errors.append("Spark collection access mismatch: " + name)
                if access == "open" and record.get(name) != expected_rows or access != "open" and record.get(name):
                    errors.append("Spark inventory differs from known objects: " + name)
        expected_status = "complete" if access == "open" else "unavailable"
    else:
        if record.get("cluster_info") != YARN_INFO or record.get("auth_required") is not (access != "open"):
            errors.append("YARN cluster/access differs from protected apps probe")
        for name, yarn_model in (("apps", YARN_APPS), ("nodes", YARN_NODES), ("metrics", YARN_METRICS)):
            if name in categories:
                allowed = access == "open" or access == "limited" and name == "metrics"
                if record.get(name + "_access") != ("allowed" if allowed else "denied"):
                    errors.append("YARN resource access mismatch: " + name)
                if allowed and record.get(name) != yarn_model or not allowed and record.get(name):
                    errors.append("YARN inventory differs from known objects: " + name)
        expected_status = (
            "complete"
            if access == "open"
            else "partial"
            if access == "limited" and "metrics" in categories and len(categories) > 1
            else "complete"
            if access == "limited" and categories == ["metrics"]
            else "unavailable"
        )
    if categories and record.get("inventory_status") != expected_status:
        errors.append("compute inventory completeness mismatch")
    return errors
