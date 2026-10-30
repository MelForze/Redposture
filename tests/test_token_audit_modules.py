"""Read-only product proof, token verdicts, inventories and secret traversal."""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.data_discovery import inspect_record

MODULES = ("vault", "nomad", "jupyter")
HEALTH = {"initialized": True, "sealed": False, "standby": False, "version": "1.21.0", "cluster_name": "qa"}
NOMAD = {
    "config": {"ACL": {"Enabled": False}, "Version": {"Version": "1.10.1"}},
    "stats": {"nomad": {"server": "true"}},
}
STATUS = {"connections": 0, "kernels": 0, "last_activity": "2026-10-20T00:00:00Z", "started": "2026-10-20T00:00:00Z"}
CONTENTS = {"name": "", "path": "", "type": "directory", "content": []}


class Pool:
    def __init__(self, replies: dict[str, Any]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, str, dict[str, str]]] = []
        self.request_options: list[tuple[str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        parsed = urlsplit(url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        self.calls.append((method, path, dict(kwargs.get("headers") or {})))
        self.request_options.append((path, kwargs))
        reply = self.replies.get(path, (404, {}))
        if isinstance(reply, HttpResponse):
            return reply
        status, data = reply
        return HttpResponse(status, json.dumps(data).encode(), {"Content-Type": "application/json"})


def context(replies: dict[str, Any], **options: Any) -> SimpleNamespace:
    return SimpleNamespace(
        host="127.0.0.1",
        port=8200,
        args=SimpleNamespace(**options),
        credential=None,
        lifecycle_state=SimpleNamespace(http=Pool(replies)),
    )


def actions(module: str) -> Any:
    return importlib.import_module(f"redposture_core.modules.{module}.actions")


def replies(module: str) -> dict[str, Any]:
    if module == "vault":
        return {"/v1/sys/health": (200, HEALTH), "/v1/sys/mounts": (403, {"errors": ["permission denied"]})}
    if module == "nomad":
        return {
            "/v1/agent/self": (200, NOMAD),
            "/v1/status/leader": (200, "127.0.0.1:4647"),
            "/v1/jobs?namespace=default": (200, []),
            "/v1/nodes": (200, []),
        }
    return {
        "/api": (200, {"version": "2.17.0"}),
        "/api/status": (200, STATUS),
        "/api/contents?content=1": (200, CONTENTS),
        "/api/kernels": (200, []),
        "/api/sessions": (200, []),
    }


@pytest.mark.parametrize("module", MODULES)
def test_cli_and_discovery_are_available(module: str) -> None:
    args = parse_args(
        [module, "-t", "http://127.0.0.1:8200/prefix", "--token", "candidate", "--discover", "--enum-cve"]
    )
    assert args.command == module and args.discover and args.enum_cve


@pytest.mark.parametrize("module", MODULES)
def test_detector_requires_multiple_product_signals(module: str) -> None:
    ctx = context(replies(module))
    record = actions(module).detect_record(ctx)
    assert record[f"is_{module}"] is True
    assert record["detection_status"] == "confirmed"
    assert record["version"]
    assert all(method == "GET" for method, _, _ in ctx.lifecycle_state.http.calls)


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize(
    "body", [{}, {"version": "2.17.0"}, [], "login", {"initialized": True, "sealed": False, "standby": False}]
)
def test_foreign_http_200_does_not_confirm_product(module: str, body: Any) -> None:
    paths = (
        "/v1/sys/health",
        "/v1/sys/seal-status",
        "/v1/agent/self",
        "/v1/status/leader",
        "/api",
        "/api/status",
        "/login",
        "/",
    )
    ctx = context({path: (200, body) for path in paths})
    assert actions(module).detect_record(ctx)[f"is_{module}"] is False


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_ambiguous_token_response_never_proves_rejection_or_success(module: str, status: int) -> None:
    ctx = context({path: (status, {}) for path in ("/v1/auth/token/lookup-self", "/v1/acl/token/self", "/api/status")})
    ctx.credential = SimpleNamespace(token="candidate", source="provided")
    record = actions(module).auth_record(
        ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "auth_required", "auth_required": True}
    )
    assert record["provided_credentials_ok"] is None
    assert record["credential_state"] not in {"valid", "invalid"}


@pytest.mark.parametrize(
    "module,path,body",
    [
        ("vault", "/v1/auth/token/lookup-self", {"data": {"id": "candidate", "policies": ["default"], "ttl": 3600}}),
        (
            "nomad",
            "/v1/acl/token/self",
            {"AccessorID": "accessor", "SecretID": "candidate", "Type": "client", "Policies": ["reader"]},
        ),
        ("jupyter", "/api/status", STATUS),
    ],
)
def test_token_requires_product_identity_or_protected_api_differential(module: str, path: str, body: Any) -> None:
    ctx = context({path: (200, body)})
    ctx.credential = SimpleNamespace(token="candidate", source="provided")
    record = actions(module).auth_record(
        ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "auth_required", "auth_required": True}
    )
    assert record["provided_credentials_ok"] is True and record["credential_state"] == "valid"
    assert "candidate" not in json.dumps({k: v for k, v in record.items() if k != "api_endpoint"})


@pytest.mark.parametrize(
    "module,path,body",
    [
        ("vault", "/v1/auth/token/lookup-self", {"errors": ["permission denied", "invalid token"]}),
        ("nomad", "/v1/acl/token/self", "ACL token not found"),
        ("jupyter", "/api/status", {"message": "Forbidden", "reason": None}),
    ],
)
def test_explicit_product_token_rejection_is_invalid(module: str, path: str, body: Any) -> None:
    ctx = context({path: (403, body), **({"/api/me": (403, body)} if module == "jupyter" else {})})
    ctx.credential = SimpleNamespace(token="candidate", source="provided")
    record = actions(module).auth_record(
        ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "auth_required", "auth_required": True}
    )
    assert record["provided_credentials_ok"] is False and record["credential_state"] == "invalid"


@pytest.mark.parametrize("module", ["nomad", "jupyter"])
def test_anonymous_open_resource_does_not_validate_arbitrary_token(module: str) -> None:
    ctx = context({"/v1/acl/token/self": (200, {"ACLsEnabled": False}), "/api/status": (200, STATUS)})
    ctx.credential = SimpleNamespace(token="anything", source="provided")
    record = actions(module).auth_record(
        ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth", "auth_required": False}
    )
    assert record["provided_credentials_ok"] is not True


def test_vault_uninitialized_sealed_is_still_initializable() -> None:
    ctx = context({"/v1/sys/health": (501, {**HEALTH, "initialized": False, "sealed": True})})
    record = actions("vault").detect_record(ctx)
    assert record["init_takeover_possible"] is True


def test_vault_kv_v1_v2_traversal_and_denied_child_are_partial() -> None:
    ctx = context(
        {
            "/v1/sys/mounts": (
                200,
                {"data": {"secret/": {"type": "kv", "options": {"version": "2"}}, "legacy/": {"type": "kv"}}},
            ),
            "/v1/secret/metadata/": (200, {"data": {"keys": ["app", "denied/"]}}),
            "/v1/secret/data/app": (200, {"data": {"data": {"password": "qa-password-value"}}}),
            "/v1/secret/metadata/denied/": (403, {}),
            "/v1/legacy/": (200, {"data": {"keys": ["app"]}}),
            "/v1/legacy/app": (200, {"data": {"token": "secret-token-value"}}),
        },
        discover=True,
    )
    record = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert len(record["kv_dump_items"]) == 2 and record["kv_discovery_partial"]
    assert inspect_record("vault", record)["status"] == "partial"
    assert all(method in {"GET", "LIST"} for method, _, _ in ctx.lifecycle_state.http.calls)


def test_nomad_acl_off_is_not_claimed_from_readable_jobs_alone() -> None:
    data = replies("nomad")
    data["/v1/agent/self"] = (
        200,
        {"config": {"ACL": {"Enabled": True}, "Version": {"Version": "1.10.1"}}, "stats": {}},
    )
    record = actions("nomad").detect_record(context(data))
    assert record["acl_enabled"] is True
    assert record["rce_potential"] is False


def test_nomad_discovery_reads_job_details_in_namespace() -> None:
    ctx = context(
        {
            "/v1/jobs?namespace=payments&per_page=100": (200, [{"ID": "billing", "Namespace": "payments"}]),
            "/v1/job/billing?namespace=payments": (
                200,
                {"ID": "billing", "TaskGroups": [{"Tasks": [{"Env": {"PASSWORD": "database-secret"}}]}]},
            ),
        },
        discover=True,
        namespace="payments",
    )
    record = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert len(record["job_specs"]) == 1
    assert inspect_record("nomad", record)["findings"]
    assert all(method == "GET" for method, _, _ in ctx.lifecycle_state.http.calls)


def test_nomad_discover_reads_jobs_after_inventory_snapshot_limit() -> None:
    first_page = [{"ID": f"job-{index}", "Namespace": "default"} for index in range(5000)]
    replies: dict[str, Any] = {
        "/v1/jobs?namespace=default&per_page=100": HttpResponse(
            200,
            json.dumps(first_page).encode(),
            {"X-Nomad-NextToken": "after-first"},
        ),
        "/v1/jobs?namespace=default&per_page=100&next_token=after-first": (
            200,
            [{"ID": "last-job", "Namespace": "default"}],
        ),
    }
    for row in first_page:
        replies[f"/v1/job/{row['ID']}?namespace=default"] = (200, {"ID": row["ID"]})
    replies["/v1/job/last-job?namespace=default"] = (
        200,
        {"ID": "last-job", "TaskGroups": [{"Tasks": [{"Env": {"TOKEN": "glpat-abcdefghijklmnopqrst"}}]}]},
    )
    ctx = context(replies, discover=True, namespace="default", discover_time=60)
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["job_discovery_partial"] is False
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])
    assert result["content_discovery"]["status"] == "complete"
    assert len(result["jobs"]) <= 5000
    assert len(result["job_specs"]) <= 5000


def test_nomad_discover_repeated_next_token_is_partial() -> None:
    page = HttpResponse(
        200,
        json.dumps([{"ID": "one", "Namespace": "default"}]).encode(),
        {"X-Nomad-NextToken": "again"},
    )
    ctx = context(
        {
            "/v1/jobs?namespace=default&per_page=100": page,
            "/v1/jobs?namespace=default&per_page=100&next_token=again": page,
            "/v1/job/one?namespace=default": (200, {"ID": "one"}),
        },
        discover=True,
    )
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["job_discovery_partial"] is True
    assert result["content_discovery"]["status"] == "partial"
    assert result["jobs_error"] == "pagination repeated a token"
    assert len(result["job_specs"]) == 1


def test_nomad_discover_retries_large_job_page_with_smaller_page_size() -> None:
    ctx = context(
        {
            "/v1/jobs?namespace=default&per_page=100": HttpResponse(200, b"[", {}, truncated=True),
            "/v1/jobs?namespace=default&per_page=50": (200, [{"ID": "found", "Namespace": "default"}]),
            "/v1/job/found?namespace=default": (
                200,
                {"ID": "found", "TaskGroups": [{"Tasks": [{"Env": {"TOKEN": "glpat-abcdefghijklmnopqrst"}}]}]},
            ),
        },
        discover=True,
        discover_time=60,
    )
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "complete"
    assert result["job_discovery_partial"] is False
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])


def test_nomad_discover_page_retry_preserves_next_token() -> None:
    ctx = context(
        {
            "/v1/jobs?namespace=default&per_page=100": HttpResponse(
                200,
                b'[{"ID":"first","Namespace":"default"}]',
                {"X-Nomad-NextToken": "after-first"},
            ),
            "/v1/jobs?namespace=default&per_page=100&next_token=after-first": HttpResponse(
                200, b"[", {}, truncated=True
            ),
            "/v1/jobs?namespace=default&per_page=50&next_token=after-first": (
                200,
                [{"ID": "last", "Namespace": "default"}],
            ),
            "/v1/job/first?namespace=default": (200, {"ID": "first"}),
            "/v1/job/last?namespace=default": (
                200,
                {"ID": "last", "TaskGroups": [{"Tasks": [{"Env": {"TOKEN": "glpat-abcdefghijklmnopqrst"}}]}]},
            ),
        },
        discover=True,
        discover_time=60,
    )
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])


def test_nomad_discover_single_oversized_job_summary_remains_partial() -> None:
    replies = {
        f"/v1/jobs?namespace=default&per_page={size}": HttpResponse(200, b"[", {}, truncated=True)
        for size in (100, 50, 25, 12, 6, 3, 1)
    }
    ctx = context(replies, discover=True, discover_time=60)
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["job_discovery_partial"] is True
    assert result["content_discovery"]["status"] == "partial"


def test_nomad_discover_streams_one_job_spec_beyond_response_cap() -> None:
    payload = json.dumps(
        {
            "ID": "big-job",
            "Description": " " * 8000,
            "TaskGroups": [{"Tasks": [{"Env": {"TOKEN": "glpat-abcdefghijklmnopqrst"}}]}],
        }
    ).encode()
    ctx = context(
        {
            "/v1/jobs?namespace=default&per_page=100": (200, [{"ID": "big-job", "Namespace": "default"}]),
            "/v1/job/big-job?namespace=default": HttpResponse(200, b"{}", {}, truncated=True),
        },
        discover=True,
        discover_max_bytes=4096,
        discover_time=60,
    )

    def stream(_method: str, _url: str, *, on_chunk: Any, on_response: Any, **_kwargs: Any) -> HttpResponse:
        on_response(200, {"Content-Type": "application/json"})
        for offset in range(0, len(payload), 257):
            on_chunk(payload[offset : offset + 257])
        return HttpResponse(200, b"", {"Content-Type": "application/json"})

    ctx.lifecycle_state.http.request_stream = stream
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["job_specs"] == []
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])


@pytest.mark.parametrize("identity", ["different-job", "x" * 8192 + "big-job"], ids=["mismatch", "oversized-suffix"])
def test_nomad_streamed_job_with_wrong_identity_is_partial(identity: str) -> None:
    payload = json.dumps(
        {"ID": identity, "TaskGroups": [{"Tasks": [{"Env": {"TOKEN": "glpat-abcdefghijklmnopqrst"}}]}]}
    ).encode()
    ctx = context(
        {
            "/v1/jobs?namespace=default&per_page=100": (200, [{"ID": "big-job", "Namespace": "default"}]),
            "/v1/job/big-job?namespace=default": HttpResponse(200, b"{}", {}, truncated=True),
        },
        discover=True,
        discover_max_bytes=4096,
        discover_time=60,
    )

    def stream(_method: str, _url: str, *, on_chunk: Any, on_response: Any, **_kwargs: Any) -> HttpResponse:
        on_response(200, {"Content-Type": "application/json"})
        for offset in range(0, len(payload), 257):
            on_chunk(payload[offset : offset + 257])
        return HttpResponse(200, b"", {"Content-Type": "application/json"})

    ctx.lifecycle_state.http.request_stream = stream
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "partial"
    assert result["job_discovery_partial"] is True


def test_jupyter_discovery_recurses_notebooks_without_starting_kernels() -> None:
    directory = {
        "name": "",
        "path": "",
        "type": "directory",
        "content": [
            {"name": "a.ipynb", "path": "a.ipynb", "type": "notebook"},
            {"name": "private", "path": "private", "type": "directory"},
        ],
    }
    notebook = {
        "name": "a.ipynb",
        "path": "a.ipynb",
        "type": "notebook",
        "format": "json",
        "content": {"cells": [{"source": "password = 'notebook-qa-secret'"}]},
    }
    ctx = context(
        {
            "/api/contents?content=1": (200, directory),
            "/api/contents/a.ipynb?content=1": (200, notebook),
            "/api/contents/private?content=1": (403, {}),
        },
        discover=True,
    )
    record = actions("jupyter").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert "notebook_contents" not in record and record["content_discovery_partial"]
    assert record["content_discovery"]["findings"]
    assert all(method == "GET" for method, _, _ in ctx.lifecycle_state.http.calls)


def test_jupyter_discover_streams_notebook_after_response_cap() -> None:
    notebook = {
        "name": "report.ipynb",
        "path": "report.ipynb",
        "type": "notebook",
        "content": {"cells": [{"source": ["API_TOKEN=glpat-abcdefghijklmnopqrst"]}]},
    }
    root = {
        "name": "",
        "path": "",
        "type": "directory",
        "content": [{"name": "report.ipynb", "path": "report.ipynb", "type": "notebook"}],
    }

    class StreamPool(Pool):
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            payload = json.dumps(notebook).encode()
            for position in range(0, len(payload), 23):
                on_chunk(payload[position : position + 23])
            return HttpResponse(200, b"", {})

    pool = StreamPool(
        {
            "/api/contents?content=1": (200, root),
            "/api/contents/report.ipynb?content=1": HttpResponse(
                200, b'{"name":"report.ipynb"', {"Content-Type": "application/json"}, truncated=True
            ),
            "/api/contents/report.ipynb?content=0": (
                200,
                {"name": "report.ipynb", "path": "report.ipynb", "type": "notebook"},
            ),
        }
    )
    ctx = context({}, discover=True, discover_time=30, path="")
    ctx.lifecycle_state.http = pool
    result = actions("jupyter").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])
    assert "notebook_contents" not in result


def test_jupyter_direct_notebook_selector_streams_large_response() -> None:
    notebook = {
        "name": "report.ipynb",
        "path": "report.ipynb",
        "type": "notebook",
        "content": {"cells": [{"source": ["API_TOKEN=glpat-abcdefghijklmnopqrst"]}]},
    }

    class StreamPool(Pool):
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            payload = json.dumps(notebook).encode()
            for position in range(0, len(payload), 23):
                on_chunk(payload[position : position + 23])
            return HttpResponse(200, b"", {})

    pool = StreamPool(
        {
            "/api/contents/report.ipynb?content=1": HttpResponse(
                200, b'{"name":"report.ipynb"', {"Content-Type": "application/json"}, truncated=True
            ),
            "/api/contents/report.ipynb?content=0": (
                200,
                {"name": "report.ipynb", "path": "report.ipynb", "type": "notebook"},
            ),
        }
    )
    ctx = context({}, discover=True, discover_time=30, path="report.ipynb")
    ctx.lifecycle_state.http = pool
    result = actions("jupyter").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])


def test_jupyter_discover_reads_after_inventory_snapshot_limit() -> None:
    children = [
        {"name": f"entry-{index}.ipynb", "path": f"entry-{index}.ipynb", "type": "notebook"} for index in range(5001)
    ]
    root = {"name": "", "path": "", "type": "directory", "content": children}
    replies: dict[str, Any] = {"/api/contents?content=1": (200, root)}
    for child in children:
        source = "API_TOKEN=glpat-abcdefghijklmnopqrst" if child is children[-1] else "ordinary notebook text"
        replies[f"/api/contents/{child['path']}?content=1"] = (
            200,
            {**child, "content": {"cells": [{"source": source}]}},
        )
    ctx = context(replies, discover=True, discover_time=30)
    result = actions("jupyter").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])
    assert "/api/contents/entry-5000.ipynb?content=1" in [path for _, path, _ in ctx.lifecycle_state.http.calls]


def test_jupyter_discover_streams_oversized_directory_listing() -> None:
    root = {
        "name": "",
        "path": "",
        "type": "directory",
        "content": [{"name": "report.ipynb", "path": "report.ipynb", "type": "notebook"}],
        "padding": "a" * (4 * 1024 * 1024),
    }

    class StreamPool(Pool):
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            payload = json.dumps(root).encode()
            for position in range(0, len(payload), 65536):
                on_chunk(payload[position : position + 65536])
            return HttpResponse(200, b"", {})

    pool = StreamPool(
        {
            "/api/contents?content=1": HttpResponse(200, b'{"name":""', {}, truncated=True),
            "/api/contents?content=0": (200, {"name": "", "path": "", "type": "directory"}),
            "/api/contents/report.ipynb?content=1": (
                200,
                {
                    "name": "report.ipynb",
                    "path": "report.ipynb",
                    "type": "notebook",
                    "content": {"cells": [{"source": "API_TOKEN=glpat-abcdefghijklmnopqrst"}]},
                },
            ),
        }
    )
    ctx = context({}, discover=True, discover_time=30)
    ctx.lifecycle_state.http = pool
    result = actions("jupyter").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])


def test_jupyter_malformed_streamed_directory_is_partial() -> None:
    class StreamPool(Pool):
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            on_chunk(b'{"name":"","path":"","type":"directory","content":["bad"]}')
            return HttpResponse(200, b"", {})

    pool = StreamPool(
        {
            "/api/contents?content=1": HttpResponse(200, b'{"name":""', {}, truncated=True),
            "/api/contents?content=0": (200, {"name": "", "path": "", "type": "directory"}),
        }
    )
    ctx = context({}, discover=True, discover_time=30)
    ctx.lifecycle_state.http = pool
    result = actions("jupyter").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "partial"
    assert not result["content_discovery"]["findings"]


def test_vault_identity_must_match_candidate() -> None:
    ctx = context({"/v1/auth/token/lookup-self": (200, {"data": {"id": "other", "policies": ["root"]}})})
    ctx.credential = SimpleNamespace(token="candidate", source="provided")
    result = actions("vault").auth_record(ctx, {"api_endpoint": "http://127.0.0.1", "status": "auth_required"})
    assert result["provided_credentials_ok"] is None


def test_vault_discovery_rejects_parent_paths_and_obeys_byte_budget() -> None:
    ctx = context(
        {
            "/v1/sys/mounts": (200, {"data": {"secret/": {"type": "kv"}}}),
            "/v1/secret/": (200, {"data": {"keys": ["../bad", "a/../../bad", "ok"]}}),
            "/v1/secret/ok": (200, {"data": {"password": "long-secret" * 100}}),
        },
        discover=True,
        discover_max_bytes=100,
    )
    result = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1", "status": "open_no_auth"})
    assert not result["kv_dump_items"] and result["kv_discovery_partial"]
    assert not any(".." in path for _, path, _ in ctx.lifecycle_state.http.calls)


def test_vault_discover_continues_after_5000_keys_without_retaining_all_values() -> None:
    keys = [f"entry-{index}" for index in range(5001)]
    replies: dict[str, Any] = {
        "/v1/sys/mounts": (200, {"data": {"secret/": {"type": "kv"}}}),
        "/v1/secret/": (200, {"data": {"keys": keys}}),
    }
    for key in keys:
        value = "API_TOKEN=glpat-abcdefghijklmnopqrst" if key == keys[-1] else "ordinary text"
        replies["/v1/secret/" + key] = (200, {"data": {"value": value}})
    ctx = context(replies, discover=True, discover_time=60)
    result = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["kv_secrets_read"] == 5001
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])
    assert len(result["kv_dump_items"]) <= 5000


def test_vault_discover_streams_large_single_kv_value() -> None:
    secret = {"data": {"padding": "ordinary " * 500_000, "api_token": "glpat-abcdefghijklmnopqrst"}}

    class StreamPool(Pool):
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            payload = json.dumps(secret).encode()
            for offset in range(0, len(payload), 65536):
                on_chunk(payload[offset : offset + 65536])
            return HttpResponse(200, b"", {})

    pool = StreamPool(
        {
            "/v1/sys/mounts": (200, {"data": {"secret/": {"type": "kv"}}}),
            "/v1/secret/": (200, {"data": {"keys": ["large"]}}),
            "/v1/secret/large": HttpResponse(200, b'{"data":{', {}, truncated=True),
        }
    )
    ctx = context({}, discover=True, discover_time=60)
    ctx.lifecycle_state.http = pool
    result = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["kv_secrets_read"] == 1
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])


def test_vault_discover_streams_large_key_listing_without_dropping_last_key() -> None:
    keys = [f"entry-{index}" for index in range(100)]

    class StreamPool(Pool):
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            payload = json.dumps({"data": {"keys": keys}}).encode()
            for offset in range(0, len(payload), 53):
                on_chunk(payload[offset : offset + 53])
            return HttpResponse(200, b"", {})

    pool = StreamPool(
        {
            "/v1/sys/mounts": (200, {"data": {"secret/": {"type": "kv"}}}),
            "/v1/secret/": HttpResponse(200, b'{"data":{"keys":[', {}, truncated=True),
            **{
                "/v1/secret/" + key: (
                    200,
                    {"data": {"value": "glpat-abcdefghijklmnopqrst" if key == keys[-1] else "ordinary"}},
                )
                for key in keys
            },
        }
    )
    ctx = context({}, discover=True, discover_time=60)
    ctx.lifecycle_state.http = pool
    result = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["kv_secrets_read"] == len(keys)
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])


@pytest.mark.parametrize("show_mounts", [False, True])
def test_vault_discover_streams_oversized_mount_catalog_before_kv_walk(show_mounts: bool) -> None:
    catalog = {
        # Vault can include the same mounts both at the root and under data.
        # The data catalog takes precedence, including the KV version.
        "secret/": {"type": "kv", "options": {"version": "1"}},
        "data": {
            "system/": {"type": "system"},
            "secret/": {"type": "kv", "options": {"version": "2"}, "description": "ordinary " * 500_000},
        },
    }

    class StreamPool(Pool):
        def request_stream(self, _method, url, *, on_chunk, on_response, **_kwargs):
            assert url.endswith("/v1/sys/mounts")
            on_response(200, {"Content-Type": "application/json"})
            payload = json.dumps(catalog).encode()
            for offset in range(0, len(payload), 65_536):
                on_chunk(payload[offset : offset + 65_536])
            return HttpResponse(200, b"", {})

    pool = StreamPool(
        {
            "/v1/sys/mounts": HttpResponse(200, b'{"data":{', {}, truncated=True),
            "/v1/secret/metadata/": (200, {"data": {"keys": ["app"]}}),
            "/v1/secret/data/app": (200, {"data": {"data": {"api_token": "glpat-abcdefghijklmnopqrst"}}}),
        }
    )
    ctx = context({}, discover=True, show_mounts=show_mounts, discover_time=60)
    ctx.lifecycle_state.http = pool
    result = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["mounts_access"] == "allowed"
    assert result["mounts_count"] == 2
    assert result["inventory_status"] == ("partial" if show_mounts else "complete")
    assert result.get("mounts_snapshot_partial") is (True if show_mounts else None)
    assert result["kv_secrets_read"] == 1
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])


def test_vault_broken_streamed_mount_catalog_remains_partial() -> None:
    class BrokenPool(Pool):
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            on_chunk(b'{"data":{"secret/":{"type":"kv"}')
            return HttpResponse(200, b"", {})

    ctx = context({}, discover=True, discover_time=60)
    ctx.lifecycle_state.http = BrokenPool({"/v1/sys/mounts": HttpResponse(200, b'{"data":{', {}, truncated=True)})
    result = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["mounts_access"] == "unknown"
    assert result["kv_discovery_partial"] is True
    assert inspect_record("vault", result)["status"] == "partial"


def test_vault_discover_marks_broken_streamed_key_listing_partial() -> None:
    class BrokenPool(Pool):
        def request_stream(self, _method, _url, *, on_chunk, on_response, **_kwargs):
            on_response(200, {"Content-Type": "application/json"})
            on_chunk(b'{"data":{"keys":["first",')
            return HttpResponse(200, b"", {})

    pool = BrokenPool(
        {
            "/v1/sys/mounts": (200, {"data": {"secret/": {"type": "kv"}}}),
            "/v1/secret/": HttpResponse(200, b'{"data":{"keys":[', {}, truncated=True),
        }
    )
    ctx = context({}, discover=True, discover_time=60)
    ctx.lifecycle_state.http = pool
    result = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["kv_discovery_partial"] is True
    assert result["content_discovery"]["status"] == "partial"
    assert "incomplete KV key listing" in result["kv_discovery_reasons"]


@pytest.mark.parametrize(
    "module,prior,source_path",
    [
        ("vault", {"status": "open_no_auth"}, "/v1/sys/mounts"),
        ("nomad", {"status": "open_no_auth"}, "/v1/jobs?namespace=default&per_page=100"),
        ("jupyter", {"status": "open_no_auth"}, "/api/contents?content=1"),
        ("spark", {"is_spark": True, "surface": "master_ui"}, "/json/"),
        ("yarn", {"is_yarn": True}, "/ws/v1/cluster/apps"),
    ],
)
def test_token_api_discovery_caps_source_read_to_remaining_budget(
    module: str, prior: dict[str, Any], source_path: str
) -> None:
    ctx = context({}, discover=True, discover_max_bytes=128, discover_time=4)
    record = {"api_endpoint": "http://127.0.0.1:8200", **prior}
    actions(module).data_record(ctx, record)
    source_calls = [options for path, options in ctx.lifecycle_state.http.request_options if path == source_path]
    assert source_calls
    assert source_calls[0]["response_size_cap"] == 128
    assert 0 < source_calls[0]["timeout"] <= 4


def test_spark_discover_scans_apps_after_5000_snapshot_entries() -> None:
    apps = [
        {
            "id": f"app-{index}",
            "name": "glpat-abcdefghijklmnopqrst" if index == 5000 else "ordinary",
            "user": "qa",
            "state": "RUNNING",
            "cores": 1,
        }
        for index in range(5001)
    ]
    ctx = context(
        {"/json/": (200, {"url": "spark://127.0.0.1:7077", "cores": 1, "workers": [], "activeapps": apps})},
        discover=True,
        discover_time=60,
    )
    result = actions("spark").data_record(
        ctx,
        {"api_endpoint": "http://127.0.0.1:8200", "is_spark": True, "surface": "master_ui", "status": "open_no_auth"},
    )
    assert len(result["spark_metadata"]["apps"]) <= 5000
    assert result["content_discovery"]["status"] == "complete"
    assert any(item["type"] == "gitlab_token" for item in result["content_discovery"]["findings"])


def test_vault_truncated_mount_response_is_partial_not_unavailable() -> None:
    ctx = context(
        {"/v1/sys/mounts": HttpResponse(200, b"{" * 128, {}, truncated=True)},
        discover=True,
        discover_max_bytes=128,
    )
    record = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    discovery = inspect_record("vault", record)
    assert discovery["status"] == "partial"
    assert "byte_budget" in discovery["partial_reasons"]


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("token", ["", "a\nb", "a\rb", "\0", "\t", "\x01", "тест", "x" * 16385])
def test_bad_tokens_are_rejected_without_echo(module: str, token: str) -> None:
    policy = importlib.import_module(f"redposture_core.modules.{module}.policy")
    errors: list[str] = []
    ctx = context({}, token=token)
    assert policy.validate_args(ctx.args, SimpleNamespace(error=errors.append)) == 2
    assert errors and (len(token) < 2 or token not in errors[0])


@pytest.mark.parametrize("module", MODULES)
def test_token_file_plan_and_ports(module: str, tmp_path: Any) -> None:
    token_file = tmp_path / "token.txt"
    token_file.write_text(" candidate \n")
    args = parse_args([module, "-t", "http://127.0.0.1:12345/prefix", "--token-file", str(token_file)])
    policy = importlib.import_module(f"redposture_core.modules.{module}.policy")
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    assert policy.validate_args(args, SimpleNamespace(error=pytest.fail)) is None
    plan = getattr(stage, f"build_{module}_plan")(args)
    assert plan.credential_runs[0].token == "candidate"
    assert plan.target_plan is not None


@pytest.mark.parametrize(
    "module,version,enterprise,cve,present",
    [
        ("vault", "1.17.5", False, "CVE-2024-7594", True),
        ("vault", "1.16.10", True, "CVE-2024-7594", False),
        ("vault", "1.16.10", False, "CVE-2024-7594", True),
        ("vault", "1.16.9", None, "CVE-2024-7594", False),
        ("nomad", "1.9.10", False, "CVE-2025-4922", True),
        ("nomad", "1.9.10+ent", True, "CVE-2025-4922", False),
        ("jupyter", "2.17.0", None, "CVE-2026-35397", True),
        ("jupyter", "2.18.0", None, "CVE-2026-35397", False),
    ],
)
def test_cve_product_edition_and_patch_boundaries(
    module: str, version: str, enterprise: bool | None, cve: str, present: bool
) -> None:
    from redposture_core.cve import enumerate_record, load_catalog

    record = {
        "version": version,
        "enterprise": enterprise,
        "anonymous_access": True,
        "status": "open_no_auth",
        "auth_required": False,
    }
    result = enumerate_record(module, record, catalog=load_catalog(), confirmed=True)
    assert any(item["id"] == cve for item in result["findings"]) is present


class RecordingConsole:
    def __init__(self) -> None:
        self.paints: list[tuple[str, str]] = []

    def _paint(self, text: str, color: str, stream: Any) -> str:
        self.paints.append((text, color))
        return text

    def plain(self, text: str) -> None:
        pass


@pytest.mark.parametrize("module", MODULES)
def test_color_baseline_matches_airflow_semantics(module: str) -> None:
    render = importlib.import_module(f"redposture_core.modules.{module}.render")
    color = getattr(render, f"_render_colored_{module}_line")
    console = RecordingConsole()
    record = {
        "host": "127.0.0.1",
        "port": 1234,
        f"is_{module}": True,
        "auth_required": False,
        "initialized": False,
        "sealed": True,
        "acl_enabled": False,
        "version": "1.0.0",
        "token_valid": True,
        "token_policies": [],
    }
    line = render._format_detect_record(record, "txt")
    assert color(console, line)
    assert any("auth required:False" in text and value == "true_red" for text, value in console.paints)
    console.paints.clear()
    assert color(console, render._format_record(record, "txt"))
    assert any("accepted" in text.lower() and value == "true_red" for text, value in console.paints)
    console.paints.clear()
    record["token_valid"] = False
    assert color(console, render._format_record(record, "txt"))
    assert any("rejected" in text.lower() and value == "white" for text, value in console.paints)
    assert render._format_detect_record(record, "json") == ""
    assert render._format_record(record, "json") == ""
    assert render._format_inventory_records(record, "json") == []


def test_nomad_acl_locked_without_headers_is_identified_by_ui_and_leader() -> None:
    ctx = context(
        {
            "/v1/agent/self": (403, {}),
            "/v1/status/leader": (200, "127.0.0.1:4647"),
            "/ui/": HttpResponse(200, b'<title>Nomad</title><meta name="nomad-ui/config/environment">', {}),
            "/v1/jobs?namespace=default": (403, {}),
        }
    )
    result = actions("nomad").detect_record(ctx)
    assert result["is_nomad"] and result["auth_required"] is True


@pytest.mark.parametrize(
    "token,status,body",
    [
        ("00000000-0000-4000-8000-000000000001", 403, "Permission denied"),
        ("not-a-token", 500, "failed to parse signed token: go-jose/go-jose: compact JWS format must have three parts"),
    ],
)
def test_nomad_token_self_explicit_real_rejections(token: str, status: int, body: str) -> None:
    ctx = context({"/v1/acl/token/self": HttpResponse(status, body.encode(), {})})
    ctx.credential = SimpleNamespace(token=token, source="provided")
    result = actions("nomad").auth_record(ctx, {"api_endpoint": "http://127.0.0.1", "status": "auth_required"})
    assert result["provided_credentials_ok"] is False


def test_jupyter_identity_verifies_token_with_restricted_status() -> None:
    ctx = context(
        {
            "/api/status": (403, {"message": "Forbidden", "reason": None}),
            "/api/me": (200, {"identity": {"username": "auditor"}, "permissions": {}}),
        }
    )
    ctx.credential = SimpleNamespace(token="candidate", source="provided")
    result = actions("jupyter").auth_record(
        ctx, {"api_endpoint": "http://127.0.0.1", "status": "auth_required", "auth_required": True}
    )
    assert result["provided_credentials_ok"] is True
    assert result["auth_http_status"] == 200


def test_jupyter_identity_rate_limit_is_preserved() -> None:
    ctx = context({"/api/status": (403, {"message": "Forbidden", "reason": None}), "/api/me": (429, {})})
    ctx.credential = SimpleNamespace(token="candidate", source="provided")
    result = actions("jupyter").auth_record(
        ctx, {"api_endpoint": "http://127.0.0.1", "status": "auth_required", "auth_required": True}
    )
    assert result["status"] == "rate_limited"
    assert result["auth_http_status"] == 429
    assert result["provided_credentials_ok"] is None


def test_vault_zero_policies_are_green_and_headings_white() -> None:
    render = importlib.import_module("redposture_core.modules.vault.render")
    console = RecordingConsole()
    line = render._format_record(
        {"host": "127.0.0.1", "port": 8200, "token_valid": True, "token_policies": [], "token_ttl": 0}, "txt"
    )
    render._render_colored_vault_line(console, line)
    assert any("policies:0" in text and color == "bright_green" for text, color in console.paints)


@pytest.mark.parametrize(
    "mount,discover,expected", [("secret", True, None), ("a/../b", True, 2), ("", True, 2), ("secret", False, 2)]
)
def test_vault_mount_validation(mount: str, discover: bool, expected: int | None) -> None:
    from redposture_core.modules.vault.policy import validate_args

    args = SimpleNamespace(mount=mount, discover=discover)
    assert validate_args(args, SimpleNamespace(error=lambda _: None)) == expected
    if expected is None:
        assert args.mount == "secret/"


@pytest.mark.parametrize(
    "module,option,value",
    [("nomad", "namespace", "a/b"), ("jupyter", "path", "../outside"), ("jupyter", "path", "/absolute")],
)
def test_selectors_reject_unsafe_paths(module: str, option: str, value: str) -> None:
    policy = importlib.import_module(f"redposture_core.modules.{module}.policy")
    args = SimpleNamespace(**{option: value})
    assert policy.validate_args(args, SimpleNamespace(error=lambda _: None)) == 2


@pytest.mark.parametrize("module", MODULES)
def test_missing_token_file_and_incomplete_tls_are_errors(module: str, tmp_path: Any) -> None:
    policy = importlib.import_module(f"redposture_core.modules.{module}.policy")
    for opts in ({"token_file": str(tmp_path / "absent")}, {"tls_cert": "cert.pem"}):
        assert policy.validate_args(SimpleNamespace(**opts), SimpleNamespace(error=lambda _: None)) == 2


@pytest.mark.parametrize("module", MODULES)
def test_response_truncation_and_transport_errors_never_confirm(module: str) -> None:
    paths = ("/v1/sys/health", "/v1/agent/self", "/v1/status/leader", "/api", "/api/status", "/login", "/ui/")
    for response in (
        HttpResponse(200, b'{"version":"2.17.0"}', {}, truncated=True),
        HttpResponse(0, b"", {}, error="timeout"),
    ):
        record = actions(module).detect_record(context({path: response for path in paths}))
        assert record[f"is_{module}"] is False


def test_discovery_request_budgets_bound_empty_directory_trees() -> None:
    from redposture_core.modules.token_api import ReadBudget

    budget = ReadBudget(SimpleNamespace())
    budget.calls = 10000
    assert budget.allowed() and not budget.partial
    budget = ReadBudget(SimpleNamespace(discover_max_bytes=2))
    assert not budget.consume(HttpResponse(200, b"123", {})) and budget.partial


def test_token_api_budget_includes_detect_and_auth_elapsed_time(monkeypatch) -> None:
    from redposture_core.modules import token_api

    monkeypatch.setattr(token_api.time, "monotonic", lambda: 105.0)
    budget = token_api.ReadBudget(SimpleNamespace(discover_time=4), started_at=100.0)
    assert budget.allowed() is False
    assert budget.partial is True


def test_token_api_timeout_during_source_read_stays_partial(monkeypatch) -> None:
    from redposture_core.modules import token_api

    clock = {"now": 100.0}
    monkeypatch.setattr(token_api.time, "monotonic", lambda: clock["now"])
    budget = token_api.ReadBudget(SimpleNamespace(discover_time=1), started_at=100.0)
    assert budget.allowed()
    clock["now"] = 102.0
    assert not budget.consume(HttpResponse(0, b"", {}, error="timed out"))
    assert budget.reason == "time_budget"


# Generated malformed and type-confused response trees exercise parser edges,
# without network access or product-specific mock implementations.

_JSON = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-(10**20), max_value=10**20) | st.text(max_size=30),
    lambda child: (
        st.lists(child, max_size=5)
        | st.dictionaries(
            st.sampled_from(
                ["version", "data", "config", "initialized", "sealed", "standby", "identity", "connections", "kernels"]
            ),
            child,
            max_size=5,
        )
    ),
    max_leaves=20,
)


@pytest.mark.parametrize("module", MODULES)
@settings(max_examples=100)
@given(body=_JSON)
def test_generated_response_trees_do_not_crash_or_invent_token_identity(module: str, body: Any) -> None:
    paths = (
        "/v1/sys/health",
        "/v1/sys/seal-status",
        "/v1/agent/self",
        "/v1/status/leader",
        "/ui/",
        "/api",
        "/api/status",
        "/api/me",
        "/login",
        "/v1/auth/token/lookup-self",
        "/v1/acl/token/self",
    )
    ctx = context({path: (200, body) for path in paths})
    record = actions(module).detect_record(ctx)
    assert type(record[f"is_{module}"]) is bool
    ctx.credential = SimpleNamespace(token="not-an-identity", source="provided")
    auth = actions(module).auth_record(
        ctx, {"api_endpoint": "http://127.0.0.1", "status": "auth_required", "auth_required": True}
    )
    assert auth["provided_credentials_ok"] is not True


def test_nomad_wildcard_discovery_uses_each_jobs_namespace() -> None:
    ctx = context(
        {
            "/v1/jobs?namespace=%2A&per_page=100": (200, [{"ID": "billing", "Namespace": "payments"}]),
            "/v1/job/billing?namespace=payments": (200, {"ID": "billing", "Namespace": "payments", "TaskGroups": []}),
        },
        namespace="*",
        discover=True,
    )
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1", "status": "open_no_auth"})
    assert len(result["job_specs"]) == 1 and not result["job_discovery_partial"]


def test_nomad_repeated_pagination_token_stops_as_partial() -> None:
    page = HttpResponse(200, b'[{"ID":"one"}]', {"X-Nomad-NextToken": "same"})
    ctx = context(
        {"/v1/jobs?namespace=default": page, "/v1/jobs?namespace=default&next_token=same": page}, show_jobs=True
    )
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1", "status": "open_no_auth"})
    assert result["inventory_status"] == "partial" and len(ctx.lifecycle_state.http.calls) == 2


def test_vault_default_token_is_one_candidate_and_does_not_prove_dev_mode() -> None:
    from redposture_core.modules.vault.stage import build_vault_plan

    args = parse_args(["vault", "-t", "127.0.0.1", "--defcreds"])
    plan = build_vault_plan(args)
    assert len(plan.credential_runs) == 1 and plan.credential_runs[0].token == "root"
    assert plan.credential_runs[0].source == "default"


def test_vault_long_directory_is_requested_and_missing_response_is_partial() -> None:
    ctx = context(
        {
            "/v1/sys/mounts": (200, {"data": {"secret/": {"type": "kv"}}}),
            "/v1/secret/": (200, {"data": {"keys": ["x" * 5000 + "/"]}}),
        },
        discover=True,
    )
    result = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1", "status": "open_no_auth"})
    assert result["kv_discovery_partial"]
    assert len(ctx.lifecycle_state.http.calls) == 3
    assert ctx.lifecycle_state.http.calls[-1][1] == "/v1/secret/" + "x" * 5000 + "/"


def test_vault_duplicate_listed_keys_are_read_once() -> None:
    ctx = context(
        {
            "/v1/sys/mounts": (200, {"data": {"secret/": {"type": "kv"}}}),
            "/v1/secret/": (200, {"data": {"keys": ["one", "one"]}}),
            "/v1/secret/one": (200, {"data": {"value": "present"}}),
        },
        discover=True,
    )
    result = actions("vault").data_record(ctx, {"api_endpoint": "http://127.0.0.1", "status": "open_no_auth"})
    assert len(result["kv_dump_items"]) == 1
    assert sum(path == "/v1/secret/one" for _, path, _ in ctx.lifecycle_state.http.calls) == 1


def test_jupyter_trailing_slash_selector_does_not_skip_notebooks() -> None:
    ctx = context(
        {
            "/api/contents/reports?content=1": (
                200,
                {
                    "name": "reports",
                    "path": "reports",
                    "type": "directory",
                    "content": [{"name": "a.ipynb", "path": "reports/a.ipynb", "type": "notebook"}],
                },
            ),
            "/api/contents/reports/?content=1": (
                200,
                {
                    "name": "reports",
                    "path": "reports",
                    "type": "directory",
                    "content": [{"name": "a.ipynb", "path": "reports/a.ipynb", "type": "notebook"}],
                },
            ),
            "/api/contents/reports/a.ipynb?content=1": (
                200,
                {"name": "a.ipynb", "path": "reports/a.ipynb", "type": "notebook", "content": {"cells": []}},
            ),
        },
        path="reports/",
        discover=True,
    )
    result = actions("jupyter").data_record(ctx, {"api_endpoint": "http://127.0.0.1", "status": "open_no_auth"})
    assert "notebook_contents" not in result and not result["content_discovery_partial"]
    assert result["content_discovery"]["status"] == "complete"


def test_malformed_unicode_paths_are_rejected_without_crashing() -> None:
    from redposture_core.modules.token_api import safe_path

    assert safe_path("\ud800") is False
    assert safe_path("reports/отчёт.ipynb") is True


def test_jupyter_status_rate_limit_does_not_try_identity() -> None:
    ctx = context({"/api/status": (429, {}), "/api/me": (200, {"identity": {"username": "auditor"}})})
    ctx.credential = SimpleNamespace(token="candidate", source="provided")
    result = actions("jupyter").auth_record(
        ctx, {"api_endpoint": "http://127.0.0.1", "status": "auth_required", "auth_required": True}
    )
    assert result["status"] == "rate_limited"
    assert result["provided_credentials_ok"] is None


def test_nomad_streams_oversized_summary_and_preserves_next_header() -> None:
    replies: dict[str, Any] = {
        f"/v1/jobs?namespace=default&per_page={size}": HttpResponse(200, b"[", {}, truncated=True)
        for size in (100, 50, 25, 12, 6, 3, 1)
    }
    replies.update(
        {
            "/v1/jobs?namespace=default&per_page=1&next_token=last": (200, [{"ID": "tail", "Namespace": "default"}]),
            "/v1/job/big?namespace=default": (200, {"ID": "big", "Env": {"password": "qa-first-secret"}}),
            "/v1/job/tail?namespace=default": (200, {"ID": "tail", "Env": {"password": "qa-last-secret"}}),
        }
    )
    ctx = context(replies, discover=True, discover_time=30, discover_max_bytes=4096)
    payload = json.dumps([{"ID": "big", "Namespace": "default", "Meta": {"note": "x" * 20000}}]).encode()

    def stream(_method, url, *, on_response, on_chunk, **kwargs):
        assert "per_page=1" in url
        headers = {"Content-Type": "application/json", "X-Nomad-NextToken": "last"}
        on_response(200, headers)
        for offset in range(0, len(payload), 257):
            on_chunk(payload[offset : offset + 257])
        return HttpResponse(200, b"", headers)

    ctx.lifecycle_state.http.request_stream = stream
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    report = result["content_discovery"]
    assert report["status"] == "complete", report["partial_reasons"]
    assert [item["value"] for item in report["findings"]] == ["qa-first-secret", "qa-last-secret"]
    assert [item["ID"] for item in result["jobs"]] == ["big", "tail"]


def test_nomad_discover_does_not_retain_large_job_summaries_in_memory() -> None:
    rows = [{"ID": f"job-{index}", "Namespace": "default", "Meta": {"notes": "n" * 400000}} for index in range(4)]
    replies: dict[str, Any] = {"/v1/jobs?namespace=default&per_page=100": (200, rows)}
    replies.update(
        {
            f"/v1/job/job-{index}?namespace=default": (
                200,
                {"ID": f"job-{index}", "Env": {"password": f"qa-password-{index}"}},
            )
            for index in range(4)
        }
    )
    ctx = context(replies, discover=True, discover_time=30)
    result = actions("nomad").data_record(ctx, {"api_endpoint": "http://127.0.0.1:8200", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "complete"
    assert len(result["content_discovery"]["findings"]) == 4
    assert len(json.dumps(result["jobs"]).encode()) < 1_050_000
