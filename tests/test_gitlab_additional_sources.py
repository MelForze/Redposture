"""Project extras must read actual content, preserve selectors and prove completeness."""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.gitlab import actions
from redposture_core.storage_discovery import DiscoveryCollector, discover_gitlab_sources

KEY = "/api/v4/projects/7"


class Streamed:
    def __init__(self, body, *, cut=None, status=200):
        self.body, self.cut, self.status = body, cut, status


def run(monkeypatch, routes, *, graph=None, capture=None, cancel_after_finding=False):
    calls = []
    streamed = {}

    def request(_host, _port, method, path, _timeout, **kwargs):
        assert method == "GET"
        assert kwargs["headers"].get("PRIVATE-TOKEN") == "qa-token"
        calls.append(path)
        if path.startswith("/api/graphql?"):
            query = parse_qs(urlsplit(path).query)["query"][0]
            assert "mutation" not in query
            value = graph(query) if callable(graph) else graph
        elif path in routes:
            value = routes[path]
        elif path.startswith(KEY + "/wikis?") and KEY + "/wikis" in routes:
            value = routes[KEY + "/wikis"]
        elif path == "/api/v4/projects/team%2Fapp":
            value = {"id": 7, "path_with_namespace": "team/app", "namespace": {"kind": "user"}}
        elif path.endswith("per_page=100&page=1"):
            value = []
        else:
            raise AssertionError(path)
        status = 200
        if isinstance(value, Streamed):
            streamed[path] = value
            return 200, b"[]", {"x-redposture-truncated": "true"}, None
        if isinstance(value, tuple):
            status, value = value
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        return status, body, {}, None

    monkeypatch.setattr(actions, "_http_request", request)

    class Pool:
        def request_stream(self, method, url, *, on_chunk, on_response, **kwargs):
            assert method == "GET"
            parsed = urlsplit(url)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            value = streamed[path]
            on_response(value.status, {"x-next-page": ""})
            data = value.body if value.cut is None else value.body[: value.cut]
            for offset in range(0, len(data), 65536):
                on_chunk(data[offset : offset + 65536])
            return HttpResponse(
                value.status,
                b"",
                {},
                error="read timeout" if value.cut is not None else None,
                truncated=value.cut is not None,
            )

    emitted = []
    ctx = SimpleNamespace(
        host="qa",
        port=80,
        args=SimpleNamespace(discover_time=30, timeout=1),
        credential=SimpleNamespace(token="qa-token"),
        lifecycle_state=SimpleNamespace(http=Pool()),
        live_emit=emitted.extend,
        cancelled=lambda: cancel_after_finding and bool(emitted),
    )
    c = DiscoveryCollector("gitlab", ctx, {"status": "valid_credentials"})
    if capture is not None:
        capture.append((c, calls))
    discover_gitlab_sources(ctx, {"token_valid": True, "project_filters": ["team/app"], "token_projects": []}, c)
    return c.result(), calls


def graph(files, *, cursor=None, more=False, errors=None, lost=False):
    result = {
        "data": {
            "snippets": {
                "nodes": [
                    {
                        "id": "gid://gitlab/ProjectSnippet/12",
                        "project": {"id": "gid://gitlab/Project/7"},
                        "blobs": {
                            "nodes": files,
                            "hasUnretrievableBlobs": lost,
                            "pageInfo": {"hasNextPage": more, "endCursor": cursor},
                        },
                    }
                ]
            }
        }
    }
    if errors:
        result["errors"] = errors
    return result


def test_reads_wiki_every_snippet_file_and_package_contents(monkeypatch):
    routes = {
        KEY + "/wikis?with_content=1&per_page=100&page=1": [
            {"slug": "ops/deploy", "content": 'password="inactive-wiki!42"'}
        ],
        KEY + "/snippets?per_page=100&page=1": [{"id": 12, "file_name": "one.env"}],
        KEY + "/snippets/12/files/sha1/one.env/raw": b'password="inactive-snippet-one!42"\n',
        KEY + "/snippets/12/files/sha1/nested%2Ftwo.env/raw": b'password="inactive-snippet-two!42"\n',
        KEY + "/packages?per_page=100&page=1": [{"id": 30, "package_type": "generic", "name": "app", "version": "1.0"}],
        KEY + "/packages/30/package_files?per_page=100&page=1": [{"id": 31, "file_name": "app.env"}],
        KEY + "/packages/30/package_files/31/download": b'password="inactive-package!42"\n',
    }
    result, calls = run(
        monkeypatch,
        routes,
        graph=graph(
            [
                {"path": name, "rawPath": "/team/app/-/snippets/12/raw/sha1/" + name}
                for name in ("one.env", "nested/two.env")
            ]
        ),
    )
    assert result["status"] == "complete", result["partial_reasons"]
    assert {f["value"] for f in result["findings"]} == {
        "inactive-wiki!42",
        "inactive-snippet-one!42",
        "inactive-snippet-two!42",
        "inactive-package!42",
    }
    assert not any("/projects?" in p or "/projects/8" in p for p in calls)
    sources = {r["id"]: r for r in result["sources"]}
    assert sources["gitlab.wiki_contents"]["read"] == 1
    assert sources["gitlab.snippet_contents"]["read"] == 2
    assert sources["gitlab.package_files"]["read"] == 1
    assert all(r["complete"] for r in sources.values() if r["requested"])
    assert all(r["read"] == 0 and not r["complete"] for r in sources.values() if not r["requested"])
    assert any("nested/two.env" in f["object_path"] for f in result["findings"])


def test_generic_download_uses_canonical_fallback_on_old_gitlab(monkeypatch):
    routes = {
        KEY + "/packages?per_page=100&page=1": [{"id": 30, "package_type": "generic", "name": "app", "version": "1.0"}],
        KEY + "/packages/30/package_files?per_page=100&page=1": [{"id": 31, "file_name": "nested/app.env"}],
        KEY + "/packages/30/package_files/31/download": (404, {"message": "404 Not Found"}),
        KEY + "/packages/generic/app/1.0/nested/app.env": b'password="inactive-fallback!42"\n',
    }
    result, _ = run(monkeypatch, routes)
    assert result["status"] == "complete", result["partial_reasons"]
    assert [f["value"] for f in result["findings"]] == ["inactive-fallback!42"]


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_denied_or_failed_extras_never_scan_error_body(monkeypatch, status):
    result, _ = run(
        monkeypatch, {KEY + "/wikis?with_content=1&per_page=100&page=1": (status, b'password="inactive-error-body!42"')}
    )
    assert result["status"] in {"partial", "unavailable"}
    assert not result["findings"]
    row = next(r for r in result["sources"] if r["id"] == "gitlab.wiki_contents")
    assert not row["complete"]
    assert row["denied"] == int(status in {401, 403})


def test_snippet_cursor_pages_and_duplicate_page_are_not_complete(monkeypatch):
    calls = 0

    def response(query):
        nonlocal calls
        calls += 1
        return graph(
            [{"path": "one.env", "rawPath": "/team/app/-/snippets/12/raw/sha1/one.env"}], cursor="again", more=True
        )

    result, _ = run(
        monkeypatch,
        {
            KEY + "/snippets?per_page=100&page=1": [{"id": 12}],
            KEY + "/snippets/12/files/sha1/one.env/raw": b'password="inactive-page!42"',
        },
        graph=response,
    )
    assert calls == 2
    assert result["status"] == "partial"
    assert [f["value"] for f in result["findings"]] == ["inactive-page!42"]
    assert any("repeated" in reason for reason in result["partial_reasons"])


def test_unretrievable_blob_keeps_read_values_but_never_complete(monkeypatch):
    result, _ = run(
        monkeypatch,
        {
            KEY + "/snippets?per_page=100&page=1": [{"id": 12}],
            KEY + "/snippets/12/files/sha/one.env/raw": b'password="inactive-read!42"',
        },
        graph=graph([{"path": "one.env", "rawPath": "/team/app/-/snippets/12/raw/sha/one.env"}], lost=True),
    )
    assert result["status"] == "partial"
    assert len(result["findings"]) == 1
    assert not next(r for r in result["sources"] if r["id"] == "gitlab.snippet_contents")["complete"]


@pytest.mark.parametrize(
    "raw_path",
    [
        "https://outside.invalid/team/app/-/snippets/12/raw/sha/one.env",
        "/team/app/-/snippets/99/raw/sha/one.env",
        "/team/app/-/snippets/12/raw/sha/other.env",
    ],
)
def test_snippet_catalog_cannot_redirect_credentials_or_change_selected_identity(monkeypatch, raw_path):
    result, calls = run(
        monkeypatch,
        {KEY + "/snippets?per_page=100&page=1": [{"id": 12}]},
        graph=graph([{"path": "one.env", "rawPath": raw_path}]),
    )
    assert result["status"] == "partial"
    assert not result["findings"]
    assert not any(p.endswith("/raw") for p in calls)


def test_maven_download_fallback_reads_file_on_gitlab17(monkeypatch):
    routes = {
        KEY + "/packages?per_page=100&page=1": [
            {"id": 30, "package_type": "maven", "name": "org/example/app", "version": "1.0"}
        ],
        KEY + "/packages/30/package_files?per_page=100&page=1": [{"id": 31, "file_name": "app-1.0.pom"}],
        KEY + "/packages/30/package_files/31/download": (404, {"message": "404 Not Found"}),
        KEY
        + "/packages/maven/org/example/app/1.0/app-1.0.pom": b"<project><password>inactive-maven!42</password></project>",
    }
    result, _ = run(monkeypatch, routes)
    assert result["status"] == "complete", result["partial_reasons"]
    assert [f["value"] for f in result["findings"]] == ["inactive-maven!42"]


def test_large_wiki_json_streams_after_page_shrinking_without_losing_tail(monkeypatch):
    text = (
        'password="inactive-wiki-begin!42"\n'
        + ("ordinary configuration line\n" * 400000)
        + 'password="inactive-wiki-end!42"\n'
    )
    payload = json.dumps([{"slug": "large", "content": text}], ensure_ascii=False).encode()
    assert len(payload) > 10_000_000
    result, calls = run(monkeypatch, {KEY + "/wikis": Streamed(payload)})
    assert result["status"] == "complete", result["partial_reasons"]
    assert {f["value"] for f in result["findings"]} == {"inactive-wiki-begin!42", "inactive-wiki-end!42"}
    assert any("per_page=1&" in p for p in calls)
    assert all(not isinstance(f["value"], bytes) for f in result["findings"])


def test_interrupted_wiki_catalog_keeps_closed_item_not_open_candidate(monkeypatch):
    payload = b'[{"slug":"finished","content":"password=inactive-closed!42"},{"slug":"unfinished","content":"password=inactive-unclosed!42'
    result, _ = run(monkeypatch, {KEY + "/wikis": Streamed(payload, cut=len(payload))})
    assert result["status"] == "partial"
    assert [f["value"] for f in result["findings"]] == ["inactive-closed!42"]
    assert not next(r for r in result["sources"] if r["id"] == "gitlab.wiki_contents")["complete"]


def test_wiki_detail_fallback_keeps_slug_and_content(monkeypatch):
    result, _ = run(
        monkeypatch,
        {
            KEY + "/wikis?with_content=1&per_page=100&page=1": [{"slug": "nested/config"}],
            KEY + "/wikis/nested%2Fconfig": {"content": 'password="inactive-detail!42"'},
        },
    )
    assert result["status"] == "complete"
    finding = result["findings"][0]
    assert finding["value"] == "inactive-detail!42"
    assert "nested/config" in finding["object_path"]


def test_cancel_then_repeat_reads_same_values_without_stale_dedup_state(monkeypatch):
    from redposture_core.scheduler import NestedSchedulerCancelled

    routes = {
        KEY + "/wikis?with_content=1&per_page=100&page=1": [
            {"slug": "first", "content": 'password="inactive-first!42"'},
            {"slug": "second", "content": 'password="inactive-second!42"'},
        ]
    }
    saved = []
    with pytest.raises(NestedSchedulerCancelled):
        run(monkeypatch, routes, capture=saved, cancel_after_finding=True)
    collector, calls = saved[0]
    interrupted = collector.result()
    assert interrupted["status"] == "partial"
    assert [f["value"] for f in interrupted["findings"]] == ["inactive-first!42"]
    assert not any("/snippets?" in p for p in calls)
    for _ in range(2):
        result, _ = run(monkeypatch, routes)
        assert result["status"] == "complete"
        assert {f["value"] for f in result["findings"]} == {"inactive-first!42", "inactive-second!42"}
        assert len(result["findings"]) == 2


def test_existing_source_manifest_counts_reads_not_just_advertised_catalogs(monkeypatch):
    result, _ = run(
        monkeypatch,
        {
            KEY + "/repository/branches?per_page=100&page=1": [{"name": "main"}],
            KEY + "/repository/tree?recursive=true&ref=main&per_page=100&page=1": [{"type": "blob", "path": "app.env"}],
            KEY + "/repository/files/app.env/raw?ref=main&lfs=true": b'password="inactive-current!42"',
            KEY + "/repository/commits?all=true&per_page=100&page=1": [{"id": "sha", "parent_ids": ["parent"]}],
            KEY + "/repository/commits/sha/diff?per_page=100&page=1": [{"new_path": "app.env"}],
            KEY + "/repository/files/app.env/raw?ref=sha&lfs=true": b'password="inactive-historical!42"',
            KEY + "/variables?per_page=100&page=1": [{"key": "DB_PASSWORD", "value": "inactive-variable!42"}],
            KEY + "/jobs?per_page=100&page=1": [{"id": 5}],
            KEY + "/jobs/5/trace": b'password="inactive-trace!42"',
        },
    )
    assert result["status"] == "complete", result["partial_reasons"]
    assert {f["value"] for f in result["findings"]} == {
        "inactive-current!42",
        "inactive-historical!42",
        "inactive-variable!42",
        "inactive-trace!42",
    }
    rows = {r["id"]: r for r in result["sources"]}
    for kind in (
        "project_catalog",
        "branch_catalog",
        "repository_tree",
        "repository_files",
        "commit_catalog",
        "commit_diffs",
        "historical_files",
        "project_variable_catalog",
        "project_variable_values",
        "job_catalog",
        "job_traces",
    ):
        row = rows["gitlab." + kind]
        assert row["read"] == 1 and row["complete"], row
    assert rows["gitlab.job_artifacts"]["requested"] == 0


def test_unsupported_old_server_package_download_is_explicit_partial(monkeypatch):
    result, _ = run(
        monkeypatch,
        {
            KEY + "/packages?per_page=100&page=1": [{"id": 30, "package_type": "helm", "name": "app", "version": "1"}],
            KEY + "/packages/30/package_files?per_page=100&page=1": [{"id": 31, "file_name": "app.tgz"}],
            KEY + "/packages/30/package_files/31/download": (404, {"message": "404 Not Found"}),
        },
    )
    assert result["status"] == "partial"
    row = next(r for r in result["sources"] if r["id"] == "gitlab.package_files")
    assert row["unsupported"] and not row["complete"] and row["read"] == 0


def test_snippet_graphql_denial_is_visible_in_source_manifest(monkeypatch):
    result, _ = run(
        monkeypatch,
        {KEY + "/snippets?per_page=100&page=1": [{"id": 12}]},
        graph=(403, {"errors": [{"message": "forbidden"}]}),
    )
    assert result["status"] == "partial"
    row = next(r for r in result["sources"] if r["id"] == "gitlab.snippet_contents")
    assert row["denied"] == 1 and not row["complete"] and row["read"] == 0


def test_graphql_denied_still_reads_available_rest_snippet_files(monkeypatch):
    files = [
        {"path": name, "raw_url": "http://qa/team/app/-/snippets/12/raw/sha/" + name}
        for name in ("one.env", "nested/two.env")
    ]
    result, _ = run(
        monkeypatch,
        {
            KEY + "/snippets?per_page=100&page=1": [{"id": 12, "files": files}],
            KEY + "/snippets/12/files/sha/one.env/raw": b'password="inactive-rest-one!42"',
            KEY + "/snippets/12/files/sha/nested%2Ftwo.env/raw": b'password="inactive-rest-two!42"',
        },
        graph=(403, {"errors": [{"message": "forbidden"}]}),
    )
    assert result["status"] == "partial"
    assert {f["value"] for f in result["findings"]} == {"inactive-rest-one!42", "inactive-rest-two!42"}
    row = next(r for r in result["sources"] if r["id"] == "gitlab.snippet_contents")
    assert row["read"] == 2 and row["denied"] == 1 and not row["complete"]


def test_null_variable_value_is_incomplete_not_an_authorized_empty_read(monkeypatch):
    result, _ = run(monkeypatch, {KEY + "/variables?per_page=100&page=1": [{"key": "PRIVATE_PASSWORD", "value": None}]})
    assert result["status"] == "partial"
    assert not result["findings"]
    row = next(r for r in result["sources"] if r["id"] == "gitlab.project_variable_values")
    assert row["requested"] == 1 and row["read"] == 0 and not row["complete"]
