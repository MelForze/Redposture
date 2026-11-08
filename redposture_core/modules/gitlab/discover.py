"""Read project wiki, every snippet blob and package file through read-only APIs."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from typing import Any
from urllib.parse import quote, unquote, urlencode, urlsplit

from ...discovery_frontier import DiscoveryFrontier
from ...discovery_sources import SourceManifest
from ...discovery_values import DiskBackedText
from ...scheduler import NestedSchedulerCancelled
from ...storage_discovery import DiscoveryCollector

Pages = Callable[[str, str, str], Iterator[Mapping[str, Any]]]
Document = Callable[[str, str], tuple[Mapping[str, Any] | None, int | None]]
Content = Callable[[str, str], tuple[bool, int | None]]


def _file_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        return None
    if any(part in {"", ".", ".."} for part in value.split("/")) or any(ord(c) < 32 for c in value):
        return None
    return value


def _snippet_path(project_id: int, snippet_id: int, blob: Mapping[str, Any]) -> tuple[str, str] | None:
    name = _file_path(blob.get("path"))
    raw = blob.get("rawPath")
    if not name or not isinstance(raw, str):
        return None
    parsed = urlsplit(raw)
    # rawPath is a path, never an instruction to send a token to another host.
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    path = unquote(parsed.path)
    marker = f"/-/snippets/{snippet_id}/raw/"
    if marker not in path:
        return None
    remainder = path.split(marker, 1)[1]
    suffix = "/" + name
    if not remainder.endswith(suffix):
        return None
    ref = remainder[: -len(suffix)]
    if not _file_path(ref):
        return None
    return (
        f"/api/v4/projects/{project_id}/snippets/{snippet_id}/files/{quote(ref, safe='')}/{quote(name, safe='')}/raw",
        name,
    )


def _rest_snippet_files(
    collector: DiscoveryCollector,
    project_id: int,
    snippet_id: int,
    snippet: Mapping[str, Any],
    source: str,
    content: Content,
    manifest: SourceManifest,
    visited: DiscoveryFrontier,
) -> None:
    """Retain available files when a proxy/ACL blocks the GraphQL catalog.

    The advertised origin is never requested. Only its ref/path are used to
    construct the selected project's authenticated REST API route.
    """
    files = snippet.get("files")
    if not isinstance(files, list):
        return
    for item in files:
        if not isinstance(item, Mapping) or not isinstance(item.get("raw_url"), str):
            collector.partial(source, "invalid_rest_snippet_file")
            continue
        raw = urlsplit(item["raw_url"])
        parsed = _snippet_path(project_id, snippet_id, {"path": item.get("path"), "rawPath": raw.path})
        if parsed is None or raw.query or raw.fragment:
            collector.partial(source, "invalid_rest_snippet_file")
            continue
        path, name = parsed
        if not visited.claim(name):
            continue
        ok, status = content(path, source + "/file/" + name)
        if ok:
            manifest.read("gitlab.snippet_contents")
        manifest.finish("gitlab.snippet_contents", complete=ok, denied=status in {401, 403})


def _snippets(
    collector: DiscoveryCollector,
    project_id: int,
    key: str,
    source: str,
    *,
    pages: Pages,
    document: Document,
    content: Content,
    manifest: SourceManifest,
) -> None:
    kind = "gitlab.snippet_contents"
    for snippet in pages(key + "/snippets", source + "/snippets", kind):
        sid = snippet.get("id")
        if type(sid) is not int or sid <= 0:
            collector.partial(source + "/snippets", "snippet_id_unavailable")
            manifest.finish(kind, complete=False)
            continue
        origin = source + f"/snippet/{sid}"
        cursor: str | None = None
        with DiscoveryFrontier() as visited, DiscoveryFrontier() as files:
            while collector.allowed():
                after = ",after:" + json.dumps(cursor) if cursor is not None else ""
                gid = f"gid://gitlab/ProjectSnippet/{sid}"
                query = (
                    "query { snippets(ids:["
                    + json.dumps(gid)
                    + "]) { nodes { id project { id } blobs(first:100"
                    + after
                    + ") { hasUnretrievableBlobs nodes { path rawPath } pageInfo { hasNextPage endCursor } } } } }"
                )
                before = collector.partial_events
                data, status = document("/api/graphql?" + urlencode({"query": query}), origin + "/files")
                if data is None:
                    manifest.finish(kind, complete=False, denied=status in {401, 403})
                    _rest_snippet_files(collector, project_id, sid, snippet, origin, content, manifest, files)
                    break
                if data.get("errors"):
                    collector.partial(origin, "snippet_graphql_errors")
                    manifest.finish(kind, complete=False)
                payload = data.get("data")
                connection = payload.get("snippets") if isinstance(payload, Mapping) else None
                nodes = connection.get("nodes") if isinstance(connection, Mapping) else None
                if not isinstance(nodes, list) or len(nodes) != 1 or not isinstance(nodes[0], Mapping):
                    collector.partial(origin, "snippet_catalog_unavailable")
                    manifest.finish(kind, complete=False)
                    break
                node = nodes[0]
                project = node.get("project")
                if (
                    node.get("id") != gid
                    or not isinstance(project, Mapping)
                    or project.get("id") != f"gid://gitlab/Project/{project_id}"
                ):
                    collector.partial(origin, "snippet_identity_mismatch")
                    manifest.finish(kind, complete=False)
                    break
                blobs, page = node.get("blobs"), None
                if isinstance(blobs, Mapping):
                    page = blobs.get("pageInfo")
                if (
                    not isinstance(blobs, Mapping)
                    or not isinstance(blobs.get("nodes"), list)
                    or not isinstance(page, Mapping)
                    or type(page.get("hasNextPage")) is not bool
                ):
                    collector.partial(origin, "invalid_snippet_file_catalog")
                    manifest.finish(kind, complete=False)
                    break
                if blobs.get("hasUnretrievableBlobs") is not False:
                    collector.partial(origin, "unretrievable_snippet_blobs")
                    manifest.finish(kind, complete=False)
                manifest.finish(kind, complete=collector.partial_events == before)
                for blob in blobs["nodes"]:
                    parsed = _snippet_path(project_id, sid, blob) if isinstance(blob, Mapping) else None
                    if parsed is None:
                        collector.partial(origin, "snippet_file_identity_unavailable")
                        manifest.finish(kind, complete=False)
                        continue
                    path, name = parsed
                    if not files.claim(name):
                        continue
                    ok, status = content(path, origin + "/file/" + name)
                    if ok:
                        manifest.read(kind)
                    manifest.finish(kind, complete=ok, denied=status in {401, 403})
                if page["hasNextPage"] is False:
                    break
                next_cursor = page.get("endCursor")
                if (
                    not isinstance(next_cursor, str)
                    or not next_cursor
                    or next_cursor == cursor
                    or not visited.claim(next_cursor)
                ):
                    collector.partial(origin, "repeated_or_missing_snippet_cursor")
                    manifest.finish(kind, complete=False)
                    break
                cursor = next_cursor
            else:
                manifest.finish(kind, complete=False)


def _packages(
    collector: DiscoveryCollector, key: str, source: str, *, pages: Pages, content: Content, manifest: SourceManifest
) -> None:
    kind = "gitlab.package_files"
    for package in pages(key + "/packages", source + "/packages", kind):
        pid = package.get("id")
        if type(pid) is not int or pid <= 0:
            collector.partial(source + "/packages", "package_id_unavailable")
            manifest.finish(kind, complete=False)
            continue
        origin = source + f"/package/{pid}"
        for file in pages(key + f"/packages/{pid}/package_files", origin + "/files", kind):
            fid, name = file.get("id"), _file_path(file.get("file_name"))
            if type(fid) is not int or fid <= 0 or name is None:
                collector.partial(origin, "package_file_identity_unavailable")
                manifest.finish(kind, complete=False)
                continue
            target = origin + "/file/" + name
            previous_reasons = len(collector.partial_reasons)
            ok, status = content(key + f"/packages/{pid}/package_files/{fid}/download", target)
            # Older servers lack the universal download route. Use only
            # documented format routes, never a URL supplied by an artifact.
            if not ok and status == 404 and package.get("package_type") in {"generic", "maven"}:
                package_name, version = _file_path(package.get("name")), _file_path(package.get("version"))
                if package_name and version:
                    primary = collector.partial_reasons[previous_reasons:]
                    route = str(package["package_type"])
                    ok, status = content(
                        key
                        + "/packages/"
                        + route
                        + "/"
                        + quote(package_name, safe="/" if route == "maven" else "")
                        + "/"
                        + quote(version, safe="")
                        + "/"
                        + quote(name, safe="/"),
                        target,
                    )
                    if ok and len(primary) == 1 and primary[0].endswith("HTTP 404"):
                        del collector.partial_reasons[previous_reasons : previous_reasons + 1]
            if ok:
                manifest.read(kind)
            manifest.finish(kind, complete=ok, denied=status in {401, 403}, unsupported=not ok and status == 404)


def _project_extras(
    collector: DiscoveryCollector,
    project: Mapping[str, Any],
    source: str,
    *,
    pages: Pages,
    document: Document,
    content: Content,
    manifest: SourceManifest,
) -> None:
    pid = project["id"]
    key = f"/api/v4/projects/{pid}"
    kind = "gitlab.wiki_contents"
    for wiki in pages(key + "/wikis?with_content=1", source + "/wikis", kind):
        slug = wiki.get("slug")
        if not isinstance(slug, str) or not slug:
            collector.partial(source + "/wikis", "wiki_slug_unavailable")
            manifest.finish(kind, complete=False)
            continue
        origin = source + "/wiki/" + slug
        if not isinstance(wiki.get("content"), (str, DiskBackedText)):
            detail, status = document(key + "/wikis/" + quote(slug, safe=""), origin)
            if detail is None:
                manifest.finish(kind, complete=False, denied=status in {401, 403})
            wiki = detail or {}
        value = wiki.get("content")
        if not isinstance(value, (str, DiskBackedText)):
            collector.partial(origin, "wiki_content_unavailable")
            manifest.finish(kind, complete=False)
            continue
        before = collector.partial_events
        collector.mark_accessible_source()
        collector.add(origin, value, charge=False, prefer_specific=True)
        manifest.read(kind)
        manifest.finish(kind, complete=collector.partial_events == before)
    _snippets(collector, pid, key, source, pages=pages, document=document, content=content, manifest=manifest)
    _packages(collector, key, source, pages=pages, content=content, manifest=manifest)


def discover_project_extras(
    collector: DiscoveryCollector,
    project: Mapping[str, Any],
    source: str,
    *,
    pages: Pages,
    document: Document,
    content: Content,
    manifest: SourceManifest,
) -> None:
    for kind in ("gitlab.wiki_contents", "gitlab.snippet_contents", "gitlab.package_files"):
        manifest.declare(kind)
    try:
        _project_extras(collector, project, source, pages=pages, document=document, content=content, manifest=manifest)
    except (NestedSchedulerCancelled, KeyboardInterrupt):
        collector.partial(source, "cancelled")
        raise
