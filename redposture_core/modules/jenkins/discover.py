"""Read archived build artifacts without executing jobs or saving downloads."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping

from ...clients.http_api import HttpResponse
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_sources import SourceManifest
from ...storage_discovery import DiscoveryCollector


def scan_build_artifacts(
    collector: DiscoveryCollector,
    *,
    build_path: str,
    source: str,
    get_page: Callable[[str], HttpResponse | None],
    artifact_path: Callable[[str], str | None],
    read_content: Callable[[str, str, str], tuple[bool, int | None]],
    manifest: SourceManifest,
    limit: int | None = None,
) -> None:
    """Use Jenkins tree ranges; never hold a whole artifact catalog in RAM."""
    kind = "jenkins.artifact_contents"
    manifest.request(kind)
    with collector.source_guard(manifest, kind):
        size, offset, read = 100, 0, 0
        with DiscoveryFrontier() as visited:
            while collector.allowed():
                path = build_path + f"/api/json?tree=artifacts[relativePath]{{{offset},{offset + size}}}"
                try:
                    response = get_page(path)
                except (OSError, ValueError) as exc:
                    collector.partial(source, type(exc).__name__)
                    manifest.finish(kind, complete=False)
                    return
                if response is None or response.error or response.status != 200:
                    denied = response is not None and response.status in {401, 403}
                    collector.partial(source, "access_denied" if denied else "artifact_catalog_unavailable")
                    manifest.finish(kind, complete=False, denied=denied)
                    return
                if response.truncated:
                    if size > 1:
                        size = max(1, size // 2)
                        continue  # same offset; no skipped or repeated index range
                    collector.partial(source, "oversized_single_artifact_metadata")
                    manifest.finish(kind, complete=False)
                    return
                try:
                    data = json.loads(response.body)
                except (ValueError, UnicodeError):
                    data = None
                items = data.get("artifacts") if isinstance(data, Mapping) else None
                if not isinstance(items, list) or any(not isinstance(item, Mapping) for item in items):
                    collector.partial(source, "invalid_artifact_catalog")
                    manifest.finish(kind, complete=False)
                    return
                signature = hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()
                if items and not visited.claim("page:" + signature):
                    collector.partial(source, "repeated_artifact_page")
                    manifest.finish(kind, complete=False)
                    return
                collector.mark_accessible_source()
                for item in items:
                    if not collector.allowed():
                        manifest.finish(kind, complete=False)
                        return
                    relative = item.get("relativePath")
                    content_path = artifact_path(relative) if isinstance(relative, str) else None
                    if content_path is None:
                        collector.partial(source, "invalid_artifact_path")
                        manifest.finish(kind, complete=False)
                        continue
                    if not visited.claim("artifact:" + content_path):
                        continue
                    if limit is not None and read >= limit:
                        collector.partial(source, "explicit_artifact_limit")
                        manifest.finish(kind, complete=False)
                        return
                    try:
                        before = collector.partial_events
                        ok, status = read_content(content_path, source + "/artifact/" + relative, relative)
                    except (OSError, ValueError) as exc:
                        collector.partial(source, type(exc).__name__)
                        ok, status = False, None
                    if ok:
                        read += 1
                        manifest.read(kind)
                        manifest.finish(kind, complete=collector.partial_events == before)
                    else:
                        if collector.partial_events == before:
                            collector.partial(source, "artifact_content_incomplete")
                        manifest.finish(kind, complete=False, denied=status in {401, 403})
                if len(items) < size:
                    return
                offset += len(items)
        manifest.finish(kind, complete=False)
