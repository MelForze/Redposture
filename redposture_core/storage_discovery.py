"""Bounded, incremental secret inspection for read-only storage discovery."""

from __future__ import annotations

import base64
import json
import re
import tarfile
import time
import zipfile
from collections.abc import Mapping
from contextlib import closing
from io import BytesIO
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from .discovery_rendering import format_discovery_finding_line
from .secret_detection import fingerprint, mask_secret, scan_value


class DiscoveryCollector:
    """Keep a single byte/time budget across API responses and decoded content."""

    def __init__(self, module: str, ctx: Any, record: Mapping[str, Any]) -> None:
        self.module = module
        self.ctx = ctx
        self.deadline = time.monotonic() + float(getattr(ctx.args, "discover_time", None) or 300)
        self.remaining = int(getattr(ctx.args, "discover_max_bytes", None) or 50 * 1024 * 1024)
        self.bytes_read = 0
        self.bytes_inspected = 0
        self.findings: list[dict[str, Any]] = []
        self.partial_reasons: list[str] = []
        self._seen: set[tuple[str, str]] = set()
        self._sources = 0
        self._live_emitted = False
        self._emitted_fingerprints: set[str] = set()
        self.source = (
            "anonymous"
            if record.get("status") == "open_no_auth" or record.get("anonymous_access") is True
            else "authenticated"
            if record.get("provided_credentials_ok") is True
            or record.get("status") in {"valid_credentials", "weak_default_creds", "auth_valid", "open_auth"}
            else "access_unverified"
        )

    def allowed(self) -> bool:
        if time.monotonic() >= self.deadline:
            self.partial("budget", "discover_time")
            return False
        if self.remaining <= 0:
            self.partial("budget", "discover_max_bytes")
            return False
        return True

    def cap(self, maximum: int = 10 * 1024 * 1024) -> int:
        return min(maximum, self.remaining) if self.allowed() else 0

    def charge(self, length: int) -> bool:
        if not self.allowed():
            return False
        if length > self.remaining:
            self.partial("budget", "discover_max_bytes")
            return False
        self.bytes_read += length
        self.remaining -= length
        return True

    def partial(self, source: str, reason: str) -> None:
        detail = f"{source}: {reason}" if source != "budget" else reason
        detail = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", detail)
        detail = "".join(char for char in detail if char >= " ")[:200]
        if detail not in self.partial_reasons:
            self.partial_reasons.append(detail)

    def add(self, path: str, value: Any, *, charge: bool = True) -> bool:
        if charge:
            serialized = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
            if not self.charge(len(serialized)):
                return False
            inspected = len(serialized)
        else:
            if time.monotonic() >= self.deadline:
                self.partial("budget", "discover_time")
                return False
            inspected = len(str(value).encode("utf-8", errors="replace"))
        if not (isinstance(value, (Mapping, list, tuple, str, bytes)) and not value):
            self._sources += 1
        self.bytes_inspected += inspected
        for match in scan_value(value, object_path=f"$.{path}"):
            identity = (match.detector, fingerprint(match.value))
            if identity in self._seen:
                continue
            self._seen.add(identity)
            finding = {
                "type": match.detector,
                "confidence": match.confidence,
                "value": mask_secret(match.value),
                "fingerprint": identity[1],
                "object_path": match.object_path,
                "source": self.source,
            }
            self.findings.append(finding)
            emit = getattr(self.ctx, "live_emit", None)
            if callable(emit):
                emit(
                    [
                        format_discovery_finding_line(
                            self.module.upper(),
                            self.ctx.host,
                            self.ctx.port,
                            severity=match.confidence,
                            finding_type=match.detector,
                            value=finding["value"],
                            place=finding["object_path"],
                        )
                    ]
                )
                self._live_emitted = True
                self._emitted_fingerprints.add(identity[1])
        return True

    def read(self, getter: Any, endpoint: str, source: str, *, maximum: int = 10 * 1024 * 1024) -> bytes | None:
        """Fetch one capped response through the owning module's HTTP transport."""
        cap = self.cap(maximum)
        if not cap:
            return None
        try:
            status, body, headers, error = getter(endpoint, cap)
        except (OSError, ValueError) as exc:
            self.partial(source, str(exc))
            return None
        if error:
            self.partial(source, str(error))
            return None
        if status in {401, 403}:
            self.partial(source, "access_denied")
            return None
        if status != 200:
            self.partial(source, f"HTTP {status}")
            return None
        if not self.charge(len(body)):
            return None
        if str(headers.get("x-redposture-truncated") or "").lower() == "true":
            self.partial(source, "response_truncated")
        return body

    def scan_archive(self, source: str, body: bytes, kind: str) -> None:
        """Inspect archive members in memory without extracting paths to disk."""
        try:
            if kind == "zip":
                with zipfile.ZipFile(BytesIO(body)) as archive:
                    for member in archive.infolist():
                        if member.is_dir():
                            continue
                        if not self.allowed():
                            break
                        if member.file_size > self.remaining:
                            self.partial(source, f"member_too_large:{member.filename}")
                            continue
                        with archive.open(member) as stream:
                            content = stream.read(self.remaining + 1)
                        self._scan_member(source, member.filename, content)
            elif kind == "tar":
                with tarfile.open(fileobj=BytesIO(body), mode="r|*") as archive:
                    for tar_member in archive:
                        if not tar_member.isfile():
                            continue
                        if not self.allowed():
                            break
                        if tar_member.size > self.remaining:
                            self.partial(source, f"member_too_large:{tar_member.name}")
                            # Advancing a streaming TAR would decompress this
                            # tar_member just to reach the next header. Stop here
                            # rather than bypass the decompression budget.
                            break
                        tar_stream = archive.extractfile(tar_member)
                        if tar_stream is None:
                            self.partial(source, f"member_unreadable:{tar_member.name}")
                            continue
                        content = tar_stream.read(self.remaining + 1)
                        self._scan_member(source, tar_member.name, content)
            else:
                self.partial(source, f"unsupported_archive:{kind}")
        except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
            self.partial(source, f"archive_error:{type(exc).__name__}")

    def _scan_member(self, source: str, name: str, content: bytes) -> None:
        if not self.charge(len(content)):
            return
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            self.partial(source, f"binary_or_non_utf8:{name}")
            return
        if "\x00" in text:
            self.partial(source, f"binary:{name}")
            return
        self.add(f"{source}/file/{name}", text, charge=False)

    def result(self) -> dict[str, Any]:
        return {
            "status": (
                "unavailable"
                if not self._sources
                and self.partial_reasons
                and all("access_denied" in item for item in self.partial_reasons)
                else "partial"
                if self.partial_reasons
                else "complete"
                if self._sources
                else "unavailable"
            ),
            "bytes_read": self.bytes_read,
            "bytes_inspected": self.bytes_inspected,
            "source": self.source,
            "findings": self.findings,
            "partial_reasons": self.partial_reasons,
            "live_emitted": self._live_emitted,
            "emitted_fingerprints": sorted(self._emitted_fingerprints),
        }


def merge_discovery_results(*results: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Combine separate accessible surfaces while retaining live-output provenance."""
    present = [item for item in results if isinstance(item, Mapping)]
    if not present:
        return None
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    emitted: set[str] = set()
    reasons: list[str] = []
    for item in present:
        item_findings = item.get("findings")
        if not isinstance(item_findings, list):
            item_findings = []
        fingerprints = item.get("emitted_fingerprints")
        if isinstance(fingerprints, list):
            emitted.update(str(value) for value in fingerprints)
        elif item.get("live_emitted"):
            emitted.update(str(value.get("fingerprint")) for value in item_findings if isinstance(value, Mapping))
        for finding in item_findings:
            if not isinstance(finding, Mapping):
                continue
            identity = (str(finding.get("type")), str(finding.get("fingerprint")))
            if identity not in seen:
                seen.add(identity)
                findings.append(dict(finding))
        for reason in item.get("partial_reasons") or []:
            if isinstance(reason, str) and reason not in reasons:
                reasons.append(reason)
    statuses = {str(item.get("status")) for item in present}
    sources = {str(item.get("source")) for item in present}
    status = "complete" if statuses == {"complete"} else "unavailable" if statuses == {"unavailable"} else "partial"
    return {
        "status": status,
        "source": next(iter(sources)) if len(sources) == 1 else "mixed",
        "bytes_read": sum(int(item.get("bytes_read") or 0) for item in present),
        "bytes_inspected": sum(int(item.get("bytes_inspected") or 0) for item in present),
        "findings": findings,
        "partial_reasons": reasons,
        "live_emitted": bool(emitted),
        "emitted_fingerprints": sorted(emitted),
    }


def _json_page(collector: DiscoveryCollector, getter: Any, path: str, source: str) -> list[dict[str, Any]] | None:
    body = collector.read(getter, path, source)
    if body is None:
        return None
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        collector.partial(source, "invalid_json")
        return None
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        collector.partial(source, "invalid_list")
        return None
    return data


def _pages(collector: DiscoveryCollector, getter: Any, base: str, source: str, *, size: int = 100) -> Any:
    """Yield API list items while detecting duplicate pages and bounded traversal."""
    seen: set[str] = set()
    for page in range(1, 101):
        if not collector.allowed():
            return
        suffix = "&" if "?" in base else "?"
        items = _json_page(collector, getter, f"{base}{suffix}per_page={size}&page={page}", source)
        if items is None:
            return
        identity = json.dumps(items, sort_keys=True, default=str)
        if identity in seen:
            collector.partial(source, "repeated_page")
            return
        seen.add(identity)
        yield from items
        if len(items) < size:
            return
    collector.partial(source, "pagination_limit")


def discover_gitlab_sources(ctx: Any, record: Mapping[str, Any], collector: DiscoveryCollector) -> None:
    """Read accessible GitLab source, CI variables, logs and artifacts."""
    from .modules.gitlab import actions

    timeout = float(getattr(ctx.args, "timeout", 5.0) or 5.0)
    token = str(getattr(ctx.credential, "token", "") or "") or None
    headers = actions._gitlab_api_headers(token)
    use_https = bool(record.get("https"))

    def get(path: str, cap: int) -> tuple[int, bytes, dict[str, str], str | None]:
        return actions._http_request(
            str(ctx.host),
            int(ctx.port),
            "GET",
            path,
            timeout,
            use_https=use_https,
            headers=headers,
            response_size_cap=cap,
        )

    def list_projects() -> list[dict[str, Any]] | None:
        projects: list[dict[str, Any]] = []
        seen_pages: set[tuple[str, ...]] = set()
        page_headers: dict[str, str] = {}
        page = 1
        for _ in range(100):
            query = {"per_page": 100, "page": page, "simple": "true", "order_by": "id", "sort": "asc"}
            if not token_scope:
                query["visibility"] = "public"
            path = "/api/v4/projects?" + urlencode(query)
            page_headers.clear()

            def get_page(endpoint: str, cap: int) -> tuple[int, bytes, dict[str, str], str | None]:
                status, body, headers, error = get(endpoint, cap)
                page_headers.update(headers)
                return status, body, headers, error

            body = collector.read(get_page, path, "projects/list")
            if body is None:
                return projects if projects else None
            try:
                items = json.loads(body)
            except (ValueError, UnicodeError):
                collector.partial("projects/list", "invalid_json")
                return projects
            if not isinstance(items, list):
                collector.partial("projects/list", "invalid_list")
                return projects
            signature = tuple(str(item.get("id")) for item in items if isinstance(item, dict))
            if signature and signature in seen_pages:
                collector.partial("projects/list", "repeated_page")
                return projects
            seen_pages.add(signature)
            projects.extend(item for item in items if isinstance(item, dict))
            next_page = str(page_headers.get("x-next-page") or "").strip()
            if next_page.isdigit() and int(next_page) > page:
                page = int(next_page)
            elif len(items) >= 100:
                page += 1
            else:
                collector.add("projects/list", {"count": len(projects)}, charge=False)
                return projects
        collector.partial("projects/list", "pagination_limit")
        return projects

    token_scope = bool(token and record.get("token_valid") is True)
    projects = record.get("token_projects" if token_scope else "public_projects")
    selected = record.get("project_filters")
    filters = [str(value) for value in selected if str(value).strip()] if isinstance(selected, list) else []
    list_error = record.get("token_projects_error" if token_scope else "public_projects_error")
    if list_error:
        collector.partial("projects", str(list_error))
    if projects is None and not filters:
        projects = list_projects()
    if not isinstance(projects, list):
        if not filters:
            if not any(reason.startswith("projects/list:") for reason in collector.partial_reasons):
                collector.partial("projects", "project_list_unavailable")
            return
        projects = []
    else:
        projects = list(projects)
    for ref in filters:
        if any(
            isinstance(project, dict)
            and ref in {str(project.get("id")), str(project.get("path_with_namespace")), str(project.get("path"))}
            for project in projects
        ):
            continue
        source = f"project/{ref}/details"
        body = collector.read(get, "/api/v4/projects/" + quote(ref, safe=""), source)
        if body is None:
            continue
        try:
            selected_project = json.loads(body)
        except (ValueError, UnicodeError):
            collector.partial(source, "invalid_json")
            continue
        if not isinstance(selected_project, dict) or type(selected_project.get("id")) is not int:
            collector.partial(source, "project_identity_unavailable")
            continue
        projects.append(selected_project)
    group_ids: set[int] = set()
    for project in projects:
        if not isinstance(project, dict) or not collector.allowed():
            continue
        project_id = project.get("id")
        if type(project_id) is not int:
            collector.partial("projects", "project_id_unavailable")
            continue
        name = str(project.get("path_with_namespace") or project_id)
        key = f"/api/v4/projects/{project_id}"
        source = f"project/{name}"
        namespace = project.get("namespace")
        if (
            isinstance(namespace, dict)
            and type(namespace.get("id")) is int
            and namespace.get("kind", "group") == "group"
        ):
            group_ids.add(namespace["id"])

        branches = list(_pages(collector, get, key + "/repository/branches", source + "/branches"))
        for branch in branches:
            branch_name = str(branch.get("name") or "")
            if not branch_name:
                collector.partial(source + "/branches", "branch_name_unavailable")
                continue
            ref = quote(branch_name, safe="")
            for item in _pages(
                collector,
                get,
                key + f"/repository/tree?recursive=true&ref={ref}",
                source + f"/branch/{branch_name}/tree",
            ):
                if item.get("type") != "blob" or not isinstance(item.get("path"), str):
                    continue
                path = str(item["path"])
                file_path = key + f"/repository/files/{quote(path, safe='')}/raw?ref={ref}&lfs=true"
                body = collector.read(get, file_path, source + f"/branch/{branch_name}/file/{path}")
                if body is not None:
                    collector.add(
                        source + f"/branch/{branch_name}/file/{path}", body.decode("utf-8", "replace"), charge=False
                    )

        commits = _pages(collector, get, key + "/repository/commits?all=true", source + "/history")
        for commit in commits:
            sha = str(commit.get("id") or "")
            if not sha:
                collector.partial(source + "/history", "commit_sha_unavailable")
                continue
            parents = commit.get("parent_ids")
            parent = str(parents[0]) if isinstance(parents, list) and parents else None
            for diff in _pages(
                collector,
                get,
                key + f"/repository/commits/{quote(sha, safe='')}/diff",
                source + f"/commit/{sha}/diff",
            ):
                if diff.get("collapsed") or diff.get("too_large"):
                    collector.partial(source + f"/commit/{sha}", "diff_truncated")
                deleted = diff.get("deleted_file") is True
                path = str(diff.get("old_path" if deleted else "new_path") or "")
                historical_ref = parent if deleted else sha
                if not path or not historical_ref:
                    collector.partial(source + f"/commit/{sha}", "historical_path_unavailable")
                    continue
                file_path = (
                    key + f"/repository/files/{quote(path, safe='')}/raw?ref={quote(historical_ref, safe='')}&lfs=true"
                )
                body = collector.read(get, file_path, source + f"/commit/{sha}/file/{path}")
                if body is not None:
                    collector.add(source + f"/commit/{sha}/file/{path}", body.decode("utf-8", "replace"), charge=False)

        if token:
            for variable in _pages(collector, get, key + "/variables", source + "/variables"):
                variable_key = str(variable.get("key") or "")
                if not variable_key or "value" not in variable:
                    collector.partial(source + "/variables", "variable_value_unavailable")
                    continue
                collector.add(source + f"/variable/{variable_key}", {variable_key: variable["value"]}, charge=False)

        for job in _pages(collector, get, key + "/jobs", source + "/jobs"):
            job_id = job.get("id")
            if type(job_id) is not int:
                collector.partial(source + "/jobs", "job_id_unavailable")
                continue
            trace = collector.read(get, key + f"/jobs/{job_id}/trace", source + f"/job/{job_id}/trace")
            if trace is not None:
                collector.add(source + f"/job/{job_id}/trace", trace.decode("utf-8", "replace"), charge=False)
            artifact = job.get("artifacts_file")
            if isinstance(artifact, dict) and artifact.get("filename"):
                body = collector.read(get, key + f"/jobs/{job_id}/artifacts", source + f"/job/{job_id}/artifacts")
                if body is not None:
                    collector.scan_archive(source + f"/job/{job_id}/artifacts", body, "zip")

    if token:
        pending = sorted(group_ids)
        visited_groups: set[int] = set()
        while pending and collector.allowed():
            group_id = pending.pop(0)
            if group_id in visited_groups:
                continue
            visited_groups.add(group_id)
            source = f"group/{group_id}/variables"
            for variable in _pages(collector, get, f"/api/v4/groups/{group_id}/variables", source):
                variable_key = str(variable.get("key") or "")
                if not variable_key or "value" not in variable:
                    collector.partial(source, "variable_value_unavailable")
                    continue
                collector.add(
                    f"group/{group_id}/variable/{variable_key}", {variable_key: variable["value"]}, charge=False
                )
            group_body = collector.read(get, f"/api/v4/groups/{group_id}", f"group/{group_id}/details")
            if group_body is not None:
                try:
                    group_data = json.loads(group_body)
                except (ValueError, UnicodeError):
                    collector.partial(f"group/{group_id}/details", "invalid_json")
                    continue
                parent_id = group_data.get("parent_id") if isinstance(group_data, dict) else None
                if type(parent_id) is int and parent_id > 0 and parent_id not in visited_groups:
                    pending.append(parent_id)
        token_user = record.get("token_user")
        if isinstance(token_user, dict) and token_user.get("is_admin") is True:
            for variable in _pages(collector, get, "/api/v4/admin/ci/variables", "admin/ci/variables"):
                variable_key = str(variable.get("key") or "")
                if variable_key and "value" in variable:
                    collector.add(f"admin/ci/variable/{variable_key}", {variable_key: variable["value"]}, charge=False)


def _registry_json(collector: DiscoveryCollector, getter: Any, path: str, source: str) -> dict[str, Any] | None:
    body = collector.read(getter, path, source)
    if body is None:
        return None
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        collector.partial(source, "invalid_json")
        return None
    if not isinstance(data, dict):
        collector.partial(source, "invalid_object")
        return None
    return data


def _registry_catalog(collector: DiscoveryCollector, getter: Any) -> list[str]:
    repositories: list[str] = []
    seen: set[str] = set()
    last: str | None = None
    for _ in range(100):
        query = "?n=100" + ("&last=" + quote(last, safe="") if last else "")
        data = _registry_json(collector, getter, "/v2/_catalog" + query, "registry/catalog")
        if data is None:
            return repositories
        page = data.get("repositories")
        if not isinstance(page, list) or any(not isinstance(item, str) for item in page):
            collector.partial("registry/catalog", "invalid_repositories")
            return repositories
        new = [name for name in page if name not in seen]
        if page and not new:
            collector.partial("registry/catalog", "repeated_page")
            return repositories
        repositories.extend(new)
        seen.update(new)
        if len(page) < 100:
            return repositories
        last = page[-1]
    collector.partial("registry/catalog", "pagination_limit")
    return repositories


def _registry_tags(collector: DiscoveryCollector, getter: Any, repository: str) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    last: str | None = None
    encoded = quote(repository, safe="/")
    for _ in range(100):
        query = "?n=100" + ("&last=" + quote(last, safe="") if last else "")
        data = _registry_json(collector, getter, f"/v2/{encoded}/tags/list{query}", f"repository/{repository}/tags")
        if data is None:
            return tags
        page = data.get("tags") or []
        if not isinstance(page, list) or any(not isinstance(item, str) for item in page):
            collector.partial(f"repository/{repository}/tags", "invalid_tags")
            return tags
        new = [tag for tag in page if tag not in seen]
        if page and not new:
            collector.partial(f"repository/{repository}/tags", "repeated_page")
            return tags
        tags.extend(new)
        seen.update(new)
        if len(page) < 100:
            return tags
        last = page[-1]
    collector.partial(f"repository/{repository}/tags", "pagination_limit")
    return tags


def _harbor_repositories(collector: DiscoveryCollector, getter: Any) -> list[str]:
    repositories: list[str] = []
    for page in range(1, 101):
        path = f"/api/v2.0/projects?page_size=100&page={page}"
        projects = _json_page(collector, getter, path, "harbor/projects")
        if projects is None:
            return repositories
        for project in projects:
            name = str(project.get("name") or "")
            if not name:
                collector.partial("harbor/projects", "project_name_unavailable")
                continue
            for repo_page in range(1, 101):
                repo_path = f"/api/v2.0/projects/{quote(name, safe='')}/repositories?page_size=100&page={repo_page}"
                items = _json_page(collector, getter, repo_path, f"harbor/project/{name}/repositories")
                if items is None:
                    break
                for item in items:
                    repository = str(item.get("name") or "")
                    if repository and repository not in repositories:
                        repositories.append(repository)
                if len(items) < 100:
                    break
            else:
                collector.partial(f"harbor/project/{name}/repositories", "pagination_limit")
        if len(projects) < 100:
            return repositories
    collector.partial("harbor/projects", "pagination_limit")
    return repositories


def _scan_registry_blob(
    collector: DiscoveryCollector, getter: Any, repository: str, digest: str, source: str, media_type: str
) -> None:
    path = f"/v2/{quote(repository, safe='/')}/blobs/{quote(digest, safe=':')}"
    body = collector.read(getter, path, source, maximum=collector.remaining)
    if body is None:
        return
    if "tar" in media_type or (len(body) > 2 and body[:2] == b"\x1f\x8b"):
        collector.scan_archive(source, body, "tar")
    elif "zip" in media_type or body.startswith(b"PK\x03\x04"):
        collector.scan_archive(source, body, "zip")
    else:
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            try:
                value = body.decode("utf-8")
            except UnicodeDecodeError:
                collector.partial(source, "binary_or_non_utf8")
                return
        collector.add(source, value, charge=False)


def _scan_registry_manifest(
    collector: DiscoveryCollector,
    getter: Any,
    repository: str,
    reference: str,
    seen_blobs: set[tuple[str, str]],
    *,
    depth: int = 0,
) -> None:
    source = f"image/{repository}/{reference}"
    if depth > 4:
        collector.partial(source, "manifest_depth_limit")
        return
    path = f"/v2/{quote(repository, safe='/')}/manifests/{quote(reference, safe=':')}"
    manifest = _registry_json(collector, getter, path, source + "/manifest")
    if manifest is None:
        return
    collector.add(source + "/manifest", manifest, charge=False)
    children = manifest.get("manifests")
    if isinstance(children, list):
        for child in children:
            digest = str(child.get("digest") or "") if isinstance(child, dict) else ""
            if digest:
                _scan_registry_manifest(collector, getter, repository, digest, seen_blobs, depth=depth + 1)
            else:
                collector.partial(source, "invalid_child_manifest")
        return
    for category, descriptors in (
        ("config", [manifest.get("config")]),
        ("layer", manifest.get("layers") or []),
        ("artifact", manifest.get("blobs") or []),
    ):
        if not isinstance(descriptors, list):
            collector.partial(source, f"invalid_{category}_descriptors")
            continue
        for descriptor in descriptors:
            if not isinstance(descriptor, dict) or not descriptor.get("digest"):
                collector.partial(source, f"invalid_{category}_descriptor")
                continue
            digest = str(descriptor["digest"])
            if (repository, digest) in seen_blobs:
                continue
            seen_blobs.add((repository, digest))
            _scan_registry_blob(
                collector,
                getter,
                repository,
                digest,
                source + f"/{category}/{digest}",
                str(descriptor.get("mediaType") or ""),
            )


def _discover_nexus_assets(collector: DiscoveryCollector, getter: Any, ctx: Any) -> None:
    repositories = collector.read(getter, "/service/rest/v1/repositories", "nexus/repositories")
    if repositories is None:
        return
    try:
        items = json.loads(repositories)
    except (ValueError, UnicodeError):
        collector.partial("nexus/repositories", "invalid_json")
        return
    if not isinstance(items, list):
        collector.partial("nexus/repositories", "invalid_list")
        return
    selected_repo = str(getattr(ctx.args, "repository", "") or "")
    selected_asset = str(getattr(ctx.args, "asset", "") or "")
    matched_asset = False
    for item in items:
        if not isinstance(item, dict) or not item.get("name"):
            collector.partial("nexus/repositories", "invalid_repository")
            continue
        name = str(item["name"])
        if selected_repo and selected_repo != name:
            continue
        if not selected_asset:
            collector.add(f"nexus/repository/{name}/metadata", item, charge=False)
        continuation: str | None = None
        seen_tokens: set[str] = set()
        for _ in range(100):
            query = {"repository": name}
            if continuation:
                query["continuationToken"] = continuation
            path = "/service/rest/v1/components?" + urlencode(query)
            page = _registry_json(collector, getter, path, f"nexus/repository/{name}/components")
            if page is None:
                break
            components = page.get("items")
            if not isinstance(components, list):
                collector.partial(f"nexus/repository/{name}/components", "invalid_items")
                break
            for component in components:
                if not isinstance(component, dict):
                    collector.partial(f"nexus/repository/{name}/components", "invalid_component")
                    continue
                assets = component.get("assets") or []
                if not isinstance(assets, list):
                    collector.partial(f"nexus/repository/{name}/assets", "invalid_assets")
                    continue
                if selected_asset:
                    assets = [
                        asset
                        for asset in assets
                        if isinstance(asset, dict)
                        and selected_asset in {str(asset.get("path") or ""), str(asset.get("downloadUrl") or "")}
                    ]
                    if not assets:
                        continue
                collector.add(
                    f"nexus/repository/{name}/component/metadata",
                    {key: value for key, value in component.items() if key != "assets"},
                    charge=False,
                )
                for asset in assets:
                    if not isinstance(asset, dict):
                        collector.partial(f"nexus/repository/{name}/assets", "invalid_asset")
                        continue
                    asset_path = str(asset.get("path") or "")
                    url = str(asset.get("downloadUrl") or "")
                    if selected_asset and selected_asset not in {asset_path, url}:
                        continue
                    matched_asset = True
                    parsed = urlsplit(url)
                    if parsed.scheme not in {"", "http", "https"} or not parsed.path.startswith("/"):
                        collector.partial(f"nexus/repository/{name}/asset/{asset_path}", "download_url_unavailable")
                        continue
                    # Nexus may advertise its internal hostname behind a proxy.
                    # Route only the path through the already confirmed target;
                    # never follow the advertised host or send credentials there.
                    source = f"nexus/repository/{name}/asset/{asset_path.lstrip('/')}"
                    body = collector.read(
                        getter,
                        parsed.path + ("?" + parsed.query if parsed.query else ""),
                        source,
                        maximum=collector.remaining,
                    )
                    if body is None:
                        continue
                    if body.startswith(b"PK\x03\x04"):
                        collector.scan_archive(source, body, "zip")
                    elif body.startswith(b"\x1f\x8b") or asset_path.endswith((".tar", ".tar.gz", ".tgz")):
                        collector.scan_archive(source, body, "tar")
                    else:
                        collector.add(source, body.decode("utf-8", "replace"), charge=False)
            next_token = str(page.get("continuationToken") or "")
            if not next_token:
                break
            if next_token in seen_tokens:
                collector.partial(f"nexus/repository/{name}/components", "repeated_page")
                break
            seen_tokens.add(next_token)
            continuation = next_token
        else:
            collector.partial(f"nexus/repository/{name}/components", "pagination_limit")
    if selected_asset and not matched_asset:
        collector.partial("nexus/asset", "selector_not_found")


def discover_registry_sources(ctx: Any, record: Mapping[str, Any], collector: DiscoveryCollector, product: str) -> None:
    """Read accessible Nexus assets and OCI manifests/configs/layers."""
    from .modules.registry import actions

    timeout = float(getattr(ctx.args, "timeout", 5.0) or 5.0)
    anonymous = record.get("status") in {"open_no_auth", "invalid_credentials_anonymous"}
    credential = ctx.credential
    headers = actions._auth_headers(
        None if anonymous else credential.username,
        None if anonymous else credential.password,
        None if anonymous else credential.token,
    )

    def get(path: str, cap: int) -> tuple[int, bytes, dict[str, str], str | None]:
        request_headers = dict(headers)
        if "/manifests/" in path:
            request_headers["Accept"] = actions._REGISTRY_MANIFEST_ACCEPT
        return actions._http_request(
            str(ctx.host),
            int(ctx.port),
            "GET",
            path,
            timeout,
            headers=request_headers,
            response_size_cap=cap,
        )

    if product == "nexus" and record.get("is_nexus") is True:
        _discover_nexus_assets(collector, get, ctx)
        # Nexus' REST endpoint identifies itself as a registry product even when
        # its OCI connector is hosted on another port. A 404 /v2 probe proves
        # this address cannot serve OCI manifests or blobs.
        if record.get("probe_status") == 404:
            if getattr(ctx.args, "image", None) or getattr(ctx.args, "tag", None):
                collector.partial("nexus/oci", "OCI endpoint unavailable on this address")
            return
    if record.get("is_registry") is not True:
        return
    image = str(getattr(ctx.args, "image", "") or "")
    repository = str(getattr(ctx.args, "repository", "") or "")
    tag = str(getattr(ctx.args, "tag", "") or "")
    if image:
        parsed_repo, parsed_ref = actions._split_image_reference(image)
        targets = {parsed_repo: [parsed_ref]} if parsed_repo and parsed_ref else {}
        if not targets:
            collector.partial("registry/image", "invalid_image_selector")
    else:
        if repository:
            repositories = [repository]
        elif product == "harbor":
            repositories = _harbor_repositories(collector, get)
            if not repositories:
                repositories = _registry_catalog(collector, get)
        else:
            repositories = _registry_catalog(collector, get)
        targets = {repo: [tag] if tag else _registry_tags(collector, get, repo) for repo in repositories}
    seen_blobs: set[tuple[str, str]] = set()
    for repo, references in targets.items():
        for reference in references:
            if not collector.allowed():
                return
            _scan_registry_manifest(collector, get, repo, reference, seen_blobs)


def _portainer_discovery_view(value: Any, *, parent: str = "") -> Any:
    """Keep exposed configuration while omitting local paths and public CA data."""
    if isinstance(value, Mapping):
        excluded = {
            "GraphDriver",
            "HostnamePath",
            "HostsPath",
            "LogPath",
            "ResolvConfPath",
            "ShmPath",
        }
        return {
            key: _portainer_discovery_view(item, parent=str(key))
            for key, item in value.items()
            if key not in excluded and not (parent == "TLSInfo" and key == "TrustRoot")
        }
    if isinstance(value, list):
        return [_portainer_discovery_view(item, parent=parent) for item in value]
    return value


def discover_portainer_sources(
    ctx: Any, record: Mapping[str, Any], inventory: Mapping[str, Any], collector: DiscoveryCollector
) -> None:
    """Read visible stack files and selected Docker environment data via Portainer."""
    from . import web_panels
    from .clients.http_session import HttpSessionPool

    ui_value = record.get("ui")
    ui = ui_value if isinstance(ui_value, dict) else {}
    base = str(ui.get("endpoint") or "")
    if not base:
        collector.partial("portainer", "panel_endpoint_unavailable")
        return
    headers: dict[str, str] = {}
    if ui.get("session_token"):
        headers["Authorization"] = "Bearer " + str(ui["session_token"])
    if ui.get("session_api_key"):
        headers["X-API-Key"] = str(ui["session_api_key"])
    if ui.get("session_cookie"):
        headers["Cookie"] = str(ui["session_cookie"])
    timeout = float(getattr(ctx.args, "timeout", 5.0) or 5.0)
    with closing(
        HttpSessionPool(
            timeout=timeout,
            insecure=not bool(getattr(ctx.args, "secure", False)),
            proxy=getattr(ctx.args, "_proxy_config", None),
            retries=0,
        )
    ) as pool:

        def get(path: str, cap: int) -> tuple[int, bytes, dict[str, str], str | None]:
            response = web_panels._get(
                pool,
                base,
                path,
                headers=headers,
                response_size_cap=cap,
                timeout=min(timeout, max(0.1, collector.deadline - time.monotonic())),
            )
            response_headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
            if response.truncated:
                response_headers["x-redposture-truncated"] = "true"
            return response.status, response.body, response_headers, response.error

        def get_json(path: str, source: str) -> Any:
            body = collector.read(get, path, source)
            if body is None:
                return None
            try:
                return json.loads(body)
            except (ValueError, UnicodeError):
                collector.partial(source, "invalid_json")
                return None

        environments = inventory.get("environments")
        env_records = environments.get("records") if isinstance(environments, dict) else None
        if not isinstance(env_records, list):
            collector.partial("portainer/environments", "inventory_unavailable")
            return
        if not env_records:
            collector.partial("portainer/environments", "no_accessible_environments (access_denied_or_none)")
        for environment in env_records:
            if isinstance(environment, dict):
                collector.add(f"portainer/environment/{environment.get('Id')}/metadata", environment)

        stacks = get_json("/api/stacks", "portainer/stacks")
        if isinstance(stacks, list):
            for stack in stacks:
                if not isinstance(stack, dict) or type(stack.get("Id")) is not int:
                    collector.partial("portainer/stacks", "invalid_stack")
                    continue
                stack_id = stack["Id"]
                collector.add(f"portainer/stack/{stack_id}/metadata", stack, charge=False)
                stack_file = get_json(f"/api/stacks/{stack_id}/file", f"portainer/stack/{stack_id}/file")
                if isinstance(stack_file, dict) and isinstance(stack_file.get("StackFileContent"), str):
                    collector.add(f"portainer/stack/{stack_id}/file", stack_file["StackFileContent"], charge=False)
                elif stack_file is not None:
                    collector.partial(f"portainer/stack/{stack_id}/file", "file_content_unavailable")
        elif stacks is not None:
            collector.partial("portainer/stacks", "invalid_list")

        containers = inventory.get("containers")
        container_records = containers.get("records") if isinstance(containers, dict) else None
        if not isinstance(container_records, list) and env_records:
            collector.partial("portainer/containers", "inventory_unavailable")
            container_records = []
        elif not isinstance(container_records, list):
            container_records = []
        selected_ids = {
            int(item["Id"]) for item in env_records if isinstance(item, dict) and type(item.get("Id")) is int
        }
        for container in container_records:
            if not isinstance(container, dict):
                continue
            endpoint_id = container.get("environment")
            container_id = str(container.get("Id") or container.get("ID") or "")
            if type(endpoint_id) is not int or endpoint_id not in selected_ids or not container_id:
                collector.partial("portainer/containers", "container_identity_unavailable")
                continue
            source = f"portainer/environment/{endpoint_id}/container/{container_id}"
            data = get_json(
                f"/api/endpoints/{endpoint_id}/docker/containers/{quote(container_id, safe='')}/json", source
            )
            if isinstance(data, dict):
                collector.add(source, _portainer_discovery_view(data), charge=False)
            elif data is not None:
                collector.partial(source, "invalid_inspect")

        for endpoint_id in sorted(selected_ids):
            source = f"portainer/environment/{endpoint_id}"
            configs = get_json(f"/api/endpoints/{endpoint_id}/docker/configs", source + "/configs")
            if isinstance(configs, list):
                for config in configs:
                    if not isinstance(config, dict):
                        collector.partial(source + "/configs", "invalid_config")
                        continue
                    config_id = str(config.get("ID") or config.get("Id") or "")
                    if not config_id:
                        collector.partial(source + "/configs", "config_id_unavailable")
                        continue
                    detail = get_json(
                        f"/api/endpoints/{endpoint_id}/docker/configs/{quote(config_id, safe='')}",
                        source + f"/config/{config_id}",
                    )
                    if isinstance(detail, dict):
                        collector.add(source + f"/config/{config_id}/metadata", detail, charge=False)
                        spec = detail.get("Spec")
                        encoded = spec.get("Data") if isinstance(spec, dict) else None
                        if isinstance(encoded, str):
                            try:
                                decoded = base64.b64decode(encoded, validate=True)
                            except ValueError:
                                collector.partial(source + f"/config/{config_id}", "invalid_base64")
                            else:
                                if collector.charge(len(decoded)):
                                    collector.add(
                                        source + f"/config/{config_id}/value",
                                        decoded.decode("utf-8", "replace"),
                                        charge=False,
                                    )
                    elif detail is not None:
                        collector.partial(source + f"/config/{config_id}", "invalid_inspect")
            elif configs is not None:
                collector.partial(source + "/configs", "invalid_list")
            secrets = get_json(f"/api/endpoints/{endpoint_id}/docker/secrets", source + "/secrets")
            if isinstance(secrets, list) and secrets:
                collector.partial(source + "/secrets", "secret_values_not_exposed_by_api")
                for secret in secrets:
                    if isinstance(secret, dict):
                        collector.add(source + "/secret/metadata", secret, charge=False)
