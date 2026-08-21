"""GitLab audit stage."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ...clients.http_api import HttpApiClient, HttpClientConfig, build_http_target_url, format_http_authority
from ...console import Console
from ...rendering import CountColorRule, render_colored_marker_line, render_tagged_detail_line
from ...scheduler import BoundedScheduler
from ...stage_runtime import (
    StageTelemetryBuilder,
    format_retry_decision,
    merge_stage_records,
)
from ...utils import utc_now_iso

_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_CONNECTION_REFUSED_PREFIX = "connection refused"
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_GITLAB_DEEP_STATUSES = {"detected", "valid_credentials", "invalid_credentials"}
_PUBLIC_ENDPOINT_PATHS: tuple[str, ...] = (
    "/api/v4/version",
    "/-/health",
    "/-/readiness",
    "/-/liveness",
    "/help",
    "/explore/projects",
)
_DEFAULT_CLONE_DIR = "./gitlab_clones"
_MAX_PER_PAGE = 100
_MAX_PROJECT_PAGES = 100
_GIT_CLONE_TIMEOUT_SECONDS = 300


@dataclass
class GitLabLifecycleState:
    token_valid: bool | None = None
    token_user: dict[str, Any] | None = None
    token_error: str | None = None
    token_capability: str | None = None
    deep_record: dict[str, Any] | None = None


def _clip(text: str, width: int = 72) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _friendly_error_text(value: str) -> str:
    from ...utils import friendly_error_text

    return friendly_error_text(value)


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ...utils import friendly_error_from_exception

    return friendly_error_from_exception(exc)


def _is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    if str(record.get("status") or "") != "fail":
        return False
    error_text = str(record.get("error") or "").strip().lower()
    return bool(error_text) and (
        error_text.startswith(_CONNECTION_TIMEOUT_PREFIX) or error_text.startswith(_CONNECTION_REFUSED_PREFIX)
    )


def _normalize_path(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "/"
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def _build_base_url(host: str, port: int, use_https: bool) -> str:
    scheme = "https" if use_https else "http"
    return f"{scheme}://{format_http_authority(host, port)}"


def _http_request(
    host: str,
    port: int,
    method: str,
    path: str,
    timeout: float,
    *,
    use_https: bool,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, bytes, dict[str, str], str | None]:
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        url = build_http_target_url(
            host,
            port,
            _normalize_path(path),
            default_scheme="https" if use_https else "http",
        )
    request_headers = {"User-Agent": "RedPosture/1.0"}
    if headers:
        request_headers.update(headers)
    response = HttpApiClient(HttpClientConfig(timeout=timeout, response_size_cap=10 * 1024 * 1024)).request(
        method,
        url,
        headers=request_headers,
        body=body,
        timeout=timeout,
    )
    if response.error:
        return 0, b"", {}, _friendly_error_text(response.error)
    return int(response.status), response.body, {str(k).lower(): str(v) for k, v in response.headers.items()}, None


def _json_loads_bytes(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", errors="replace"))


def _gitlab_api_headers(token: str | None) -> dict[str, str]:
    if not token:
        return {}
    return {"PRIVATE-TOKEN": token}


def _looks_like_gitlab_user(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    user_id = payload.get("id")
    username = payload.get("username")
    return (
        isinstance(user_id, int)
        and not isinstance(user_id, bool)
        and isinstance(username, str)
        and bool(username.strip())
    )


def _api_get_json(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    use_https: bool,
    token: str | None = None,
) -> tuple[int, Any, dict[str, str], str | None]:
    status, payload, headers, error = _http_request(
        host,
        port,
        "GET",
        path,
        timeout,
        use_https=use_https,
        headers=_gitlab_api_headers(token),
    )
    if error:
        return status, None, headers, error
    if not payload:
        return status, None, headers, None
    try:
        return status, _json_loads_bytes(payload), headers, None
    except json.JSONDecodeError:
        return status, None, headers, None


def _detect_login_page(body: str) -> bool:
    text = body.lower()
    return "gitlab" in text and ("sign in" in text or "users/sign_in" in text)


def _normalize_project_filters(values: list[str] | None) -> list[str]:
    if not values:
        return []
    items: list[str] = []
    seen: set[str] = set()
    for raw in values:
        for part in str(raw).split(","):
            token = part.strip()
            if not token:
                continue
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            items.append(token)
    return items


def _project_path(project: dict[str, Any]) -> str:
    value = str(project.get("path_with_namespace") or project.get("path") or project.get("name") or "-").strip()
    return value or "-"


def _project_matches_filters(project: dict[str, Any], filters: list[str]) -> bool:
    if not filters:
        return True
    path_value = _project_path(project).lower()
    id_value = str(project.get("id") or "").strip()
    for item in filters:
        clean = item.strip()
        if not clean:
            continue
        if path_value == clean.lower():
            return True
        if id_value and id_value == clean:
            return True
    return False


def _extract_access_level(project: dict[str, Any]) -> int | None:
    permissions = project.get("permissions")
    if not isinstance(permissions, dict):
        return None
    levels: list[int] = []
    for key in ("project_access", "group_access"):
        section = permissions.get(key)
        if not isinstance(section, dict):
            continue
        raw_level = section.get("access_level")
        if isinstance(raw_level, int):
            levels.append(raw_level)
        elif isinstance(raw_level, str) and raw_level.isdigit():
            levels.append(int(raw_level))
    if not levels:
        return None
    return max(levels)


def _status_to_access_flag(status: int) -> bool | None:
    if status == 200:
        return True
    if status in {401, 403, 404}:
        return False
    return None


def _probe_project_capabilities(
    host: str,
    port: int,
    timeout: float,
    *,
    use_https: bool,
    token: str,
    project: dict[str, Any],
) -> dict[str, Any]:
    project_id = project.get("id")
    project_path = _project_path(project)
    project_id_text = str(project_id) if project_id is not None else ""
    encoded_project_id = urllib.parse.quote(project_id_text, safe="") if project_id_text else ""

    repo_read: bool | None = None
    issues_read: bool | None = None
    members_read: bool | None = None
    repo_error: str | None = None
    issues_error: str | None = None
    members_error: str | None = None

    if encoded_project_id:
        repo_status, _repo_json, _repo_headers, repo_error = _api_get_json(
            host,
            port,
            f"/api/v4/projects/{encoded_project_id}/repository/tree?per_page=1",
            timeout,
            use_https=use_https,
            token=token,
        )
        repo_read = _status_to_access_flag(repo_status) if repo_error is None else None

        issues_status, _issues_json, _issues_headers, issues_error = _api_get_json(
            host,
            port,
            f"/api/v4/projects/{encoded_project_id}/issues?per_page=1",
            timeout,
            use_https=use_https,
            token=token,
        )
        issues_read = _status_to_access_flag(issues_status) if issues_error is None else None

        members_status, _members_json, _members_headers, members_error = _api_get_json(
            host,
            port,
            f"/api/v4/projects/{encoded_project_id}/members/all?per_page=1",
            timeout,
            use_https=use_https,
            token=token,
        )
        members_read = _status_to_access_flag(members_status) if members_error is None else None

    return {
        "id": project_id,
        "path_with_namespace": project_path,
        "visibility": project.get("visibility"),
        "access_level": _extract_access_level(project),
        "repo_read": repo_read,
        "issues_read": issues_read if bool(project.get("issues_enabled", True)) else False,
        "members_read": members_read,
        "merge_requests_enabled": bool(project.get("merge_requests_enabled", False)),
        "issues_enabled": bool(project.get("issues_enabled", False)),
        "wiki_enabled": bool(project.get("wiki_enabled", False)),
        "snippets_enabled": bool(project.get("snippets_enabled", False)),
        "http_url_to_repo": project.get("http_url_to_repo"),
        "web_url": project.get("web_url"),
        "repo_error": repo_error,
        "issues_error": issues_error,
        "members_error": members_error,
    }


def _paginate_projects(
    host: str,
    port: int,
    timeout: float,
    *,
    use_https: bool,
    token: str | None,
    public_only: bool,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    page = 1
    projects: list[dict[str, Any]] = []
    visited_pages: set[int] = set()
    while len(visited_pages) < _MAX_PROJECT_PAGES:
        if page in visited_pages:
            return projects, "partial: GitLab pagination loop detected"
        visited_pages.add(page)
        query: list[tuple[str, str]] = [
            ("per_page", str(_MAX_PER_PAGE)),
            ("page", str(page)),
            ("simple", "true"),
            ("order_by", "id"),
            ("sort", "asc"),
        ]
        if public_only:
            query.append(("visibility", "public"))
        path = "/api/v4/projects?" + urllib.parse.urlencode(query)
        status, payload, headers, error = _api_get_json(
            host,
            port,
            path,
            timeout,
            use_https=use_https,
            token=token,
        )
        if error:
            return (projects if projects else None), f"partial: {error}" if projects else error
        if status == 401 or status == 403:
            message = "authentication required"
            return (projects if projects else None), f"partial: {message}" if projects else message
        if status == 404:
            message = "GitLab API v4 not available"
            return (projects if projects else None), f"partial: {message}" if projects else message
        if status != 200:
            message = f"unexpected API status={status}"
            return (projects if projects else None), f"partial: {message}" if projects else message
        if not isinstance(payload, list):
            message = "unexpected API payload"
            return (projects if projects else None), f"partial: {message}" if projects else message

        page_items: list[dict[str, Any]] = [item for item in payload if isinstance(item, dict)]
        projects.extend(page_items)

        next_page = str(headers.get("x-next-page") or "").strip()
        if next_page.isdigit() and int(next_page) > page:
            page = int(next_page)
            continue
        if len(page_items) >= _MAX_PER_PAGE:
            page += 1
            continue
        return projects, None
    return projects, "partial: GitLab pagination limit exceeded"


def _fetch_project_by_ref(
    host: str,
    port: int,
    timeout: float,
    *,
    use_https: bool,
    token: str | None,
    project_ref: str,
) -> tuple[dict[str, Any] | None, str | None]:
    ref = str(project_ref or "").strip()
    if not ref:
        return None, "empty project ref"
    if ref.isdigit():
        encoded = ref
    else:
        encoded = urllib.parse.quote(ref, safe="")
    status, payload, _headers, error = _api_get_json(
        host,
        port,
        f"/api/v4/projects/{encoded}",
        timeout,
        use_https=use_https,
        token=token,
    )
    if error:
        return None, error
    if status == 404:
        return None, "project not found"
    if status in {401, 403}:
        return None, "access denied"
    if status != 200 or not isinstance(payload, dict):
        return None, f"unexpected project lookup status={status}"
    return payload, None


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value))
    slug = slug.strip("._-")
    return slug or "item"


def _safe_repo_relative_path(path_with_namespace: str) -> str:
    raw = str(path_with_namespace or "").replace("\\", "/")
    segments: list[str] = []
    for token in raw.split("/"):
        clean = token.strip()
        if not clean or clean in {".", ".."}:
            continue
        segments.append(_safe_slug(clean))
    if not segments:
        segments.append(_safe_slug(path_with_namespace))
    return os.path.join(*segments)


def _clone_url_with_token(clone_url: str, token: str | None) -> str:
    if not token:
        return clone_url
    parsed = urllib.parse.urlsplit(clone_url)
    if parsed.scheme not in {"http", "https"}:
        return clone_url
    hostport = parsed.netloc.rsplit("@", 1)[-1]
    userinfo = "oauth2:" + urllib.parse.quote(token, safe="")
    new_netloc = f"{userinfo}@{hostport}"
    return urllib.parse.urlunsplit((parsed.scheme, new_netloc, parsed.path, parsed.query, parsed.fragment))


def _probe_repository_token(
    host: str,
    port: int,
    *,
    use_https: bool,
    token: str,
    project_ref: str,
) -> tuple[bool | None, str | None]:
    """Check a read_repository-only token without cloning repository data."""

    project_path = str(project_ref or "").strip().strip("/")
    if not project_path or project_path.isdigit():
        return None, "repository path is required to validate a repository-scoped token"
    git_path = shutil.which("git")
    if not git_path:
        return None, "git binary not found in PATH"
    clone_url = build_http_target_url(
        host,
        port,
        f"/{project_path}.git",
        default_scheme="https" if use_https else "http",
    )
    authenticated_url = _clone_url_with_token(clone_url, token)
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        completed = subprocess.run(
            [git_path, "ls-remote", authenticated_url, "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=min(_GIT_CLONE_TIMEOUT_SECONDS, 30),
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None, "git repository capability probe timed out"
    except OSError as exc:
        return None, f"git repository capability probe failed: {exc}"
    if completed.returncode == 0:
        return True, None
    return False, _clip((completed.stderr or completed.stdout or "repository access denied").strip(), 160)


def _clone_project(
    project: dict[str, Any],
    host: str,
    port: int,
    *,
    use_https: bool,
    token: str | None,
    clone_dir: str,
) -> dict[str, Any]:
    path_with_namespace = _project_path(project)
    project_id = project.get("id")
    http_url = str(project.get("http_url_to_repo") or "").strip()
    if http_url and "://" in http_url:
        try:
            parsed = urllib.parse.urlsplit(http_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                http_url = ""
        except ValueError:
            http_url = ""
    if not http_url or "://" not in http_url:
        http_url = build_http_target_url(
            host,
            port,
            f"/{path_with_namespace}.git",
            default_scheme="https" if use_https else "http",
        )

    final_url = _clone_url_with_token(http_url, token)
    dest_root = os.path.join(clone_dir, _safe_slug(f"{host}_{port}"))
    dest_root_abs = os.path.abspath(dest_root)
    relative_repo_path = _safe_repo_relative_path(path_with_namespace)
    candidate_dest_path = os.path.abspath(os.path.normpath(os.path.join(dest_root_abs, relative_repo_path)))
    try:
        in_root = os.path.commonpath([dest_root_abs, candidate_dest_path]) == dest_root_abs
    except ValueError:
        in_root = False
    dest_path = candidate_dest_path if in_root else os.path.join(dest_root_abs, _safe_slug(path_with_namespace))
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    if os.path.isdir(os.path.join(dest_path, ".git")):
        return {
            "project": path_with_namespace,
            "project_id": project_id,
            "status": "exists",
            "dest": dest_path,
            "error": None,
        }
    if os.path.exists(dest_path):
        return {
            "project": path_with_namespace,
            "project_id": project_id,
            "status": "failed",
            "dest": dest_path,
            "error": "destination exists but is not a complete git repository",
        }

    git_path = shutil.which("git")
    if not git_path:
        return {
            "project": path_with_namespace,
            "project_id": project_id,
            "status": "failed",
            "dest": dest_path,
            "error": "git binary not found in PATH",
        }

    temporary_path = f"{dest_path}.redposture-{uuid.uuid4().hex}.tmp"
    command = [git_path, "clone", "--depth", "1", final_url, temporary_path]

    def _run_clone(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_CLONE_TIMEOUT_SECONDS,
        )

    try:
        completed = _run_clone(command)
    except subprocess.TimeoutExpired:
        shutil.rmtree(temporary_path, ignore_errors=True)
        return {
            "project": path_with_namespace,
            "project_id": project_id,
            "status": "failed",
            "dest": dest_path,
            "error": "git clone timeout",
        }
    except OSError as exc:
        shutil.rmtree(temporary_path, ignore_errors=True)
        return {
            "project": path_with_namespace,
            "project_id": project_id,
            "status": "failed",
            "dest": dest_path,
            "error": f"git clone failed: {exc}",
        }

    stderr = (completed.stderr or "").strip()
    stdout = (completed.stdout or "").strip()
    shallow_unsupported = (
        completed.returncode != 0
        and "dumb http transport does not support shallow capabilities" in (stderr or stdout).lower()
    )
    if shallow_unsupported:
        shutil.rmtree(temporary_path, ignore_errors=True)
        fallback_command = [git_path, "clone", final_url, temporary_path]
        try:
            completed = _run_clone(fallback_command)
        except subprocess.TimeoutExpired:
            shutil.rmtree(temporary_path, ignore_errors=True)
            return {
                "project": path_with_namespace,
                "project_id": project_id,
                "status": "failed",
                "dest": dest_path,
                "error": "git clone timeout",
            }
        except OSError as exc:
            shutil.rmtree(temporary_path, ignore_errors=True)
            return {
                "project": path_with_namespace,
                "project_id": project_id,
                "status": "failed",
                "dest": dest_path,
                "error": f"git clone failed: {exc}",
            }
        stderr = (completed.stderr or "").strip()
        stdout = (completed.stdout or "").strip()

    if completed.returncode == 0:
        try:
            os.replace(temporary_path, dest_path)
        except OSError as exc:
            shutil.rmtree(temporary_path, ignore_errors=True)
            return {
                "project": path_with_namespace,
                "project_id": project_id,
                "status": "failed",
                "dest": dest_path,
                "error": f"failed to publish cloned repository: {exc}",
            }
        return {
            "project": path_with_namespace,
            "project_id": project_id,
            "status": "cloned",
            "dest": dest_path,
            "error": None,
        }

    error = stderr or stdout or f"git clone exit={completed.returncode}"
    shutil.rmtree(temporary_path, ignore_errors=True)
    return {
        "project": path_with_namespace,
        "project_id": project_id,
        "status": "failed",
        "dest": dest_path,
        "error": _clip(error, 160),
    }


def _audit_gitlab_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    use_https: bool,
    token: str | None,
    project_filters: list[str],
    clone: bool,
    clone_dir: str,
    workers: int,
    run_deep_checks: bool = True,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    token_provided = bool(token)

    for attempt in range(attempts):
        started = time.monotonic()
        login_page: bool | None = None
        version: str | None = None
        open_endpoints: list[dict[str, Any]] = []
        public_projects: list[dict[str, Any]] = []
        public_projects_error: str | None = None
        token_valid: bool | None = None
        token_user: dict[str, Any] | None = None
        token_projects: list[dict[str, Any]] = []
        token_projects_error: str | None = None
        token_access: list[dict[str, Any]] = []
        clone_results: list[dict[str, Any]] = []
        clone_scope: str | None = None

        try:
            login_status, login_payload, _login_headers, login_error = _http_request(
                host, port, "GET", "/users/sign_in", timeout, use_https=use_https
            )
            if login_error:
                raise ValueError(login_error)
            login_body = login_payload.decode("utf-8", errors="replace")
            login_page = login_status == 200 and _detect_login_page(login_body)

            version_status, version_payload, _version_headers, version_error = _http_request(
                host, port, "GET", "/api/v4/version", timeout, use_https=use_https
            )
            if version_error:
                version = None
            else:
                if version_status == 200:
                    try:
                        version_json = _json_loads_bytes(version_payload)
                    except json.JSONDecodeError:
                        version_json = None
                    if isinstance(version_json, dict):
                        raw_version = str(version_json.get("version") or "").strip()
                        version = raw_version or None
                if (not token_provided) and version_status < 400:
                    open_endpoints.append({"path": "/api/v4/version", "status": version_status})

            if not token_provided:
                for path in _PUBLIC_ENDPOINT_PATHS[1:]:
                    status, _payload, _headers, error = _http_request(
                        host, port, "GET", path, timeout, use_https=use_https
                    )
                    if error:
                        continue
                    if status < 400:
                        open_endpoints.append({"path": path, "status": status})

            projects_all, public_projects_error = _paginate_projects(
                host,
                port,
                timeout,
                use_https=use_https,
                token=None,
                public_only=True,
            )
            if isinstance(projects_all, list):
                public_projects = [item for item in projects_all if _project_matches_filters(item, project_filters)]
                if not token_provided:
                    open_endpoints.append({"path": "/api/v4/projects?visibility=public", "status": 200})
            elif public_projects_error == "authentication required":
                pass

            is_gitlab = bool(login_page) or bool(version) or isinstance(projects_all, list)

            if token_provided:
                user_status, user_payload, _user_headers, user_error = _api_get_json(
                    host,
                    port,
                    "/api/v4/user",
                    timeout,
                    use_https=use_https,
                    token=token,
                )
                if user_error:
                    token_valid = False
                    token_projects_error = user_error
                elif user_status == 200 and _looks_like_gitlab_user(user_payload):
                    token_valid = True
                    token_user = user_payload
                elif user_status in {401, 403}:
                    token_valid = False
                    token_projects_error = "invalid token or insufficient API access"
                else:
                    token_valid = False
                    token_projects_error = f"unexpected /api/v4/user status={user_status}"

                if token_valid and run_deep_checks:
                    token_projects_all, token_projects_error = _paginate_projects(
                        host,
                        port,
                        timeout,
                        use_https=use_https,
                        token=token,
                        public_only=False,
                    )
                    if isinstance(token_projects_all, list):
                        token_projects = [
                            item for item in token_projects_all if _project_matches_filters(item, project_filters)
                        ]
                        scheduler = BoundedScheduler[dict[str, Any], dict[str, Any]](
                            max_workers=max(1, min(workers, 20)),
                            max_inflight=max(1, min(workers, 20)) * 4,
                        )

                        def _probe_project(project: dict[str, Any]) -> dict[str, Any]:
                            return _probe_project_capabilities(
                                host,
                                port,
                                timeout,
                                use_https=use_https,
                                token=token or "",
                                project=project,
                            )

                        for _project, access_record in scheduler.iter_completed(token_projects, _probe_project):
                            token_access.append(access_record)
                        token_access.sort(key=lambda item: str(item.get("path_with_namespace") or ""))

            clone_candidates: list[dict[str, Any]] = []
            if clone and run_deep_checks:
                if token_valid:
                    clone_scope = "token"
                    clone_candidates = token_projects
                else:
                    clone_scope = "public"
                    clone_candidates = public_projects

                if project_filters and not clone_candidates:
                    for ref in project_filters:
                        fetched, fetch_error = _fetch_project_by_ref(
                            host,
                            port,
                            timeout,
                            use_https=use_https,
                            token=token if token_valid else None,
                            project_ref=ref,
                        )
                        if fetched is not None and _project_matches_filters(fetched, project_filters):
                            clone_candidates.append(fetched)
                            continue
                        clone_results.append(
                            {
                                "project": ref,
                                "project_id": None,
                                "status": "failed",
                                "dest": None,
                                "error": fetch_error or "project lookup failed",
                            }
                        )

                seen_clone_ids: set[str] = set()
                deduped_candidates: list[dict[str, Any]] = []
                for item in clone_candidates:
                    clone_key = str(item.get("id") or _project_path(item))
                    if clone_key in seen_clone_ids:
                        continue
                    seen_clone_ids.add(clone_key)
                    deduped_candidates.append(item)
                clone_candidates = deduped_candidates

                for project in sorted(clone_candidates, key=lambda item: _project_path(item)):
                    clone_results.append(
                        _clone_project(
                            project,
                            host,
                            port,
                            use_https=use_https,
                            token=token if token_valid else None,
                            clone_dir=clone_dir,
                        )
                    )

            # E2E-batch fix: previously the status was always `detected` when
            # the target looked like a GitLab instance, regardless of whether
            # the supplied token was valid. Operators couldn't distinguish
            # "we tried the token and it worked" from "we tried the token and
            # it was rejected" without parsing the token_valid / token_user
            # fields by hand. Reflect the token verdict in the status:
            #   - token_valid=True  → `valid_credentials`
            #   - token provided but token_valid=False → `invalid_credentials`
            #   - otherwise the instance is up but we didn't authenticate → `detected`
            if is_gitlab:
                if token_valid is True:
                    computed_status = "valid_credentials"
                elif token_provided and token_valid is False:
                    computed_status = "invalid_credentials"
                else:
                    computed_status = "detected"
            else:
                computed_status = "not_gitlab"
            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "https": use_https,
                "is_gitlab": is_gitlab,
                "status": computed_status,
                "login_page": login_page,
                "version": version,
                "open_endpoints": open_endpoints,
                "public_projects": public_projects,
                "public_projects_error": public_projects_error,
                "project_filters": list(project_filters),
                "token_provided": token_provided,
                "token_valid": token_valid,
                "token_user": token_user,
                "token_projects": token_projects,
                "token_projects_error": token_projects_error,
                "token_access": token_access,
                "clone_requested": bool(clone),
                "clone_scope": clone_scope,
                "clone_dir": clone_dir if clone else None,
                "clone_results": clone_results,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": None,
            }
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "https": use_https,
        "is_gitlab": False,
        "status": "fail",
        "login_page": None,
        "version": None,
        "open_endpoints": [],
        "public_projects": [],
        "public_projects_error": None,
        "project_filters": list(project_filters),
        "token_provided": token_provided,
        "token_valid": None,
        "token_user": None,
        "token_projects": [],
        "token_projects_error": None,
        "token_access": [],
        "clone_requested": bool(clone),
        "clone_scope": None,
        "clone_dir": clone_dir if clone else None,
        "clone_results": [],
        "elapsed_ms": None,
        "error": _friendly_error_text(last_error or "connection failed"),
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'GITLAB':<8}\t{host}\t{port}\t"


def _bool_text(value: bool | None) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    return "unknown"


def _format_gitlab_text(value: Any) -> str:
    return str(value if value is not None else "").replace("\n", "\\n")


def _gitlab_access_level_name(value: int | None) -> str:
    if value is None:
        return "-"
    names = {
        0: "no_access",
        5: "minimal_access",
        10: "guest",
        15: "planner",
        20: "reporter",
        30: "developer",
        40: "maintainer",
        50: "owner",
    }
    return names.get(value, str(value))


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        payload = dict(record)
        if payload.get("token_provided"):
            payload["token_provided"] = True
        return json.dumps(payload, ensure_ascii=False)

    prefix = _nxc_prefix(record)
    status = str(record.get("status") or "fail")
    if status == "fail":
        err = _clip(str(record.get("error") or "connection failed"), 96)
        return f"{prefix} [!] connection failed err={err}"

    if status == "not_gitlab":
        return f"{prefix} [-] not a GitLab service"

    login_page_text = _bool_text(record.get("login_page"))
    version_text = str(record.get("version") or "-")
    return f"{prefix} [*] GitLab Service (login page:{login_page_text}) (version:{version_text})"


def _project_summary_line(project: dict[str, Any]) -> str:
    path = _project_path(project)
    visibility = str(project.get("visibility") or "-")
    archived = "True" if bool(project.get("archived")) else "False"
    return f"{path} (visibility:{visibility}) (archived:{archived})"


def _token_access_summary_line(item: dict[str, Any]) -> str:
    path = str(item.get("path_with_namespace") or "-")
    access_level = item.get("access_level")
    access_text = _gitlab_access_level_name(access_level if isinstance(access_level, int) else None)
    repo_text = _bool_text(item.get("repo_read"))
    issues_text = _bool_text(item.get("issues_read"))
    members_text = _bool_text(item.get("members_read"))
    mr_text = "True" if bool(item.get("merge_requests_enabled")) else "False"
    wiki_text = "True" if bool(item.get("wiki_enabled")) else "False"
    snippets_text = "True" if bool(item.get("snippets_enabled")) else "False"
    return (
        f"{path} (access:{access_text}) (repo:{repo_text}) (issues:{issues_text}) "
        f"(members:{members_text}) (mr:{mr_text}) (wiki:{wiki_text}) (snippets:{snippets_text})"
    )


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format == "json":
        return []

    # E2E fix: the summary detail block now also renders for valid/invalid
    # credentials — before, only `detected` records reached the summary lines,
    # so token-auth outcomes were rendered without their access breakdown.
    if str(record.get("status") or "fail") not in {"detected", "valid_credentials", "invalid_credentials"}:
        return []

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    project_filters = record.get("project_filters")
    targeted_mode = bool(record.get("clone_requested")) or (isinstance(project_filters, list) and bool(project_filters))
    normalized_filters = [
        str(item).strip()
        for item in (project_filters if isinstance(project_filters, list) else [])
        if str(item).strip()
    ]

    open_endpoints = record.get("open_endpoints")
    if not targeted_mode and isinstance(open_endpoints, list) and open_endpoints:
        lines.append(f"{prefix} [*] Open Endpoints")
        for item in sorted(
            (entry for entry in open_endpoints if isinstance(entry, dict)),
            key=lambda entry: str(entry.get("path") or ""),
        ):
            path = str(item.get("path") or "-")
            status = str(item.get("status") or "-")
            lines.append(f"{prefix} {path} status={status}")

    public_projects = record.get("public_projects")
    if isinstance(public_projects, list):
        if normalized_filters:
            lines.append(f"{prefix} [*] Project Filter ({len(normalized_filters)}): {','.join(normalized_filters)}")
            lines.append(f"{prefix} [+] public access (projects:{len(public_projects)},filtered:True)")
        else:
            lines.append(f"{prefix} [+] public access (projects:{len(public_projects)})")
        if public_projects:
            if normalized_filters:
                lines.append(f"{prefix} [*] Public Projects (filtered)")
            else:
                lines.append(f"{prefix} [*] Public Projects")
            for project in sorted(
                (item for item in public_projects if isinstance(item, dict)),
                key=lambda item: _project_path(item),
            ):
                lines.append(f"{prefix} {_project_summary_line(project)}")
        else:
            public_projects_error = str(record.get("public_projects_error") or "").strip()
            if public_projects_error:
                lines.append(f"{prefix} [-] public projects unavailable: {_clip(public_projects_error, 96)}")

    token_provided = bool(record.get("token_provided"))
    if token_provided:
        token_valid = record.get("token_valid")
        if token_valid is True:
            token_user = record.get("token_user")
            if isinstance(token_user, dict):
                username = str(token_user.get("username") or token_user.get("name") or "-")
                user_id = str(token_user.get("id") or "-")
                lines.append(f"{prefix} [+] token valid user={username} id={user_id}")
            else:
                lines.append(f"{prefix} [+] token valid")

            token_access = record.get("token_access")
            if not targeted_mode and isinstance(token_access, list):
                lines.append(f"{prefix} [*] Token Project Access")
                for item in sorted(
                    (entry for entry in token_access if isinstance(entry, dict)),
                    key=lambda entry: str(entry.get("path_with_namespace") or ""),
                ):
                    lines.append(f"{prefix} {_token_access_summary_line(item)}")
        elif token_valid is False:
            err = _clip(str(record.get("token_projects_error") or "invalid token"), 96)
            lines.append(f"{prefix} [-] token invalid err={err}")

    if bool(record.get("clone_requested")):
        clone_scope = str(record.get("clone_scope") or "none")
        clone_results = record.get("clone_results")
        lines.append(f"{prefix} [*] Clone Projects (scope:{clone_scope})")
        if isinstance(clone_results, list) and clone_results:
            for item in clone_results:
                if not isinstance(item, dict):
                    continue
                project_name = str(item.get("project") or "-")
                dest = str(item.get("dest") or "-")
                status = str(item.get("status") or "failed")
                error = str(item.get("error") or "").strip()
                if status == "cloned":
                    lines.append(f"{prefix} [+] {project_name} -> {dest}")
                elif status == "exists":
                    lines.append(f"{prefix} [*] {project_name} already exists -> {dest}")
                else:
                    body = f"{project_name}"
                    if error:
                        body += f" err={_clip(error, 96)}"
                    lines.append(f"{prefix} [-] clone failed {body}")
        else:
            lines.append(f"{prefix} <no clone targets>")

    return lines


def _render_colored_gitlab_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag="GITLAB",
        include_auth_required=False,
        literals=(
            ("(login page:True)", "bright_green"),
            ("(login page:False)", "yellow"),
            ("(repo:True)", "red"),
            ("(issues:True)", "red"),
            ("(members:True)", "red"),
        ),
        counts=(CountColorRule("projects", "red"),),
    ):
        return True
    if line.startswith("GITLAB") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="GITLAB", default_color="orange")
    return False


def _call_audit_gitlab_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    use_https: bool,
    token: str | None,
    project_filters: list[str],
    clone: bool,
    clone_dir: str,
    workers: int,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    call_kwargs: dict[str, Any] = {
        "use_https": use_https,
        "token": token,
        "project_filters": project_filters if run_deep_checks else [],
        "clone": clone if run_deep_checks else False,
        "clone_dir": clone_dir,
        "workers": workers,
    }
    try:
        record = _audit_gitlab_host(
            host,
            port,
            timeout,
            retries,
            run_deep_checks=run_deep_checks,
            **call_kwargs,
        )
    except TypeError as exc:
        # Keep monkeypatched test doubles compatible when they don't accept new optional kwargs.
        if "run_deep_checks" not in str(exc):
            raise
        record = _audit_gitlab_host(
            host,
            port,
            timeout,
            retries,
            **call_kwargs,
        )
    result: dict[str, Any] = dict(record)
    attempts = max(1, retries + 1)
    status = str(result.get("status") or "fail")
    is_gitlab = bool(result.get("is_gitlab"))
    elapsed_ms = int((time.monotonic() - started) * 1000)
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)
    if attempts > 1 and status == "fail":
        telemetry.debug(format_retry_decision(_STAGE_DETECT_PROTOCOL, 1, attempts, _retry_delay(0), "error"))

    detect_result = "ok" if is_gitlab else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = "ok" if is_gitlab else detect_result
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _GITLAB_DEEP_STATUSES:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_result = "error" if status == "fail" and result.get("error") else "ok"
        telemetry.stage(
            _STAGE_DATA,
            data_result,
            str(result.get("error") or "") if data_result == "error" else None,
            elapsed_ms,
        )
    else:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
        telemetry.stage(_STAGE_DATA, "skip", "deep checks disabled", 0)

    stage_durations_ms = {
        str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in telemetry.stages
    }
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={stage_durations_ms.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={stage_durations_ms.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={stage_durations_ms.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={stage_durations_ms.get(_STAGE_DATA, 0)} total_ms={elapsed_ms}"
    )
    return telemetry.attach(result, status=status, total_ms=elapsed_ms)


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


def detect_gitlab(ctx: Any, options: dict[str, Any]) -> dict[str, Any]:
    attempts = max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1)
    target_scheme = str(ctx.target.scheme or "").lower() if ctx.target is not None else ""
    use_https = (
        target_scheme == "https" if target_scheme in {"http", "https"} else bool(getattr(ctx.args, "https", False))
    )
    last_error: str | None = None
    for attempt in range(attempts):
        started = time.monotonic()
        login_status, login_payload, _login_headers, login_error = _http_request(
            str(ctx.host),
            int(ctx.port),
            "GET",
            "/users/sign_in",
            float(getattr(ctx.args, "timeout", 5.0)),
            use_https=use_https,
        )
        version_status, version_payload, _version_headers, version_error = _http_request(
            str(ctx.host),
            int(ctx.port),
            "GET",
            "/api/v4/version",
            float(getattr(ctx.args, "timeout", 5.0)),
            use_https=use_https,
        )
        login_page = (
            login_error is None
            and login_status == 200
            and _detect_login_page(login_payload.decode("utf-8", errors="replace"))
        )
        version: str | None = None
        if version_error is None and version_status == 200:
            try:
                payload = _json_loads_bytes(version_payload)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                version = str(payload.get("version") or "").strip() or None
        if login_page or version is not None:
            return {
                "timestamp": utc_now_iso(),
                "host": str(ctx.host),
                "port": int(ctx.port),
                "https": use_https,
                "is_gitlab": True,
                "status": "detected",
                "login_page": login_page,
                "version": version,
                "open_endpoints": [],
                "public_projects": [],
                "public_projects_error": None,
                "project_filters": list(options["project_filters"]),
                "token_provided": False,
                "token_valid": None,
                "token_user": None,
                "token_projects": [],
                "token_projects_error": None,
                "token_access": [],
                "clone_requested": bool(options["clone"]),
                "clone_scope": None,
                "clone_dir": options["clone_dir"] if options["clone"] else None,
                "clone_results": [],
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": None,
            }
        last_error = login_error or version_error
        if last_error is None:
            return {
                "timestamp": utc_now_iso(),
                "host": str(ctx.host),
                "port": int(ctx.port),
                "https": use_https,
                "is_gitlab": False,
                "status": "not_gitlab",
                "login_page": False,
                "version": None,
                "error": None,
            }
        if attempt < attempts - 1:
            time.sleep(_retry_delay(attempt))
    return {
        "timestamp": utc_now_iso(),
        "host": str(ctx.host),
        "port": int(ctx.port),
        "https": use_https,
        "is_gitlab": False,
        "status": "fail",
        "login_page": None,
        "version": None,
        "error": _friendly_error_text(last_error or "connection failed"),
    }


def authenticate_gitlab(ctx: Any, detect_record: Any, options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, GitLabLifecycleState):
        raise TypeError("gitlab lifecycle state is unavailable")
    record = dict(detect_record.to_dict() if hasattr(detect_record, "to_dict") else detect_record)
    token = str(ctx.credential.token or "").strip()
    if not token:
        return record
    status, payload, _headers, error = _api_get_json(
        str(ctx.host),
        int(ctx.port),
        "/api/v4/user",
        float(getattr(ctx.args, "timeout", 5.0)),
        use_https=bool(record.get("https")),
        token=token,
    )
    state.token_valid = error is None and status == 200 and _looks_like_gitlab_user(payload)
    state.token_user = payload if state.token_valid and isinstance(payload, dict) else None
    state.token_capability = "identity" if state.token_valid else None
    state.token_error = error or (None if state.token_valid else "invalid token or insufficient API access")
    if error is None and status == 403:
        state.token_valid = True
        state.token_capability = "authenticated_forbidden"
        state.token_error = "token accepted but /api/v4/user is outside its scope"
    elif error is None and status == 401:
        probe_errors: list[str] = []
        for project_ref in options["project_filters"]:
            repository_ok, repository_error = _probe_repository_token(
                str(ctx.host),
                int(ctx.port),
                use_https=bool(record.get("https")),
                token=token,
                project_ref=str(project_ref),
            )
            if repository_ok is True:
                state.token_valid = True
                state.token_capability = "repository"
                state.token_error = "token accepted for repository access; identity API is outside its scope"
                break
            if repository_error:
                probe_errors.append(repository_error)
        if state.token_valid is not True and probe_errors:
            state.token_error = "; ".join(dict.fromkeys(probe_errors))
    record.update(
        {
            "timestamp": utc_now_iso(),
            "status": "valid_credentials" if state.token_valid else "invalid_credentials",
            "token_provided": True,
            "token_valid": state.token_valid,
            "token_user": state.token_user,
            "token_capability": state.token_capability,
            "token_projects_error": state.token_error if not state.token_valid else None,
        }
    )
    return record


def collect_gitlab_data(ctx: Any, source_record: Any, options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, GitLabLifecycleState):
        raise TypeError("gitlab lifecycle state is unavailable")
    if state.deep_record is not None:
        return state.deep_record
    record = dict(source_record.to_dict() if hasattr(source_record, "to_dict") else source_record)
    host, port = str(ctx.host), int(ctx.port)
    timeout = float(getattr(ctx.args, "timeout", 5.0))
    use_https = bool(record.get("https"))
    token = str(ctx.credential.token or "").strip() or None
    project_filters = list(options["project_filters"])
    open_endpoints: list[dict[str, Any]] = []
    if not token and record.get("version"):
        open_endpoints.append({"path": "/api/v4/version", "status": 200})
    if not token:
        for path in _PUBLIC_ENDPOINT_PATHS[1:]:
            status, _payload, _headers, error = _http_request(host, port, "GET", path, timeout, use_https=use_https)
            if error is None and status < 400:
                open_endpoints.append({"path": path, "status": status})
    public_all, public_error = _paginate_projects(
        host,
        port,
        timeout,
        use_https=use_https,
        token=None,
        public_only=True,
    )
    public_projects = (
        [item for item in public_all if _project_matches_filters(item, project_filters)]
        if isinstance(public_all, list)
        else []
    )
    if isinstance(public_all, list) and not token:
        open_endpoints.append({"path": "/api/v4/projects?visibility=public", "status": 200})

    token_projects: list[dict[str, Any]] = []
    token_access: list[dict[str, Any]] = []
    token_projects_error = state.token_error
    if state.token_valid and token:
        token_all, token_projects_error = _paginate_projects(
            host,
            port,
            timeout,
            use_https=use_https,
            token=token,
            public_only=False,
        )
        if isinstance(token_all, list):
            token_projects = [item for item in token_all if _project_matches_filters(item, project_filters)]
            scheduler = BoundedScheduler[dict[str, Any], dict[str, Any]](
                max_workers=max(1, min(int(getattr(ctx.args, "workers", 1) or 1), 20)),
                max_inflight=max(1, min(int(getattr(ctx.args, "workers", 1) or 1), 20)) * 4,
            )
            for _project, access in scheduler.iter_completed(
                token_projects,
                lambda project: _probe_project_capabilities(
                    host,
                    port,
                    timeout,
                    use_https=use_https,
                    token=token,
                    project=project,
                ),
            ):
                token_access.append(access)
            token_access.sort(key=lambda item: str(item.get("path_with_namespace") or ""))
        if state.token_capability == "repository" and not token_projects:
            token_projects = [
                {
                    "id": None,
                    "path_with_namespace": str(project_ref),
                    "http_url_to_repo": build_http_target_url(
                        host,
                        port,
                        f"/{str(project_ref).strip('/')}.git",
                        default_scheme="https" if use_https else "http",
                    ),
                }
                for project_ref in project_filters
                if str(project_ref).strip() and not str(project_ref).strip().isdigit()
            ]

    clone_results: list[dict[str, Any]] = []
    clone_scope: str | None = None
    if options["clone"]:
        clone_scope = "token" if state.token_valid else "public"
        clone_candidates = list(token_projects if state.token_valid else public_projects)
        if project_filters and not clone_candidates:
            for ref in project_filters:
                fetched, fetch_error = _fetch_project_by_ref(
                    host,
                    port,
                    timeout,
                    use_https=use_https,
                    token=token if state.token_valid else None,
                    project_ref=ref,
                )
                if fetched is not None and _project_matches_filters(fetched, project_filters):
                    clone_candidates.append(fetched)
                else:
                    clone_results.append(
                        {
                            "project": ref,
                            "project_id": None,
                            "status": "failed",
                            "dest": None,
                            "error": fetch_error or "project lookup failed",
                        }
                    )
        deduped: dict[str, dict[str, Any]] = {}
        for project in clone_candidates:
            deduped.setdefault(str(project.get("id") or _project_path(project)), project)
        for project in sorted(deduped.values(), key=_project_path):
            clone_results.append(
                _clone_project(
                    project,
                    host,
                    port,
                    use_https=use_https,
                    token=token if state.token_valid else None,
                    clone_dir=str(options["clone_dir"]),
                )
            )
    record.update(
        {
            "open_endpoints": open_endpoints,
            "public_projects": public_projects,
            "public_projects_error": public_error,
            "project_filters": project_filters,
            "token_projects": token_projects,
            "token_projects_error": token_projects_error,
            "token_access": token_access,
            "clone_requested": bool(options["clone"]),
            "clone_scope": clone_scope,
            "clone_dir": options["clone_dir"] if options["clone"] else None,
            "clone_results": clone_results,
        }
    )
    state.deep_record = record
    return record


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_gitlab_host_with_stage_debug
