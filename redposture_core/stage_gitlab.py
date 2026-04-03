"""GitLab audit stage."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .progress import iter_completed_with_progress
from .utils import collect_scan_ports, collect_scan_targets, utc_now_iso

_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_CONNECTION_REFUSED_PREFIX = "connection refused"
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
_GIT_CLONE_TIMEOUT_SECONDS = 300


def _clip(text: str, width: int = 72) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _friendly_error_text(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "connection failed"
    if text.startswith("<urlopen error ") and text.endswith(">"):
        text = text[len("<urlopen error ") : -1].strip()
    lower = text.lower()
    if "connection refused" in lower:
        return "connection refused (service is not listening on target port)"
    if "timed out" in lower or "timeout" in lower:
        return "connection timeout"
    if "name or service not known" in lower or "nodename nor servname provided" in lower:
        return "dns lookup failed"
    if "temporary failure in name resolution" in lower:
        return "dns lookup temporary failure"
    if "no route to host" in lower or "network is unreachable" in lower:
        return "network unreachable"
    if "operation not permitted" in lower:
        return "operation not permitted by local environment"
    match = re.search(r"\[errno\s+(-?\d+)\]\s*(.*)", text, flags=re.IGNORECASE)
    if match:
        errno_num = match.group(1)
        detail = (match.group(2) or "").strip()
        if errno_num in {"61", "111"}:
            return "connection refused (service is not listening on target port)"
        if errno_num in {"60", "110"}:
            return "connection timeout"
        if errno_num in {"8", "-2"}:
            return "dns lookup failed"
        if errno_num in {"65", "101", "113"}:
            return "network unreachable"
        if detail:
            return detail
    return text


def _friendly_error_from_exception(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, BaseException):
            return _friendly_error_text(str(reason))
        return _friendly_error_text(str(reason or exc))
    if isinstance(exc, TimeoutError):
        return "connection timeout"
    return _friendly_error_text(str(exc))


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
    return f"{scheme}://{host}:{port}"


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
        url = _build_base_url(host, port, use_https) + _normalize_path(path)
    request_headers = {"User-Agent": "RedPosture/1.0"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, data=body, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            payload = response.read()
            response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            return status, payload, response_headers, None
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        response_headers = {str(k).lower(): str(v) for k, v in exc.headers.items()}
        return int(exc.code), payload, response_headers, None
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        return 0, b"", {}, _friendly_error_from_exception(exc)


def _json_loads_bytes(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", errors="replace"))


def _gitlab_api_headers(token: str | None) -> dict[str, str]:
    if not token:
        return {}
    return {"PRIVATE-TOKEN": token}


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
    while True:
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
            return None, error
        if status == 401 or status == 403:
            return None, "authentication required"
        if status == 404:
            return None, "GitLab API v4 not available"
        if status != 200:
            return None, f"unexpected API status={status}"
        if not isinstance(payload, list):
            return None, "unexpected API payload"

        page_items: list[dict[str, Any]] = [item for item in payload if isinstance(item, dict)]
        projects.extend(page_items)

        next_page = str(headers.get("x-next-page") or "").strip()
        if next_page.isdigit() and int(next_page) > page:
            page = int(next_page)
            continue
        if len(page_items) >= _MAX_PER_PAGE:
            page += 1
            continue
        break
    return projects, None


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
            repo_path = parsed.path or f"/{path_with_namespace}.git"
            repo_query = parsed.query
            scheme = "https" if use_https else "http"
            http_url = urllib.parse.urlunsplit((scheme, f"{host}:{port}", repo_path, repo_query, ""))
        except ValueError:
            http_url = ""
    if not http_url or "://" not in http_url:
        scheme = "https" if use_https else "http"
        http_url = f"{scheme}://{host}:{port}/{path_with_namespace}.git"

    final_url = _clone_url_with_token(http_url, token)
    dest_root = os.path.join(clone_dir, _safe_slug(f"{host}_{port}"))
    dest_path = os.path.join(dest_root, path_with_namespace.replace("/", os.sep))
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    if os.path.isdir(dest_path):
        return {
            "project": path_with_namespace,
            "project_id": project_id,
            "status": "exists",
            "dest": dest_path,
            "error": None,
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

    command = [git_path, "clone", "--depth", "1", final_url, dest_path]

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
        return {
            "project": path_with_namespace,
            "project_id": project_id,
            "status": "failed",
            "dest": dest_path,
            "error": "git clone timeout",
        }
    except OSError as exc:
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
        fallback_command = [git_path, "clone", final_url, dest_path]
        try:
            completed = _run_clone(fallback_command)
        except subprocess.TimeoutExpired:
            return {
                "project": path_with_namespace,
                "project_id": project_id,
                "status": "failed",
                "dest": dest_path,
                "error": "git clone timeout",
            }
        except OSError as exc:
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
        return {
            "project": path_with_namespace,
            "project_id": project_id,
            "status": "cloned",
            "dest": dest_path,
            "error": None,
        }

    error = stderr or stdout or f"git clone exit={completed.returncode}"
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
                elif user_status == 200 and isinstance(user_payload, dict):
                    token_valid = True
                    token_user = user_payload
                elif user_status in {401, 403}:
                    token_valid = False
                    token_projects_error = "invalid token or insufficient API access"
                else:
                    token_valid = False
                    token_projects_error = f"unexpected /api/v4/user status={user_status}"

                if token_valid:
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
                        with ThreadPoolExecutor(max_workers=max(1, min(workers, 20))) as executor:
                            future_map = {
                                executor.submit(
                                    _probe_project_capabilities,
                                    host,
                                    port,
                                    timeout,
                                    use_https=use_https,
                                    token=token or "",
                                    project=project,
                                ): project
                                for project in token_projects
                            }
                            for future in iter_completed_with_progress(future_map, label="GITLAB"):
                                token_access.append(future.result())
                        token_access.sort(key=lambda item: str(item.get("path_with_namespace") or ""))

            clone_candidates: list[dict[str, Any]] = []
            if clone:
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

            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "https": use_https,
                "is_gitlab": is_gitlab,
                "status": "detected" if is_gitlab else "not_gitlab",
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

    if str(record.get("status") or "fail") != "detected":
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
                project = str(item.get("project") or "-")
                dest = str(item.get("dest") or "-")
                status = str(item.get("status") or "failed")
                error = str(item.get("error") or "").strip()
                if status == "cloned":
                    lines.append(f"{prefix} [+] {project} -> {dest}")
                elif status == "exists":
                    lines.append(f"{prefix} [*] {project} already exists -> {dest}")
                else:
                    body = f"{project}"
                    if error:
                        body += f" err={_clip(error, 96)}"
                    lines.append(f"{prefix} [-] clone failed {body}")
        else:
            lines.append(f"{prefix} <no clone targets>")

    return lines


def _render_colored_gitlab_line(console: Console, line: str) -> bool:
    if not line.startswith("GITLAB"):
        return False

    marker_color = {
        "[*]": "cyan",
        "[+]": "bright_green",
        "[-]": "red",
        "[!]": "red",
    }
    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue
        left, right = line.split(token, 1)
        tag = "GITLAB"
        rest = left[len(tag) :] if left.startswith(tag) else left

        spans: list[tuple[int, int, str]] = []
        projects_match = re.search(r"\(projects:(\d+)\)", right)
        if projects_match and int(projects_match.group(1)) > 0:
            spans.append((projects_match.start(), projects_match.end(), "red"))
        login_true = "(login page:True)"
        login_false = "(login page:False)"
        idx_true = right.find(login_true)
        if idx_true >= 0:
            spans.append((idx_true, idx_true + len(login_true), "bright_green"))
        idx_false = right.find(login_false)
        if idx_false >= 0:
            spans.append((idx_false, idx_false + len(login_false), "yellow"))
        for fragment in ("(repo:True)", "(issues:True)", "(members:True)"):
            idx = right.find(fragment)
            if idx >= 0:
                spans.append((idx, idx + len(fragment), "red"))

        if not spans:
            right_colored = console._paint(right, "white", sys.stdout)
        else:
            chunks: list[str] = []
            cursor = 0
            for start, end, color in sorted(spans, key=lambda item: item[0]):
                if start < cursor:
                    continue
                if start > cursor:
                    chunks.append(console._paint(right[cursor:start], "white", sys.stdout))
                chunks.append(console._paint(right[start:end], color, sys.stdout))
                cursor = end
            if cursor < len(right):
                chunks.append(console._paint(right[cursor:], "white", sys.stdout))
            right_colored = "".join(chunks)

        console.plain(
            f"{console._paint(tag, 'blue', sys.stdout)}"
            f"{console._paint(rest, 'white', sys.stdout)} "
            f"{console._paint(marker, marker_color[marker], sys.stdout)} "
            f"{right_colored}"
        )
        return True
    return False


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def audit_gitlab_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    *,
    use_https: bool,
    token: str | None,
    project_filters: list[str],
    clone: bool,
    clone_dir: str,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_timeout_status_lines: bool = False,
) -> tuple[int, int, int]:
    total = 0
    detected = 0
    failed = 0

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(
                    _audit_gitlab_host,
                    host,
                    port,
                    timeout,
                    retries,
                    use_https=use_https,
                    token=token,
                    project_filters=project_filters,
                    clone=clone,
                    clone_dir=clone_dir,
                    workers=workers,
                ): host
                for host in hosts
            }
            for future in iter_completed_with_progress(future_map, label="GITLAB"):
                record = future.result()
                total += 1
                status = str(record.get("status") or "fail")
                if status == "detected":
                    detected += 1
                elif status == "fail":
                    failed += 1

                suppress_timeout_status_line = (
                    suppress_timeout_status_lines
                    and output_format == "txt"
                    and status == "fail"
                )
                if not suppress_timeout_status_line:
                    _emit_line(out_fh, emit_line, _format_record(record, output_format))
                for detail in _format_detail_records(record, output_format):
                    _emit_line(out_fh, emit_line, detail)

                if logger is not None:
                    logger.log(
                        "gitlab",
                        (str(record.get("host") or "-"), int(record.get("port") or port)),
                        phase="audit",
                        status=record.get("status"),
                        version=record.get("version"),
                        login_page=record.get("login_page"),
                        public_projects=len(record.get("public_projects") or []),
                        token_valid=record.get("token_valid"),
                        clone_requested=record.get("clone_requested"),
                        error=record.get("error"),
                    )
    finally:
        if out_fh is not None:
            out_fh.close()

    return total, detected, failed


def run_gitlab_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    try:
        ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --port: {exc}")
        return 2
    if not ports:
        ports = [int(args.port)]

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None)
    hosts_file = getattr(args, "hosts_file", None)
    if hosts_file:
        targets = f"{targets},{hosts_file}" if targets else hosts_file

    try:
        hosts = collect_scan_targets(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2

    if not hosts:
        console.error("gitlab requires -t/--targets")
        return 2

    project_filters = _normalize_project_filters(getattr(args, "project", None))
    clone = bool(getattr(args, "clone", False))
    clone_dir = str(getattr(args, "clone_dir", _DEFAULT_CLONE_DIR) or _DEFAULT_CLONE_DIR).strip() or _DEFAULT_CLONE_DIR

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("GITLAB") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "GITLAB", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_gitlab_line(console, line):
            return
        if args.debug:
            console.plain(line)

    if args.debug and stream_to_stdout and args.output_format == "txt":
        mode_parts = ["public"]
        if args.token:
            mode_parts.append("token")
        if project_filters:
            mode_parts.append(f"project={','.join(project_filters)}")
        if clone:
            mode_parts.append("clone")
        if args.https:
            mode_parts.append("https")
        console.info(
            f"gitlab audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={'+'.join(mode_parts)} format=txt"
        )

    total = 0
    detected = 0
    failed = 0
    try:
        for idx, audit_port in enumerate(ports):
            part_total, part_detected, part_failed = audit_gitlab_targets(
                hosts=hosts,
                port=audit_port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                use_https=bool(getattr(args, "https", False)),
                token=str(args.token).strip() if getattr(args, "token", None) else None,
                project_filters=project_filters,
                clone=clone,
                clone_dir=clone_dir,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
                suppress_timeout_status_lines=not bool(args.debug),
            )
            total += part_total
            detected += part_detected
            failed += part_failed
    except OSError as exc:
        console.error(f"failed to process gitlab output: {exc}")
        return 2

    if args.debug:
        summary = f"gitlab audit complete: total={total} detected={detected} fail={failed}"
        if stream_to_stdout and args.output_format == "txt":
            console.info(summary)
        else:
            console.info(f"{summary} format={args.output_format} output={args.output}")
    return 0
