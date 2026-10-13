"""Thin Apache Airflow REST API client over the shared HttpSessionPool.

Read-only apart from the `POST /auth/token` login used by Airflow 3.x (it creates
no server-side state). Supports both auth carriers: HTTP Basic (Airflow 2.x) and a
Bearer JWT (Airflow 3.x). Transport errors are normalized so callers never see raw
exceptions; JSON parsing is best-effort.
"""

from __future__ import annotations

import base64
import json
import zlib
from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urljoin, urlsplit

if TYPE_CHECKING:
    from .http_session import HttpSessionPool

_RESPONSE_CAP = 2 * 1024 * 1024


class _FabLoginForm(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_login_form = False
        self.action = ""
        self.fields: dict[str, str] = {}
        self.warning_depth = 0
        self.invalid_login_flash = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form" and values.get("name") == "login" and (values.get("method") or "").lower() == "post":
            self.in_login_form = True
            self.action = values.get("action") or ""
            self.fields.clear()
        elif tag == "input" and self.in_login_form:
            name = values.get("name")
            if name:
                self.fields[name] = values.get("value") or ""
        elif tag == "div":
            if self.warning_depth:
                self.warning_depth += 1
            elif {"alert", "alert-warning"} <= set((values.get("class") or "").split()):
                self.warning_depth = 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.in_login_form = False
        elif tag == "div" and self.warning_depth:
            self.warning_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.warning_depth and data.strip() == "Invalid login. Please try again.":
            self.invalid_login_flash = True


def _header(headers: dict[str, str], name: str) -> str:
    return next((str(value) for key, value in headers.items() if key.lower() == name.lower()), "")


def _session_cookie(headers: dict[str, str]) -> str | None:
    raw = _header(headers, "set-cookie")
    if not raw:
        return None
    try:
        parsed = SimpleCookie()
        parsed.load(raw)
        morsel = parsed.get("session")
    except Exception:  # noqa: BLE001 - malformed cookies are not proof of a login
        return None
    return f"session={morsel.value}" if morsel is not None and morsel.value else None


@dataclass(frozen=True)
class AirflowResponse:
    http_status: int
    headers: dict[str, str]
    body: bytes
    transport_error: str | None = None
    request_url: str | None = None
    final_url: str | None = None
    redirect_history: tuple[str, ...] = ()
    truncated: bool = False

    def json(self) -> Any | None:
        if self.transport_error or self.truncated or not self.body:
            return None
        body = self.body
        encoding = next((value for key, value in self.headers.items() if key.lower() == "content-encoding"), "")
        if encoding.strip().lower() == "gzip":
            try:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                body = decoder.decompress(body, _RESPONSE_CAP + 1)
                if len(body) > _RESPONSE_CAP or not decoder.eof or decoder.unused_data:
                    return None
            except zlib.error:
                return None
        try:
            return json.loads(body)
        except (ValueError, TypeError):
            return None


class AirflowClient:
    def __init__(
        self,
        pool: HttpSessionPool,
        *,
        scheme: str,
        host: str,
        port: int,
        base_path: str = "",
        basic_user: str | None = None,
        basic_password: str | None = None,
        bearer_token: str | None = None,
    ) -> None:
        self._pool = pool
        self.scheme = scheme
        self.host = host
        self.port = int(port)
        self.base_path = "/" + base_path.strip("/") if base_path.strip("/") else ""
        self.basic_user = basic_user
        self.basic_password = basic_password
        self.bearer_token = bearer_token

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def _auth_header(self) -> dict[str, str]:
        if self.bearer_token:
            return {"Authorization": f"Bearer {self.bearer_token}"}
        if self.basic_user is not None and self.basic_password is not None:
            token = base64.b64encode(f"{self.basic_user}:{self.basic_password}".encode()).decode()
            return {"Authorization": f"Basic {token}"}
        return {}

    def _request(
        self,
        method: str,
        path: str,
        *,
        authed: bool,
        body: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
        response_size_cap: int = _RESPONSE_CAP,
    ) -> AirflowResponse:
        headers: dict[str, str] = dict(extra_headers or {})
        if authed:
            headers.update(self._auth_header())
        try:
            resp = self._pool.request(
                method,
                f"{self.base_url}{self.base_path}{path}",
                headers=headers,
                body=body,
                response_size_cap=response_size_cap,
            )
        except Exception as exc:  # noqa: BLE001 - transport errors normalized for callers
            return AirflowResponse(http_status=0, headers={}, body=b"", transport_error=str(exc))
        if getattr(resp, "error", None):
            return AirflowResponse(
                http_status=0,
                headers={},
                body=b"",
                transport_error=str(resp.error),
                request_url=getattr(resp, "request_url", None),
                final_url=getattr(resp, "final_url", None),
                redirect_history=tuple(getattr(resp, "redirect_history", ()) or ()),
            )
        return AirflowResponse(
            http_status=int(resp.status),
            headers=dict(resp.headers or {}),
            body=resp.body or b"",
            request_url=getattr(resp, "request_url", None),
            final_url=getattr(resp, "final_url", None),
            redirect_history=tuple(getattr(resp, "redirect_history", ()) or ()),
            truncated=bool(getattr(resp, "truncated", False)),
        )

    def get(
        self,
        path: str,
        *,
        authed: bool = True,
        extra_headers: dict[str, str] | None = None,
        response_size_cap: int = _RESPONSE_CAP,
    ) -> AirflowResponse:
        return self._request(
            "GET", path, authed=authed, extra_headers=extra_headers, response_size_cap=response_size_cap
        )

    def post_json(self, path: str, payload: dict[str, Any], *, authed: bool = False) -> AirflowResponse:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self._request("POST", path, authed=authed, body=body, extra_headers={"Content-Type": "application/json"})

    def verify_fab_login(self, username: str, password: str) -> str:
        """Resolve an ambiguous Airflow 2.x API 403 using a local FAB login form.

        Each attempt gets a fresh CSRF session. The POST is sent once, without
        redirects or transport retries; only same-origin Airflow pages can prove
        the result. SSO, CAPTCHA, lockout and unfamiliar forms stay unverified.
        """

        login_url = f"{self.base_url}{self.base_path}/login/"
        try:
            page = self._pool.request_once("GET", login_url, response_size_cap=256 * 1024)
            if page.error or page.truncated or page.status != 200:
                return "unverified"
            if "text/html" not in _header(page.headers, "content-type").lower():
                return "unverified"
            markup = page.body.decode("utf-8", "replace")
            if "/static/appbuilder/" not in markup:
                return "unverified"
            form = _FabLoginForm()
            form.feed(markup)
            if not {"username", "password", "csrf_token"} <= form.fields.keys() or not form.fields["csrf_token"]:
                return "unverified"
            cookie = _session_cookie(page.headers)
            if cookie is None:
                return "unverified"
            action_url = urljoin(login_url, form.action)
            action = urlsplit(action_url)
            expected = urlsplit(login_url)
            if (action.scheme, action.hostname, action.port, action.path) != (
                expected.scheme,
                expected.hostname,
                expected.port,
                expected.path,
            ):
                return "unverified"
            body = urlencode({"csrf_token": form.fields["csrf_token"], "username": username, "password": password})
            posted = self._pool.request_once(
                "POST",
                action_url,
                headers={"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"},
                body=body.encode("utf-8"),
                response_size_cap=64 * 1024,
            )
            if posted.error or posted.status not in {302, 303}:
                return "unverified"
            destination = urljoin(login_url, _header(posted.headers, "location"))
            final = urlsplit(destination)
            if (final.scheme, final.hostname, final.port) != (expected.scheme, expected.hostname, expected.port):
                return "unverified"
            posted_cookie = _session_cookie(posted.headers)
            if posted_cookie is None:
                return "unverified"
            followed = self._pool.request_once(
                "GET", destination, headers={"Cookie": posted_cookie}, response_size_cap=256 * 1024
            )
            if followed.error or followed.truncated or followed.status != 200:
                return "unverified"
            result_html = followed.body.decode("utf-8", "replace")
            if (
                final.path == f"{self.base_path}/home"
                and posted_cookie != cookie
                and "/logout/" in result_html
                and "Log Out" in result_html
            ):
                return "valid"
            if final.path == f"{self.base_path}/login/" and "/static/appbuilder/" in result_html:
                failed_form = _FabLoginForm()
                failed_form.feed(result_html)
                if {
                    "username",
                    "password",
                    "csrf_token",
                } <= failed_form.fields.keys() and failed_form.invalid_login_flash:
                    return "invalid"
        except Exception:  # noqa: BLE001 - login/transport failures never prove a password verdict
            return "unverified"
        return "unverified"


__all__ = ["AirflowClient", "AirflowResponse"]
