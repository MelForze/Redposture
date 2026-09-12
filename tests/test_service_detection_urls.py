"""Run URL/file targets through the actual plans, lifecycle and detection hooks."""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.minio import actions as minio_actions
from redposture_core.modules.minio import stage as minio_stage
from redposture_core.modules.rabbitmq import actions as rabbit_actions
from redposture_core.modules.rabbitmq import stage as rabbit_stage
from redposture_core.stage_runtime import AuditCommandRunner


class DetectionPool:
    def __init__(self, module, *, console=False):
        self.module = module
        self.console = console
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((url, kwargs.get("headers", {})))
        if urlsplit(url).scheme != "https":
            return HttpResponse(400, b"Client sent an HTTP request to an HTTPS server.", {})
        if self.module == "minio":
            if self.console:
                return HttpResponse(200, b'<html><title data-x="1">\n MinIO Console </title></html>', {})
            if urlsplit(url).path == "/minio/health/live":
                return HttpResponse(404, b"", {})  # reverse proxy blocks diagnostics
            return HttpResponse(403, b"<Error><Code>AccessDenied</Code></Error>", {"SERVER": "MinIO"})
        return HttpResponse(
            401, b'{"error":"not_authorised"}', {"WWW-Authenticate": 'Basic realm="RabbitMQ Management"'}
        )

    def close(self):
        pass


@pytest.mark.parametrize("module", ["minio", "rabbitmq"])
@pytest.mark.parametrize("target_kind", ["url", "file", "bare"])
def test_https_nonstandard_port_is_detected(monkeypatch, tmp_path, module, target_kind):
    actions, stage = (minio_actions, minio_stage) if module == "minio" else (rabbit_actions, rabbit_stage)
    pool = DetectionPool(module)
    monkeypatch.setattr(actions, "HttpSessionPool", lambda **kwargs: pool)
    target = "https://10.15.12.102:8083"
    if target_kind == "file":
        path = tmp_path / "masscan_urls.txt"
        path.write_text(target + "\n")
        target = str(path)
    elif target_kind == "bare":
        target = "10.15.12.102:8083"
    args = parse_args([module, "-t", target, "-f", "json"])
    plan = getattr(stage, f"build_{module}_plan")(args)
    spec = getattr(stage, f"build_{module}_spec")(args)
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None).run_plan(plan)
    assert result.detected_count == 1
    assert len(result.records) == 1
    record = result.records[0]
    assert record["detection_status"] == "confirmed"
    assert record["api_endpoint"] == "https://10.15.12.102:8083"
    assert record["auth_required"] is True
    schemes = [urlsplit(url).scheme for url, _ in pool.calls]
    assert schemes[0] == ("http" if target_kind == "bare" else "https")
    assert all(scheme == "https" for scheme in schemes[1:])


def test_console_is_visible_without_s3_credential_attempts(monkeypatch):
    pool = DetectionPool("minio", console=True)
    monkeypatch.setattr(minio_actions, "HttpSessionPool", lambda **kwargs: pool)
    args = parse_args(["minio", "-t", "https://host:8083", "--defcreds"])
    lines = []
    result = AuditCommandRunner(args=args, spec=minio_stage.build_minio_spec(args), emit_line=lines.append).run_plan(
        minio_stage.build_minio_plan(args)
    )
    assert result.detected_count == 1
    record = result.records[0]
    assert record["console_endpoint"] == "https://host:8083"
    assert record["api_endpoint"] is None
    assert record["credential_verification_status"] == "unavailable"
    assert any("MinIO Console (S3 API:unverified)" in line for line in lines)
    assert not any(headers.get("Authorization") for _, headers in pool.calls)


def test_minio_defcreds_continue_on_https_after_explicit_http_redirect(monkeypatch):
    class RedirectingMinioPool(DetectionPool):
        def __init__(self):
            super().__init__("minio")

        def request(self, method, url, **kwargs):
            headers = kwargs.get("headers", {})
            self.calls.append((url, headers))
            parsed = urlsplit(url)
            if parsed.scheme == "http":
                return HttpResponse(
                    200,
                    b"<html><title>MinIO Console</title></html>",
                    {},
                    request_url=url,
                    final_url=f"https://{parsed.netloc}/",
                    redirect_history=(url,),
                )
            if parsed.path == "/minio/health/live":
                return HttpResponse(200, b"", {})
            authorization = str(headers.get("Authorization") or "")
            if parsed.path == "/" and authorization:
                if "Credential=minioadmin/" in authorization:
                    return HttpResponse(200, b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>", {})
                return HttpResponse(403, b"<Error><Code>InvalidAccessKeyId</Code></Error>", {"Server": "MinIO"})
            return HttpResponse(403, b"<Error><Code>AccessDenied</Code></Error>", {"Server": "MinIO"})

    pool = RedirectingMinioPool()
    monkeypatch.setattr(minio_actions, "HttpSessionPool", lambda **kwargs: pool)
    args = parse_args(["minio", "-t", "http://host:8083", "--defcreds"])
    lines: list[str] = []
    result = AuditCommandRunner(args=args, spec=minio_stage.build_minio_spec(args), emit_line=lines.append).run_plan(
        minio_stage.build_minio_plan(args)
    )

    assert result.detected_count == 1
    record = result.records[0]
    assert record["api_endpoint"] == "https://host:8083"
    assert record["credential_state"] == "valid"
    assert record["default_credentials"] is True
    assert any("[+] minioadmin:minioadmin" in line for line in lines)
    assert not any("credential verification unavailable" in line for line in lines)
    assert [urlsplit(url).scheme for url, _headers in pool.calls].count("http") == 1


def test_minio_defcreds_continue_on_https_after_http_tls_required_response(monkeypatch):
    class TlsRequiredMinioPool(DetectionPool):
        def __init__(self):
            super().__init__("minio")

        def request(self, method, url, **kwargs):
            headers = kwargs.get("headers", {})
            self.calls.append((url, headers))
            parsed = urlsplit(url)
            if parsed.scheme == "http":
                return HttpResponse(400, b"Client sent an HTTP request to an HTTPS server.", {})
            if parsed.path == "/minio/health/live":
                return HttpResponse(200, b"", {"Server": "MinIO"})
            authorization = str(headers.get("Authorization") or "")
            if parsed.path == "/" and authorization:
                if "Credential=minioadmin/" in authorization:
                    return HttpResponse(200, b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>", {})
                return HttpResponse(403, b"<Error><Code>InvalidAccessKeyId</Code></Error>", {"Server": "MinIO"})
            return HttpResponse(403, b"<Error><Code>AccessDenied</Code></Error>", {"Server": "MinIO"})

    pool = TlsRequiredMinioPool()
    monkeypatch.setattr(minio_actions, "HttpSessionPool", lambda **kwargs: pool)
    args = parse_args(["minio", "-t", "http://host:8083", "--defcreds"])
    lines: list[str] = []

    result = AuditCommandRunner(args=args, spec=minio_stage.build_minio_spec(args), emit_line=lines.append).run_plan(
        minio_stage.build_minio_plan(args)
    )

    assert result.detected_count == 1
    record = result.records[0]
    assert record["api_endpoint"] == "https://host:8083"
    assert record["credential_state"] == "valid"
    assert record["default_credentials"] is True
    assert any("[+] minioadmin:minioadmin" in line for line in lines)
    assert not any("S3 API:unverified" in line or "credential verification unavailable" in line for line in lines)
    schemes = [urlsplit(url).scheme for url, _headers in pool.calls]
    assert schemes[0] == "http"
    assert all(scheme == "https" for scheme in schemes[1:])


def test_minio_explicit_http_upgrades_when_endpoint_requires_tls(monkeypatch):
    pool = DetectionPool("minio")
    monkeypatch.setattr(minio_actions, "HttpSessionPool", lambda **kwargs: pool)
    ctx = SimpleNamespace(
        args=SimpleNamespace(timeout=1, retries=0),
        host="host",
        port=443,
        target=SimpleNamespace(scheme="http", path=""),
    )
    state = minio_actions.minio_lifecycle_state_factory(ctx)
    assert state.resolve_scheme() == "https"
    assert [urlsplit(url).scheme for url, _headers in pool.calls] == ["http"]


def test_rabbitmq_explicit_http_upgrades_when_endpoint_requires_tls(monkeypatch):
    pool = DetectionPool("rabbitmq")
    monkeypatch.setattr(rabbit_actions, "HttpSessionPool", lambda **kwargs: pool)
    ctx = SimpleNamespace(
        args=SimpleNamespace(timeout=1, retries=0),
        host="host",
        port=443,
        target=SimpleNamespace(scheme="http", path=""),
    )
    state = rabbit_actions.RabbitMQLifecycleState(ctx)
    state.resolve()
    assert state.scheme == "https"
    assert len(pool.calls) == 2


@pytest.mark.parametrize("path", ["/rabbit/api/overview", "/rabbit/api/", "/rabbit/index.html", "/rabbit/"])
def test_rabbitmq_page_urls_preserve_proxy_mount(monkeypatch, path):
    pool = DetectionPool("rabbitmq")
    monkeypatch.setattr(rabbit_actions, "HttpSessionPool", lambda **kwargs: pool)
    ctx = SimpleNamespace(
        args=SimpleNamespace(timeout=1, retries=0),
        host="host",
        port=8083,
        target=SimpleNamespace(scheme="https", path=path),
    )
    state = rabbit_actions.RabbitMQLifecycleState(ctx)
    state.resolve()
    assert pool.calls[0][0] == "https://host:8083/rabbit/api/overview"


@pytest.mark.parametrize("transport_error", [False, True])
def test_minio_debug_distinguishes_unrelated_http_and_connection_failure(monkeypatch, capsys, transport_error):
    pool = DetectionPool("minio")
    reply = (
        HttpResponse(0, b"", {}, error="connection refused")
        if transport_error
        else HttpResponse(200, b"<html>nginx</html>", {})
    )
    monkeypatch.setattr(pool, "request", lambda *a, **kw: reply)
    monkeypatch.setattr(minio_actions, "HttpSessionPool", lambda **kwargs: pool)
    args = parse_args(["minio", "-t", "https://host:8083", "-d", "--retries", "0"])
    minio_stage.run_minio_stage(args, logger=SimpleNamespace(log=lambda *a, **kw: None))
    output = capsys.readouterr().out
    assert "all minio targets are unreachable" not in output
    if transport_error:
        assert "audit inconclusive" in output
        assert "No MINIO service detected" not in output
    else:
        assert "No MINIO service detected" in output
        assert "audit inconclusive" not in output
