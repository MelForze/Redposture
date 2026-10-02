"""Deterministic property checks for untrusted HTTP detection inputs."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from redposture_core.audit_models import AuditRecord
from redposture_core.clients.grpc import _decode_grpc_web_frames
from redposture_core.clients.http_api import http_response_requires_https, infer_http_base_path
from redposture_core.modules.etcd.actions import _looks_like_etcd_version
from redposture_core.stage_runtime import _with_http_detection_diagnostics


@given(
    segments=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_", min_size=1, max_size=12), min_size=1, max_size=4
    ),
    suffix=st.sampled_from(("/api/v1/version", "/v1/status/leader", "/api2/json/version", "/minio/health/live")),
)
def test_known_api_suffix_preserves_only_explicit_prefix(segments: list[str], suffix: str) -> None:
    prefix = "/" + "/".join(segments)
    assert infer_http_base_path(prefix + suffix, (suffix,)) == prefix
    assert infer_http_base_path(prefix + "/other", (suffix,)) == prefix + "/other"


@given(text=st.text(max_size=400), status=st.integers(min_value=100, max_value=599))
def test_http_to_https_requires_only_canonical_400(text: str, status: int) -> None:
    expected = status == 400 and text.strip().removesuffix(".").strip().casefold() == (
        "client sent an http request to an https server"
    )
    assert http_response_requires_https(status, text) is expected


@given(
    payload=st.dictionaries(
        st.text(max_size=20), st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=50)), max_size=8
    )
)
def test_etcd_version_requires_product_specific_field(payload: dict[str, object]) -> None:
    confirmed, _version = _looks_like_etcd_version(payload)
    if "etcdserver" not in payload:
        assert confirmed is False


@given(payload=st.binary(max_size=512))
def test_malformed_grpc_web_frames_never_raise(payload: bytes) -> None:
    messages, trailers, error = _decode_grpc_web_frames(payload)
    assert isinstance(messages, list)
    assert isinstance(trailers, dict)
    assert error is None or isinstance(error, str)


@given(status=st.text(max_size=80), error=st.text(max_size=100))
def test_detection_diagnostic_never_confirms_from_status_or_error_alone(status: str, error: str) -> None:
    record = AuditRecord(
        host="127.0.0.1", port=8080, service="etcd", module="etcd", status=status, extra={"error": error}
    )
    diagnosed = _with_http_detection_diagnostics(record, confirmed=False)
    assert diagnosed.extra["detection_status"] != "confirmed"
    assert isinstance(diagnosed.extra["detection_signals"], list)
