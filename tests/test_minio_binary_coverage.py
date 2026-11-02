"""Binary negative controls must be stable; malformed XML must remain partial."""

from __future__ import annotations

import pytest

from redposture_core.modules.minio.discover import Budget, discover_secrets
from tests.test_minio_discover import _Client, _obj


@pytest.mark.parametrize("body", [bytes(4096), bytes(range(256)) * 16])
@pytest.mark.parametrize("chunk_size", [1, 7, 128, 8192])
def test_unclassified_binary_control_is_fully_read_without_findings(body, chunk_size):
    client = _Client({"blob.bin": (200, body)})
    result = discover_secrets(client, [_obj("blob.bin", size=len(body))], budget=Budget(chunk_size=chunk_size))
    assert result.coverage_complete is True
    assert result.partial_reasons == []
    assert result.findings == []
    assert result.objects_scanned == 1
    assert result.bytes_read == len(body)


@pytest.mark.parametrize(
    "body,reason",
    [
        (b'<root password="unfinished', "unterminated_xml_tag"),
        (b"<password>unfinished", "unterminated_xml_secret"),
    ],
)
@pytest.mark.parametrize("chunk_size", [1, 7, 128, 8192])
def test_incomplete_xml_is_partial_and_never_publishes_an_incomplete_secret(body, reason, chunk_size):
    result = discover_secrets(
        _Client({"config.xml": (200, body)}),
        [_obj("config.xml", size=len(body))],
        budget=Budget(chunk_size=chunk_size),
    )
    assert result.coverage_complete is False
    assert result.partial_reasons == [reason]
    assert result.findings == []
    assert result.bytes_read == len(body)


@pytest.mark.parametrize("chunk_size", [1, 7, 128, 8192])
def test_binary_source_keeps_embedded_text_secret(chunk_size):
    body = bytes(range(256)) + b"\npassword=fixture-binary-password-7Z9\n\x00\xff"
    result = discover_secrets(
        _Client({"blob.bin": (200, body)}),
        [_obj("blob.bin", size=len(body))],
        budget=Budget(chunk_size=chunk_size),
    )
    assert result.coverage_complete is True
    assert result.partial_reasons == []
    assert result.bytes_read == len(body)
    assert [finding["value"] for finding in result.findings] == ["fixture-binary-password-7Z9"]


@pytest.mark.parametrize("chunk_size", [1, 7, 128, 8192])
def test_complete_xml_keeps_the_full_secret_and_complete_coverage(chunk_size):
    body = b'<root password="minio-qa-complete-secret"></root>'
    result = discover_secrets(
        _Client({"config.xml": (200, body)}),
        [_obj("config.xml", size=len(body))],
        budget=Budget(chunk_size=chunk_size),
    )
    assert result.coverage_complete is True
    assert result.partial_reasons == []
    assert [finding["value"] for finding in result.findings] == ["minio-qa-complete-secret"]
