"""Quoted values retain context and exact contents across bounded portions."""

from __future__ import annotations

import hashlib
import json
from io import BytesIO
from types import SimpleNamespace

import pytest

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.storage_discovery import DiscoveryCollector


def digest(value):
    return value.digest if isinstance(value, DiskBackedText) else hashlib.sha256(value.encode()).hexdigest()


@pytest.mark.parametrize("reader", ["record", "archive", "text_field", "scalars"])
@pytest.mark.parametrize("quote", ["'", '"'])
def test_quoted_large_password_keeps_field_and_never_includes_quotes(reader, quote) -> None:
    from redposture_core.clients.http_api import HttpResponse

    password = "qa-" + "Ab0λ" * 40_000 + "-tail"
    text = "ordinary status\npassword=" + quote + password + quote + "\nAPI_TOKEN=glpat-abcdefghijklmnopqrst\n"
    if reader == "record":
        matches, _bytes, covered = _scan_portioned_value({"message": text}, "$.source", 1024)
        assert covered
        passwords = [match.value for match in matches if match.detector == "password"]
        assert len(passwords) == 1 and digest(passwords[0]) == hashlib.sha256(password.encode()).hexdigest()
        assert any(match.value == "glpat-abcdefghijklmnopqrst" for match in matches)
        return
    payload = json.dumps({"message": text}, ensure_ascii=False).encode()

    class Pool:
        def request_stream(self, _method, _url, *, on_response, on_chunk, **kwargs):
            on_response(200, {"Content-Type": "application/json"})
            for pos in range(0, len(payload), 511):
                on_chunk(payload[pos : pos + 511])
            return HttpResponse(200, b"", {})

    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=1024, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("portainer", ctx, {"status": "open_no_auth"})
    if reader == "archive":
        collector._scan_member_stream("source", "app.env", BytesIO(text.encode()), prefer_specific=True)
    elif reader == "scalars":
        collector.stream_json_scalars(
            Pool(), "http://qa", "source", headers={}, timeout=1, root_kind="object", prefer_specific=True
        )
    else:
        collector.stream_json_text_field(
            Pool(), "http://qa", "source", "message", headers={}, timeout=1, prefer_specific=True
        )
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 2
    passwords = [finding["value"] for finding in result["findings"] if finding["type"] == "password"]
    assert len(passwords) == 1 and digest(passwords[0]) == hashlib.sha256(password.encode()).hexdigest()
    assert any(finding["value"] == "glpat-abcdefghijklmnopqrst" for finding in result["findings"])


@pytest.mark.parametrize("label,kind", [("RSA PRIVATE KEY", "private_key"), ("CERTIFICATE", "certificate")])
@pytest.mark.parametrize("length", [20, 20000])
def test_pem_block_stays_one_complete_finding_across_text_portions(label, kind, length) -> None:
    pem = f"-----BEGIN {label}-----\n" + "QWJjMTIzAb0=" * length + f"\n-----END {label}-----"
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=512, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    collector._scan_member_stream("source", "credential.pem", BytesIO(pem.encode()), prefer_specific=True)
    result = collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["type"] == kind
    assert digest(finding["value"]) == hashlib.sha256(pem.encode()).hexdigest()


def test_interrupted_pem_preserves_previous_completed_password_without_pem_prefix() -> None:
    content = b"password=qa-before-secret\n-----BEGIN PRIVATE KEY-----\n" + b"QWJjMTIz" * 40000
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=512, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    collector._scan_member_stream("source", "credential.pem", BytesIO(content), prefer_specific=True)
    result = collector.result()
    assert result["status"] == "partial"
    assert [(item["type"], item["value"]) for item in result["findings"]] == [("password", "qa-before-secret")]


def test_multiline_quoted_password_preserves_spaces_and_escaped_quote() -> None:
    password = "Ab0 " * 30000 + '\\"tail\nnext line'
    text = 'password="' + password + '"\n'
    matches, _bytes, covered = _scan_portioned_value({"message": text}, "$.source", 512)
    assert covered
    assert len(matches) == 1 and matches[0].detector == "password"
    assert digest(matches[0].value) == hashlib.sha256(password.encode()).hexdigest()


def test_small_scalar_does_not_lose_secret_field_when_pair_exceeds_portion() -> None:
    value = "qa-long-enough-credential-value"
    matches, _bytes, covered = _scan_portioned_value({"AWS_SECRET_ACCESS_KEY": value}, "$.source", 40)
    assert covered
    assert any(match.detector == "generic_secret" and match.value == value for match in matches)


@pytest.mark.parametrize("quote", ["'", '"'])
def test_unterminated_quoted_value_keeps_previous_finding_and_discards_candidate(quote) -> None:
    text = "password=qa-before-secret\npassword=" + quote + "Ab0λ " * 30000
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=512, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    collector._scan_member_stream("source", "app.env", BytesIO(text.encode()), prefer_specific=True)
    result = collector.result()
    assert result["status"] == "partial"
    assert any("unterminated_secret_value" in reason for reason in result["partial_reasons"])
    assert [(item["type"], item["value"]) for item in result["findings"]] == [("password", "qa-before-secret")]


def test_two_complete_pem_blocks_remain_two_distinct_values() -> None:
    blocks = ["-----BEGIN PRIVATE KEY-----\n" + letter * 80000 + "\n-----END PRIVATE KEY-----" for letter in "AB"]
    with DiskBackedText() as text:
        text.append_text("\n".join(blocks))
        text.finish()
        matches, _size, covered = _scan_portioned_value(text, "$.source", 512)
        assert covered
        assert len(matches) == 2 and all(match.detector == "private_key" for match in matches)
        assert {digest(match.value) for match in matches} == {
            hashlib.sha256(block.encode()).hexdigest() for block in blocks
        }


def test_default_collector_portion_never_emits_a_prefix_of_large_quoted_password() -> None:
    password = "Ab0λ " * 20000 + "-tail"
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("nexus", ctx, {"status": "open_no_auth"})
    collector.add("source/asset.env", 'password="' + password + '"\n', prefer_specific=True)
    result = collector.result()
    assert result["status"] == "complete"
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["type"] == "password"
    assert digest(finding["value"]) == hashlib.sha256(password.encode()).hexdigest()


def test_large_bytes_field_never_builds_a_full_repr_or_decoded_copy() -> None:
    import tracemalloc

    value = b"a" * 20_000_000
    tracemalloc.start()
    try:
        matches, _size, covered = _scan_portioned_value(value, "$.password", 65_536)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert covered and len(matches) == 1
    assert isinstance(matches[0].value, DiskBackedText)
    assert matches[0].value.digest == hashlib.sha256(value).hexdigest()
    assert peak < 8_000_000, peak


@pytest.mark.parametrize("slashes", [1, 3])
def test_escaped_quote_split_at_portion_boundary_is_part_of_the_value(slashes) -> None:
    password = "A" * (2038 - slashes) + "\\" * slashes + '"tail'
    text = 'password="' + password + '"\n'
    matches, _size, covered = _scan_portioned_value({"message": text}, "$.source", 512)
    assert covered
    assert len(matches) == 1 and matches[0].detector == "password"
    assert digest(matches[0].value) == hashlib.sha256(password.encode()).hexdigest()


@pytest.mark.parametrize(
    "prefix,tail,kind",
    [
        ("ALTER USER qa PASSWORD '", "';", "password"),
        ("Authorization: Bearer ", "\n", "bearer_token"),
        ("Authorization: Basic ", "\n", "basic_auth"),
    ],
)
def test_large_contextual_value_never_becomes_an_ignored_neutral_run(prefix, tail, kind) -> None:
    value = "a" * 100_000
    matches, _size, covered = _scan_portioned_value({"message": prefix + value + tail}, "$.source", 512)
    assert covered
    selected = [match for match in matches if match.detector == kind]
    assert len(selected) == 1
    assert digest(selected[0].value) == hashlib.sha256(value.encode()).hexdigest()


def test_pem_body_does_not_replace_the_whole_key_with_an_auth_fragment() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nBearer abcdefghijklmnopqrstuvwxyz\n-----END PRIVATE KEY-----"
    ctx = SimpleNamespace(args=SimpleNamespace(discover_max_bytes=512, discover_time=30), host="qa", port=80)
    collector = DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    collector._scan_member_stream("source", "key.pem", BytesIO(pem.encode()), prefer_specific=True)
    result = collector.result()
    assert result["status"] == "complete"
    # Existing detector semantics may also report a literal Bearer inside the
    # block; it must not replace or truncate the complete PEM itself.
    keys = [finding for finding in result["findings"] if finding["type"] == "private_key"]
    assert len(keys) == 1
    assert digest(keys[0]["value"]) == hashlib.sha256(pem.encode()).hexdigest()


@pytest.mark.parametrize(
    "body,expected",
    [
        ("abcdefgh", "abcdefgh"),
        ("abcdefgh=", "abcdefgh="),
        ("abcdefgh==", "abcdefgh=="),
        ("abcdefgh===", "abcdefgh=="),
        ("abcdefgh=tail", "abcdefgh="),
        ("abcdefg", None),
    ],
)
def test_basic_padding_matches_complete_detector_grammar(body, expected) -> None:
    # Force the text stream through the large-value path without enlarging auth.
    text = "ordinary\n" * 100 + "Authorization: Basic " + body + "\n"
    matches, _, covered = _scan_portioned_value({"message": text}, "$.source", 64)
    assert covered
    actual = [match.value for match in matches if match.detector == "basic_auth"]
    assert actual == ([] if expected is None else [expected])
