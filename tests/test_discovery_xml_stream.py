"""Large XML element and attribute values are decoded without a document tree."""

from __future__ import annotations

import hashlib
from io import BytesIO
from types import SimpleNamespace

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.storage_discovery import DiscoveryCollector


def collector():
    return DiscoveryCollector(
        "jenkins",
        SimpleNamespace(args=SimpleNamespace(discover_max_bytes=1024, discover_time=30), host="qa", port=80),
        {"status": "open_no_auth"},
    )


def value_text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize("shape", ["element", "attribute", "namespace"])
def test_large_xml_secret_keeps_full_decoded_value_with_entities(shape) -> None:
    raw = "Ab0λ" * 40000 + "&amp;&lt;&#65;&#x1F511;tail"
    expected = "Ab0λ" * 40000 + "&<A🔑tail"
    if shape == "element":
        body = f"<config><password>{raw}</password></config>"
    elif shape == "attribute":
        body = f'<config password="{raw}"/>'
    else:
        body = f'<config xmlns:auth="urn:qa"><auth:password>{raw}</auth:password></config>'
    result_collector = collector()
    result_collector._scan_member_stream("source", "config.xml", BytesIO(body.encode()), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["type"] == "password"
    assert (
        hashlib.sha256(value_text(finding["value"]).encode()).hexdigest()
        == hashlib.sha256(expected.encode()).hexdigest()
    )


def test_xml_sensitive_container_does_not_replace_leaf_password_with_markup() -> None:
    body = "<credentials><username>qa</username><password>qa-full-password</password></credentials>"
    result_collector = collector()
    result_collector._scan_member_stream("source", "config.xml", BytesIO(body.encode()), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert [(f["type"], value_text(f["value"])) for f in result["findings"]] == [("password", "qa-full-password")]


def test_xml_large_cdata_keeps_literal_entities_and_close_tag_text() -> None:
    expected = "Ab0λ" * 40000 + "&amp;</password>tail"
    body = "<config><password><![CDATA[" + expected + "]]></password></config>"
    result_collector = collector()
    result_collector._scan_member_stream("source", "config.xml", BytesIO(body.encode()), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert len(result["findings"]) == 1
    assert value_text(result["findings"][0]["value"]) == expected


def test_unterminated_xml_secret_withholds_candidate_and_preserves_prior_value() -> None:
    body = "<config><password>qa-before-password</password><password>" + "Ab0λ" * 40000
    result_collector = collector()
    result_collector._scan_member_stream("source", "config.xml", BytesIO(body.encode()), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "partial"
    assert [(f["type"], value_text(f["value"])) for f in result["findings"]] == [("password", "qa-before-password")]


def test_long_attribute_before_secret_element_does_not_detach_element_name() -> None:
    body = '<config><password padding="' + "z" * 100000 + '">qa-final-password</password></config>'
    result_collector = collector()
    result_collector._scan_member_stream("source", "config.xml", BytesIO(body.encode()), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert [(f["type"], value_text(f["value"])) for f in result["findings"]] == [("password", "qa-final-password")]


@pytest.mark.parametrize("chunk_size", [1, 3, 64])
@pytest.mark.parametrize(
    "encoded,expected",
    [
        ("qa&amp;&lt;&#65;&#x1F511;tail", "qa&<A🔑tail"),
        ("qa&unrecognized;tail", "qa&unrecognized;tail"),
        ("qa&#;tail", "qa&#;tail"),
        ("qa&#x;tail", "qa&#x;tail"),
        ("qa&#x110000;tail", "qa�tail"),
        ("qa&#00000000000000000000000000065;tail", "qaAtail"),
    ],
)
def test_xml_entities_preserve_exact_value_across_network_boundaries(chunk_size, encoded, expected) -> None:
    from redposture_core.discovery_text import DiscoveryTextStream

    values, errors = [], []
    scanner = DiscoveryTextStream(values.append, errors.append, portion=64)
    source = "<config><password>" + encoded + "</password></config>"
    for position in range(0, len(source), chunk_size):
        scanner.feed(source[position : position + chunk_size])
    scanner.finish()
    assert not errors
    assert [value_text(item["password"]) for item in values if isinstance(item, dict)] == [expected]


def test_xml_attribute_backslash_does_not_escape_its_closing_quote() -> None:
    source = '<config password="qa-backslash\\" token="glpat-abcdefghijklmnopqrst"/>'
    result_collector = collector()
    result_collector._scan_member_stream("source", "config.xml", BytesIO(source.encode()), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert {(f["type"], value_text(f["value"])) for f in result["findings"]} == {
        ("password", "qa-backslash\\"),
        ("gitlab_token", "glpat-abcdefghijklmnopqrst"),
    }


@pytest.mark.parametrize("name_first", [True, False])
@pytest.mark.parametrize("count", [10, 40000])
def test_html_named_secret_input_keeps_value_in_either_attribute_order(name_first, count) -> None:
    expected = "Ab0λ" * count + "&tail"
    name, value = 'name="password"', 'value="' + "Ab0λ" * count + '&amp;tail"'
    attributes = name + " " + value if name_first else value + " " + name
    source = "<form><input " + attributes + "/></form>"
    result_collector = collector()
    result_collector._scan_member_stream("source", "form.html", BytesIO(source.encode()), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete", result["partial_reasons"]
    assert [(f["type"], value_text(f["value"])) for f in result["findings"]] == [("password", expected)]


def test_html_neutral_input_still_scans_an_explicit_token_in_value() -> None:
    source = b'<input name="display" value="glpat-abcdefghijklmnopqrst"/>'
    result_collector = collector()
    result_collector._scan_member_stream("source", "form.html", BytesIO(source), prefer_specific=True)
    result = result_collector.result()
    assert result["status"] == "complete"
    assert [(f["type"], f["value"]) for f in result["findings"]] == [("gitlab_token", "glpat-abcdefghijklmnopqrst")]


def test_completed_xml_secret_is_emitted_before_later_transport_failure() -> None:
    from redposture_core.clients.http_api import HttpResponse

    expected = "Ab0λ" * 40000
    events = []

    def emit(_module, _host, _port, *, value, **fields):
        events.append(("finding", value.digest))

    class Pool:
        def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
            on_response(200, {"Content-Type": "application/json"})
            on_chunk(b'{"message":"<config><password>')
            for offset in range(0, len(expected), 511):
                on_chunk(expected[offset : offset + 511].encode())
            on_chunk(b"</password><later>")
            events.append(("transport_failure", None))
            return HttpResponse(200, b"", {}, error="connection reset", truncated=True)

    result_collector = DiscoveryCollector(
        "jenkins",
        SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80, live_discovery_value=emit),
        {"status": "open_no_auth"},
    )
    assert not result_collector.stream_json_text_field(Pool(), "http://qa", "source", "message", headers={}, timeout=1)
    result = result_collector.result()
    assert result["status"] == "partial"
    assert len(result["findings"]) == 1
    assert events == [("finding", hashlib.sha256(expected.encode()).hexdigest()), ("transport_failure", None)]
