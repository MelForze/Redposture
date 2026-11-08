"""Neutral markup must not rescan all later attributes before every tag."""

from __future__ import annotations

import pytest

from redposture_core import discovery_text


@pytest.mark.parametrize("shape", ["xml", "html"])
def test_dense_neutral_markup_has_bounded_field_classification_work(shape, monkeypatch):
    count = 512
    unit = '<metric name="state">ready</metric>' if shape == "xml" else '<div class="row"><span>ready</span></div>'
    source = "<root>" + unit * count + "<password>qa-final-password</password></root>"
    original = discovery_text.is_secret_field_name
    calls = []

    def classify(name):
        calls.append(name)
        return original(name)

    monkeypatch.setattr(discovery_text, "is_secret_field_name", classify)
    values, partials = [], []
    scanner = discovery_text.DiscoveryTextStream(values.append, partials.append)
    try:
        scanner.feed(source)
        scanner.finish()
        assert partials == []
        assert [v for v in values if isinstance(v, dict)] == [{"password": "qa-final-password"}]
        assert len(calls) <= count * 30, f"{len(calls)} field checks for {count} neutral records"
    finally:
        scanner.close()


@pytest.mark.parametrize("prefix", ["ordinary boundary ", "Authorization: Bearer qaABCDEFGHIJKLMNOP1234 "])
def test_xml_fast_path_keeps_the_entire_prefix_for_the_classifier(prefix):
    rows, reasons = [], []
    scanner = discovery_text.DiscoveryTextStream(rows.append, reasons.append)
    try:
        scanner.feed(prefix + "<config><password>qa-final-password</password></config>")
        scanner.finish()
        assert rows[0] == prefix
        assert reasons == []
        assert [row for row in rows if isinstance(row, dict)] == [{"password": "qa-final-password"}]
    finally:
        scanner.close()


@pytest.mark.parametrize("chunk", [1, 65536])
def test_xml_head_inside_pem_does_not_replace_the_key_capture(chunk):
    pem = "-----BEGIN PRIVATE KEY-----\nqa-<key>literal-key-data</key>\n-----END PRIVATE KEY-----"
    rows, reasons = [], []
    scanner = discovery_text.DiscoveryTextStream(rows.append, reasons.append)
    source = pem + "\n<config><password>qa-after-password</password></config>"
    try:
        for index in range(0, len(source), chunk):
            scanner.feed(source[index : index + chunk])
        scanner.finish()
        assert reasons == []
        # The downstream classifier receives the entire PEM as one raw value.
        assert rows[0] == pem
        assert [row for row in rows if isinstance(row, dict)] == [{"password": "qa-after-password"}]
    finally:
        scanner.close()


@pytest.mark.parametrize("chunk", [1, 7, 64, 65536])
@pytest.mark.parametrize(
    "prefix",
    [
        'password="qa-before-password"\n',
        "password=qa-before-password\n",
        'password="qa-before-<tag>-password"\n',
        "--password: 'qa-before-password'\n",
    ],
)
def test_xml_fast_path_preserves_sensitive_assignment_before_tag(prefix, chunk):
    rows, reasons = [], []
    source = prefix + '<config name="neutral"><password>qa-after-password</password></config>'
    scanner = discovery_text.DiscoveryTextStream(rows.append, reasons.append)
    try:
        for index in range(0, len(source), chunk):
            scanner.feed(source[index : index + chunk])
        scanner.finish()
        assert reasons == []
        # Closed lines are deliberately delivered verbatim to the shared
        # classifier; XML values use a field dictionary. Keep both events.
        assert prefix in rows
        assert [row for row in rows if isinstance(row, dict)] == [{"password": "qa-after-password"}]
    finally:
        scanner.close()
