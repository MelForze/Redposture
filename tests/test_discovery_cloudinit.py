"""Shared literal cloud-init block parsing, without general YAML guessing."""

from __future__ import annotations

import base64

import pytest

from redposture_core.discovery_cloudinit import CloudInitPasswords
from redposture_core.discovery_engine import _scan_portioned_value, _scan_text_chunks
from redposture_core.discovery_rules import analyze_value
from redposture_core.discovery_values import DiskBackedText


def text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


@pytest.mark.parametrize("portion", [1, 3, 64, 65536])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_literal_list_keeps_large_password_and_ignores_other_fields(portion, newline):
    secret = "Ab0λ " * 20000
    body = newline.join(
        [
            "#cloud-config",
            "chpasswd:",
            "  list: |",
            "    root:" + secret,
            "    dev:second-password",
            "  expire: false",
            "ssh_authorized_keys:",
            "  - ordinary-public-key",
            "",
        ]
    )
    found = []
    partial = []
    reader = CloudInitPasswords(found.append, partial.append)
    try:
        for offset in range(0, len(body), portion):
            reader.feed(body[offset : offset + portion])
        reader.finish()
    finally:
        reader.close()
    assert not partial
    assert [text(value) for value in found] == [secret, "second-password"]


@pytest.mark.parametrize("entry", ["scalar", "common", "disk", "stream", "base64"])
def test_shared_scanners_extract_actual_password(entry):
    secret = "inactive-cloud-password"
    body = "#cloud-config\nchpasswd:\n  list: |\n    root:" + secret + "\n  expire: false\n"
    if entry == "scalar":
        values = [r.value for r in analyze_value(body) if r.available]
    elif entry == "stream":
        rows, complete = _scan_text_chunks((body[i : i + 3] for i in range(0, len(body), 3)), "$", 64)
        assert complete
        values = [r.value for r in rows]
    elif entry == "disk":
        with DiskBackedText() as source:
            source.append_text(body)
            source.finish()
            rows, _, complete = _scan_portioned_value(source, "$", 64)
            assert complete
            values = [r.value for r in rows]
    else:
        value = base64.b64encode(body.encode()).decode() if entry == "base64" else body
        rows, _, complete = _scan_portioned_value(value, "$", 65536)
        assert complete
        values = [r.value for r in rows]
    assert [text(value) for value in values] == [secret]


@pytest.mark.parametrize(
    "body",
    [
        "chpasswd:\n  list: |\n    root:not-a-cloud-config\n",
        "#cloud-config\nssh_authorized_keys:\n  - ordinary-public-key\n",
        "#cloud-config\nchpasswd:\n  list: |\n    root:********\n",
    ],
)
def test_unrelated_content_and_placeholders_do_not_become_passwords(body):
    found = []
    reader = CloudInitPasswords(found.append, lambda _: None)
    try:
        reader.feed(body)
        reader.finish()
    finally:
        reader.close()
    assert not found


def test_interrupted_password_is_not_published():
    found = []
    reader = CloudInitPasswords(found.append, lambda _: None)
    reader.feed("#cloud-config\nchpasswd:\n  list: |\n    root:completed-password\n    dev:" + "Ab0λ" * 20000)
    reader.close()
    assert [text(value) for value in found] == ["completed-password"]


def test_scalar_password_at_eof_keeps_original_trailing_spaces():
    body = "#cloud-config\nchpasswd:\n  list: |\n    root:inactive-password  "
    assert [row.value for row in analyze_value(body) if row.available] == ["inactive-password  "]
