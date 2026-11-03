"""A complete short assignment preserves the original stream's events."""

from __future__ import annotations

import pytest

from redposture_core import discovery_text as text
from redposture_core.discovery_values import DiskBackedText


def _events(source: str, chunk: int):
    values, reasons = [], []

    def normalize(value):
        if isinstance(value, DiskBackedText):
            return "".join(value.iter_text_chunks())
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        return value

    def publish(value):
        values.append(normalize(value))

    scanner = text.DiscoveryTextStream(publish, reasons.append, portion=128)
    try:
        for offset in range(0, len(source), chunk):
            scanner.feed(source[offset : offset + chunk])
        scanner.finish()
    finally:
        scanner.close()
    return values, reasons


def test_short_closed_assignment_does_not_enter_unrelated_xml_heuristic(monkeypatch: pytest.MonkeyPatch) -> None:
    class NoXML:
        def search(self, *args):
            pytest.fail("a closed single assignment with no XML needs no XML state-machine search")

    monkeypatch.setattr(text, "_XML_HEAD", NoXML())
    assert _events('password="closed-secret"\n', 100) == (['password="closed-secret"\n'], [])


@pytest.mark.parametrize(
    "source",
    [
        'password="closed-secret"\n',
        "\tapi_key='ключ-λ' \r\n",
        'password="escaped\\"quote"\n',
        'password="unfinished\nmore',
        'password="first"\ntoken="second"\n',
        'password="<password>nested</password>"\n',
        'note="Bearer abcdef0123456789"\n',
        'password="-----BEGIN PRIVATE KEY-----x"\n',
        'password="long-' + "q" * 300 + '"\n',
        "password=\"prefix\"\nWITH\nPASSWORD 'other-secret'\n",
        'password="first"\n<password>second</password>\n',
    ],
)
@pytest.mark.parametrize("chunk", [1, 7, 31, 1000])
def test_short_line_emissions_match_legacy_parser(monkeypatch: pytest.MonkeyPatch, source: str, chunk: int) -> None:
    actual = _events(source, chunk)

    class Legacy:
        def fullmatch(self, *args):
            return None

    with monkeypatch.context() as patch:
        patch.setattr(text, "_SINGLE_ASSIGNMENT_LINE", Legacy())
        expected = _events(source, chunk)
    assert actual == expected
