"""Short completed secrets need no empty entropy/PEM candidate catalogs."""

from __future__ import annotations

import pytest

from redposture_core import secret_detection as sd


def test_no_word_candidate_does_not_build_unused_pem_spans(monkeypatch: pytest.MonkeyPatch) -> None:
    class NoPEM:
        def finditer(self, _text):
            pytest.fail("no entropy word candidate can use a PEM span")

    monkeypatch.setattr(sd, "_PEM_BLOCK_RE", NoPEM())
    matches = sd.scan_value('password="short-secret"\n')
    assert [(m.detector, m.value, m.object_path) for m in matches] == [("password", "short-secret", "$")]


@pytest.mark.parametrize("value", ["neutral", 'password="short-secret"', 'token="small"', "пароль λ", "url=http://x"])
def test_empty_entropy_word_stream_keeps_explicit_matches(value: str) -> None:
    assert not sd._WORD_RE.search(value)
    with_entropy = sd.scan_value(value)
    explicit_only = sd.scan_value(value, enabled=[name for name in sd.detector_names() if name != "high_entropy"])
    assert with_entropy == explicit_only
