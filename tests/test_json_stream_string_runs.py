"""Batched JSON string runs retain character-stepped grammar and events."""

from __future__ import annotations

import json

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.json_stream import DiskJSONKey, JSONScalarStream


class CharacterStream(JSONScalarStream):
    """Reference dispatch: the original one-character feed state machine."""

    def feed(self, chunk):
        try:
            for char in self.decoder.decode(chunk):
                self._character(char)
        except BaseException:
            self.close()
            raise


def path_text(path):
    return tuple("".join(part.iter_text_chunks()) if isinstance(part, DiskBackedText) else part for part in path)


def trace(parser_type, payload, width):
    events = []
    parser = parser_type(
        lambda path, text, final: events.append(("string", path_text(path), text, final)),
        on_primitive=lambda item: events.append(("primitive", path_text(item[0]), item[1])),
        on_container=lambda path, kind: events.append(("start", path_text(path), kind)),
        on_container_end=lambda path, kind: events.append(("end", path_text(path), kind)),
    )
    failure = None
    try:
        for offset in range(0, len(payload), width):
            parser.feed(payload[offset : offset + width])
            assert sum(map(len, parser.string_parts)) == parser._string_chars
            assert parser._string_chars <= (4096 if parser.string_mode == "key" and parser._key is None else 4095)
        parser.finish()
    except (ValueError, UnicodeError) as exc:
        failure = (type(exc), str(exc))
    finally:
        parser.close()
    return events, failure, parser.root_kind


def string_leaves(value, path=()):
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        return [leaf for key, child in value.items() for leaf in string_leaves(child, (*path, key))]
    if isinstance(value, list):
        return [leaf for index, child in enumerate(value) for leaf in string_leaves(child, (*path, index))]
    return []


@pytest.mark.parametrize("ensure_ascii", [False, True])
@pytest.mark.parametrize("width", [1, 3, 17, 4095, 4096, 4097, 65536])
def test_batched_event_log_matches_character_reference_and_json_loads(ensure_ascii, width):
    original = {
        "ключ😀": ["a" * 4095 + "é" + "tail", "b" * 8192, "", 17, -2.5e3, True, False, None],
        "nested": {"long-" + "λ" * 4097: "head" + '\\"\n\t\b\f\r/' + "😀" + "tail"},
        "controls": "".join(map(chr, range(32))),
    }
    payload = json.dumps(original, ensure_ascii=ensure_ascii).encode()
    actual = trace(JSONScalarStream, payload, width)
    assert actual == trace(CharacterStream, payload, width)
    events, failure, kind = actual
    assert failure is None and kind == "object"
    completed, parts = [], []
    for event in events:
        if event[0] != "string":
            continue
        _tag, path, text, final = event
        assert len(text) <= 4096
        parts.append(text)
        if final:
            completed.append((path, "".join(parts)))
            parts.clear()
    assert completed == string_leaves(json.loads(payload))


@pytest.mark.parametrize("length", [4095, 4096, 4097, 8192, 8193, 12289])
@pytest.mark.parametrize("width", [31, 4096, 65536])
@pytest.mark.parametrize("ensure_ascii", [False, True])
def test_key_spill_threshold_and_write_boundaries_count_characters(monkeypatch, length, width, ensure_ascii):
    writes, paths = [], []
    original = DiskJSONKey.append_text

    def append(self, text):
        writes.append(len(text))
        return original(self, text)

    monkeypatch.setattr(DiskJSONKey, "append_text", append)
    key = "😀" * length
    payload = json.dumps({key: "value"}, ensure_ascii=ensure_ascii).encode()
    parser = JSONScalarStream(lambda path, _text, _final: paths.append(path))
    try:
        for offset in range(0, len(payload), width):
            parser.feed(payload[offset : offset + width])
        parser.finish()
        actual = paths[0][0]
        if length <= 4096:
            assert isinstance(actual, str) and actual == key
            assert writes == []
        else:
            assert isinstance(actual, DiskJSONKey)
            assert "".join(actual.iter_text_chunks()) == key
            assert writes[0] == 4097
            assert all(size <= 4096 for size in writes[1:])
            assert sum(writes) == length
    finally:
        parser.close()
        for path in paths:
            if isinstance(path[0], DiskBackedText):
                path[0].close()


def test_duplicate_keys_keep_both_original_string_events():
    payload = b'{"key":"first","key":"second"}'
    actual = trace(JSONScalarStream, payload, 65536)
    assert actual == trace(CharacterStream, payload, 65536)
    assert [event for event in actual[0] if event[0] == "string"] == [
        ("string", ("key",), "first", True),
        ("string", ("key",), "second", True),
    ]


def test_run_then_escape_uses_decoded_character_count_and_exact_final_events():
    fragments = []
    parser = JSONScalarStream(lambda path, text, final: fragments.append((path, text, final)))
    parser.feed(b'"' + b"a" * 4095)
    assert parser._string_chars == 4095 and len(parser.string_parts) == 1
    parser.feed(b"\\n" + b"b" * 4096 + b'"')
    parser.finish()
    assert fragments == [((), "a" * 4095 + "\n", False), ((), "b" * 4096, False), ((), "", True)]
    assert parser._string_chars == 0 and not parser.string_parts


@pytest.mark.parametrize(
    "tail",
    [
        b'"bad\\x"}',
        b'"bad\x00"}',
        b'"bad\x1f"}',
        b'"bad\\uD800x"}',
        b'"bad\\uDC00"}',
        b'"bad\\uD800\\u0041"}',
        b'"unterminated',
        b'"ok"}trailing',
        b'"bad\xff"}',
        b'"bad\xf0\x9f',
        b'"ok",}',
    ],
)
@pytest.mark.parametrize("width", [1, 4096, 65536])
def test_malformed_runs_keep_the_same_prefix_events_and_error_as_character_reference(tail, width):
    payload = b'{"password":"first-secret","neutral":"' + b"q" * 8200 + b'","broken":' + tail
    actual = trace(JSONScalarStream, payload, width)
    assert actual == trace(CharacterStream, payload, width)
    assert actual[1] is not None
    finals = [event for event in actual[0] if event[0] == "string" and event[-1]]
    if width == 1 or b"\xff" not in tail and b"\xf0" not in tail:
        # A strict UTF-8 decode error invalidates that entire feed chunk before
        # callbacks, exactly as the original incremental decoder did.
        assert ("string", ("password",), "first-secret", True) in finals


class CountedStream(JSONScalarStream):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.character_calls = 0
        self.append_sizes = []

    def _character(self, char):
        self.character_calls += 1
        return super()._character(char)

    def _append_string(self, text):
        self.append_sizes.append(len(text))
        return super()._append_string(text)


def test_plain_run_dispatch_count_is_bounded_by_chunks_not_value_characters():
    fragments = []
    length = 2 * 1024 * 1024
    parser = CountedStream(lambda _path, text, final: fragments.append((len(text), final)))
    parser.feed(b'{"value":"' + b"q" * length + b'"}')
    parser.finish()
    assert parser.character_calls < 32
    assert len(parser.append_sizes) <= length // 4096 + 4
    assert max(parser.append_sizes) <= 4096
    assert sum(size for size, _final in fragments) == length
    assert fragments[-1] == (0, True)


def test_deadline_changed_after_a_run_is_checked_before_another_4096_characters():
    events = []

    class ExpiringStream(CountedStream):
        def _append_string(self, text):
            result = super()._append_string(text)
            if len(text) > 1 and text[0] == "q":
                self.deadline = float("-inf")
            return result

    parser = ExpiringStream(lambda path, text, final: events.append((path, text, final)))
    parser.feed(b'{"password":"first-secret","neutral":"')
    before = len(parser.append_sizes)
    with pytest.raises(TimeoutError, match="discover_time"):
        parser.feed(b"q" * 100000)
    assert parser.append_sizes[before:] == [4096]
    assert (("password",), "first-secret", True) in events
    assert not any(path == ("neutral",) and final for path, _text, final in events)
    assert parser._string_chars == 0 and not parser.string_parts


def test_deadline_after_key_spill_closes_unfinished_file_without_mocking_time():
    paths = []

    class ExpiringKeyStream(JSONScalarStream):
        def _append_string(self, text):
            result = super()._append_string(text)
            if self._key is not None:
                paths.append(self._key.path)
                self.deadline = float("-inf")
            return result

    parser = ExpiringKeyStream(lambda *_args: None)
    with pytest.raises(TimeoutError, match="discover_time"):
        parser.feed(b'{"' + b"q" * 100000)
    assert paths and all(not path.exists() for path in paths)
    assert parser._key is None and parser._string_chars == 0
