"""Nested JSON values can be read without materializing the response."""

from __future__ import annotations

import json
import random

import pytest

from redposture_core.json_stream import JSONScalarStream


def test_nested_json_string_values_are_emitted_with_paths_across_byte_seams() -> None:
    payload = (
        b'{"Config":{"Env":["PASSWORD=qa-secret","plain"],"Labels":{"owner":"\\u043a\\u043b\\u044e\\u0447"}},"count":2}'
    )
    fragments: list[tuple[tuple[str | int, ...], str, bool]] = []
    parser = JSONScalarStream(lambda path, text, final: fragments.append((path, text, final)))
    for byte in payload:
        parser.feed(bytes((byte,)))
    parser.finish()
    assert parser.root_kind == "object"
    assert [item for item in fragments if item[2]] == [
        (("Config", "Env", 0), "PASSWORD=qa-secret", True),
        (("Config", "Env", 1), "plain", True),
        (("Config", "Labels", "owner"), "ключ", True),
    ]


def test_one_large_json_scalar_is_emitted_in_bounded_fragments() -> None:
    fragments: list[str] = []
    parser = JSONScalarStream(lambda _path, text, _final: fragments.append(text))
    parser.feed(b'{"content":"' + b"a" * 100_000 + b'"}')
    parser.finish()
    assert sum(map(len, fragments)) == 100_000
    assert max(map(len, fragments)) <= 4096


def test_json_object_key_is_spooled_without_a_length_cutoff() -> None:
    from redposture_core.discovery_values import DiskBackedText

    paths = []
    parser = JSONScalarStream(lambda path, _text, _final: paths.append(path))
    parser.feed(b'{"' + b"k" * 100_000 + b'":"value"}')
    parser.finish()
    assert isinstance(paths[0][0], DiskBackedText)
    assert sum(map(len, paths[0][0].iter_text_chunks())) == 100_000
    assert not parser.string_parts


def test_nonstring_values_preserve_paths_for_key_based_detection() -> None:
    primitives = []
    parser = JSONScalarStream(lambda _path, _text, _final: None, on_primitive=primitives.append)
    parser.feed(b'{"password":123456,"nested":[true,false,null,-1.5e2]}')
    parser.finish()
    assert primitives == [
        (("password",), 123456),
        (("nested", 0), True),
        (("nested", 1), False),
        (("nested", 2), None),
        (("nested", 3), -150.0),
    ]


@pytest.mark.parametrize("payload", [b'{"a":1,}', b'{"a":"bad\\x"}', b'{"a":1}garbage'])
def test_malformed_json_is_not_accepted_as_complete(payload: bytes) -> None:
    parser = JSONScalarStream(lambda _path, _text, _final: None)
    with pytest.raises(ValueError):
        parser.feed(payload)
        parser.finish()


def test_nested_json_scalar_stream_matches_decoded_strings_for_fixed_corpus() -> None:
    rng = random.Random(20261025)
    atoms = ["plain", "é", "ключ", 'quote"slash\\', "line\nnext", "😀", 0, -12, 3.5, True, False, None]

    def value(depth: int):
        if depth and rng.randrange(3) == 0:
            return {f"key_{index}": value(depth - 1) for index in range(rng.randrange(4))}
        if depth and rng.randrange(3) == 0:
            return [value(depth - 1) for _ in range(rng.randrange(4))]
        return rng.choice(atoms)

    def strings(item, path=()):
        if isinstance(item, str):
            return [(path, item)]
        if isinstance(item, dict):
            return [entry for key, child in item.items() for entry in strings(child, (*path, key))]
        if isinstance(item, list):
            return [entry for index, child in enumerate(item) for entry in strings(child, (*path, index))]
        return []

    for _ in range(100):
        item = value(4)
        payload = json.dumps(item, ensure_ascii=False).encode()
        actual = []
        pending = ""

        def on_string(path, text, final, output=actual):
            nonlocal pending
            pending += text
            if final:
                output.append((path, pending))
                pending = ""

        parser = JSONScalarStream(on_string)
        offset = 0
        while offset < len(payload):
            width = rng.randint(1, 13)
            parser.feed(payload[offset : offset + width])
            offset += width
        parser.finish()
        assert actual == strings(item)
