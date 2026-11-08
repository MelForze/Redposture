"""Shared bounded discovery engine; product adapters supply values and locators.

The engine owns inspection and completeness semantics, not authentication,
network traversal, selectors or product-specific source enumeration.
"""

from __future__ import annotations

import codecs
import json
import re
import tempfile
import time
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any

from .discovery_containers import DiskContainer
from .discovery_csv import CSVCell
from .discovery_encoded import (
    compressed_text_prefix,
    decode_disk_structured_blob,
    encoded_text_prefix,
    mime_text_prefix,
)
from .discovery_keys import disk_key_hint
from .discovery_matches import SpoolingSecretMatches
from .discovery_paths import Text, concat_discovery_text, json_discovery_path, path_suffix
from .discovery_payloads import scan_payload_file
from .discovery_text import _XML_HEAD, DiscoveryTextStream, _Value
from .discovery_values import DiskBackedText
from .json_stream import JSONPath, JSONScalarStream
from .secret_detection import SecretMatch, _key_detector, is_secret_field_name, scan_disk_atomic_token, scan_value


def _minimum_json_size(value: Any, limit: int) -> int:
    """Cheap lower bound that rejects large strings before JSON copies them."""
    pending = [value]
    visited: set[int] = set()
    size = 0
    while pending and size <= limit:
        item = pending.pop()
        if isinstance(item, (str, bytes)):
            size += len(item) + 2
        elif isinstance(item, (DiskBackedText, DiskContainer)):
            return limit + 1
        elif isinstance(item, (dict, list, tuple)):
            if id(item) in visited:
                continue
            visited.add(id(item))
            size += 2
            if isinstance(item, dict):
                for key, child in item.items():
                    if isinstance(key, DiskBackedText):
                        return limit + 1
                    size += len(key) + 3 if isinstance(key, str) else 1
                    pending.append(child)
                    if size > limit:
                        return size
            else:
                # Do not duplicate a huge container merely to reject it.
                size += max(0, len(item) - 1)
                if size > limit:
                    return size
                pending.extend(item)
        else:
            size += 1
    return size


def _bounded_json_size(value: Any, limit: int) -> int | None:
    if _minimum_json_size(value, limit) > limit:
        return None
    # Mapping portions commonly contain one small string pair. The C encoder
    # avoids a Python generator per JSON field, but only after bounding the
    # input; larger/nested values retain the incremental path below.
    small_text = type(value) is str and len(value) <= 65_536
    if type(value) is dict and len(value) == 1:
        key, child = next(iter(value.items()))
        small_text = type(key) is str and type(child) is str and len(key) + len(child) <= 65_536
    if small_text:
        size = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
        return size if size <= limit else None
    size = 0
    for chunk in json.JSONEncoder(ensure_ascii=False, default=str).iterencode(value):
        if len(chunk) > limit - size:
            return None
        size += len(chunk.encode("utf-8"))
        if size > limit:
            return None
    return size


def _text_prefix(value: str | bytes) -> str:
    for position in range(0, len(value), 65_536):
        part = value[position : position + 65_536].lstrip()
        if part:
            prefix = part[:4096]
            return prefix.decode("utf-8", errors="replace") if isinstance(prefix, bytes) else prefix
    return ""


def _json_container_prefix(value: str | bytes) -> bool:
    """Distinguish a possible JSON container from plain labels such as [INFO]."""
    prefix = _text_prefix(value)
    if not prefix or prefix[0] not in "{[":
        return False
    tail = prefix[1:].lstrip()
    if not tail:
        return True  # Keep genuinely incomplete JSON subject to validation.
    if prefix[0] == "{":
        return tail[0] in '"}'
    if tail[0] in '"]{[':
        return True
    if tail[0] in "-0123456789":
        number = re.match(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", tail)
        if number is None:
            return tail == "-"  # A split negative JSON number is still possible.
        remainder = tail[number.end() :].lstrip()
        return not remainder or remainder[0] in ",]" or remainder in {".", "e", "E", "e+", "e-", "E+", "E-"}
    for literal in ("true", "false", "null"):
        if literal.startswith(tail):
            return True
        if tail.startswith(literal) and (len(tail) == len(literal) or tail[len(literal)] in " \t\r\n,]"):
            return True
    return False


def _scan_disk_json(
    value: DiskBackedText, path: str, portion_bytes: int, decode_depth: int, deadline: float | None = None
) -> tuple[list[Any], bool]:
    from .discovery_context import JSONFieldContext

    matches = SpoolingSecretMatches()
    covered = True
    scalar: _Value | None = None

    def visit(parts: JSONPath, value: Any, field_name: str | None = None) -> None:
        nonlocal covered
        named = bool(parts) and isinstance(parts[-1], (str, DiskBackedText))
        parent = parts[:-1] if named else parts
        location = json_discovery_path(parts if field_name is not None else parent, path)
        found, _size, complete = _scan_portioned_value(
            {parts[-1]: value} if named and field_name is None else value,
            location,
            portion_bytes,
            _decode_depth=decode_depth,
            _deadline=deadline,
            _field_name=field_name,
        )
        matches.extend(found)
        covered &= complete
        if reason := getattr(found, "incomplete_reason", None):
            matches.incomplete_reason = reason

    def text(parts: JSONPath, chunk: str, final: bool) -> None:
        nonlocal scalar
        if scalar is None:
            scalar = _Value(portion_bytes)
        scalar.append(chunk)
        if final:
            completed = scalar.finish()
            scalar = None
            contexts.value(parts, completed)

    def context_partial(reason: str) -> None:
        nonlocal covered
        covered = False
        matches.incomplete_reason = reason

    contexts = JSONFieldContext(visit, context_partial, deadline=deadline)
    decoder = JSONScalarStream(
        text,
        on_primitive=lambda item: contexts.value(*item),
        deadline=deadline,
        on_container=contexts.container,
        on_container_end=contexts.end,
    )
    try:
        for chunk in value.iter_text_chunks():
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("discover_time")
            decoder.feed(chunk.encode("utf-8"))
        decoder.finish()
    except TimeoutError:
        matches.incomplete_reason = "discover_time"
        covered = False
    except OSError:
        matches.incomplete_reason = "storage_failure"
        covered = False
    except (ValueError, UnicodeError):
        matches.incomplete_reason = "invalid_json"
        covered = False
    finally:
        try:
            contexts.close(flush=covered or getattr(matches, "incomplete_reason", None) == "invalid_json")
        finally:
            decoder.close()
            if scalar is not None:
                scalar.close()
    return matches, covered


def _small_encoded_blob(value: Any) -> bool:
    if isinstance(value, bytes):
        # Byte sources require format/encoding dispatch before scalar rules.
        # Passing a mapping containing bytes to the small JSON shortcut would
        # otherwise turn its content into a replacement-decoded text value.
        return True
    if isinstance(value, str):
        return (
            compressed_text_prefix(value)
            or mime_text_prefix(value)
            or _json_container_prefix(value)
            or value.lstrip().startswith("#cloud-config")
            # XML elements/attributes use the same bounded lexer at every
            # size; the old scalar regex had 2048/4096-character cutoffs.
            or ("<" in value and _XML_HEAD.search(value) is not None)
        )
    if isinstance(value, Mapping):
        return (len(value) == 1 and "$binary" in value) or any(_small_encoded_blob(child) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_small_encoded_blob(child) for child in value)
    return False


def _scan_decoded_text(
    value: DiskBackedText, path: str, portion_bytes: int, decode_depth: int, deadline: float | None = None
) -> tuple[list[Any], bool]:
    for chunk in value.iter_text_chunks(max_chars=4096):
        prefix = chunk.lstrip()
        if prefix:
            if prefix.startswith(("{", "[")):
                return _scan_disk_json(value, path, portion_bytes, decode_depth, deadline)
            break
    return _scan_text_chunks(value.iter_text_chunks(), path, portion_bytes, decode_depth, deadline)


def _scan_small_value(value: Any, path: str, field_name: str | None = None) -> tuple[list[SecretMatch], bool]:
    reason: str | None = None

    def incomplete(detail: str) -> None:
        nonlocal reason
        if reason is None:
            reason = detail

    try:
        matches = scan_value(value, object_path=path, _on_incomplete=incomplete, _field_name=field_name)
    except OSError:
        retained = SpoolingSecretMatches()
        retained.incomplete_reason = "storage_failure"
        return retained, False
    if reason is not None:
        retained = SpoolingSecretMatches(matches)
        retained.incomplete_reason = reason
        return retained, False
    return matches, True


def _scan_text_chunks(
    chunks: Iterable[str], path: str, portion_bytes: int, decode_depth: int = 0, deadline: float | None = None
) -> tuple[list[Any], bool]:
    matches = SpoolingSecretMatches()
    covered = True

    def incomplete(reason: str) -> None:
        nonlocal covered
        covered = False
        matches.incomplete_reason = reason

    def emit(item: Any) -> None:
        nonlocal covered
        if isinstance(item, CSVCell):
            found, _size, complete = _scan_portioned_value(item, path, portion_bytes, _deadline=deadline)
            matches.extend(found)
            covered &= complete
        elif isinstance(item, SecretMatch):
            found, _size, complete = _scan_portioned_value(item, path, portion_bytes, _deadline=deadline)
            matches.extend(found)
            covered &= complete
        elif isinstance(item, DiskBackedText):
            if item.obvious_placeholder or (
                item.uniform and next(item.iter_text_chunks(max_chars=1), "") not in {"{", "["}
            ):
                return
            found = scan_disk_atomic_token(item, object_path=path, deadline=deadline)
            # A completed disk-backed neutral scalar is fully inspected even
            # when it is neither a token nor a structured encoding.
            complete = True
            if not found:
                decoded = decode_disk_structured_blob(item, layers=max(0, 2 - decode_depth), deadline=deadline)
                if decoded is not None:
                    try:
                        found, complete = _scan_decoded_text(
                            decoded.text, path, portion_bytes, decode_depth + decoded.layers, deadline
                        )
                    finally:
                        decoded.text.close()
            matches.extend(found)
            covered &= complete
        elif isinstance(item, Mapping) and any(isinstance(child, DiskBackedText) for child in item.values()):
            found, _size, complete = _scan_portioned_value(
                item, path, portion_bytes, _decode_depth=decode_depth, _deadline=deadline
            )
            matches.extend(found)
            covered &= complete
        else:
            found, complete = _scan_small_value(item, path)
            if isinstance(item, str) and scanner.cloudinit is not None and scanner.cloudinit.active:
                # The incremental block reader already owns this grammar.
                # Ordinary lexer leftovers may contain the same whole block;
                # keep their other rules without publishing it a second time.
                found = [match for match in found if "cloud_init_password" not in match.rule_ids]
            matches.extend(found)
            covered &= complete

    scanner = DiscoveryTextStream(emit, incomplete, portion=portion_bytes)
    try:
        for chunk in chunks:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("discover_time")
            scanner.feed(chunk)
        scanner.finish()
    except OSError:
        matches.incomplete_reason = "storage_failure"
        covered = False
    except TimeoutError:
        covered = False
    finally:
        scanner.close()
    return matches, covered


def _scan_disk_mapping_key(
    key: DiskBackedText,
    child: Any,
    path: str,
    portion: int,
    decode_depth: int,
    deadline: float | None,
) -> tuple[list[Any], int, bool]:
    matches = SpoolingSecretMatches()
    inspected = key.byte_length
    try:
        hint = disk_key_hint(key, deadline)
        nested, size, covered = _scan_portioned_value(
            {hint: child}, "$", portion, _decode_depth=decode_depth, _deadline=deadline
        )
        inspected += size
        for match in nested:
            relative_prefix = json_discovery_path((hint,))
            assert isinstance(relative_prefix, str)
            full_path = concat_discovery_text(
                json_discovery_path((key,), path), path_suffix(match.object_path, relative_prefix)
            )
            value = match.value
            if not isinstance(value, DiskBackedText):
                disk = DiskBackedText()
                try:
                    for offset in range(0, len(value), 65536):
                        disk.append_text(value[offset : offset + 65536])
                    disk.finish()
                except BaseException:
                    disk.close()
                    raise
                value = disk
            matches.append(replace(match, object_path=full_path, value=value))
        if reason := getattr(nested, "incomplete_reason", None):
            matches.incomplete_reason = reason
        return matches, inspected, covered
    except TimeoutError:
        matches.incomplete_reason = "discover_time"
    except OSError:
        matches.incomplete_reason = "storage_failure"
    return matches, inspected, False


def _scan_payload_source(
    source: Any,
    path: Text,
    portion: int,
    decode_depth: int,
    deadline: float | None,
    field_name: str | None = None,
) -> tuple[list[Any], bool]:
    matches = SpoolingSecretMatches()
    complete = True

    def check() -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("discover_time")

    def partial(reason: str) -> None:
        nonlocal complete
        complete = False
        if matches.incomplete_reason is None:
            matches.incomplete_reason = reason

    def publish(item: Any, location: Text) -> None:
        found, _size, covered = _scan_portioned_value(
            item, location, portion, _decode_depth=decode_depth, _deadline=deadline, _field_name=field_name
        )
        matches.extend(found)
        if not covered:
            partial(getattr(found, "incomplete_reason", None) or "incomplete_payload")
        if isinstance(item, DiskBackedText) and not any(match.value is item for match in found):
            item.close()

    try:
        scan_payload_file(source, path, publish=publish, partial=partial, check=check)
    except TimeoutError:
        partial("discover_time")
    except OSError:
        partial("storage_failure")
    return matches, complete


def _scan_byte_source(
    value: bytes,
    path: Text,
    portion: int,
    decode_depth: int,
    deadline: float | None,
    field_name: str | None = None,
) -> tuple[list[Any], int, bool]:
    try:
        with tempfile.SpooledTemporaryFile(max_size=portion) as retained:
            for offset in range(0, len(value), portion):
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("discover_time")
                retained.write(value[offset : offset + portion])
            retained.seek(0)
            matches, complete = _scan_payload_source(retained, path, portion, decode_depth, deadline, field_name)
            return matches, len(value), complete
    except (OSError, TimeoutError) as exc:
        matches = SpoolingSecretMatches()
        matches.incomplete_reason = "discover_time" if isinstance(exc, TimeoutError) else "storage_failure"
        return matches, len(value), False


def _scan_bson_binary_source(
    value: Mapping[str, Any],
    path: Text,
    portion: int,
    decode_depth: int,
    deadline: float | None,
    field_name: str | None,
) -> tuple[list[Any], int, bool]:
    from .discovery_base64 import decoded_base64_file

    def check() -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("discover_time")

    try:
        schema = value["$binary"]
        if not isinstance(schema, Mapping) or set(schema) != {"base64", "subType"}:
            raise ValueError("unsupported BSON binary schema")
        encoded, subtype = schema["base64"], schema["subType"]
        if (
            not isinstance(encoded, (str, DiskBackedText))
            or not isinstance(subtype, str)
            or not re.fullmatch(r"[0-9a-fA-F]{2}", subtype)
        ):
            raise ValueError("unsupported BSON binary schema")
        # Encrypted/compressed or user-defined BSON subtypes need their own
        # schema. Only generic binary declares arbitrary readable byte content.
        if subtype.lower() != "00":
            matches = SpoolingSecretMatches()
            matches.incomplete_reason = "unsupported_binary_subtype"
            return matches, 0, False
        with decoded_base64_file(encoded, check) as (source, size):
            scanned, complete = _scan_payload_source(source, path, portion, decode_depth, deadline, field_name)
            return scanned, size, complete
    except (ValueError, UnicodeError):
        matches = SpoolingSecretMatches()
        matches.incomplete_reason = "invalid_binary_encoding"
        return matches, 0, False
    except (OSError, TimeoutError) as exc:
        matches = SpoolingSecretMatches()
        matches.incomplete_reason = "discover_time" if isinstance(exc, TimeoutError) else "storage_failure"
        return matches, 0, False


def _scan_portioned_value(
    value: Any,
    path: Text,
    portion_bytes: int,
    *,
    _decode_depth: int = 0,
    _deadline: float | None = None,
    _field_name: str | None = None,
) -> tuple[list[Any], int, bool]:
    """Scan a materialized record without treating its size as a total quota.

    Source readers still own network bounds. Here each bounded part is scanned
    and released before visiting the next part of a large record. Recognized
    continuous tokens and secret fields use disk-backed validation; unknown
    long grammars remain incomplete instead of being guessed from their size.
    """
    # This bounds local regex/JSON allocations, not how much source data is
    # inspected. Larger values continue through the streaming text reader.
    portion_bytes = max(1, min(portion_bytes, 65_536))
    if isinstance(value, CSVCell):
        csv_path = concat_discovery_text(path, f".csv[{value.row}]")
        if isinstance(value.name, DiskBackedText):
            return _scan_disk_mapping_key(
                value.name, value.value, str(csv_path), portion_bytes, _decode_depth, _deadline
            )
        return _scan_portioned_value(
            {value.name: value.value}, csv_path, portion_bytes, _decode_depth=_decode_depth, _deadline=_deadline
        )
    if isinstance(path, DiskBackedText):
        nested, size, covered = _scan_portioned_value(
            value, "$", portion_bytes, _decode_depth=_decode_depth, _deadline=_deadline, _field_name=_field_name
        )
        matches = SpoolingSecretMatches()
        for match in nested:
            retained = match.value
            if not isinstance(retained, DiskBackedText):
                retained = DiskBackedText()
                try:
                    retained.append_text(match.value)
                    retained.finish()
                except BaseException:
                    retained.close()
                    raise
            matches.append(
                replace(
                    match, object_path=concat_discovery_text(path, path_suffix(match.object_path, "$")), value=retained
                )
            )
        matches.incomplete_reason = getattr(nested, "incomplete_reason", None)
        return matches, size, covered
    if isinstance(value, SecretMatch):
        size = value.value.byte_length if isinstance(value.value, DiskBackedText) else len(value.value.encode("utf-8"))
        if value.detector == "certificate":
            return [], size, True
        if value.detector == "basic_auth":
            from .discovery_credentials import valid_basic_carrier

            return (
                (
                    [
                        replace(
                            value,
                            object_path=path,
                            rule_ids=("basic_auth", "credential_pair"),
                            detector_aliases=("password",),
                        )
                    ]
                    if valid_basic_carrier(value.value, deadline=_deadline)
                    else []
                ),
                size,
                True,
            )
        if value.detector in {"jwt", "jwe"}:
            if isinstance(value.value, DiskBackedText):
                return scan_disk_atomic_token(value.value, object_path=path, deadline=_deadline), size, True
            from .discovery_rules import _validated_jwe, _validated_jwt

            validator = _validated_jwt if value.detector == "jwt" else _validated_jwe
            return (
                ([replace(value, object_path=path, confidence="high")] if validator(value.value) else []),
                size,
                True,
            )
        return [replace(value, object_path=path)], size, True
    if _deadline is not None and time.monotonic() >= _deadline:
        # A small plain prefix may have arrived in the response that reported
        # the timeout. Keep its finished findings, but do not start expansion
        # or a new large scan after the target deadline.
        try:
            received_size = _bounded_json_size(value, portion_bytes)
        except (TypeError, ValueError):
            received_size = None
        if received_size is not None and not _small_encoded_blob(value):
            small_matches, _complete = _scan_small_value(value, path)
            return small_matches, received_size, False
        return [], 0, False
    if isinstance(value, bytes):
        return _scan_byte_source(value, path, portion_bytes, _decode_depth, _deadline, _field_name)
    if isinstance(value, Mapping) and len(value) == 1 and "$binary" in value:
        return _scan_bson_binary_source(value, path, portion_bytes, _decode_depth, _deadline, _field_name)
    if isinstance(value, DiskBackedText):
        key = _field_name or path.rsplit(".", 1)[-1]
        if value.obvious_placeholder:
            return [], value.byte_length, True
        prefix = next(value.iter_text_chunks(max_chars=4096), "").lstrip()
        from .discovery_credentials import valid_basic_carrier
        from .discovery_dsn import dsn_carrier

        dsn = dsn_carrier(value, deadline=_deadline)
        if dsn.placeholder:
            return [], value.byte_length, True
        if not dsn.complete:
            matches = SpoolingSecretMatches()
            matches.incomplete_reason = "unterminated_connection_dsn"
            return matches, value.byte_length, False
        if key.lower().split(".")[-1] == "auth" and valid_basic_carrier(value, deadline=_deadline, encoded=True):
            return (
                [SecretMatch("encoded_credentials", "high", path, value, ("registry_auth", "credential_pair"))],
                value.byte_length,
                True,
            )
        if _json_container_prefix(prefix):
            json_matches, covered = _scan_disk_json(value, path, portion_bytes, _decode_depth, _deadline)
            return json_matches, value.byte_length, covered
        try:
            decoded = decode_disk_structured_blob(value, layers=max(0, 2 - _decode_depth), deadline=_deadline)
        except TimeoutError:
            return [], value.byte_length, False
        if decoded is not None and not decoded.structured and is_secret_field_name(key):
            # An opaque password can happen to be printable base64. Keep its
            # actual stored value unless the decoded payload has structure.
            decoded.text.close()
            decoded = None
        if decoded is not None:
            try:
                decoded_matches, covered = _scan_decoded_text(
                    decoded.text, path, portion_bytes, _decode_depth + decoded.layers, _deadline
                )
                return decoded_matches, value.byte_length, covered
            finally:
                decoded.text.close()
        if compressed_text_prefix(prefix):
            return [], value.byte_length, False
        atomic_matches = scan_disk_atomic_token(value, object_path=path, deadline=_deadline)
        if atomic_matches:
            return atomic_matches, value.byte_length, True
        if is_secret_field_name(key) and value.byte_length >= 4:
            from .discovery_confirmation import confirm_disk_field

            confirmed = confirm_disk_field(value, field_name=key, deadline=_deadline)
            if confirmed is None:
                return [], value.byte_length, True
            detector = _key_detector(key)
            return (
                [
                    SecretMatch(
                        detector,
                        "high" if confirmed.score >= 75 else "medium" if confirmed.score >= 60 else "low",
                        path,
                        confirmed.value,
                        confirmed.detectors,
                        () if detector == "password" else ("secret",),
                    )
                ],
                value.byte_length,
                True,
            )
        if value.uniform and next(value.iter_text_chunks(max_chars=1), "") not in {"{", "["}:
            return [], value.byte_length, True
        text_matches, covered = _scan_text_chunks(
            value.iter_text_chunks(), path, portion_bytes, _decode_depth, _deadline
        )
        return text_matches, value.byte_length, covered
    try:
        small_size = _bounded_json_size(value, portion_bytes)
    except (TypeError, ValueError):
        return [], 0, False
    compressed = _small_encoded_blob(value) if small_size is not None else False
    if small_size is not None and not compressed:
        small_matches, complete = _scan_small_value(value, path, _field_name)
        return small_matches, small_size, complete
    if isinstance(value, Mapping):
        from .discovery_context import field_binding
        from .discovery_groups import credential_groups

        matches = SpoolingSecretMatches()
        total = 0
        complete = True
        try:
            binding = field_binding(value, deadline=_deadline)
            grouped_keys: set[str] = set()
            for group in credential_groups(value, deadline=_deadline):
                grouped_keys.update(group.fields)
                grouped = group.value()
                matches.append(SecretMatch(group.kind, "high", path, grouped, group.rules, group.aliases))
                total += grouped.byte_length
            for raw_key, child in value.items():
                if raw_key in grouped_keys:
                    continue
                if _deadline is not None and time.monotonic() >= _deadline:
                    complete = False
                    break
                if isinstance(raw_key, DiskBackedText):
                    nested, size, covered = _scan_disk_mapping_key(
                        raw_key, child, path, portion_bytes, _decode_depth, _deadline
                    )
                    matches.extend(nested)
                    total += size
                    complete &= covered
                    if reason := getattr(nested, "incomplete_reason", None):
                        matches.incomplete_reason = reason
                    continue
                key = str(raw_key)
                if binding is not None and raw_key == binding.key:
                    found, size, covered = _scan_portioned_value(
                        child,
                        json_discovery_path((key,), path),
                        portion_bytes,
                        _decode_depth=_decode_depth,
                        _deadline=_deadline,
                        _field_name=binding.field_name,
                    )
                    matches.extend(found)
                    complete &= covered
                    total += size
                    continue
                # A small key/value pair needs the parent's key context for the
                # detector that recognizes secrets by field name.
                pair = {key: child}
                try:
                    pair_size = _bounded_json_size(pair, portion_bytes)
                except (TypeError, ValueError):
                    pair_size = None
                child_size = (
                    _bounded_json_size(child, portion_bytes)
                    if pair_size is None and isinstance(child, (str, bytes))
                    else None
                )
                if (pair_size is not None or child_size is not None) and not _small_encoded_blob(child):
                    found, covered = _scan_small_value(pair, path)
                    matches.extend(found)
                    complete &= covered
                    total += pair_size if pair_size is not None else int(child_size or 0)
                else:
                    nested, size, covered = _scan_portioned_value(
                        child,
                        json_discovery_path((key,), path),
                        portion_bytes,
                        _decode_depth=_decode_depth,
                        _deadline=_deadline,
                        _field_name=key,
                    )
                    matches.extend(nested)
                    total += size
                    complete &= covered
                    if reason := getattr(nested, "incomplete_reason", None):
                        matches.incomplete_reason = reason
        except TimeoutError:
            matches.incomplete_reason = "discover_time"
            complete = False
        except OSError:
            matches.incomplete_reason = "storage_failure"
            complete = False
        return matches, total, complete
    if isinstance(value, (list, tuple, set)):
        matches = SpoolingSecretMatches()
        total = 0
        complete = True
        try:
            for index, child in enumerate(value):
                if _deadline is not None and time.monotonic() >= _deadline:
                    complete = False
                    break
                nested, size, covered = _scan_portioned_value(
                    child, f"{path}[{index}]", portion_bytes, _decode_depth=_decode_depth, _deadline=_deadline
                )
                matches.extend(nested)
                total += size
                complete &= covered
                if reason := getattr(nested, "incomplete_reason", None):
                    matches.incomplete_reason = reason
        except OSError:
            matches.incomplete_reason = "storage_failure"
            complete = False
        return matches, total, complete
    if not isinstance(value, (str, bytes)):
        return [], len(str(value).encode("utf-8", errors="replace")), True

    def text_chunks() -> Iterable[str]:
        if isinstance(value, bytes):
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
            for position in range(0, len(value), 65_536):
                yield decoder.decode(value[position : position + 65_536])
            tail = decoder.decode(b"", final=True)
            if tail:
                yield tail
        else:
            for position in range(0, len(value), 65_536):
                yield value[position : position + 65_536]

    key = _field_name or path.rsplit(".", 1)[-1]
    if compressed or encoded_text_prefix(value) or _json_container_prefix(value) or is_secret_field_name(key):
        disk_value = DiskBackedText()
        for chunk in text_chunks():
            if _deadline is not None and time.monotonic() >= _deadline:
                disk_value.close()
                return [], 0, False
            disk_value.append_text(chunk)
        disk_value.finish()
        found, size, covered = _scan_portioned_value(
            disk_value, path, portion_bytes, _decode_depth=_decode_depth, _deadline=_deadline, _field_name=_field_name
        )
        if not found:
            disk_value.close()
        return found, size, covered
    inspected = 0

    def measured_chunks() -> Iterable[str]:
        nonlocal inspected
        for chunk in text_chunks():
            inspected += len(chunk.encode("utf-8"))
            yield chunk

    text_matches, covered = _scan_text_chunks(measured_chunks(), path, portion_bytes, _decode_depth, _deadline)
    return text_matches, inspected, covered
