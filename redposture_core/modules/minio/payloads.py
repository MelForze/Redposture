"""Bounded disk-backed parsing of encoded objects and archive members."""

from __future__ import annotations

import codecs
import gzip
import re
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from typing import Any

from ...discovery_paths import Text, concat_discovery_text
from ...discovery_tar import open_tar_stream
from ...discovery_text import DiscoveryTextStream
from ...discovery_values import DiskBackedText
from ...discovery_zip import BoundedZipFile
from ...scheduler import NestedSchedulerCancelled

_PORTION = 65_536
_BROKEN_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ufffd]+")


def _recover_text(
    stream: Any,
    path: Text,
    encoding: str,
    *,
    publish: Callable[[Any, Text], None],
    partial: Callable[[str], None],
    check: Callable[[], None],
) -> None:
    """Keep completed text findings, never join candidates across bad bytes."""
    stream.seek(0)
    decoder = codecs.getincrementaldecoder(encoding)("replace")

    def make_scanner() -> DiscoveryTextStream:
        return DiscoveryTextStream(lambda value: publish(value, path), partial, portion=_PORTION)

    scanner = make_scanner()

    def feed(text: str) -> None:
        nonlocal scanner
        start = 0
        for boundary in _BROKEN_TEXT.finditer(text):
            check()
            scanner.feed(text[start : boundary.start()])
            # close abandons only an unfinished candidate; finish would turn
            # an interrupted unquoted password into a false complete value.
            scanner.close()
            scanner = make_scanner()
            start = boundary.end()
        scanner.feed(text[start:])

    try:
        while True:
            check()
            chunk = stream.read(_PORTION)
            if not chunk:
                break
            feed(decoder.decode(chunk))
        feed(decoder.decode(b"", final=True))
        scanner.finish()
    finally:
        scanner.close()


def needs_payload_reader(prefix: bytes, key: str) -> bool:
    return (
        prefix.startswith(
            (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")
        )
        or b"\0" in prefix[:4]
        or key.lower().endswith((".zip", ".tar", ".gz", ".tgz"))
    )


def _encoding(prefix: bytes) -> str:
    if prefix.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if prefix.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if len(prefix) >= 8:
        # Only infer BOM-less UTF-16 from a consistent ASCII/NUL pattern.
        sample = prefix[:8]
        if sample[1::2] == bytes(4) and all(32 <= x < 127 or x in b"\r\n\t" for x in sample[::2]):
            return "utf-16le"
        if sample[::2] == bytes(4) and all(32 <= x < 127 or x in b"\r\n\t" for x in sample[1::2]):
            return "utf-16be"
    return "utf-8"


def scan_payload_file(
    stream: Any,
    path: Text,
    *,
    publish: Callable[[Any, Text], None],
    partial: Callable[[str], None],
    check: Callable[[], None],
    key: str = "",
    depth: int = 0,
) -> None:
    """Inspect a completed source; every decoded read is portioned/deadlined."""
    if depth > 4:
        partial("archive_depth")
        return

    def child(member: Any, name: Text) -> None:
        with tempfile.SpooledTemporaryFile(max_size=_PORTION) as retained:
            while True:
                check()
                chunk = member.read(_PORTION)
                if not chunk:
                    break
                retained.write(chunk)
            retained.seek(0)
            scan_payload_file(
                retained,
                concat_discovery_text(path, "/file/", name),
                publish=publish,
                partial=partial,
                check=check,
                depth=depth + 1,
            )

    check()
    prefix = stream.read(512)
    stream.seek(0)
    text_encoding: str | None = None
    try:
        if prefix.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=stream, mode="rb") as decoded:
                with tempfile.SpooledTemporaryFile(max_size=_PORTION) as retained:
                    while True:
                        check()
                        chunk = decoded.read(_PORTION)
                        if not chunk:
                            break
                        retained.write(chunk)
                    retained.seek(0)
                    scan_payload_file(retained, path, publish=publish, partial=partial, check=check, depth=depth + 1)
            return
        if prefix.startswith(b"PK"):
            with BoundedZipFile(stream, check_deadline=check) as archive:
                for member in archive.infolist():
                    check()
                    if not member.is_dir():
                        with archive.open(member) as source:
                            child(source, member.filename)
            return
        if prefix[257:262] == b"ustar" or key.lower().endswith((".tar", ".tgz")):
            with open_tar_stream(stream, check=check) as tar_archive:
                for member in tar_archive:
                    check()
                    if member.isfile():
                        source = tar_archive.extractfile(member)
                        if source is None:
                            partial("archive_member_unreadable")
                        else:
                            with source:
                                child(source, member.name)
            return
        if key.lower().endswith((".zip", ".gz")):
            # A filename is not a format proof. Preserve readable plaintext
            # while exposing the archive/content mismatch as incomplete.
            partial("archive_format_mismatch")
        text_encoding = _encoding(prefix)
        decoder = codecs.getincrementaldecoder(text_encoding)("strict")
        value = DiskBackedText()
        retained_value = False
        try:
            while True:
                check()
                chunk = stream.read(_PORTION)
                if not chunk:
                    break
                text = decoder.decode(chunk)
                if "\0" in text:
                    raise UnicodeError("binary data")
                value.append_text(text)
            value.append_text(decoder.decode(b"", final=True))
            value.finish()
            publish(value, path)
            retained_value = True
        finally:
            if not retained_value:
                value.close()
    except NestedSchedulerCancelled:
        raise
    except UnicodeError:
        partial("binary_or_unsupported_encoding")
        if text_encoding is not None:
            _recover_text(stream, path, text_encoding, publish=publish, partial=partial, check=check)
    except (EOFError, gzip.BadGzipFile, tarfile.TarError, zipfile.BadZipFile, RuntimeError, ValueError):
        partial("invalid_archive_or_payload")
