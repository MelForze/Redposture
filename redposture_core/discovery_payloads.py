"""Product-neutral bounded parsing of encoded objects and archive members.

Adapters provide a completed seekable source, a locator and the target's
deadline/cancellation check. Parsing never opens the network or extracts files
into a user directory; completed values retain their full locator.
"""

from __future__ import annotations

import codecs
import gzip
import re
import tarfile
import tempfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from typing import Any

from .discovery_paths import Text, concat_discovery_text
from .discovery_tar import open_tar_stream
from .discovery_text import DiscoveryTextStream
from .discovery_values import DiskBackedText
from .discovery_zip import BoundedZipFile
from .scheduler import NestedSchedulerCancelled

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
    finish: bool = True,
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
        if finish:
            scanner.finish()
    finally:
        scanner.close()


def _key_suffix(key: Text) -> str:
    if isinstance(key, DiskBackedText):
        tail = ""
        for chunk in key.iter_text_chunks():
            tail = (tail + chunk)[-32:]
        return tail.lower()
    return key[-32:].lower()


def is_tar_header(prefix: bytes) -> bool:
    """A TAR-looking word is not proof; validate the bounded header checksum."""
    if len(prefix) < 512:
        return False
    try:
        tarfile.TarInfo.frombuf(prefix[:512], "utf-8", "surrogateescape")
    except tarfile.HeaderError:
        return False
    return True


def iter_payload_members(stream: Any, kind: str, check: Callable[[], None]) -> Iterator[tuple[Text, Any]]:
    """Iterate regular members with bounded metadata and caller-owned input.

    A declared TAR can be forward-only (including compressed input). The
    member is consumed before advancing, preserving completed members if a
    later trailer fails. ZIP retains the existing disk-backed catalog reader.
    """
    if kind == "zip":
        with BoundedZipFile(stream, check_deadline=check) as archive:
            for member in archive.infolist():
                check()
                if not member.is_dir():
                    with archive.open(member) as source:
                        yield member.filename, source
    elif kind == "tar":
        with open_tar_stream(stream, check=check) as archive:
            for member in archive:
                check()
                if member.isfile():
                    source = archive.extractfile(member)
                    if source is None:
                        raise tarfile.ReadError("archive member unreadable")
                    with source:
                        yield member.name, source
    else:
        raise ValueError(f"unsupported_archive:{kind}")


def needs_payload_reader(prefix: bytes, key: Text) -> bool:
    return (
        prefix.startswith(
            (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")
        )
        or b"\0" in prefix[:4]
        or is_tar_header(prefix)
        or _key_suffix(key).endswith((".zip", ".tar", ".gz", ".tgz"))
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
    key: Text = "",
    depth: int = 0,
    source_complete: bool = True,
) -> None:
    """Inspect a completed source; every decoded read is portioned/deadlined."""
    if depth > 4:
        partial("archive_depth")
        return

    def child(member: Any, name: Text, ordinal: int) -> None:
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
                concat_discovery_text(path, f"/member/{ordinal}/file/", name),
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
                    complete_gzip = True
                    try:
                        while True:
                            check()
                            # read1 publishes a decoded portion before a later
                            # missing trailer; read may lose that entire prefix
                            # while trying to fill its requested buffer.
                            chunk = decoded.read1(_PORTION)
                            if not chunk:
                                break
                            retained.write(chunk)
                    except (EOFError, gzip.BadGzipFile, zlib.error):
                        partial("invalid_archive_or_payload")
                        complete_gzip = False
                    retained.seek(0)
                    scan_payload_file(
                        retained,
                        path,
                        publish=publish,
                        partial=partial,
                        check=check,
                        key="content.tar"
                        if _key_suffix(key).endswith((".tar", ".tar.gz", ".tar.gzip", ".tgz"))
                        else "",
                        depth=depth + 1,
                        source_complete=complete_gzip,
                    )
            return
        if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            for ordinal, (name, source) in enumerate(iter_payload_members(stream, "zip", check)):
                child(source, name, ordinal)
            return
        if is_tar_header(prefix) or _key_suffix(key).endswith((".tar", ".tgz")):
            for ordinal, (name, source) in enumerate(iter_payload_members(stream, "tar", check)):
                child(source, name, ordinal)
            return
        if _key_suffix(key).endswith((".zip", ".gz")):
            # A filename is not a format proof. Preserve readable plaintext
            # while exposing the archive/content mismatch as incomplete.
            partial("archive_format_mismatch")
        text_encoding = _encoding(prefix)
        if not source_complete:
            # A truncated container is not an EOF delimiter for a secret.
            # This recovery publishes only candidates closed in actual bytes.
            _recover_text(stream, path, text_encoding, publish=publish, partial=partial, check=check, finish=False)
            return
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
            if value.byte_length <= _PORTION:
                # Preserve the small-scalar contract. The conversion is
                # strictly bounded; large values retain their disk lease.
                publish("".join(value.iter_text_chunks()), path)
            else:
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
    except (EOFError, gzip.BadGzipFile, zlib.error, tarfile.TarError, zipfile.BadZipFile, RuntimeError, ValueError):
        partial("invalid_archive_or_payload")
