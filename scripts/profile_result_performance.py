#!/usr/bin/env python3
"""Bounded offline scan/TXT/JSON cost for many distinct known findings.

Decimal MB, one owned process, no product/network/physical-host speed claim.
Neither the observer nor its JSON checker materializes the whole finding set.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import resource
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TextIO

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from scripts.performance_container import container_sample  # noqa: E402
from scripts.profile_module_performance import (  # noqa: E402
    PROFILE_FILES,
    activate_source,
    environment_evidence,
    source_hash,
)
from scripts.profile_processing_performance import file_sha256, resources  # noqa: E402

ROW_BYTES = 1024
PLACE = "$.benchmark/file/runtime/unique.log"
FILES = tuple(
    dict.fromkeys(
        (
            *PROFILE_FILES,
            "scripts/performance_container.py",
            "scripts/profile_processing_performance.py",
            "scripts/profile_result_performance.py",
        )
    )
)


def unique_value(index: int) -> str:
    return f"processing-unique-{index:09d}-{hashlib.sha256(str(index).encode()).hexdigest()[:32]}"


def write_payload(path: Path, size: int, expected: Path) -> int:
    if size < ROW_BYTES or expected.exists():
        raise ValueError("require at least one row and unused expected catalogue")
    count, padding = divmod(size, ROW_BYTES)
    with closing(sqlite3.connect(expected)) as db, path.open("xb") as stream:
        db.execute("CREATE TABLE known (fingerprint TEXT PRIMARY KEY)")
        for index in range(count):
            value = unique_value(index)
            row = ("password=" + value).encode()
            stream.write(row + b" " * (ROW_BYTES - len(row) - 1) + b"\n")
            db.execute("INSERT INTO known VALUES (?)", (hashlib.sha256(value.encode()).hexdigest(),))
        stream.write(b" " * padding)
        db.commit()
    return count


class JSONCursor:
    """Independent stdlib decoder, bounded to one small known fixture record."""

    def __init__(self, stream: TextIO, *, chunk: int = 32768) -> None:
        self.stream, self.chunk = stream, chunk
        self.buffer = ""
        self.eof = False
        self.decoder = json.JSONDecoder()

    def more(self) -> bool:
        if self.eof:
            return False
        block = self.stream.read(self.chunk)
        if not block:
            self.eof = True
            return False
        if "\x1b" in block:
            raise ValueError("ANSI in serialized JSON")
        self.buffer += block
        if len(self.buffer) > 262144:
            raise ValueError("fixture JSON record exceeds bounded verifier")
        return True

    def peek(self) -> str:
        while True:
            self.buffer = self.buffer.lstrip()
            if self.buffer or not self.more():
                return self.buffer[:1]

    def take(self, character: str) -> None:
        if self.peek() != character:
            raise ValueError("invalid or interrupted JSON framing")
        self.buffer = self.buffer[1:]

    def value(self) -> Any:
        self.peek()
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buffer)
            except json.JSONDecodeError:
                if not self.more():
                    raise ValueError("incomplete JSON value") from None
            else:
                # A numeric scalar can end at the current chunk boundary.
                if end == len(self.buffer) and not self.eof and self.more():
                    continue
                self.buffer = self.buffer[end:]
                return value

    def array(self):
        self.take("[")
        if self.peek() != "]":
            while True:
                yield self.value()
                if self.peek() == "]":
                    break
                self.take(",")
        self.take("]")


def verify_json(path: Path, count: int, expected: Path) -> None:
    with path.open(encoding="utf-8") as stream, closing(sqlite3.connect(expected)) as db:
        cursor = JSONCursor(stream)
        cursor.take("{")
        keys = set()
        while True:
            key = cursor.value()
            if not isinstance(key, str) or key in keys:
                raise ValueError("invalid/duplicate result key")
            keys.add(key)
            cursor.take(":")
            if key == "findings":
                seen = 0
                for index, row in enumerate(cursor.array()):
                    value = unique_value(index)
                    if (
                        not isinstance(row, dict)
                        or set(row) != {"type", "confidence", "value", "fingerprint", "object_path", "source"}
                        or row.get("confidence") not in ("high", "medium", "low")
                        or row.get("type") != "password"
                        or row.get("value") != value
                        or row.get("object_path") != PLACE
                    ):
                        raise ValueError("missing/extra/duplicate/reordered or changed finding")
                    if (
                        row.get("fingerprint") != hashlib.sha256(value.encode()).hexdigest()
                        or row.get("source") != "anonymous"
                    ):
                        raise ValueError("finding identity/source mismatch")
                    seen += 1
                if seen != count:
                    raise ValueError("finding count mismatch")
            elif key == "emitted_fingerprints":
                expected_rows = iter(db.execute("SELECT fingerprint FROM known ORDER BY fingerprint"))
                seen = 0
                for fingerprint in cursor.array():
                    row = next(expected_rows, None)
                    if row is None or fingerprint != row[0]:
                        raise ValueError("emitted identity mismatch")
                    seen += 1
                if seen != count or next(expected_rows, None) is not None:
                    raise ValueError("emitted identity count mismatch")
            else:
                value = cursor.value()
                if (
                    key == "status"
                    and value != "complete"
                    or key == "partial_reasons"
                    and value != []
                    or key == "live_emitted"
                    and value is not True
                    or key == "source"
                    and value != "anonymous"
                    or key in {"bytes_read", "bytes_inspected"}
                    and (not isinstance(value, int) or isinstance(value, bool) or value < 0)
                ):
                    raise ValueError("incomplete result state")
            if cursor.peek() == "}":
                break
            cursor.take(",")
        cursor.take("}")
        if cursor.peek() or keys != {
            "status",
            "bytes_read",
            "bytes_inspected",
            "source",
            "findings",
            "partial_reasons",
            "live_emitted",
            "emitted_fingerprints",
        }:
            raise ValueError("extra content or missing result fields")


def verify_txt(path: Path, count: int) -> None:
    seen = 0
    with path.open(encoding="utf-8") as stream:
        for index, line in enumerate(stream):
            expected = f'JENKINS\tqa\t80\t [!] Pass Value="{unique_value(index)}" Place="{PLACE}"\n'
            if line != expected:
                raise ValueError("missing/extra/duplicate/reordered or changed TXT finding")
            seen += 1
    if seen != count:
        raise ValueError("TXT count mismatch")


def instrument() -> tuple[str, dict[str, str]]:
    manifest = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return digest, manifest


def measure(args: argparse.Namespace) -> dict[str, Any]:
    if not (args.source / "redposture_core/__init__.py").is_file():
        raise ValueError("source must contain redposture_core/__init__.py")
    activate_source(args.source)
    from redposture_core.discovery_values import iter_json_chunks
    from redposture_core.storage_discovery import DiscoveryCollector

    activate_source(args.source)
    core = source_hash(args.source)
    tool, _ = instrument()
    before_fd, before_threads = len(os.listdir("/proc/self/fd")), threading.active_count()
    first = None
    with tempfile.TemporaryDirectory(prefix="redposture-distinct-results-") as directory:
        temporary = Path(directory)
        payload, expected = temporary / "input", temporary / "expected.sqlite3"
        size = args.megabytes * 1_000_000
        count = write_payload(payload, size, expected)
        input_sha = file_sha256(payload)
        txt, encoded = temporary / "result.txt", temporary / "result.json"
        previous = tempfile.tempdir
        tempfile.tempdir = str(temporary)
        stop = threading.Event()
        peaks = list(resources(temporary))
        sample_errors = []

        def sample() -> None:
            while not stop.wait(0.02):
                try:
                    for index, value in enumerate(resources(temporary)):
                        peaks[index] = max(peaks[index], value)
                except OSError as exc:
                    sample_errors.append(type(exc).__name__)
                    return

        sampler = threading.Thread(target=sample, name="result-profile-sampler")
        started, cpu = time.monotonic(), time.process_time()
        sampler.start()
        try:
            with txt.open("w", encoding="utf-8", newline="") as output:

                def emit(lines):
                    nonlocal first
                    if first is None:
                        first = time.monotonic() - started
                    for line in lines:
                        output.write(line + "\n")

                collector = DiscoveryCollector(
                    "jenkins",
                    SimpleNamespace(
                        args=SimpleNamespace(discover_time=args.discover_time), host="qa", port=80, live_emit=emit
                    ),
                    {"status": "open_no_auth"},
                )
                with payload.open("rb") as reader:
                    collector._scan_member_stream("benchmark", "runtime/unique.log", reader, prefer_specific=True)
                result = collector.result()
            scan_wall, scan_cpu = time.monotonic() - started, time.process_time() - cpu
            json_start, json_cpu_start = time.monotonic(), time.process_time()
            with encoded.open("w", encoding="utf-8") as output:
                for chunk in iter_json_chunks(result):
                    output.write(chunk)
            json_wall, json_cpu = time.monotonic() - json_start, time.process_time() - json_cpu_start
            verify_json(encoded, count, expected)
            verify_txt(txt, count)
            observation = {
                "quality": "PASS",
                "case": "distinct-lines",
                "findings": count,
                "megabytes": args.megabytes,
                "input_bytes": size,
                "input_sha256": input_sha,
                "source_status": result["status"],
                "partial_reasons": result["partial_reasons"],
                "scan_and_txt_wall_seconds": scan_wall,
                "scan_and_txt_cpu_seconds": scan_cpu,
                "json_wall_seconds": json_wall,
                "json_cpu_seconds": json_cpu,
                "first_finding_seconds": first,
                "txt_bytes": txt.stat().st_size,
                "json_bytes": encoded.stat().st_size,
                "txt_sha256": file_sha256(txt),
                "json_sha256": file_sha256(encoded),
            }
            for index, value in enumerate(resources(temporary)):
                peaks[index] = max(peaks[index], value)
            del result, collector
            gc.collect()
        finally:
            stop.set()
            sampler.join(5)
            tempfile.tempdir = previous
        if sampler.is_alive() or sample_errors:
            raise RuntimeError("resource sampler did not complete")
    if core != source_hash(args.source) or tool != instrument()[0]:
        raise RuntimeError("source or instrument changed")
    observation.update(
        source_sha256=core,
        profile_sha256=tool,
        environment=environment_evidence(),
        peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        sampled_peak_fd=peaks[0],
        sampled_peak_threads=peaks[1],
        sampled_peak_temp_file_bytes=peaks[2],
        fd_before=before_fd,
        fd_after=len(os.listdir("/proc/self/fd")),
        threads_before=before_threads,
        threads_after=threading.active_count(),
        temporary_directory_removed=not temporary.exists(),
        discover_time=args.discover_time,
        scope="Offline actual shared member scanner/live TXT formatter/full JSON serializer. One known unique finding per1024inputbytes; exact full ordered type/value/Place/fingerprint,all emitted IDs verified via bounded stdlib JSON cursor and disk catalogue. Not physical services or full CLI rendering. First finding includes prior whole-member validation. Sampled20ms resource peaks include verifier SQLite/input/output/spools; RSS includes imports and validation;one sampler thread. Generation/provenance outside timed scan/TXT and JSON;verification outside those times,not excluded from peak RSS.",
    )
    if observation["fd_after"] != before_fd or observation["threads_after"] != before_threads:
        raise RuntimeError("resource cleanup mismatch")
    return observation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--megabytes", type=int, choices=(1, 10, 100), default=10)
    parser.add_argument("--discover-time", type=float, default=900)
    parser.add_argument("--container-image")
    args = parser.parse_args()
    if args.output.exists() or not (args.source / "redposture_core/__init__.py").is_file() or args.discover_time <= 0:
        parser.error("unused output, existing source and positive discover-time required")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.container_image:
        digest, manifest = instrument()
        frozen = args.output.parent / ("instrument-" + digest)
        frozen.mkdir(exist_ok=True)
        for name, expected in manifest.items():
            target = frozen / name
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
                raise RuntimeError("frozen instrument changed")
        (frozen / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return container_sample(
            frozen.resolve(),
            (frozen / "scripts/profile_result_performance.py").resolve(),
            args.source,
            args.output,
            args.container_image,
            ["--megabytes", str(args.megabytes), "--discover-time", str(args.discover_time)],
        )
    if sys.platform != "linux":
        parser.error("use an isolated Linux container for /proc metrics")
    try:
        result = measure(args)
    except Exception as exc:
        args.output.write_text(
            json.dumps(
                {
                    "quality": "FAIL",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "case": "distinct-lines",
                    "megabytes": args.megabytes,
                    "source_sha256": source_hash(args.source),
                    "profile_sha256": instrument()[0],
                },
                indent=2,
            )
            + "\n"
        )
        raise
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "quality",
                    "case",
                    "megabytes",
                    "findings",
                    "scan_and_txt_wall_seconds",
                    "json_wall_seconds",
                )
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
