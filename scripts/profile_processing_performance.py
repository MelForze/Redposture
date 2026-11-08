#!/usr/bin/env python3
"""Deterministic offline XML/HTML/search/dedup profiles, in decimal megabytes.

The actual shared member reader validates and spools the input before scanning.
First-finding latency includes that first pass; it is not network streaming
latency. Each invocation is one fresh process, not a physical service benchmark.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from scripts.performance_container import container_sample  # noqa: E402
from scripts.profile_module_performance import activate_source, environment_evidence, source_hash  # noqa: E402

CASES = ("xml-dense", "html-inputs", "duplicate-lines")
FIRST, LAST = "processing-first-secret", "processing-last-secret"


def payload_parts(case: str) -> tuple[bytes, bytes, bytes, str]:
    if case == "xml-dense":
        return (
            f"<config><password>{FIRST}</password>\n".encode(),
            b'<metric name="state">ready</metric>\n',
            f"\n<password>{LAST}</password></config>".encode(),
            "runtime/config.xml",
        )
    if case == "html-inputs":
        return (
            f'<!doctype html><html><body><input name="password" value="{FIRST}"/>\n'.encode(),
            b'<div class="metric"><span>ready</span></div>\n',
            f'\n<input value="{LAST}" name="password"/></body></html>'.encode(),
            "runtime/form.html",
        )
    if case == "duplicate-lines":
        row = f"password={FIRST}\n".encode()
        return row, row, f"\npassword={LAST}\n".encode(), "runtime/repeated.log"
    raise ValueError(f"unknown processing case: {case}")


def write_payload(path: Path, case: str, size: int) -> str:
    prefix, unit, suffix, name = payload_parts(case)
    if size < len(prefix) + len(suffix):
        raise ValueError("payload is too short for both known findings")
    count, padding = divmod(size - len(prefix) - len(suffix), len(unit))
    with path.open("wb") as stream:
        stream.write(prefix)
        batch = unit * 1024
        batches, remaining = divmod(count, 1024)
        for _ in range(batches):
            stream.write(batch)
        stream.write(unit * remaining)
        stream.write(b" " * padding)
        stream.write(suffix)
    return name


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65536):
            digest.update(block)
    return digest.hexdigest()


def expected_findings(case: str, name: str) -> list[dict[str, str]]:
    path = f"$.benchmark/file/{name}" + ("" if case == "duplicate-lines" else ".password")
    return [{"type": "password", "value": value, "place": path} for value in (FIRST, LAST)]


def verify_findings(case: str, name: str, findings: list[dict[str, Any]]) -> bool:
    # Exact ordered rows: no missing, extra, duplicate, truncated or relocated
    # finding can be hidden by a value-only set comparison.
    return findings == expected_findings(case, name)


def resources(directory: Path) -> tuple[int, int, int]:
    """Include unlinked temporary files, without counting a file twice."""
    entries = list(Path("/proc/self/fd").iterdir())
    files: dict[tuple[int, int], int] = {}
    paths = list(directory.rglob("*"))
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        if target.startswith(str(directory) + os.sep):
            paths.append(entry)
    for path in paths:
        try:
            info = path.stat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode):
            files[info.st_dev, info.st_ino] = info.st_size
    return len(entries), threading.active_count(), sum(files.values())


def measure(args: argparse.Namespace) -> dict[str, Any]:
    if not (args.source / "redposture_core/__init__.py").is_file():
        raise ValueError("source must contain redposture_core/__init__.py")
    activate_source(args.source)
    from redposture_core.discovery_values import iter_json_chunks
    from redposture_core.storage_discovery import DiscoveryCollector

    activate_source(args.source)  # Verify the imported package actually belongs to this snapshot.
    before_hash = source_hash(args.source)
    baseline_fd = len(os.listdir("/proc/self/fd"))
    baseline_threads = threading.active_count()
    emitted: list[float] = []
    with tempfile.TemporaryDirectory(prefix="redposture-processing-") as directory:
        root = Path(directory)
        payload = root / "payload"
        size = args.megabytes * 1_000_000
        name = write_payload(payload, args.case, size)
        input_sha = file_sha256(payload)
        previous_tempdir = tempfile.tempdir
        tempfile.tempdir = str(root)
        stopped = threading.Event()
        peaks = list(resources(root))
        sample_errors: list[str] = []

        def sample() -> None:
            while not stopped.wait(0.02):
                try:
                    current = resources(root)
                    for index, value in enumerate(current):
                        peaks[index] = max(peaks[index], value)
                except OSError as exc:
                    sample_errors.append(type(exc).__name__)
                    break

        started = time.monotonic()
        cpu_started = time.process_time()

        def emit(_lines: Any) -> None:
            if not emitted:
                emitted.append(time.monotonic() - started)

        sampler = threading.Thread(target=sample, name="processing-resource-sampler")
        sampler.start()
        try:
            collector = DiscoveryCollector(
                "jenkins",
                SimpleNamespace(
                    args=SimpleNamespace(discover_time=args.discover_time), host="qa", port=80, live_emit=emit
                ),
                {"status": "open_no_auth"},
            )
            with payload.open("rb") as stream:
                collector._scan_member_stream("benchmark", name, stream, prefer_specific=True)
            result = collector.result()
            findings = [
                {"type": row["type"], "value": row["value"], "place": row["object_path"]} for row in result["findings"]
            ]
            scan_wall = time.monotonic() - started
            scan_cpu = time.process_time() - cpu_started
            encoded = root / "result.json"
            with encoded.open("wb") as output_stream:
                for part in iter_json_chunks(result):
                    output_stream.write(part.encode())
            saved = encoded.read_bytes()  # Exactly two small, known findings.
            roundtrip = json.loads(saved)
            valid = (
                result["status"] == "complete"
                and verify_findings(args.case, name, findings)
                and [row["value"] for row in roundtrip["findings"]] == [FIRST, LAST]
                and b"\x1b" not in saved
                and not sample_errors
            )
            total_wall = time.monotonic() - started
            total_cpu = time.process_time() - cpu_started
            peaks = [max(a, b) for a, b in zip(peaks, resources(root), strict=True)]
        finally:
            stopped.set()
            sampler.join(timeout=5)
            tempfile.tempdir = previous_tempdir
        if sampler.is_alive():
            raise RuntimeError("resource sampler did not stop")
    after_hash = source_hash(args.source)
    if before_hash != after_hash:
        raise RuntimeError("source changed during measurement")
    observation = {
        "quality": "PASS" if valid else "FAIL",
        "case": args.case,
        "megabytes": args.megabytes,
        "input_bytes": size,
        "input_sha256": input_sha,
        "findings": findings,
        "source_status": result["status"],
        "partial_reasons": result["partial_reasons"],
        "wall_seconds": scan_wall,
        "cpu_seconds": scan_cpu,
        "scan_and_json_wall_seconds": total_wall,
        "scan_and_json_cpu_seconds": total_cpu,
        "first_finding_seconds": emitted[0] if emitted else None,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "sampled_peak_fd": peaks[0],
        "sampled_peak_threads": peaks[1],
        "sampled_peak_temp_file_bytes": peaks[2],
        "fd_before": baseline_fd,
        "fd_after": len(os.listdir("/proc/self/fd")),
        "threads_before": baseline_threads,
        "threads_after": threading.active_count(),
        "output_sha256": hashlib.sha256(saved).hexdigest(),
        "no_ansi": b"\x1b" not in saved,
        "temporary_directory_removed": not root.exists(),
        "source_sha256": before_hash,
        "profile_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "environment": environment_evidence(),
        "discover_time": args.discover_time,
        "note": "Offline shared reader, not a product or network. First finding follows member validation. "
        "RSS includes imports; disk includes input and open anonymous temp files. "
        "20ms sampled FD/disk peaks can miss shorter transients. One sampler thread is included.",
    }
    if observation["fd_after"] != baseline_fd or observation["threads_after"] != baseline_threads:
        observation["quality"] = "FAIL"
    return observation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--megabytes", type=int, choices=(1, 10, 100), default=10)
    parser.add_argument("--discover-time", type=float, default=900)
    parser.add_argument("--container-image")
    args = parser.parse_args()
    if args.output.exists() or not (args.source / "redposture_core/__init__.py").is_file() or args.discover_time <= 0:
        parser.error("require unused output, existing source and positive discover time")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.container_image:
        return container_sample(
            ROOT,
            Path(__file__).resolve(),
            args.source,
            args.output,
            args.container_image,
            ["--case", args.case, "--megabytes", str(args.megabytes), "--discover-time", str(args.discover_time)],
        )
    if sys.platform != "linux":
        parser.error("use an isolated Linux container for consistent resource metrics")
    result = measure(args)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("case", "megabytes", "quality", "wall_seconds")}))
    return 0 if result["quality"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
