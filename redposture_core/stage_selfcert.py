"""Standalone self-signed certificate generation stage."""

from __future__ import annotations

import argparse
import time

from .console import Console
from .servers import write_self_signed_cert_files


def run_selfcert_stage(args: argparse.Namespace) -> int:
    console = Console(debug=args.debug)
    pipeline_started_at = time.monotonic()
    if args.debug:
        console.debug("pass=1 detect start total=1")

    detect_started_at = time.monotonic()
    try:
        cert_path, key_path = write_self_signed_cert_files(
            args.cert_out,
            args.key_out,
            force=bool(getattr(args, "force", False)),
        )
    except ValueError as exc:
        if args.debug:
            detect_ms = int((time.monotonic() - detect_started_at) * 1000)
            total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
            console.debug("pass=1 detect complete success=0")
            console.debug(
                f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=error error={exc}"
            )
            console.debug("pass=2 deep start total=0")
            console.debug("stage2_gate=skip reason=error")
            console.debug("pass=2 deep complete processed=0")
            console.debug("stage_trace stage_name=data attempt=1 duration_ms=0 result=skip error=error")
            console.debug(
                f"stage_timing_summary status=error attempts=1/1 detect_ms={detect_ms} data_ms=0 total_ms={total_ms}"
            )
        console.error(str(exc))
        return 2
    except OSError as exc:
        if args.debug:
            detect_ms = int((time.monotonic() - detect_started_at) * 1000)
            total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
            console.debug("pass=1 detect complete success=0")
            console.debug(
                f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=error error={exc}"
            )
            console.debug("pass=2 deep start total=0")
            console.debug("stage2_gate=skip reason=error")
            console.debug("pass=2 deep complete processed=0")
            console.debug("stage_trace stage_name=data attempt=1 duration_ms=0 result=skip error=error")
            console.debug(
                f"stage_timing_summary status=error attempts=1/1 detect_ms={detect_ms} data_ms=0 total_ms={total_ms}"
            )
        console.error(f"failed to write cert/key files: {exc}")
        return 1

    detect_ms = int((time.monotonic() - detect_started_at) * 1000)
    total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
    if args.debug:
        console.debug("pass=1 detect complete success=1")
        console.debug(f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=ok error=-")
        console.debug("pass=2 deep start total=1")
        console.debug("stage2_gate=run reason=status=ready")
        console.debug("pass=2 deep complete processed=1")
        console.debug("stage_trace stage_name=data attempt=1 duration_ms=0 result=ok error=-")
        console.debug(
            f"stage_timing_summary status=ok attempts=1/1 detect_ms={detect_ms} data_ms=0 total_ms={total_ms}"
        )

    console.success(f"self-signed certificate written: {cert_path}")
    console.success(f"private key written: {key_path}")
    return 0
