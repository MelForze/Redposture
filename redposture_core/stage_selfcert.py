"""Standalone self-signed certificate generation stage."""

from __future__ import annotations

import argparse

from .console import Console
from .servers import write_self_signed_cert_files


def run_selfcert_stage(args: argparse.Namespace) -> int:
    console = Console(debug=args.debug)

    try:
        cert_path, key_path = write_self_signed_cert_files(
            args.cert_out,
            args.key_out,
            force=bool(getattr(args, "force", False)),
        )
    except ValueError as exc:
        console.error(str(exc))
        return 2
    except OSError as exc:
        console.error(f"failed to write cert/key files: {exc}")
        return 1

    console.success(f"self-signed certificate written: {cert_path}")
    console.success(f"private key written: {key_path}")
    return 0
