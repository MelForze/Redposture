"""Main CLI orchestration."""

from __future__ import annotations

import sys

from .cli_args import COMMAND_COLLECT, COMMAND_LISTEN, COMMAND_SCAN, COMMAND_TRIGGER, parse_args
from .listener_runtime import run_listeners
from .logger import AttemptLogger
from .stage_collect import run_collect_stage
from .stage_scan import run_scan_stage
from .stage_trigger import run_trigger_stage


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logger = AttemptLogger()
    try:
        if args.command == COMMAND_SCAN:
            return run_scan_stage(args, logger)

        if args.command == COMMAND_TRIGGER:
            return run_trigger_stage(args, logger)

        if args.command == COMMAND_COLLECT:
            return run_collect_stage(args, logger)

        if args.command != COMMAND_LISTEN:
            print(f"[error] unsupported command: {args.command}", file=sys.stderr)
            return 2

        return run_listeners(args, logger)
    finally:
        logger.close()
