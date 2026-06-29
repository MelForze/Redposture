#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


@dataclass(frozen=True)
class MatrixCase:
    kind: str
    module: str
    label: str
    expected_exit: str
    command_key: str
    tokens: tuple[str, ...]
    implicit_options: tuple[str, ...]


_COMMON_EXCLUDED_DESTS: dict[str, str] = {
    "help": "argparse built-in help is covered by CLI smoke tests, not by live lab cases.",
    "hosts": "target string aliases are unit-tested; live matrix uses -t/--targets target values.",
    "hosts_file": "target file ingestion is unit-tested; live matrix keeps targets inline for reproducibility.",
    "log": "log mirroring is unit-tested; matrix already captures stdout/stderr per label.",
    "no_color": "color/no-color rendering is unit-tested; JSON matrix artifacts do not need ANSI controls.",
    "profiles_file": "custom profile file parsing is covered by unit tests; live matrix uses built-in profiles.",
    "proxy": "shared proxy transport is covered by proxy-isolated extended labels, not repeated for every module.",
    "retries": "retry behavior is unit-tested; live lab services are deterministic.",
    "timeout": "timeout parsing is unit-tested and used in selected live Oracle cases.",
    "workers": "worker scheduling is unit-tested; live matrix uses representative concurrency only.",
}

_COMMAND_EXCLUDED_DESTS: dict[str, dict[str, str]] = {
    "exporters trigger": {
        "bind": "listener bind address is covered by listener unit tests; live matrix avoids host bind variability.",
        "cert_file": "TLS listener certificate wiring is unit-tested; live trigger coverage uses no-listen mode.",
        "check_credentials": "credential callback verification needs passive listener timing and is covered by trigger tests.",
        "key_file": "TLS listener key wiring is unit-tested with certificate handling.",
        "listen_seconds": "listener wait timing is covered by baseline trigger smoke and unit tests.",
        "with_listen": "baseline trigger case covers listener mode; extended cases focus no-listen flag combinations.",
    },
    "postgres": {
        "os_shell": "interactive shell is intentionally excluded from non-interactive matrix.",
        "sql_shell": "interactive SQL shell is intentionally excluded from non-interactive matrix.",
    },
    "mongodb": {
        "nosql_shell": "interactive NoSQL shell is intentionally excluded from non-interactive matrix.",
    },
    "oracle": {
        "as_sysdba": "SYSDBA attach requires privileged lab setup and is covered by unit/privilege planner tests.",
        "delete": "destructive file delete is excluded from sequential matrix; file ops are covered by read/download cases.",
        "os_write": "server-side file write is excluded from regular matrix to keep Oracle lab idempotent.",
        "pass_list": "password list mode is covered together with spray/user-list behavior.",
        "reverse_shell": "reverse shell callbacks are intentionally excluded from matrix; controlled RCE readback is covered.",
        "reverse_shell_type": "reverse shell payload variants are excluded with reverse_shell.",
        "sid": "service-name connection is the primary Oracle lab path; SID probing is covered by sid-list enum.",
        "ssl_server_dn": "TCPS server DN verification requires profile-specific cert material and is unit-tested.",
        "user_list": "user-list mode is covered together with spray/pass-list behavior.",
        "wallet": "client wallet connection requires external wallet material; wallet search/extract is covered.",
    },
    "clickhouse": {
        "os_shell": "interactive OS shell is intentionally excluded from non-interactive matrix.",
        "sql_shell": "interactive SQL shell is intentionally excluded from non-interactive matrix.",
    },
    "consul": {
        "delete": "destructive check deletion is unit-tested; matrix creates no persistent revshell checks.",
        "listen": "local reverse-shell listener is excluded from sequential matrix.",
        "revshell_check_id": "targeted revshell check IDs are excluded with revshell cleanup behavior.",
        "revshell_host": "reverse-shell listener host is excluded with revshell listener behavior.",
        "revshell_listen": "local reverse-shell listener is excluded from sequential matrix.",
        "revshell_payload": "custom revshell payload is excluded from non-destructive matrix.",
        "revshell_port": "reverse-shell listener port is excluded with revshell listener behavior.",
        "revshell": "script-check RCE is intentionally excluded from regular matrix.",
        "delete_revshell": "destructive check deletion is unit-tested; matrix creates no persistent revshell checks.",
    },
    "docker": {
        "tls_ca": "client-certificate success requires separate mTLS daemon; invalid pairing is covered.",
        "tls_key": "client key handling is covered by TLS pairing validation tests.",
    },
    "elastic": {
        "ca_file": "custom CA bundle loading is unit-tested; lab uses HTTP/basic-auth paths.",
    },
    "kubeapi": {
        "ca_file": "CA bundle loading is unit-tested; live lab uses --insecure/self-signed shortcuts.",
        "exec_command": "pod exec is excluded from sequential matrix to avoid pod-name drift; resource visibility is covered.",
    },
}


def _logical_shell_lines(text: str) -> list[str]:
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            buffer += line[:-1].rstrip() + " "
            continue
        if buffer:
            line = buffer + line
            buffer = ""
        lines.append(line)
    if buffer:
        lines.append(buffer)
    return lines


def parse_matrix_cases(script_text: str) -> list[MatrixCase]:
    cases: list[MatrixCase] = []
    for line in _logical_shell_lines(script_text):
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        while parts and "=" in parts[0] and not parts[0].startswith("-"):
            parts = parts[1:]
        if not parts or parts[0] not in {"run_case", "run_text_case", "run_raw_case"}:
            continue
        if len(parts) < 5:
            continue
        kind, module, label, expected_exit = parts[:4]
        tokens = tuple(parts[4:])
        if not tokens:
            continue
        if tokens[0] == "exporters" and len(tokens) > 1:
            command_key = f"exporters {tokens[1]}"
        else:
            command_key = tokens[0]
        implicit: tuple[str, ...] = ()
        if kind == "run_case":
            implicit = ("--format", "--output")
        elif kind == "run_text_case":
            implicit = ("--output",)
        cases.append(
            MatrixCase(
                kind=kind,
                module=module,
                label=label,
                expected_exit=expected_exit,
                command_key=command_key,
                tokens=tokens,
                implicit_options=implicit,
            )
        )
    return cases


def _parser_map() -> dict[str, argparse.ArgumentParser]:
    from redposture_core.cli_args import build_parser

    root = build_parser()
    result: dict[str, argparse.ArgumentParser] = {}
    for action in root._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for name, parser in action.choices.items():
            if name == "exporters":
                for child_action in parser._actions:
                    if not isinstance(child_action, argparse._SubParsersAction):
                        continue
                    for child_name, child_parser in child_action.choices.items():
                        result[f"exporters {child_name}"] = child_parser
            else:
                result[name] = parser
    return result


def _option_actions(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    return [action for action in parser._actions if action.option_strings]


def _present_options(cases: list[MatrixCase]) -> dict[str, set[str]]:
    present: dict[str, set[str]] = {}
    for case in cases:
        options = present.setdefault(case.command_key, set())
        options.update(case.implicit_options)
        for token in case.tokens:
            if not token.startswith("-"):
                continue
            if token == "-":
                continue
            options.add(token.split("=", 1)[0])
    return present


def _read_status_labels(path: Path | None) -> set[str] | None:
    if path is None:
        return None
    labels: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        header = fh.readline()
        _ = header
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            parts = raw.split("\t")
            if len(parts) >= 2:
                labels.add(parts[1])
    return labels


def build_coverage_report(script_path: Path, *, status_file: Path | None = None) -> dict[str, Any]:
    cases = parse_matrix_cases(script_path.read_text(encoding="utf-8"))
    labels = _read_status_labels(status_file)
    if labels is not None:
        cases = [case for case in cases if case.label in labels]
    present = _present_options(cases)
    parsers = _parser_map()
    missing: dict[str, list[dict[str, Any]]] = {}
    covered: dict[str, list[str]] = {}
    excluded: dict[str, list[dict[str, str]]] = {}

    for command_key, parser in sorted(parsers.items()):
        covered[command_key] = []
        excluded[command_key] = []
        command_present = present.get(command_key, set())
        command_exclusions = _COMMAND_EXCLUDED_DESTS.get(command_key, {})
        for action in _option_actions(parser):
            option_strings = tuple(action.option_strings)
            if any(option in command_present for option in option_strings):
                covered[command_key].extend(option_strings)
                continue
            reason = _COMMON_EXCLUDED_DESTS.get(action.dest) or command_exclusions.get(action.dest)
            if reason:
                excluded[command_key].append(
                    {
                        "dest": action.dest,
                        "options": ",".join(option_strings),
                        "reason": reason,
                    }
                )
                continue
            missing.setdefault(command_key, []).append(
                {
                    "dest": action.dest,
                    "options": list(option_strings),
                }
            )

    total_actions = 0
    for parser in parsers.values():
        total_actions += len(_option_actions(parser))
    total_covered = sum(len(values) for values in covered.values())
    report = {
        "matrix_script": str(script_path),
        "status_file": str(status_file) if status_file is not None else None,
        "case_count": len(cases),
        "commands": sorted(parsers),
        "covered_options": covered,
        "excluded_actions": excluded,
        "missing_actions": missing,
        "summary": {
            "total_parser_actions": total_actions,
            "covered_option_strings": total_covered,
            "excluded_actions": sum(len(values) for values in excluded.values()),
            "missing_actions": sum(len(values) for values in missing.values()),
        },
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Check lab matrix CLI flag coverage.")
    parser.add_argument("--matrix-script", default="scripts/run_lab_matrix_sequential.sh")
    parser.add_argument("--status-file")
    parser.add_argument("--out")
    args = parser.parse_args()

    status_file = Path(args.status_file) if args.status_file else None
    report = build_coverage_report(Path(args.matrix_script), status_file=status_file)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    if report["missing_actions"]:
        print(json.dumps(report["missing_actions"], indent=2, ensure_ascii=False), file=__import__("sys").stderr)
        return 1
    print(json.dumps(report["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
