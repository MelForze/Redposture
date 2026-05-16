"""Artifact writers for collect validation results."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from ..utils import utc_now_iso


def write_unique_lines(path: str, values: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for value in values:
            text = str(value or "").strip()
            if not text:
                continue
            fh.write(text + "\n")


def write_lines(path: str, values: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for value in values:
            fh.write(str(value or "").strip() + "\n")


def markdown_cell(value: object) -> str:
    if isinstance(value, list):
        text = "<br>".join(str(item) for item in value if str(item or "").strip())
    else:
        text = str(value or "")
    text = text.replace("|", "\\|").replace("\n", "<br>")
    return text or "-"


def write_vulnerable_findings_markdown(path: str, findings: list[dict[str, object]]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# RedPosture Vulnerable Findings\n\n")
        fh.write(f"- generated_at: {utc_now_iso()}\n")
        fh.write(f"- findings: {len(findings)}\n\n")
        fh.write("| Host | Port | Endpoint | Exporter | Users | Passwords | API keys | Reason |\n")
        fh.write("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
        for finding in findings:
            row = [
                finding.get("host"),
                finding.get("port"),
                finding.get("endpoint"),
                finding.get("exporter"),
                finding.get("users"),
                finding.get("passwords"),
                finding.get("api_keys"),
                finding.get("reason"),
            ]
            fh.write("| " + " | ".join(markdown_cell(value) for value in row) + " |\n")


def write_vulnerable_targets_files(
    *,
    base_dir: str,
    validator: Any,
    debug: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    if not hasattr(validator, "vulnerable_targets_from_shown_hits"):
        return {}

    ips_path = os.path.join(base_dir, "vulnerable_ips.txt")
    urls_path = os.path.join(base_dir, "vulnerable_urls.txt")
    users_path = os.path.join(base_dir, "vulnerable_users.txt")
    pass_path = os.path.join(base_dir, "vulnerable_pass.txt")
    user_pass_path = os.path.join(base_dir, "vulnerable_user_pass.txt")
    api_keys_path = os.path.join(base_dir, "vulnerable_apikeys.txt")
    findings_path = os.path.join(base_dir, "vulnerable_findings.md")

    hosts, urls = validator.vulnerable_targets_from_shown_hits()
    write_unique_lines(urls_path, urls)

    login_rows: list[tuple[str, str, str]] = []
    if hasattr(validator, "vulnerable_login_rows_from_shown_hits"):
        login_rows = validator.vulnerable_login_rows_from_shown_hits()
    if login_rows:
        write_lines(ips_path, [row[0] for row in login_rows])
        write_lines(users_path, [row[1] for row in login_rows])
        write_lines(pass_path, [row[2] for row in login_rows])
        write_lines(user_pass_path, [f"{row[1]}:{row[2]}" for row in login_rows])
    else:
        write_unique_lines(ips_path, hosts)
        write_lines(users_path, [])
        write_lines(pass_path, [])
        write_lines(user_pass_path, [])

    users: list[str] = []
    passwords: list[str] = []
    api_keys: list[str] = []
    if hasattr(validator, "vulnerable_credentials_from_shown_hits"):
        users, passwords, api_keys = validator.vulnerable_credentials_from_shown_hits()
    write_unique_lines(api_keys_path, api_keys)

    findings: list[dict[str, object]] = []
    if hasattr(validator, "vulnerable_findings_from_shown_hits"):
        findings = validator.vulnerable_findings_from_shown_hits()
    write_vulnerable_findings_markdown(findings_path, findings)

    summary = {
        "hosts": len(hosts),
        "urls": len(urls),
        "login_rows": len(login_rows),
        "users": len(users),
        "passwords": len(passwords),
        "api_keys": len(api_keys),
        "findings": len(findings),
        "ips_file": ips_path,
        "urls_file": urls_path,
        "users_file": users_path,
        "pass_file": pass_path,
        "user_pass_file": user_pass_path,
        "api_keys_file": api_keys_path,
        "findings_file": findings_path,
    }
    if debug is not None:
        debug(
            "vulnerable targets written "
            f"hosts={summary['hosts']} urls={summary['urls']} login_rows={summary['login_rows']} "
            f"users={summary['users']} passwords={summary['passwords']} api_keys={summary['api_keys']} "
            f"findings={summary['findings']} ips_file={ips_path} urls_file={urls_path}"
        )
    return summary


__all__ = [
    "markdown_cell",
    "write_lines",
    "write_unique_lines",
    "write_vulnerable_findings_markdown",
    "write_vulnerable_targets_files",
]
