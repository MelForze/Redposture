"""Read capability evidence owned by one verified credential attempt."""

from __future__ import annotations

from typing import Any


def attempt_capabilities(record: dict[str, Any], attempt: dict[str, Any], *, selected: bool = False) -> dict[str, Any]:
    evidence = attempt.get("credential_capabilities")
    if isinstance(evidence, dict):
        return evidence
    # Native adapters may retain their own attempt list alongside the runtime
    # ledger. Match the full identity; two passwords for one login can differ.
    runtime_attempts = record.get("attempted_credentials")
    matches: list[dict[str, Any]] = []
    for candidate in runtime_attempts if isinstance(runtime_attempts, list) else []:
        if not isinstance(candidate, dict):
            continue
        if (
            candidate.get("username") == attempt.get("username")
            and candidate.get("password") == attempt.get("password")
            and ("source" not in attempt or candidate.get("source", "provided") == attempt["source"])
        ):
            evidence = candidate.get("credential_capabilities")
            if isinstance(evidence, dict):
                matches.append(evidence)
    # Legacy credential_attempts can omit source. Only a unique full pair is
    # safe in that case; never pick arbitrary evidence from an ambiguous list.
    if len(matches) == 1:
        return matches[0]
    # Compatibility with saved records from before per-pair evidence existed.
    # Missing data for another identity must never inherit the selected ACLs.
    return record if selected else {}
