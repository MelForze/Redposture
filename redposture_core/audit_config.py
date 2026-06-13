"""Typed view over the argparse Namespace for staged audits.

`args` flows through the runtime as an untyped `argparse.Namespace`, so every
`getattr(args, "field", default)` is invisible to mypy (this is the class of bug
behind the `--sql-shell` crash). `AuditConfig` is a typed *view* built once at the
CLI→runtime boundary via `from_namespace`; it captures the **effective** common
config (defaults already applied), so it is meant for use *after* arg validation.
The Namespace itself is left untouched — this is additive and incremental.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuditConfig:
    # connection / execution
    timeout: float = 5.0
    retries: int = 0
    workers: int = 1
    proxy: str | None = None
    # output
    output: str | None = None
    output_format: str = "txt"
    debug: bool = False
    no_color: bool = False
    log: str | None = None
    # credentials (raw: username/password may be "" as a credential-file marker)
    username: str | None = None
    password: str | None = None
    token: str | None = None
    defcreds: bool = False
    database: str | None = None
    # tls
    cert_file: str | None = None
    key_file: str | None = None

    @classmethod
    def from_namespace(cls, args: Any) -> AuditConfig:
        """Build the effective config from an argparse Namespace.

        Coercions mirror the scattered `getattr(args, …)` defaults exactly:
        `--timeout` is validated `> 0` and `--workers` `>= 1`, so `or 5.0` /
        `max(1, …)` only apply the not-provided default.
        """
        return cls(
            timeout=float(getattr(args, "timeout", 5.0) or 5.0),
            retries=int(getattr(args, "retries", 0) or 0),
            workers=max(1, int(getattr(args, "workers", 1) or 1)),
            proxy=getattr(args, "proxy", None),
            output=getattr(args, "output", None),
            output_format=str(getattr(args, "output_format", "txt") or "txt"),
            debug=bool(getattr(args, "debug", False)),
            no_color=bool(getattr(args, "no_color", False)),
            log=getattr(args, "log", None),
            username=getattr(args, "username", None),
            password=getattr(args, "password", None),
            token=getattr(args, "token", None) or getattr(args, "api_token", None),
            defcreds=bool(getattr(args, "defcreds", False)),
            database=getattr(args, "database", None),
            cert_file=getattr(args, "cert_file", None),
            key_file=getattr(args, "key_file", None),
        )
