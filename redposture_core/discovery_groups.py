"""Bounded, same-object grouping of explicitly related credential fields."""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .discovery_values import CredentialObject, DiskBackedText

AWS_FIELDS = frozenset(
    {
        "aws_access_key_id",
        "access_key_id",
        "aws_secret_access_key",
        "secret_access_key",
        "aws_session_token",
        "session_token",
        "region",
        "aws_region",
        "expiration",
    }
)
OAUTH_FIELDS = frozenset(
    {
        "client_id",
        "client_secret",
        "access_token",
        "refresh_token",
        "token_type",
        "scope",
        "expires_in",
        "expires_at",
        "audience",
        "issuer",
        "token_endpoint",
    }
)
CREDENTIAL_FIELDS = AWS_FIELDS | OAUTH_FIELDS


def credential_field(key: Any) -> str | None:
    # Every supported key is short ASCII. Do not scan or retain wide JSON keys.
    if not isinstance(key, str) or len(key) > 64:
        return None
    from .discovery_rules import normalize_field_name

    name = normalize_field_name(key)
    return name if name in CREDENTIAL_FIELDS else None


def _text(value: Any, maximum: int) -> str | None:
    if isinstance(value, DiskBackedText):
        if value.byte_length > maximum:
            return None
        return "".join(value.iter_text_chunks())
    return value if isinstance(value, str) and len(value) <= maximum else None


def _secret(value: Any) -> bool:
    from .discovery_rules import _looks_placeholder

    if isinstance(value, DiskBackedText):
        return value.byte_length >= 4 and not value.obvious_placeholder
    return isinstance(value, str) and len(value) >= 4 and not _looks_placeholder(value)


@dataclass(frozen=True)
class CredentialGroup:
    kind: str
    fields: Mapping[str, Any]

    def value(self) -> CredentialObject:
        return CredentialObject.from_fields(self.fields)

    @property
    def aliases(self) -> tuple[str, ...]:
        return (
            ("aws_secret_access_key", "aws_access_key", "generic_secret")
            if self.kind == "aws_credentials"
            else ("client_secret", "access_token", "refresh_token", "generic_secret")
        )

    @property
    def rules(self) -> tuple[str, ...]:
        return (self.kind, "aws_credential_pair" if self.kind == "aws_credentials" else "oauth_credential_pair")


def credential_groups(value: Mapping[Any, Any], *, deadline: float | None = None) -> list[CredentialGroup]:
    entries: dict[str, tuple[str, Any]] = {}
    ambiguous: set[str] = set()
    for key, item in value.items():
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("discover_time")
        if (name := credential_field(key)) is not None:
            if name in entries:
                ambiguous.add(name)
            entries[name] = (key, item)

    def get(*names: str) -> Any:
        matches = [entries[name][1] for name in names if name in entries and name not in ambiguous]
        return matches[0] if len(matches) == 1 else None

    def fields(names: frozenset[str]) -> dict[str, Any]:
        return {
            key: item
            for name, (key, item) in entries.items()
            if name in names and name not in ambiguous and isinstance(item, (str, DiskBackedText, int, float))
        }

    groups = []
    access = _text(get("aws_access_key_id", "access_key_id"), 20)
    secret = _text(get("aws_secret_access_key", "secret_access_key"), 40)
    if (
        access is not None
        and re.fullmatch(r"(?:AKIA|ASIA)[A-Z0-9]{16}", access)
        and secret is not None
        and re.fullmatch(r"[A-Za-z0-9/+=]{40}", secret)
        and _secret(secret)
    ):
        groups.append(CredentialGroup("aws_credentials", fields(AWS_FIELDS)))
    from .discovery_rules import _looks_placeholder

    client_id = get("client_id")
    # An opaque public identity needs no bounded-format regex. Keep large
    # identifiers on disk just like their associated secret, rather than
    # changing grouping at a byte/character threshold.
    has_client_id = isinstance(client_id, (str, DiskBackedText)) and not _looks_placeholder(client_id)
    if (has_client_id and _secret(get("client_secret"))) or (
        _secret(get("access_token")) and _secret(get("refresh_token"))
    ):
        groups.append(CredentialGroup("oauth_credentials", fields(OAUTH_FIELDS)))
    return groups
