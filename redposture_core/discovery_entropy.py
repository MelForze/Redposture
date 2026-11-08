"""Shared bounded entropy heuristic; candidates are not verified credentials."""

from __future__ import annotations

import base64
import binascii
import math
import re
from bisect import bisect_right
from collections import Counter
from itertools import chain

from .secret_fields import _NON_SECRET_FIELD_RE, _normalize_secret_key, is_secret_metadata_field
from .secret_literals import AssignmentLiterals

_WORD_RE = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{20,256}(?![A-Za-z0-9_+/=-])")
_PEM_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----[\s\S]+?-----END \1-----")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _looks_like_resource_route(candidate: str) -> bool:
    """Reject unlabelled URL/path fragments from the entropy fallback."""
    if candidate.count("/") < 2:
        return False
    if "-" in candidate:
        return True
    return sum(bool(re.fullmatch(r"[A-Za-z]{3,}", part)) for part in candidate.split("/")) >= 2


def entropy_candidates(
    text: str, path: str, explicit_values: set[str], spans: list[tuple[int, int]], literals: AssignmentLiterals
) -> list[str]:
    """Retain the established filters and bounded token grammar for every facade."""
    found: list[str] = []
    span_starts = [span[0] for span in spans]
    path_field = _normalize_secret_key(path)
    # Build/version identifiers may look random. This is only an entropy
    # exclusion: explicit password/provider syntax in the same field still
    # reaches the normal detectors. Check the leaf, not a sensitive descendant.
    leaf = _normalize_secret_key(re.split(r"[./]", path)[-1])
    if leaf in {"version", "release", "build", "build_id", "revision", "commit", "commit_id"}:
        return found
    if not _NON_SECRET_FIELD_RE.search(path_field) and not is_secret_metadata_field(path_field):
        if "=" not in text and text in explicit_values and _WORD_RE.fullmatch(text):
            # The entropy loop has exactly one unmodified candidate, already
            # excluded by explicit_values. Keep assignment/structured cases
            # on the original path, where a different substring may be found.
            return found
        words = _WORD_RE.finditer(text)
        first_word = next(words, None)
        if first_word is None:
            return found
        pem_spans = [match.span() for match in _PEM_BLOCK_RE.finditer(text)]
        # Candidate length is bounded at256. Substring membership therefore
        # depends on that bound, not on the number of earlier findings.
        value_lengths = sorted({len(value) for value in explicit_values if len(value) <= 256})
        for token_match in chain((first_word,), words):
            interval = bisect_right(span_starts, token_match.start()) - 1
            if interval >= 0 and token_match.end() <= spans[interval][1]:
                continue
            if literals.overlap(*token_match.span()) is not None:
                continue
            candidate = token_match.group(0)
            if "=" in candidate:
                key, assigned = candidate.split("=", 1)
                if assigned and assigned[0].isalnum() and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key):
                    # Entropy belongs to the assigned value, not to the
                    # long environment variable name or its '=' separator.
                    candidate = assigned
            if len(candidate) < 20:
                continue
            if any(start <= token_match.start() and token_match.end() <= end for start, end in pem_spans):
                # The PEM body is already classified as one explicit object;
                # its encoded lines are not separate credentials.
                continue
            if candidate.startswith("/") and token_match.start() > 0 and text[token_match.start() - 1] == "<":
                # XML closing tag names are structure, even when camel case
                # makes them look like high-entropy tokens.
                continue
            if _looks_like_resource_route(candidate):
                # Random project IDs can make ordinary API/UI paths look like
                # tokens. Explicit token/assignment detectors already ran.
                continue
            if candidate in explicit_values:
                continue
            if "=" in candidate and any(
                candidate[start : start + length] in explicit_values
                for length in value_lengths
                if length <= len(candidate)
                for start in range(len(candidate) - length + 1)
            ):
                continue
            classes = sum(
                bool(re.search(pattern, candidate)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
            )
            if classes >= 3 and re.search(r"[a-z]", candidate) and _entropy(candidate) >= 4.2:
                try:
                    decoded_candidate = base64.b64decode(
                        candidate + "=" * (-len(candidate) % 4), altchars=b"-_", validate=True
                    ).decode("utf-8")
                except (ValueError, UnicodeDecodeError, binascii.Error):
                    decoded_candidate = ""
                if decoded_candidate and all(
                    character.isprintable() or character.isspace() for character in decoded_candidate
                ):
                    continue
                found.append(candidate)
    return found
