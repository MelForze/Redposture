"""Product-neutral confirmation of completed disk-backed discovery scalars."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from .discovery_rules import (
    DetectedSecret,
    _candidate,
    _disk_field_hint,
    _secret_key_kind,
    analyze_value,
    classify_field,
    classify_field_name,
)
from .discovery_sequences import SpoolingSequence
from .discovery_validation import disk_entropy, validated_disk_jose
from .discovery_values import DiskBackedText


def confirm_disk_field(
    value: DiskBackedText, *, field_name: str, deadline: float | None = None
) -> DetectedSecret | None:
    """A weak field cannot become a secret solely by crossing a size threshold."""
    classification = classify_field_name(field_name)
    if value.obvious_placeholder or classification not in {"strong", "medium"}:
        return None
    if value.byte_length <= 65536:
        text = "".join(value.iter_text_chunks())
        confirmed = next(
            (
                item
                for item in analyze_value(text, path=field_name, field_classification=classification)
                if item.available
            ),
            None,
        )
        # A bounded confirmation should not replace the original disk lease
        # with a second inline copy when the whole field value was confirmed.
        if confirmed is not None and isinstance(confirmed.value, str) and confirmed.value == text:
            return replace(confirmed, value=value)
        return confirmed
    kind = _secret_key_kind(field_name) or "secret"
    if classification == "strong":
        return _candidate(value, kind, 85, "sensitive_field")
    entropy, classes = disk_entropy(value, deadline=deadline)
    if entropy >= 3.0 and (classes >= 2 or value.byte_length >= 24):
        return _candidate(value, kind, 73 if entropy >= 3.5 else 68, "sensitive_field")
    return None


def _detection_list() -> SpoolingSequence[DetectedSecret]:
    def encode(item: DetectedSecret) -> dict[str, Any]:
        return {
            "value": item.value,
            "secret_type": item.secret_type,
            "score": item.score,
            "detectors": list(item.detectors),
            "available": item.available,
            "span": item.span,
            "field_name": item.field_name,
        }

    def decode(item: Mapping[str, Any]) -> DetectedSecret:
        span = (int(item["span"][0]), int(item["span"][1])) if item.get("span") is not None else None
        return DetectedSecret(
            item["value"],
            item["secret_type"],
            item["score"],
            tuple(item["detectors"]),
            item["available"],
            span,
            item.get("field_name"),
        )

    return SpoolingSequence(encode=encode, decode=decode, estimate=lambda item: item.value.__sizeof__() + 256)


def _analyze_disk_value(
    value: DiskBackedText, *, path: str, deadline: float | None = None
) -> tuple[list[DetectedSecret], bool]:
    """Confirm completed bounded reader candidates with common evidence rules."""
    from .discovery_engine import _scan_portioned_value

    if value.obvious_placeholder:
        return [], True
    jose = validated_disk_jose(value, deadline=deadline)
    if jose is not None:
        return [_candidate(value, jose, 95, f"{jose}_structure")], True
    matches, _bytes, complete = _scan_portioned_value(value, "$", 65_536, _deadline=deadline)
    detections = _detection_list()
    confirmed_provider_types = {
        "api_token",
        "grafana_token",
        "digitalocean_token",
        "shopify_token",
        "docker_token",
        "pypi_token",
    }
    try:
        for match in matches:
            raw = match.value
            if match.detector == "high_entropy":
                detections.append(_candidate(raw, "high_entropy", 55, "entropy_candidate"))
                continue
            if isinstance(raw, DiskBackedText):
                if raw.obvious_placeholder:
                    continue
                if match.detector == "jwt":
                    kind = validated_disk_jose(raw, deadline=deadline)
                    if kind is not None:
                        detections.append(_candidate(raw, kind, 95, f"{kind}_structure"))
                elif (
                    match.detector
                    in {
                        "connection_string",
                        "signed_url",
                        "basic_auth",
                        "aws_credentials",
                        "oauth_credentials",
                        "encoded_credentials",
                    }
                    or "cookie_carrier" in match.rule_ids
                ):
                    detections.append(_candidate(raw, match.detector, 96, *match.rule_ids))
                elif match.detector in confirmed_provider_types:
                    detections.append(_candidate(raw, match.detector, 96, "provider_token_format"))
                elif match.detector in {
                    "password",
                    "client_secret",
                    "access_token",
                    "api_key",
                    "generic_secret",
                    "session_cookie",
                }:
                    key = (
                        _disk_field_hint(match.object_path, deadline)
                        if isinstance(match.object_path, DiskBackedText)
                        else match.object_path.rsplit(".", 1)[-1]
                    )
                    field_class = classify_field(key)
                    kind = "password" if match.detector == "password" else (_secret_key_kind(key) or "secret")
                    if field_class == "strong" or match.detector == "password":
                        detections.append(_candidate(raw, kind, 85, "credential_pair", "sensitive_field"))
                    elif field_class == "medium":
                        entropy, classes = disk_entropy(raw, deadline=deadline)
                        if entropy >= 3.0 and (classes >= 2 or raw.byte_length >= 24):
                            detections.append(_candidate(raw, kind, 73 if entropy >= 3.5 else 68, "sensitive_field"))
                elif match.detector == "private_key":
                    detections.append(_candidate(raw, "private_key", 100, "private_key_pem"))
                elif match.detector == "bearer_token":
                    detections.append(_candidate(raw, "bearer_token", 90, "bearer_auth"))
                elif match.detector != "certificate":
                    complete = False
                continue
            # Confirm small common-reader candidates through the common rules;
            # a common JWT or AWS-shaped ID alone is not sufficient evidence.
            key = (
                _disk_field_hint(match.object_path, deadline)
                if isinstance(match.object_path, DiskBackedText)
                else match.object_path.rsplit(".", 1)[-1]
            )
            hint = "password" if match.detector == "password" else key
            scalar = f"Bearer {raw}" if match.detector == "bearer_token" else raw
            detections.extend(analyze_value(scalar, path=hint, field_classification=classify_field(hint)))
    except OSError:
        detections.incomplete_reason = "storage_failure"
        return detections, False
    if not detections:
        field_class = classify_field(path)
        if field_class == "strong":
            return [_candidate(value, _secret_key_kind(path) or "secret", 85, "sensitive_field")], True
        if field_class == "medium":
            entropy, classes = disk_entropy(value, deadline=deadline)
            if entropy >= 3.0 and (classes >= 2 or value.byte_length >= 24):
                return [
                    _candidate(
                        value, _secret_key_kind(path) or "secret", 73 if entropy >= 3.5 else 68, "sensitive_field"
                    )
                ], True
            return [], True
    return detections, complete
