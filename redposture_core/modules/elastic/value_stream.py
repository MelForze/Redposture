"""Compatibility facade for the common bounded discovery sequence primitives."""

from __future__ import annotations

from ...discovery_sequences import SpoolingSequence as SpoolingSequence
from ...discovery_sequences import stable_json_chunks as stable_json_chunks
from ...discovery_spool import SpoolingRecords as SpoolingRecords
from ...discovery_validation import _URLSAFE as _URLSAFE
from ...discovery_validation import _check as _check
from ...discovery_validation import _JSONPart as _JSONPart
from ...discovery_validation import disk_basic_password as disk_basic_password
from ...discovery_validation import disk_entropy as disk_entropy
from ...discovery_validation import validated_disk_jose as validated_disk_jose
