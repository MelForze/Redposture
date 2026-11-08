"""Generated index identifiers are metadata; document UUID candidates remain visible."""

from __future__ import annotations

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.elastic.discover import DiscoverEngine, DiscoverResponse

INDEX_UUID = "7ebVoqm5Rq6PuUCS-vRNnA"


@pytest.mark.parametrize("disk", [False, True])
def test_generated_index_uuid_does_not_become_an_entropy_finding(disk):
    with DiskBackedText() as value:
        value.append_text(INDEX_UUID)
        value.finish()
        engine = DiscoverEngine(lambda req: DiscoverResponse(200, b"{}"))
        engine._scan_configuration(
            "index_settings",
            {"settings": {"index": {"uuid": value if disk else INDEX_UUID}}},
            object_name="qa/_settings",
            source_kind="index_settings",
            index="qa",
        )
        report = engine._finalize()
        assert report.coverage.surfaces["index_settings"].objects_scanned == 1
        assert report.findings == []


@pytest.mark.parametrize("kind", ["document", "task_log"])
def test_same_uuid_in_unlabelled_content_stays_a_low_candidate(kind):
    engine = DiscoverEngine(lambda req: DiscoverResponse(200, b"{}"))
    engine._scan_configuration("qa", {"settings": {"index": {"uuid": INDEX_UUID}}}, object_name="qa", source_kind=kind)
    assert [(r.secret_type, r.confidence, r.value) for r in engine._finalize().findings] == [
        ("high_entropy", "low", INDEX_UUID)
    ]


@pytest.mark.parametrize("value", ["glpat-InactiveOnly0123456789abcdef", 'password="inactive-index-settings!42"'])
def test_explicit_secret_evidence_in_the_same_metadata_field_is_not_suppressed(value):
    engine = DiscoverEngine(lambda req: DiscoverResponse(200, b"{}"))
    engine._scan_configuration(
        "index_settings",
        {"settings": {"index": {"uuid": value}}},
        object_name="qa/_settings",
        source_kind="index_settings",
    )
    assert engine._finalize().findings
