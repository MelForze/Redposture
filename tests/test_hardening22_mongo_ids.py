"""BSON document subtype is required for the read-only mongo-express URL."""

import pytest

from redposture_core.web_panels import _mongo_document_paths


@pytest.mark.parametrize("subtype", [3, 4])
def test_mongo_document_urls_preserve_required_binary_subtype_and_deduplicate_skip(subtype: int) -> None:
    source = f"""loadDocument('/db/qa/values/%22uuid%22?skip=0&amp;subtype={subtype}'); loadDocument('/db/qa/values/%22uuid%22?skip=100&amp;subtype={subtype}');"""
    assert _mongo_document_paths(source) == [f"/db/qa/values/%22uuid%22?subtype={subtype}"]


def test_mongo_plain_document_urls_still_deduplicate_pagination() -> None:
    assert _mongo_document_paths("loadDocument('/db/qa/values/one?skip=0'); loadDocument('/db/qa/values/one')") == [
        "/db/qa/values/one"
    ]
