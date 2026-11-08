"""Contents metadata and readable notebook bodies are separate evidence."""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.jupyter import actions


@pytest.mark.parametrize("denied", [None, "catalog", "notebook"])
def test_model_reads_and_notebook_content_are_explicit(denied):
    class Pool:
        def request(self, method, url, **kwargs):
            assert method == "GET"
            path = urlsplit(url).path
            notebook = path.endswith("a.ipynb")
            kind = "notebook" if notebook else "catalog"
            model = (
                {
                    "name": "a.ipynb",
                    "path": "a.ipynb",
                    "type": "notebook",
                    "content": {"cells": [{"source": 'password="inactive-notebook!42"'}]},
                }
                if notebook
                else {
                    "name": "",
                    "path": "",
                    "type": "directory",
                    "content": [{"name": "a.ipynb", "path": "a.ipynb", "type": "notebook"}],
                }
            )
            return HttpResponse(403 if kind == denied else 200, json.dumps(model).encode(), {})

    ctx = SimpleNamespace(
        host="qa",
        port=8888,
        args=SimpleNamespace(discover=True, discover_time=30),
        credential=None,
        lifecycle_state=SimpleNamespace(http=Pool()),
    )
    result = actions.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})["content_discovery"]
    rows = {r["id"]: r for r in result["sources"]}
    assert rows["jupyter.contents_models"]["read"] == (2 if denied is None else 0 if denied == "catalog" else 1)
    assert rows["jupyter.contents_models"]["denied"] == int(denied is not None)
    if denied is None:
        assert rows["jupyter.notebook_contents"]["read"] == 1 and rows["jupyter.notebook_contents"]["complete"]
        assert result["status"] == "complete"
        assert [f["value"] for f in result["findings"]] == ["inactive-notebook!42"]
    else:
        assert not rows["jupyter.contents_models"]["complete"] and not result["findings"]
        assert result["status"] != "complete"
