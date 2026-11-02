"""Forwarded legacy module attributes must restore their real owner on undo."""

from __future__ import annotations

import importlib

import pytest

from tests.test_module_stage_wrappers import MODULES


@pytest.mark.parametrize("module_name", MODULES)
def test_runtime_alias_monkeypatch_restores_forwarded_owner(module_name, monkeypatch):
    facade = importlib.import_module(f"redposture_core.stage_{module_name}")
    for alias, (owner, attribute) in facade._RUNTIME_COMPAT_NAMES.items():
        original = getattr(owner, attribute)

        def replacement(*_args, **_kwargs):
            pytest.fail("the test must not invoke a forwarded runtime hook")

        try:
            with monkeypatch.context() as patch:
                patch.setattr(facade, alias, replacement)
                assert getattr(owner, attribute) is replacement
                assert getattr(facade, alias) is replacement
            assert getattr(owner, attribute) is original, (module_name, alias)
            assert getattr(facade, alias) is original
        finally:
            # A failing regression must not poison subsequent parametrizations.
            setattr(owner, attribute, original)
