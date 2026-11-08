"""Measure the actual scheduler construction, never guess auto capacity."""

from __future__ import annotations

import pytest

from scripts import performance_contracts as contracts


def scheduler_type():
    class Scheduler:
        def __init__(self, *, detect_workers, deep_workers, flag=None):
            if detect_workers < 0:
                raise ValueError("rejected")
            self.detect_workers = max(1, detect_workers)
            self.deep_workers = max(1, deep_workers)
            self.flag = flag

    return Scheduler


def test_probe_records_actual_normalized_capacity_and_preserves_arguments_and_identity():
    cls = scheduler_type()
    original = cls.__init__
    factory = getattr(contracts, "SchedulerAdmissionProbe", None)
    assert callable(factory), "missing actual scheduler observation"
    with factory(cls) as probe:
        marker = object()
        value = cls(detect_workers=512, deep_workers=4, flag=marker)
        assert type(value) is cls and value.flag is marker
        cls(detect_workers=0, deep_workers=0)
    assert cls.__init__ is original
    assert probe.selected_detect_workers() is None  # Two different actual capacities were used.
    assert probe.snapshot() == {
        "constructor_calls": 2,
        "configurations": [{"detect_workers": 512, "deep_workers": 4}, {"detect_workers": 1, "deep_workers": 1}],
        "overflow": 0,
        "restore_conflict": False,
    }


def test_no_constructed_scheduler_is_zero_observations_not_a_guessed_64():
    factory = getattr(contracts, "SchedulerAdmissionProbe", None)
    assert callable(factory)
    with factory(scheduler_type()) as probe:
        pass
    assert probe.snapshot()["constructor_calls"] == 0 and probe.snapshot()["configurations"] == []
    assert probe.selected_detect_workers() == 0


def test_single_auto_capacity_is_observed_without_an_optional_runtime_observer():
    cls = scheduler_type()
    factory = getattr(contracts, "SchedulerAdmissionProbe", None)
    assert callable(factory)
    with factory(cls) as probe:
        cls(detect_workers=40, deep_workers=4)
    assert probe.selected_detect_workers() == 40


def test_constructor_failure_and_body_failure_restore_the_original_method():
    cls = scheduler_type()
    original = cls.__init__
    factory = getattr(contracts, "SchedulerAdmissionProbe", None)
    assert callable(factory)
    with pytest.raises(ValueError, match="rejected"), factory(cls) as probe:
        cls(detect_workers=-1, deep_workers=4)
    assert cls.__init__ is original and probe.snapshot()["constructor_calls"] == 0
    with pytest.raises(RuntimeError, match="body"), factory(cls):
        raise RuntimeError("body")
    assert cls.__init__ is original


def test_unique_configuration_storage_is_bounded_without_losing_total_calls():
    cls = scheduler_type()
    factory = getattr(contracts, "SchedulerAdmissionProbe", None)
    assert callable(factory)
    with factory(cls, limit=2) as probe:
        for i in range(1, 20):
            cls(detect_workers=i, deep_workers=4)
    assert probe.snapshot()["constructor_calls"] == 19
    assert len(probe.snapshot()["configurations"]) == 2 and probe.snapshot()["overflow"] == 17
    assert probe.selected_detect_workers() is None


def test_restore_does_not_silently_overwrite_an_unrelated_external_override():
    cls = scheduler_type()
    factory = getattr(contracts, "SchedulerAdmissionProbe", None)
    assert callable(factory)

    def replacement(self, **kwargs):
        pass

    with factory(cls) as probe:
        cls.__init__ = replacement
    assert cls.__init__ is replacement and probe.snapshot()["restore_conflict"] is True
