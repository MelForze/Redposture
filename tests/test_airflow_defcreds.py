from __future__ import annotations

from redposture_core.modules.airflow import actions


def test_default_catalog_is_broad_unique_and_leads_with_real_default():
    assert actions._DEFAULT_CREDENTIALS[0] == ("airflow", "airflow")
    assert len(actions._DEFAULT_CREDENTIALS) == 18
    assert len(set(actions._DEFAULT_CREDENTIALS)) == len(actions._DEFAULT_CREDENTIALS)
    assert {
        ("admin", "admin"),
        ("airflow", "admin"),
        ("airflow", "airflow123"),
        ("root", "root"),
        ("service", "service"),
        ("guest", "guest"),
    }.issubset(actions._DEFAULT_CREDENTIALS)


def test_candidates_provided_first_then_defaults_deduped():
    cands = actions._build_credential_candidates("airflow", "airflow", True)
    assert cands[0] == ("airflow", "airflow", "provided")
    # the provided pair is not repeated from the default catalog
    assert sum(1 for u, p, _ in cands if (u, p) == ("airflow", "airflow")) == 1
    assert ("admin", "admin", "default") in cands


def test_candidates_no_defcreds_only_provided():
    assert actions._build_credential_candidates("u", "p", False) == [("u", "p", "provided")]


def test_candidates_defcreds_only():
    cands = actions._build_credential_candidates(None, None, True)
    assert all(source == "default" for _, _, source in cands)
    assert len(cands) == len(actions._DEFAULT_CREDENTIALS)
