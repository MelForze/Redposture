"""Independent scalar examples carry documented stable evidence IDs."""

from __future__ import annotations

import base64

import pytest

from redposture_core.discovery_catalog import rule_catalog
from redposture_core.discovery_rules import analyze_value


@pytest.mark.parametrize(
    "body,path,expected,rule",
    [
        (
            "postgres://qa:inactive%40pass@db.invalid/db",
            "",
            "postgres://qa:inactive%40pass@db.invalid/db",
            "credential_uri",
        ),
        (
            "Basic " + base64.b64encode(b"qa:inactive-basic-password").decode(),
            "",
            "Basic " + base64.b64encode(b"qa:inactive-basic-password").decode(),
            "basic_auth",
        ),
        ("ALTER USER qa IDENTIFIED BY 'inactive''sql-password';", "", "inactive'sql-password", "sql_password"),
        ("password=inactive-field-password", "", "inactive-field-password", "credential_pair"),
        ("inactive-field-password", "password", "inactive-field-password", "sensitive_field"),
        ("user,password\nqa,inactive-csv-password\n", "", "inactive-csv-password", "csv_secret_column"),
        ("<password>inactive&lt;xml-password</password>", "", "inactive<xml-password", "xml_secret_element"),
        (
            "glpat-" + "Inactive0123456789abcdefghijklmnop",
            "",
            "glpat-" + "Inactive0123456789abcdefghijklmnop",
            "gitlab_token_format",
        ),
        (
            "hvs." + "Inactive0123456789abcdefghijklmnop",
            "",
            "hvs." + "Inactive0123456789abcdefghijklmnop",
            "vault_token_format",
        ),
    ],
)
def test_observed_rule_ids_have_exact_value_and_minimum_syntax(body, path, expected, rule):
    policies = rule_catalog()
    available = [finding for finding in analyze_value(body, path=path) if finding.available]
    selected = [finding for finding in available if finding.value == expected]
    assert selected and any(rule in finding.detectors for finding in selected)
    assert all(tag in policies for finding in available for tag in finding.detectors)
    assert policies[rule].id == rule and policies[rule].minimum_syntax and policies[rule].value_policy


@pytest.mark.parametrize(
    "body",
    ["postgres://db.invalid/app", "Basic !!!!", "ALTER USER qa IDENTIFIED BY 'unfinished", "glpat-short", "hvs.short"],
)
def test_catalog_examples_do_not_find_incomplete_syntax(body):
    assert not [row for row in analyze_value(body) if row.available]
