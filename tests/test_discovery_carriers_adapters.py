"""Agreed credential carriers survive every discover DTO/reader adapter."""

from __future__ import annotations

import base64
import json

import pytest

from scripts.discovery_accuracy import MODULES, READERS, scan

URI = "postgres://qa:p%40ss@db.invalid/db"
BASIC = "Basic " + base64.b64encode(b"qa:inactive-basic-password").decode()
JDBC = "jdbc:postgresql://db.invalid/app?user=qa&password=inactive-password-42"
ODBC = "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.invalid;UID=qa;PWD={Inactive;Odbc Password!42}"
SAS = (
    "https://qa.blob.core.windows.net/private/a.txt?sv=2023-11-03&se=2030-01-01T00%3A00%3A00Z&sp=r&sr=b&sig="
    + base64.b64encode(bytes(range(32))).decode().replace("=", "%3D")
)
AWS = {
    "aws_access_key_id": "AKIA" + "Q" * 16,
    "aws_secret_access_key": "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6uV9x",
    "aws_session_token": "inactive-session-token-42",
    "region": "eu-west-1",
}
OAUTH = {
    "client_id": "qa-application",
    "client_secret": "inactive-client-secret-42",
    "access_token": "inactive-access-token-42",
    "refresh_token": "inactive-refresh-token-42",
    "token_type": "Bearer",
    "scope": "read:qa",
}


@pytest.mark.parametrize("route", (*MODULES, *READERS))
@pytest.mark.parametrize(
    "value,kind",
    [
        (URI, "connection_string"),
        (BASIC, "basic_auth"),
        (SAS, "signed_url"),
        (ODBC, "connection_string"),
        (JDBC, "connection_string"),
    ],
)
def test_complete_carrier_value_type_and_path_per_adapter(route, value, kind):
    rows, status = scan(route, {"body": value})
    assert status == "complete"
    assert [(r["value"], r["type"], r["path"]) for r in rows] == [(value, kind, "$.body")]


@pytest.mark.parametrize("route", (*MODULES, *READERS))
@pytest.mark.parametrize("credentials,kind", [(AWS, "aws_credentials"), (OAUTH, "oauth_credentials")])
def test_structured_group_value_type_and_parent_path_per_adapter(route, credentials, kind):
    rows, status = scan(route, {"credentials": credentials})
    assert status == "complete"
    assert [(json.loads(r["value"]), r["type"], r["path"]) for r in rows] == [(credentials, kind, "$.credentials")]
