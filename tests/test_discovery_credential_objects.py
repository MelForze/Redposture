"""Related credentials retain their object, identity, and physical location."""

from __future__ import annotations

import json

import pytest

from redposture_core.discovery_engine import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.elastic.discover import FindingAccumulator, scan_value_tree

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


def decode(value):
    return json.loads("".join(iter_json_chunks(value)))


def run(value, route, portion=65536):
    if route == "elastic":
        tree = scan_value_tree(value, source_kind="document", object_name="qa")
        acc = FindingAccumulator()
        for detection, location in tree.detections:
            if detection.available:
                acc.add(detection, location)
        return [(decode(f.value), f.secret_type) for f in acc.findings()], not tree.truncated_reasons
    if route == "json":
        value = json.dumps(value)
    if route == "disk":
        with DiskBackedText() as source:
            source.append_text(json.dumps(value))
            source.finish()
            matches, _, complete = _scan_portioned_value(source, "$", portion)
            return [(decode(m.value), m.detector) for m in matches], complete
    matches, _, complete = _scan_portioned_value(value, "$", portion)
    return [(decode(m.value), m.detector) for m in matches], complete


@pytest.mark.parametrize("route", ["common", "elastic", "json", "disk"])
@pytest.mark.parametrize("credential,kind", [(AWS, "aws_credentials"), (OAUTH, "oauth_credentials")])
def test_related_credentials_are_one_json_object(route, credential, kind):
    found, complete = run({"credentials": credential}, route)
    assert complete
    assert found == [(credential, kind)]


@pytest.mark.parametrize("route", ["common", "elastic", "json", "disk"])
def test_group_does_not_absorb_unrelated_neighbor_password(route):
    found, complete = run({"cloud": {**AWS, "password": "unrelated-password-42"}}, route)
    assert complete
    assert (AWS, "aws_credentials") in found
    assert ("unrelated-password-42", "password") in found
    assert len(found) == 2


@pytest.mark.parametrize("route", ["common", "elastic", "json", "disk"])
def test_group_does_not_join_credentials_from_different_objects(route):
    found, complete = run({"one": {"client_id": "qa-app"}, "two": {"client_secret": "inactive-secret-42"}}, route)
    assert complete
    assert len(found) == 1 and found[0][0] == "inactive-secret-42"
    assert found[0][1] not in {"oauth_credentials", "aws_credentials"}


@pytest.mark.parametrize("route", ["common", "elastic", "json", "disk"])
def test_long_group_member_stays_complete_and_structured(route):
    credential = {**OAUTH, "refresh_token": "inactive-" + "q" * 100000 + "-end"}
    found, complete = run({"credential": credential}, route)
    assert complete
    assert found == [(credential, "oauth_credentials")]


def test_group_spills_as_object_and_keeps_distinct_identity():
    from redposture_core.discovery_spool import SpoolingRecords
    from redposture_core.discovery_values import CredentialObject
    from redposture_core.secret_detection import fingerprint

    value = CredentialObject.from_fields(OAUTH)
    records = SpoolingRecords()
    records.append({"value": value})
    records.finish()
    restored = records[0]["value"]
    assert decode(restored) == OAUTH
    assert fingerprint(restored) == fingerprint(value)
    assert fingerprint(restored) != fingerprint("".join(value.iter_text_chunks()))


@pytest.mark.parametrize("route", ["common", "elastic", "json", "disk"])
@pytest.mark.parametrize("bad", ["${CLIENT_SECRET}", "****", "", "null"])
def test_placeholder_does_not_prove_an_oauth_group(route, bad):
    found, complete = run({"client_id": "qa", "client_secret": bad}, route)
    assert complete
    assert found == []


def test_incomplete_object_retains_closed_scalar_but_does_not_invent_group():
    raw = '{"client_id":"qa","client_secret":"inactive-secret-42"'
    matches, _, complete = _scan_portioned_value(raw, "$", 64)
    assert not complete
    assert [(decode(m.value), m.detector) for m in matches] == [("inactive-secret-42", "client_secret")]


def test_json_object_group_reports_parent_path():
    matches, _, complete = _scan_portioned_value({"oauth": OAUTH}, "$", 64)
    assert complete
    assert len(matches) == 1 and matches[0].object_path == "$.oauth"
    tree = scan_value_tree({"oauth": OAUTH}, source_kind="document", object_name="qa")
    assert [(location.path, decode(d.value)) for d, location in tree.detections if d.available] == [("/oauth", OAUTH)]


@pytest.mark.parametrize("module", ["AIRFLOW", "ELASTIC", "GITLAB", "MINIO"])
def test_structured_value_keeps_json_type_in_saved_txt_json_and_airflow_colors(tmp_path, capsys, module):
    from redposture_core.discovery_rendering import discovery_color_spans
    from redposture_core.discovery_values import CredentialObject
    from redposture_core.stage_runtime import LineOutputSink

    credential = {"client_id": "qa-app", "client_secret": 'inactive-λ-"quoted"\\tail\x1b[31m'}
    value = CredentialObject.from_fields(credential)
    output = tmp_path / "result.txt"
    sink = LineOutputSink(str(output), print)
    try:
        sink.emit_discovery_value(module, "qa", 80, finding_type="oauth_credentials", value=value, place="$.oauth")
    finally:
        sink.close()
    saved = output.read_text()
    terminal = capsys.readouterr().out
    assert "\x1b" not in saved and "\x1b" not in terminal
    assert "CredentialObject" not in saved and "DiskBackedText" not in saved
    assert json.loads(saved.split(" Value=", 1)[1].split(" Place=", 1)[0]) == credential
    json_output = "".join(iter_json_chunks({"findings": [{"value": value}]}))
    assert json.loads(json_output)["findings"][0]["value"] == credential
    payload = saved.split("[!] ", 1)[1].rstrip("\n")
    assert discovery_color_spans("[!]", payload) == [(0, len(payload), "orange")]


@pytest.mark.parametrize("route", ["common", "elastic", "json", "disk"])
def test_ambiguous_client_aliases_do_not_form_a_group(route):
    found, complete = run({"client_id": "qa-one", "clientId": "qa-two", "client_secret": "inactive-secret-42"}, route)
    assert complete
    assert found and all(kind != "oauth_credentials" for _value, kind in found)
    assert [value for value, _kind in found] == ["inactive-secret-42"]


def test_credential_group_selectors_and_order_independent_deduplication():
    from types import SimpleNamespace

    from redposture_core.secret_detection import scan_value
    from redposture_core.storage_discovery import DiscoveryCollector

    assert [m.detector for m in scan_value(OAUTH, enabled=("client_secret",))] == ["oauth_credentials"]
    collector = DiscoveryCollector(
        "gitlab",
        SimpleNamespace(host="qa", port=80, args=SimpleNamespace(discover_time=30)),
        {"status": "open_no_auth"},
    )
    assert collector.add("one", OAUTH)
    assert collector.add("two", dict(reversed(list(OAUTH.items()))))
    result = collector.result()
    assert result["status"] == "complete"
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert decode(finding["value"]) == OAUTH
    assert finding["occurrence_count"] == 2


def test_source_read_failure_keeps_closed_credential_field_without_inventing_group():
    from types import SimpleNamespace

    from redposture_core.storage_discovery import DiscoveryCollector

    collector = DiscoveryCollector(
        "gitlab",
        SimpleNamespace(host="qa", port=80, args=SimpleNamespace(discover_time=30)),
        {"status": "open_no_auth"},
    )

    def chunks():
        yield b'{"client_id":"qa","client_secret":"closed-secret-42",'
        raise OSError("source interrupted")

    assert not collector.scan_json_chunks("source", chunks())
    report = collector.result()
    assert report["status"] == "partial"
    assert [decode(f["value"]) for f in report["findings"]] == ["closed-secret-42"]
    assert all(f["type"] != "oauth_credentials" for f in report["findings"])


def test_duplicate_json_credential_member_is_partial_and_not_grouped():
    raw = '{"client_id":"qa-one","client_id":"qa-two","client_secret":"inactive-secret-42"}'
    matches, _, complete = _scan_portioned_value(raw, "$", 64)
    assert not complete
    assert getattr(matches, "incomplete_reason", None) == "duplicate_credential_field"
    assert [decode(m.value) for m in matches] == ["inactive-secret-42"]
    assert all(m.detector != "oauth_credentials" for m in matches)


@pytest.mark.parametrize("route", ["common", "elastic", "json", "disk"])
def test_group_storage_failure_is_partial_instead_of_crashing(monkeypatch, route):
    from redposture_core.discovery_values import CredentialObject

    def fail(*args, **kwargs):
        raise OSError("no space for grouped credential")

    monkeypatch.setattr(CredentialObject, "from_fields", fail)
    _findings, complete = run({"credentials": OAUTH}, route)
    assert not complete


@pytest.mark.parametrize("route", ["common", "elastic", "json", "disk"])
def test_group_storage_failure_keeps_prior_completed_findings(monkeypatch, route):
    from redposture_core.discovery_values import CredentialObject

    def fail(*args, **kwargs):
        raise OSError("no space for grouped credential")

    monkeypatch.setattr(CredentialObject, "from_fields", fail)
    found, complete = run([{"password": "completed-before-disk-error-42"}, {"oauth": OAUTH}], route)
    assert not complete
    assert ("completed-before-disk-error-42", "password") in found


@pytest.mark.parametrize("route", ["common", "elastic", "json", "disk"])
@pytest.mark.parametrize("client_id", ["qa-" + "λ" * 3072, "qa-" + "client-identifier-" * 10000])
def test_public_client_identity_does_not_drop_group_at_a_size_or_utf8_boundary(route, client_id):
    credential = {"client_id": client_id, "client_secret": "inactive-client-secret-42"}
    found, complete = run({"credentials": credential}, route, portion=64)
    assert complete
    assert found == [(credential, "oauth_credentials")]
