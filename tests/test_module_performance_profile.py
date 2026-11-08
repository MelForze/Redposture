"""Broad profiles must describe the real registry and reproducible settings."""

from __future__ import annotations

import pytest

from scripts import profile_module_performance as profile


@pytest.mark.parametrize("http_peer", ["async", "threaded"])
@pytest.mark.parametrize(
    "module,path,header",
    [
        ("vault", "/v1/auth/token/lookup-self", "X-Vault-Token"),
        ("nomad", "/v1/acl/token/self", "X-Nomad-Token"),
        ("jupyter", "/api/me", "Authorization"),
    ],
)
def test_both_measurement_peers_preserve_actual_wire_token_and_identity(module, path, header, http_peer):
    import http.client
    import ipaddress
    import json
    import threading

    from scripts.performance_http_fixtures import profile_token

    index = int(ipaddress.IPv4Address("127.0.0.1")) - profile.BASE_IP
    before = threading.active_count()
    fixture = profile.Fixture(
        module,
        {index: "positive"},
        0,
        False,
        mode="credentials",
        auth_case="valid",
        bind_host="127.0.0.1",
        http_peer=http_peer,
    )
    token = profile_token(module, "valid")
    client = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=1)
    try:
        client.request("GET", path, headers={header: ("token " if module == "jupyter" else "") + token})
        reply = client.getresponse()
        assert reply.status == 200 and reply.will_close
        body = json.loads(reply.read())
        identity = (
            body["data"]["id"]
            if module == "vault"
            else body["SecretID"]
            if module == "nomad"
            else body["identity"]["username"]
        )
        assert identity == ("profile-reader" if module == "jupyter" else token)
        assert fixture.pop_token_identity(index) == token
        assert fixture.pop_token_identity(index) is None
        assert fixture.stats["http_requests"] == fixture.stats["connections"] == 1
        assert fixture.routes.snapshot()["complete"]
    finally:
        client.close()
        fixture.close()
    assert not fixture.errors
    assert threading.active_count() == before


@pytest.mark.parametrize("module", ["docker", "spark", "yarn"])
def test_pair_auth_is_not_applicable_when_parser_only_offers_client_certificates(module):
    assert "pair/token" in profile.unsupported_auth_reason(module, "credentials")
    assert profile.unsupported_auth_reason(module, "detect") is None


@pytest.mark.parametrize("module", ["mongodb", "postgres", "redis"])
def test_async_native_fixture_uses_the_shared_owned_loop_without_server_threads(module):
    import ipaddress
    import threading

    index = int(ipaddress.IPv4Address("127.0.0.1")) - profile.BASE_IP
    before = threading.active_count()
    fixture = profile.Fixture(
        module, {index: "positive"}, 0, False, mode="credentials", bind_host="127.0.0.1", native_peer="async"
    )
    try:
        assert fixture.thread.name == "native-fixture-loop"
        assert threading.active_count() == before + 1
    finally:
        fixture.close()
    assert threading.active_count() == before and not fixture.errors


@pytest.mark.parametrize("module", ["grafana", "consul", "qdrant", "postgres"])
def test_existing_pair_or_token_parser_contract_remains_applicable(module):
    assert profile.unsupported_auth_reason(module, "credentials") is None


def test_not_applicable_mode_starts_no_fixture_and_records_source_provenance(monkeypatch):
    from argparse import Namespace

    monkeypatch.setattr(profile.sys, "platform", "linux")

    def forbidden(*args, **kwargs):
        pytest.fail("unsupported pair mode started a socket fixture")

    monkeypatch.setattr(profile, "Fixture", forbidden)
    result = profile.measure(Namespace(source=profile.ROOT, module="docker", mode="credentials", model="positive"))
    assert result["quality"] == result["cleanup"] == "NOT_APPLICABLE"
    assert len(result["source_sha256"]) == len(result["profile_sha256"]) == 64


def test_mixed_roles_are_exact_repeatable_and_include_real_negative_controls():
    first = profile.case_roles(1000, "mixed", 20261107)
    assert first == profile.case_roles(1000, "mixed", 20261107)
    assert first != profile.case_roles(1000, "mixed", 20261108)
    assert sum(value == "positive" for value in first.values()) == 50
    assert set(first.values()) == {"positive", "foreign", "closed"}
    assert set(first) == set(range(1000))


@pytest.mark.parametrize("count,model", [(0, "mixed"), (1_000_001, "mixed"), (10, "unknown")])
def test_profile_rejects_undefined_or_unbounded_case(count, model):
    with pytest.raises(ValueError):
        profile.case_roles(count, model, 1)


@pytest.mark.parametrize("module", ["consul", "kubeapi", "vault", "nomad", "gitlab", "jupyter"])
def test_token_products_get_an_explicit_token_in_the_credential_profile(module):
    args = profile.module_options(module, "credentials", "127.0.0.1:1", 0.5)
    assert "--token" in args
    assert "-u" not in args


def test_provided_valid_and_default_catalogue_modes_do_not_share_a_fabricated_catalogue():
    supplied = profile.module_options("grafana", "credentials", "127.0.0.1:1", 0.5, auth_case="valid")
    assert supplied[supplied.index("-u") + 1] == "profile-user"
    defaults = profile.module_options("grafana", "defcreds", "127.0.0.1:1", 0.5, auth_case="valid")
    assert "--defcreds" in defaults and "-u" not in defaults


def test_inventory_covers_every_registered_module_and_additional_surfaces():
    from redposture_core.module_registry import AUDIT_MODULE_NAMES
    from redposture_core.modules.kafka.http_surfaces import _PRODUCTS

    matrix = profile.inventory(profile.ROOT)
    rows = {row["module"]: row for row in matrix["audit_modules"]}
    assert set(rows) == set(AUDIT_MODULE_NAMES)
    assert set(rows["kafka"]["additional_surfaces"]) == {"provectus", "kafbat", *_PRODUCTS}
    assert rows["grpc"]["additional_surfaces"] == ["grpc_web"]
    assert rows["clickhouse"]["additional_surfaces"] == ["clickhouse_http"]
    assert "--namespaces" in rows["kubeapi"]["inventory_flags"]
    assert "--containers" in rows["docker"]["inventory_flags"]
    assert {row["name"] for row in matrix["other_workflows"]} == {"spray", "exporters collect", "exporters trigger"}
    assert all(set(row["inventory_flags"]) <= set(row["all_flags"]) for row in rows.values())


def test_profile_hash_includes_quality_and_fixture_helpers(tmp_path, monkeypatch):
    for name in profile.PROFILE_FILES:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(name)
    monkeypatch.setattr(profile, "ROOT", tmp_path)
    original = profile.profile_hash()
    (tmp_path / "scripts/performance_contracts.py").write_text("a different quality gate")
    assert profile.profile_hash() != original
    original = profile.profile_hash()
    (tmp_path / "tests/application_markup.py").write_text("a different fixture")
    assert profile.profile_hash() != original


def test_profile_hash_covers_the_application_markup_data_not_only_its_loader(tmp_path, monkeypatch):
    for name in profile.PROFILE_FILES:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(name)
    catalog = tmp_path / "tests/fixtures/detection_pages/application-markup.json"
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text("[]")
    monkeypatch.setattr(profile, "ROOT", tmp_path)
    original = profile.profile_hash()
    catalog.write_text('[{"product":"changed fixture"}]')
    assert profile.profile_hash() != original


@pytest.mark.parametrize(
    "corrupt_file",
    [
        "tests/application_markup.py",
        "tests/fixtures/detection_pages/application-markup.json",
        "scripts/performance_native_fixtures.py",
        "scripts/performance_native_server.py",
        "scripts/performance_fixture_process.py",
    ],
)
def test_snapshot_retains_all_measurement_sources_and_rejects_corruption(tmp_path, corrupt_file):
    destination = profile.save_instrument_snapshot(tmp_path)
    retained = {str(path.relative_to(destination)) for path in destination.rglob("*") if path.is_file()}
    assert retained == {*profile.PROFILE_FILES, "MANIFEST.json"}
    assert profile.save_instrument_snapshot(tmp_path) == destination
    (destination / corrupt_file).write_text("corrupted")
    with pytest.raises(ValueError, match="snapshot changed"):
        profile.save_instrument_snapshot(tmp_path)


def test_environment_records_versions_and_missing_packages_explicitly():
    evidence = profile.environment_evidence()
    assert len(evidence["sha256"]) == 64
    assert evidence["details"]["python"]
    assert "pymongo" in evidence["details"]["packages"]


def test_cannot_relabel_already_imported_core_as_another_snapshot(tmp_path):
    import redposture_core  # noqa: F401

    with pytest.raises(RuntimeError, match="fresh process"):
        profile.activate_source(tmp_path)


def test_thread_attribution_has_no_per_target_or_unbounded_labels():
    names = [
        "pymongo_server_monitor_thread",
        "pymongo_kill_cursors_thread",
        "Thread-100 (process_request_thread)",
        "redposture-scheduler-12-3",
        "module-profile-server",
        "workflow-fixture-loop",
        "native-fixture-loop",
        "MainThread",
        "unknown-target-127.32.0.1",
    ]
    assert [profile.thread_family(name) for name in names] == [
        "pymongo_monitor",
        "pymongo_cursor",
        "fixture_client",
        "runtime",
        "fixture_control",
        "fixture_control",
        "fixture_control",
        "main",
        "other",
    ]
