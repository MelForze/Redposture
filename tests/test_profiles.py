from __future__ import annotations

import json
from pathlib import Path

import pytest

from redposture_core.profiles import (
    _as_port,
    _as_str_list,
    _validate_collect_endpoints,
    _validate_collect_exporters,
    _validate_discovery_exporters,
    _validate_trigger_exporters,
    load_profiles,
)


def test_load_profiles_defaults() -> None:
    profiles = load_profiles(None)
    assert "trigger_exporters" in profiles
    assert "discovery_exporters" in profiles
    assert "collect_exporters" in profiles
    assert "collect_debug_endpoints" in profiles
    assert profiles["trigger_exporters"]
    blackbox = next(item for item in profiles["trigger_exporters"] if item["name"] == "blackbox_exporter")
    assert blackbox["target_fmt"] == "http://{our_host}"
    discovery_names = {str(item.get("name") or "") for item in profiles["discovery_exporters"]}
    collect_names = {str(item.get("name") or "") for item in profiles["collect_exporters"]}
    for name in (
        "nats_exporter",
        "statsd_exporter",
        "mysqld_exporter",
        "haproxy_exporter",
        "memcached_exporter",
        "elasticsearch_exporter",
        "nginx_exporter",
        "apache_exporter",
        "bind_exporter",
        "ceph_exporter",
        "varnish_exporter",
        "rabbitmq_exporter",
        "windows_exporter",
        "ipmi_exporter",
        "sql_exporter",
        "snmp_exporter",
    ):
        assert name in discovery_names
        assert name in collect_names


def test_load_profiles_override_subset(tmp_path: Path) -> None:
    profiles_file = tmp_path / "profiles.json"
    profiles_file.write_text(
        json.dumps(
            {
                "trigger_exporters": [
                    {
                        "name": "custom_trigger",
                        "port": 9199,
                        "detect_path": "/metrics",
                        "markers": ["custom_up"],
                        "trigger_path": "/probe",
                        "target_fmt": "{our_host}:9999",
                    }
                ],
                "collect_debug_endpoints": ["/debug/vars"],
            }
        ),
        encoding="utf-8",
    )

    profiles = load_profiles(str(profiles_file))
    assert len(profiles["trigger_exporters"]) == 1
    assert profiles["trigger_exporters"][0]["name"] == "custom_trigger"
    assert profiles["collect_debug_endpoints"] == ("/debug/vars",)


def test_load_profiles_rejects_unknown_keys(tmp_path: Path) -> None:
    profiles_file = tmp_path / "profiles.json"
    profiles_file.write_text(json.dumps({"unknown": []}), encoding="utf-8")

    with pytest.raises(ValueError):
        load_profiles(str(profiles_file))


def test_port_and_string_list_validators_cover_edge_cases() -> None:
    assert _as_port("5432", "ctx") == 5432
    with pytest.raises(ValueError, match="must be an integer"):
        _as_port("nope", "ctx")
    with pytest.raises(ValueError, match="must be in range 1..65535"):
        _as_port(70000, "ctx")

    assert _as_str_list(["a", "b"], "ctx") == ("a", "b")
    with pytest.raises(ValueError, match="must be a non-empty list"):
        _as_str_list([], "ctx")
    with pytest.raises(ValueError, match=r"ctx\[1\]: must be a non-empty string"):
        _as_str_list(["a", ""], "ctx")


def test_trigger_discovery_collect_validators_reject_invalid_shapes() -> None:
    with pytest.raises(ValueError, match="trigger_exporters: must be a list"):
        _validate_trigger_exporters({})
    with pytest.raises(ValueError, match="trigger_exporters\\[0\\]: name is required"):
        _validate_trigger_exporters(
            [
                {
                    "port": 9100,
                    "detect_path": "/metrics",
                    "markers": ["up"],
                    "trigger_path": "/probe",
                    "target_fmt": "{our_host}",
                }
            ]
        )
    with pytest.raises(ValueError, match="trigger_exporters\\[0\\]: detect_path is required"):
        _validate_trigger_exporters(
            [{"name": "x", "port": 9100, "markers": ["up"], "trigger_path": "/probe", "target_fmt": "{our_host}"}]
        )
    with pytest.raises(ValueError, match="trigger_exporters\\[0\\].markers\\[0\\]: must be a non-empty string"):
        _validate_trigger_exporters(
            [
                {
                    "name": "x",
                    "port": 9100,
                    "detect_path": "/metrics",
                    "markers": [""],
                    "trigger_path": "/probe",
                    "target_fmt": "{our_host}",
                }
            ]
        )

    with pytest.raises(ValueError, match="discovery_exporters: must be a list"):
        _validate_discovery_exporters({})
    with pytest.raises(ValueError, match="discovery_exporters\\[0\\]: name is required"):
        _validate_discovery_exporters([{"port": 9100, "markers": ["up"]}])
    with pytest.raises(ValueError, match="collect_exporters: must be a list"):
        _validate_collect_exporters({})
    with pytest.raises(ValueError, match="collect_exporters\\[0\\]: name is required"):
        _validate_collect_exporters([{"port": 9100}])


def test_collect_endpoint_validator_rejects_invalid_entries() -> None:
    assert _validate_collect_endpoints(["/debug/vars"]) == ("/debug/vars",)

    with pytest.raises(ValueError, match="must be a non-empty list"):
        _validate_collect_endpoints([])
    with pytest.raises(ValueError, match="must be a string starting with '/'"):
        _validate_collect_endpoints(["debug/vars"])


def test_load_profiles_rejects_non_object_json(tmp_path: Path) -> None:
    profiles_file = tmp_path / "profiles.json"
    profiles_file.write_text(json.dumps(["bad"]), encoding="utf-8")

    with pytest.raises(ValueError, match="profiles file must be a JSON object"):
        load_profiles(str(profiles_file))
