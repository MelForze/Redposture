from __future__ import annotations

import json
from pathlib import Path

import pytest

from redposture_core.profiles import load_profiles


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
