from __future__ import annotations

from redposture_core.constants import COLLECT_EXPORTERS, DISCOVERY_EXPORTERS


def _to_port_map(items: tuple[dict[str, object], ...]) -> dict[str, set[int]]:
    result: dict[str, set[int]] = {}
    for item in items:
        name = str(item.get("name") or "")
        port = int(item.get("port") or 0)
        result.setdefault(name, set()).add(port)
    return result


def test_discovery_exporters_include_new_defaults() -> None:
    ports = _to_port_map(DISCOVERY_EXPORTERS)
    assert ports["nats_exporter"] == {7777}
    assert ports["statsd_exporter"] == {9102}
    assert ports["mysqld_exporter"] == {9104}
    assert ports["haproxy_exporter"] == {9101}
    assert ports["memcached_exporter"] == {9150}
    assert ports["elasticsearch_exporter"] == {9114}
    assert ports["nginx_exporter"] == {9113}
    assert ports["apache_exporter"] == {9117}
    assert ports["bind_exporter"] == {9119}
    assert ports["ceph_exporter"] == {9128}
    assert ports["varnish_exporter"] == {9131}
    assert ports["rabbitmq_exporter"] == {9419}
    assert ports["windows_exporter"] == {9182}
    assert ports["ipmi_exporter"] == {9290}
    assert ports["sql_exporter"] == {9399}
    assert ports["pgbackrest_exporter"] == {9854}
    assert ports["victoriametrics_exporter"] == {8428, 8429}
    assert ports["snmp_exporter"] == {9117}


def test_node_exporter_profiles_include_production_metric_markers() -> None:
    node_profiles = [item for item in DISCOVERY_EXPORTERS if item.get("name") == "node_exporter"]
    assert {int(item.get("port") or 0) for item in node_profiles} == {9100, 9101}

    for profile in node_profiles:
        strong = set(profile.get("strong_markers") or ())
        weak = set(profile.get("weak_markers") or ())
        negative = set(profile.get("negative_markers") or ())
        assert {"node_cpu_seconds_total", "node_boot_time_seconds"}.issubset(strong)
        assert {"node_filesystem_avail_bytes", "node_memory_MemAvailable_bytes"}.issubset(weak)
        assert "haproxy_exporter_build_info" in negative


def test_collect_exporters_include_new_defaults() -> None:
    ports = _to_port_map(COLLECT_EXPORTERS)
    assert ports["nats_exporter"] == {7777}
    assert ports["statsd_exporter"] == {9102}
    assert ports["mysqld_exporter"] == {9104}
    assert ports["haproxy_exporter"] == {9101}
    assert ports["memcached_exporter"] == {9150}
    assert ports["elasticsearch_exporter"] == {9114}
    assert ports["nginx_exporter"] == {9113}
    assert ports["apache_exporter"] == {9117}
    assert ports["bind_exporter"] == {9119}
    assert ports["ceph_exporter"] == {9128}
    assert ports["varnish_exporter"] == {9131}
    assert ports["rabbitmq_exporter"] == {9419}
    assert ports["windows_exporter"] == {9182}
    assert ports["ipmi_exporter"] == {9290}
    assert ports["sql_exporter"] == {9399}
    assert ports["pgbackrest_exporter"] == {9854}
    assert ports["victoriametrics_exporter"] == {8428, 8429}
    assert ports["snmp_exporter"] == {9117}
