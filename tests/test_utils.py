from __future__ import annotations

from pathlib import Path

import pytest

from redposture_core.targeting import (
    collect_scan_ports as collect_scan_ports_from_targeting,
)
from redposture_core.targeting import (
    collect_scan_targets as collect_scan_targets_from_targeting,
)
from redposture_core.utils import (
    ScanExecutionGroup,
    ScanTargetSpec,
    TargetParsePolicy,
    build_scan_execution_groups,
    collect_scan_ports,
    collect_scan_target_specs,
    collect_scan_targets,
    is_signature_compat_typeerror,
    normalize_ip_literal,
    normalize_scan_host,
    parse_proxmox_api_token_auth,
    parse_scan_target_specs,
    parse_username_password_credential_file,
    stream_scan_target_specs,
)


def test_normalize_scan_host_strips_scheme_and_port() -> None:
    assert normalize_scan_host("http://10.0.0.1:9115") == "10.0.0.1"
    assert normalize_scan_host(" 10.0.0.2 ") == "10.0.0.2"


def test_normalize_ip_literal_accepts_only_ip_addresses() -> None:
    assert normalize_ip_literal("10.0.0.1") == "10.0.0.1"
    assert normalize_ip_literal("http://10.0.0.2:9115") == "10.0.0.2"
    assert normalize_ip_literal("redposture.example.com") is None


def test_collect_scan_targets_deduplicates_and_ignores_comments(tmp_path: Path) -> None:
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text(
        "# comment\n10.0.0.1\nhttp://10.0.0.2:9115\n10.0.0.1 # dup\n",
        encoding="utf-8",
    )

    hosts = collect_scan_targets(f"10.0.0.3,10.0.0.2,{hosts_file}")
    assert hosts == ["10.0.0.3", "10.0.0.2", "10.0.0.1"]
    assert collect_scan_targets_from_targeting(f"10.0.0.3,10.0.0.2,{hosts_file}") == hosts


def test_collect_scan_targets_keeps_file_precedence_when_token_matches_existing_file(tmp_path: Path) -> None:
    host_like_file = tmp_path / "api.local"
    host_like_file.write_text("10.10.10.10\n", encoding="utf-8")
    hosts = collect_scan_targets(str(host_like_file))
    assert hosts == ["10.10.10.10"]


def test_collect_scan_targets_expands_cidr() -> None:
    hosts = collect_scan_targets("10.0.1.0/30")
    assert hosts == ["10.0.1.1", "10.0.1.2"]


def test_collect_scan_targets_accepts_ipv4_16_network() -> None:
    hosts = collect_scan_targets("10.153.0.0/16")
    assert len(hosts) == 65534
    assert hosts[0] == "10.153.0.1"
    assert hosts[-1] == "10.153.255.254"


def test_collect_scan_targets_accepts_ipv4_16_from_file_and_rejects_15(tmp_path: Path) -> None:
    hosts_file = tmp_path / "targets.txt"
    hosts_file.write_text("10.0.0.10\n10.153.0.0/16\n", encoding="utf-8")

    hosts = collect_scan_targets(str(hosts_file))

    assert len(hosts) == 65535
    assert hosts[:3] == ["10.0.0.10", "10.153.0.1", "10.153.0.2"]
    assert hosts[-1] == "10.153.255.254"
    with pytest.raises(ValueError, match=r"expands to 131070 hosts \(limit: 65536\)"):
        collect_scan_targets("10.152.0.0/15")


def test_stream_scan_target_specs_accepts_large_ipv4_cidr_without_materializing() -> None:
    plan = stream_scan_target_specs("10.0.0.0/8")

    assert plan.target_count == 16_777_214
    assert plan.no_port_count == 16_777_214
    assert plan.hosts_sample(3) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert plan.first_spec() is not None
    assert plan.single_spec() is None


def test_stream_scan_target_specs_accepts_ipv4_zero_cidr_count() -> None:
    plan = stream_scan_target_specs("0.0.0.0/0")

    assert plan.target_count == 4_294_967_294
    assert plan.hosts_sample(3) == ["0.0.0.1", "0.0.0.2", "0.0.0.3"]


def test_stream_scan_target_specs_deduplicates_overlapping_ipv4_ranges() -> None:
    plan = stream_scan_target_specs("10.0.0.1,10.0.0.0/30,10.0.0.2,10.0.0.0/31")

    assert plan.target_count == 3
    assert list(plan.iter_hosts()) == ["10.0.0.1", "10.0.0.2", "10.0.0.0"]


def test_collect_scan_targets_rejects_invalid_cidr() -> None:
    with pytest.raises(ValueError, match="invalid network target"):
        collect_scan_targets("10.0.0.0/999")


def test_collect_scan_targets_rejects_non_network_slash_tokens() -> None:
    with pytest.raises(ValueError, match="invalid network target"):
        collect_scan_targets("not_a_host/24")


def test_collect_scan_target_specs_parses_http_and_https_urls() -> None:
    specs = collect_scan_target_specs("http://10.0.0.1:8500/v1/status/leader,https://api.local:9200/_cat/health")
    assert specs == [
        ScanTargetSpec(host="10.0.0.1", scheme="http", explicit_port=8500, path="/v1/status/leader"),
        ScanTargetSpec(host="api.local", scheme="https", explicit_port=9200, path="/_cat/health"),
    ]


def test_collect_scan_target_specs_preserves_url_path_and_query() -> None:
    specs = collect_scan_target_specs("http://grafana.local:3000/login?next=%2F")
    assert specs == [
        ScanTargetSpec(host="grafana.local", scheme="http", explicit_port=3000, path="/login", query="next=%2F")
    ]
    assert specs[0].path == "/login"
    assert specs[0].query == "next=%2F"
    assert specs[0].normalized_key == "http://grafana.local:3000/login?next=%2F"


def test_collect_scan_target_specs_preserves_mixed_url_variants() -> None:
    specs = collect_scan_target_specs(
        "http://Example.local:9200/_cluster/health,http://example.local:9200/_cat/health?format=json,example.local"
    )
    assert specs == [
        ScanTargetSpec(host="example.local", scheme="http", explicit_port=9200, path="/_cluster/health"),
        ScanTargetSpec(
            host="example.local", scheme="http", explicit_port=9200, path="/_cat/health", query="format=json"
        ),
        ScanTargetSpec(host="example.local", scheme=None, explicit_port=None),
    ]


def test_collect_scan_target_specs_keeps_distinct_ipv6_url_targets() -> None:
    specs = collect_scan_target_specs("http://[2001:db8::1]:443,http://[2001:db8::1:443]")

    assert [(item.host, item.explicit_port, item.normalized_key) for item in specs] == [
        ("2001:db8::1", 443, "http://[2001:db8::1]:443"),
        ("2001:db8::1:443", None, "http://[2001:db8::1:443]"),
    ]


def test_collect_scan_target_specs_handles_mixed_hosts_and_file(tmp_path: Path) -> None:
    hosts_file = tmp_path / "targets.txt"
    hosts_file.write_text(
        "http://10.0.0.2:9200/_cluster/health\n10.0.0.3\n10.0.1.0/30\n",
        encoding="utf-8",
    )
    specs = collect_scan_target_specs(f"10.0.0.1,{hosts_file}")
    assert specs == [
        ScanTargetSpec(host="10.0.0.1", scheme=None, explicit_port=None),
        ScanTargetSpec(host="10.0.0.2", scheme="http", explicit_port=9200, path="/_cluster/health"),
        ScanTargetSpec(host="10.0.0.3", scheme=None, explicit_port=None),
        ScanTargetSpec(host="10.0.1.1", scheme=None, explicit_port=None),
        ScanTargetSpec(host="10.0.1.2", scheme=None, explicit_port=None),
    ]


def test_collect_scan_target_specs_rejects_unsupported_url_scheme() -> None:
    with pytest.raises(ValueError, match="unsupported target URL scheme"):
        collect_scan_target_specs("redis://10.0.0.1:6379")


def test_parse_scan_target_specs_can_strip_or_reject_urls() -> None:
    stripped = parse_scan_target_specs(
        "https://api.local:9200/_cat/health",
        policy=TargetParsePolicy(url_mode="strip"),
    )
    assert stripped == [ScanTargetSpec(host="api.local", scheme=None, explicit_port=None)]

    with pytest.raises(ValueError, match="URL targets are not supported"):
        parse_scan_target_specs(
            "https://api.local:9200/_cat/health",
            policy=TargetParsePolicy(url_mode="reject"),
        )


def test_build_scan_execution_groups_url_port_overrides_matrix() -> None:
    specs = [
        ScanTargetSpec(host="10.0.0.1", scheme=None, explicit_port=None),
        ScanTargetSpec(host="10.0.0.2", scheme="http", explicit_port=8500),
    ]
    groups = build_scan_execution_groups(specs, [8500, 8501], include_scheme_in_key=False)
    assert groups == [
        ScanExecutionGroup(hosts=["10.0.0.1", "10.0.0.2"], port=8500, scheme_hint=None),
        ScanExecutionGroup(hosts=["10.0.0.1"], port=8501, scheme_hint=None),
    ]


def test_build_scan_execution_groups_can_group_by_scheme_hint() -> None:
    specs = [
        ScanTargetSpec(host="gitlab-http.local", scheme="http", explicit_port=8080),
        ScanTargetSpec(host="gitlab-https.local", scheme="https", explicit_port=8080),
    ]
    groups = build_scan_execution_groups(specs, [80], include_scheme_in_key=True)
    assert groups == [
        ScanExecutionGroup(hosts=["gitlab-http.local"], port=8080, scheme_hint="http"),
        ScanExecutionGroup(hosts=["gitlab-https.local"], port=8080, scheme_hint="https"),
    ]


def test_collect_scan_ports_deduplicates_and_expands_ranges() -> None:
    ports = collect_scan_ports("9100,9115,9200-9202,9115")
    assert ports == [9100, 9115, 9200, 9201, 9202]
    assert collect_scan_ports_from_targeting("9100,9115,9200-9202,9115") == ports


def test_collect_scan_ports_accepts_single_port() -> None:
    ports = collect_scan_ports("9100")
    assert ports == [9100]


def test_collect_scan_ports_accepts_file_path(tmp_path: Path) -> None:
    ports_file = tmp_path / "ports.txt"
    ports_file.write_text("# list\n9100\n9115,9121\n9200-9201\n", encoding="utf-8")
    ports = collect_scan_ports(str(ports_file))
    assert ports == [9100, 9115, 9121, 9200, 9201]


def test_collect_scan_ports_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        collect_scan_ports("abc")
    with pytest.raises(ValueError):
        collect_scan_ports("70000")
    with pytest.raises(ValueError):
        collect_scan_ports("9300-9200")


def test_parse_proxmox_api_token_auth_parses_standard_header() -> None:
    token_id, token_secret = parse_proxmox_api_token_auth("PVEAPIToken=prometheus@pve!metrics=super-secret-token-value")
    assert token_id == "prometheus@pve!metrics"
    assert token_secret == "super-secret-token-value"


def test_parse_proxmox_api_token_auth_accepts_space_variant() -> None:
    token_id, token_secret = parse_proxmox_api_token_auth("PVEAPIToken prometheus@pve!metrics=super-secret-token-value")
    assert token_id == "prometheus@pve!metrics"
    assert token_secret == "super-secret-token-value"


def test_parse_proxmox_api_token_auth_rejects_other_schemes() -> None:
    assert parse_proxmox_api_token_auth("Basic dXNlcjpwYXNz") == (None, None)


def test_is_signature_compat_typeerror_matches_expected_keywords() -> None:
    exc = TypeError("got an unexpected keyword argument 'run_deep_checks'")
    assert is_signature_compat_typeerror(exc, expected_keywords={"run_deep_checks"}) is True
    assert is_signature_compat_typeerror(exc, expected_keywords={"debug"}) is False


def test_is_signature_compat_typeerror_positional_mismatch_toggle() -> None:
    exc = TypeError("takes 2 positional arguments but 3 were given")
    assert is_signature_compat_typeerror(exc, expected_keywords={"run_deep_checks"}) is False
    assert (
        is_signature_compat_typeerror(
            exc,
            expected_keywords={"run_deep_checks"},
            allow_positional_mismatch=True,
        )
        is True
    )


def test_parse_username_password_credential_file_colon_mode(tmp_path: Path) -> None:
    creds_file = tmp_path / "creds.txt"
    creds_file.write_text("admin:secret\nuser:\nadmin:secret\n", encoding="utf-8")

    creds = parse_username_password_credential_file(str(creds_file), None)

    assert [(item.username, item.password, item.source) for item in creds or []] == [
        ("admin", "secret", "file"),
        ("user", "", "file"),
    ]


def test_parse_username_password_credential_file_username_only_mode(tmp_path: Path) -> None:
    creds_file = tmp_path / "users.txt"
    creds_file.write_text("admin\noperator\n", encoding="utf-8")

    creds = parse_username_password_credential_file(str(creds_file), "shared")

    assert [(item.username, item.password) for item in creds or []] == [("admin", "shared"), ("operator", "shared")]


@pytest.mark.parametrize(
    ("content", "password", "message"),
    [
        ("admin:secret\noperator\n", None, "mixed username"),
        (":secret\n", None, "username must not be empty"),
        ("admin\n", None, "-p/--password is required"),
        ("admin:secret\n", "shared", "cannot be combined"),
        ("\n# not a comment here?\n", None, "-p/--password is required"),
    ],
)
def test_parse_username_password_credential_file_rejects_invalid_files(
    tmp_path: Path,
    content: str,
    password: str | None,
    message: str,
) -> None:
    creds_file = tmp_path / "bad.txt"
    creds_file.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        parse_username_password_credential_file(str(creds_file), password)
