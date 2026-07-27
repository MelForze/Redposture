#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

_EXPECTED_MODULES = (
    "exporters",
    "registry",
    "grafana",
    "gitlab",
    "consul",
    "kubeapi",
    "postgres",
    "mongodb",
    "oracle",
    "docker",
    "clickhouse",
    "redis",
    "etcd",
    "qdrant",
    "elastic",
    "grpc",
    "kafka",
    "zookeeper",
    "keeper",
    "proxmox",
)

_EXPECTED_LABELS = (
    "exporters_scan",
    "exporters_collect",
    "exporters_trigger",
    "exporters_scan_url_http",
    "exporters_scan_url_https_reject",
    "exporters_collect_url_http",
    "exporters_collect_url_https_reject",
    "exporters_trigger_url_http",
    "exporters_trigger_url_https_reject",
    "registry_open",
    "registry_auth",
    "registry_harbor",
    "registry_gitlab",
    "registry_nexus",
    "registry_url_http",
    "registry_url_https_reject",
    "registry_multi_instance_urls",
    "grafana_default",
    "grafana_apitoken",
    "grafana_url_http",
    "grafana_url_https_reject",
    "grafana_ssrf_edge",
    "grafana_multi_instance_urls",
    "gitlab_public",
    "gitlab_analyst",
    "gitlab_url_override_http",
    "gitlab_multi_instance_urls",
    "consul_open",
    "consul_acl_read",
    "consul_acl_mgmt",
    "consul_url_hint_http",
    "consul_multi_instance_urls",
    "kubeapi_open",
    "kubeapi_auditor",
    "kubeapi_admin",
    "kubeapi_url_override_https",
    "kubeapi_multi_instance_urls",
    "postgres_default",
    "postgres_multi_ports",
    "mongodb_open",
    "mongodb_auth",
    "mongodb_defcreds",
    "mongodb_multi_ports",
    "mongodb_query_dump",
    "mongodb_debug_smoke",
    "oracle_listener",
    "oracle_sid_service_enum",
    "oracle_auth",
    "oracle_defcreds",
    "oracle_combo_file",
    "oracle_spray",
    "oracle_multi_ports",
    "oracle_pdb_cdb",
    "oracle_privesc_check",
    "oracle_privesc_chain",
    "oracle_nne_check",
    "oracle_listener_dump",
    "oracle_listener_protected",
    "oracle_query_dump",
    "oracle_rce_scheduler",
    "oracle_external_table_rce",
    "oracle_dbms_cloud_capability",
    "oracle_privesc_chain_execute",
    "oracle_file_read",
    "oracle_wallet_search",
    "oracle_wallet_extract",
    "oracle_large_file_resume",
    "oracle_arbitrary_fs",
    "oracle_hashes",
    "oracle_dblink",
    "oracle_debug_smoke",
    "oracle_json_smoke",
    "docker_open",
    "docker_tls",
    "docker_multi_ports",
    "docker_inventory",
    "docker_exec",
    "docker_debug_smoke",
    "clickhouse_native_open",
    "clickhouse_http_open",
    "clickhouse_native_auth",
    "clickhouse_http_auth",
    "clickhouse_multi_ports",
    "redis_default",
    "redis_multi_ports",
    "etcd_open",
    "etcd_auth",
    "etcd_auth_defcreds",
    "etcd_auth_user_pass",
    "etcd_url_http",
    "etcd_url_https_reject",
    "etcd_multi_instance_urls",
    "qdrant_default",
    "qdrant_url_http",
    "qdrant_url_https_reject",
    "qdrant_multi_instance_urls",
    "elastic_open",
    "elastic_auth",
    "elastic_url_hint_https",
    "elastic_plugins_edge",
    "elastic_multi_instance_urls",
    "grpc_open",
    "grpc_auth_token",
    "grpc_auth_defcreds",
    "grpc_multi_ports",
    "grpc_debug_smoke",
    "grpc_invoke_health",
    "grpc_proto_invoke",
    "grpc_protoset_invoke",
    "grpc_openapi_export",
    "grpc_web_detect",
    "kafka_open",
    "kafka_auth",
    "kafka_multi_ports",
    "kafka_tls_defcreds",
    "kafka_tls_explicit_user",
    "zookeeper_default",
    "zookeeper_multi_ports",
    "keeper_cluster",
    "keeper_tls",
    "keeper_no4lw",
    "keeper_apache_control",
    "proxmox_audit",
    "proxmox_admin",
    "proxmox_url_override_https",
    "proxmox_multi_instance_urls",
)

_EXTENDED_EXPECTED_LABELS = (
    "exporters_debug_smoke",
    "exporters_scan_extended_controls",
    "exporters_collect_extended_controls",
    "exporters_collect_resume_checkpoint",
    "exporters_collect_debug_smoke",
    "exporters_trigger_extended_controls",
    "exporters_trigger_debug_smoke",
    "registry_debug_smoke",
    "registry_extended_tags_metadata",
    "registry_extended_ports_flag",
    "grafana_debug_smoke",
    "grafana_extended_auth_ssrf_controls",
    "grafana_extended_ports_flag",
    "gitlab_debug_smoke",
    "gitlab_extended_token_project_clone",
    "gitlab_extended_ports_flag",
    "consul_debug_smoke",
    "consul_extended_ports_basic_auth",
    "consul_extended_inventory_filters",
    "consul_extended_ssrf_probe",
    "kubeapi_debug_smoke",
    "kubeapi_extended_ports_flag",
    "kubeapi_extended_selectors_basic_auth",
    "postgres_debug_smoke",
    "postgres_extended_defcreds",
    "postgres_extended_query_privs",
    "postgres_extended_execute",
    "postgres_extended_os_read",
    "postgres_extended_defcreds_both_fail",
    "mongodb_extended_document_index_cmd",
    "mongodb_extended_invalid_document_query",
    "oracle_extended_schema_sensitive_protocol",
    "docker_extended_tls_files_pairing_error",
    "docker_extended_exec_worker",
    "clickhouse_debug_smoke",
    "clickhouse_extended_defcreds",
    "clickhouse_extended_query_columns",
    "clickhouse_extended_execute",
    "redis_debug_smoke",
    "redis_extended_key_dump_count",
    "redis_extended_defcreds",
    "redis_extended_paged_dump",
    "etcd_debug_smoke",
    "etcd_extended_key_dump_count",
    "etcd_extended_ports_flag",
    "etcd_extended_paged_dump",
    "qdrant_debug_smoke",
    "qdrant_extended_collection_dump_count",
    "qdrant_extended_ports_flag",
    "qdrant_extended_ssrf_probe",
    "elastic_debug_smoke",
    "elastic_extended_ports_defcreds",
    "elastic_extended_all_actions",
    "elastic_extended_apitoken_invalid",
    "grpc_extended_metadata_invoke",
    "grpc_extended_basic_empty_password",
    "kafka_debug_smoke",
    "kafka_tls_debug_smoke",
    "kafka_extended_topic_dump_count",
    "kafka_extended_dump_max_conflict",
    "kafka_extended_defcreds",
    "kafka_extended_empty_password",
    "kafka_extended_probe_write",
    "kafka_tls_extended_topic",
    "kafka_tls_extended_bad_password",
    "zookeeper_debug_smoke",
    "zookeeper_extended_znode_limits",
    "zookeeper_extended_empty_password",
    "keeper_debug_smoke",
    "keeper_force_plaintext",
    "keeper_force_tls",
    "proxmox_debug_smoke",
    "proxmox_extended_ports_flag",
    "proxmox_extended_defcreds",
    "proxmox_extended_defcreds_empty_password",
    "proxmox_extended_add_user_mock",
    "proxy_exporters_socks4a",
    "proxy_exporters_socks5h",
    "proxy_exporters_http",
    "proxy_exporters_https",
    "proxy_redis_socks4a",
    "proxy_redis_socks5h",
    "proxy_redis_http",
    "proxy_redis_https",
    # P4-D idempotency twins (must produce same normalized JSON as the base case).
    "redis_idempotency",
    "postgres_idempotency",
    "etcd_idempotency",
    "mongodb_idempotency",
    "kafka_idempotency",
    "kafka_tls_idempotency",
    # P4-C mutate-config: varying --show-keys value on the same lab service.
    "redis_mutate_show_keys_3",
    "redis_mutate_show_keys_100",
    # P4-E fuzz: CLI must reject invalid inputs with exit=2 (no Python traceback).
    "fuzz_exporters_scan_missing_targets",
    "fuzz_exporters_scan_invalid_ports",
    "fuzz_exporters_scan_zero_timeout",
    "fuzz_exporters_collect_zero_max_inflight",
    "fuzz_exporters_trigger_missing_callback",
    "fuzz_exporters_trigger_bad_callback_ip",
    "fuzz_exporters_trigger_check_without_listen",
    "fuzz_exporters_trigger_json_listen_without_output",
    "fuzz_exporters_trigger_negative_listen_seconds",
    "fuzz_registry_missing_targets",
    "fuzz_grafana_missing_targets",
    "fuzz_gitlab_missing_targets",
    "fuzz_consul_missing_targets",
    "fuzz_kubeapi_missing_targets",
    "fuzz_postgres_missing_targets",
    "fuzz_mongodb_missing_targets",
    "fuzz_oracle_missing_targets",
    "fuzz_docker_missing_targets",
    "fuzz_clickhouse_missing_targets",
    "fuzz_redis_missing_targets",
    "fuzz_etcd_missing_targets",
    "fuzz_qdrant_missing_targets",
    "fuzz_elastic_missing_targets",
    "fuzz_grpc_missing_targets",
    "fuzz_kafka_missing_targets",
    "fuzz_zookeeper_missing_targets",
    "fuzz_keeper_missing_targets",
    "fuzz_proxmox_missing_targets",
    "fuzz_registry_username_without_password",
    "fuzz_registry_token_basic_conflict",
    "fuzz_registry_show_tags_without_repository",
    "fuzz_registry_metadata_without_tag",
    "fuzz_registry_assets_without_nexus",
    "fuzz_registry_download_without_image",
    "fuzz_grafana_username_without_password",
    "fuzz_kubeapi_username_without_password",
    "fuzz_elastic_username_without_password",
    "fuzz_grpc_username_without_password",
    "fuzz_kafka_username_without_password",
    "fuzz_zookeeper_username_without_password",
    "fuzz_proxmox_username_without_password",
    "fuzz_redis_username_without_password",
    "fuzz_consul_username_without_password",
    "fuzz_consul_key_without_dump",
    "fuzz_consul_service_without_dump",
    "fuzz_consul_agent_without_dump",
    "fuzz_consul_node_without_dump",
    "fuzz_consul_ssrf_port_without_target",
    "fuzz_consul_delete_without_revshell",
    "fuzz_consul_listen_without_revshell",
    "fuzz_consul_revshell_missing_lhost",
    "fuzz_consul_revshell_bad_lhost",
    "fuzz_consul_revshell_listen_missing_lport",
    "fuzz_qdrant_listen_without_ssrf_target",
    "fuzz_qdrant_ssrf_without_collection",
    "fuzz_qdrant_bad_ssrf_port",
    "fuzz_postgres_username_without_password",
    "fuzz_postgres_show_columns_without_table",
    "fuzz_postgres_column_without_table",
    "fuzz_postgres_execute_sql_conflict",
    "fuzz_postgres_execute_os_read_conflict",
    "fuzz_postgres_os_shell_sql_shell_conflict",
    "fuzz_mongodb_username_without_password",
    "fuzz_mongodb_invalid_query_json",
    "fuzz_mongodb_query_without_collection",
    "fuzz_mongodb_document_without_collection",
    "fuzz_mongodb_document_query_conflict",
    "fuzz_mongodb_invalid_projection_json",
    "fuzz_mongodb_invalid_nosql_cmd_json",
    "fuzz_mongodb_nosql_cmd_shell_conflict",
    "fuzz_oracle_username_without_password",
    "fuzz_oracle_service_sid_conflict",
    "fuzz_oracle_non_select_query",
    "fuzz_oracle_os_write_bad_syntax",
    "fuzz_oracle_download_bad_syntax",
    "fuzz_docker_container_without_exec",
    "fuzz_docker_exec_without_container",
    "fuzz_docker_tls_cert_without_key",
    "fuzz_docker_tls_key_without_cert",
    "fuzz_clickhouse_username_without_password",
    "fuzz_clickhouse_show_columns_without_table",
    "fuzz_clickhouse_column_without_table",
    "fuzz_clickhouse_execute_sql_conflict",
    "fuzz_clickhouse_os_shell_sql_shell_conflict",
    "fuzz_clickhouse_os_shell_execute_conflict",
    "fuzz_zookeeper_zero_max_znodes",
    "fuzz_zookeeper_zero_enum_workers",
    "fuzz_keeper_incomplete_mtls",
    "fuzz_keeper_incomplete_mtls_key",
    "fuzz_keeper_ca_insecure_conflict",
    "fuzz_keeper_removed_tls_flag",
    "fuzz_keeper_removed_no_tls_flag",
    "fuzz_redis_invalid_port_negative",
    "fuzz_redis_invalid_port_huge",
    "fuzz_redis_zero_dump",
    "fuzz_redis_negative_show_keys",
    "fuzz_redis_invalid_dump_batch",
    "fuzz_redis_negative_dump_delay",
    "fuzz_postgres_empty_credentials",
    "fuzz_etcd_garbage_target",
    "fuzz_etcd_invalid_dump_batch",
    "fuzz_etcd_negative_show_keys",
    "fuzz_mongodb_zero_timeout",
    "fuzz_mongodb_invalid_workers",
    "fuzz_mongodb_negative_retries",
    "fuzz_kafka_negative_workers",
    "fuzz_kafka_zero_max_messages",
    "fuzz_kafka_invalid_port",
    "fuzz_registry_malformed_target",
    "fuzz_registry_invalid_port",
    "fuzz_grafana_invalid_target",
    "fuzz_grafana_huge_port",
    "fuzz_gitlab_invalid_port",
    "fuzz_gitlab_zero_timeout",
    "fuzz_consul_zero_workers",
    "fuzz_consul_negative_dump",
    "fuzz_kubeapi_zero_timeout",
    "fuzz_kubeapi_huge_port",
    "fuzz_oracle_invalid_port",
    "fuzz_oracle_zero_timeout",
    "fuzz_docker_invalid_port",
    "fuzz_docker_zero_timeout",
    "fuzz_clickhouse_negative_timeout",
    "fuzz_clickhouse_invalid_port",
    "fuzz_qdrant_zero_timeout",
    "fuzz_qdrant_invalid_port",
    "fuzz_elastic_negative_retries",
    "fuzz_elastic_invalid_port",
    "fuzz_grpc_invalid_port",
    "fuzz_grpc_zero_workers",
    "fuzz_zookeeper_invalid_port",
    "fuzz_zookeeper_zero_workers",
    "fuzz_proxmox_negative_workers",
    "fuzz_proxmox_invalid_port",
)

_PROGRESS_EXPECTED_TARGETS = {
    "exporters_scan": 51,
    "registry_multi_instance_urls": 5,
    "grafana_multi_instance_urls": 5,
    "gitlab_multi_instance_urls": 5,
    "consul_multi_instance_urls": 5,
    "kubeapi_multi_instance_urls": 5,
    "postgres_multi_ports": 5,
    "mongodb_multi_ports": 5,
    "oracle_multi_ports": 5,
    "docker_multi_ports": 5,
    "clickhouse_multi_ports": 5,
    "redis_multi_ports": 5,
    "etcd_multi_instance_urls": 5,
    "qdrant_multi_instance_urls": 5,
    "elastic_multi_instance_urls": 5,
    "grpc_multi_ports": 5,
    "kafka_multi_ports": 5,
    "zookeeper_multi_ports": 5,
    "keeper_cluster": 2,
    "proxmox_multi_instance_urls": 5,
}

_PROGRESS_LINE_RE = re.compile(r"Running redposture against (\d+) targets?")

_RICH_OUTPUT_REQUIRED_SUBSTRINGS = {
    "registry_open": ("redposture/demo-api", "redposture/web-ui"),
    "registry_harbor": ("core/control-plane", "security/scanner-adapter"),
    "registry_gitlab": ("gitlab/project-api", "team/ops-sidecar"),
    "registry_nexus": ("raw-internal", "raw-observability", "raw-security", "release-metadata.json"),
    "gitlab_public": ("redposture-lab/public-api", "team-platform/ops-scripts"),
    "gitlab_analyst": ("redposture-lab/security-reports", "redposture-lab/incident-timeline"),
    "consul_open": ("redposture/kafka/sasl_password", "svc-redposture-api", "gitlab-runner"),
    "consul_acl_read": ("redposture/kafka/sasl_password", "redposture/env", "lab-acl"),
    "consul_multi_instance_urls": ("redposture/kafka/sasl_password", "inventory/services/gitlab/url"),
    "mongodb_open": ("demo_accounts", "service_tokens", "billing"),
    "oracle_auth": ("FREEPDB1", "SYSTEM"),
    "oracle_query_dump": ("ACCOUNTS", "OracleAdmin!2026"),
    "oracle_privesc_check": ("privesc_findings", "DBA/SYSDBA"),
    "oracle_nne_check": ("nne_check", "tcp_available"),
    "oracle_listener_dump": ("listener_dump", "services_ok"),
    "oracle_listener_protected": ("Listener Dump", "password_protected=True"),
    "oracle_external_table_rce": ("exec_result", "external-table", "ext-rce-ok"),
    "oracle_dbms_cloud_capability": ("DBMS_CLOUD",),
    "oracle_privesc_chain_execute": ("privesc_chain_executed", "scheduler_rce"),
    "oracle_wallet_extract": ("wallet_findings", "redposture_wallet_hint"),
    "oracle_large_file_resume": ("file_results", "redposture_large_file"),
    "oracle_arbitrary_fs": ("file_results", "scheduler_readback"),
    "docker_inventory": ("redposture-web", "redposture-worker", "redposture-prod-net", "redposture-secrets"),
    "docker_exec": ("uid=0", "root"),
    "qdrant_default": ("demo_vectors", "audit_logs", "service_inventory"),
    "qdrant_multi_instance_urls": ("demo_vectors", "audit_logs", "service_inventory"),
    "grpc_open": ("grpc.health.v1.Health", "grpc.reflection.v1alpha.ServerReflection"),
    "kafka_open": ("orders", "payments.events", "audit.logs", "security.alerts", "ord-1001"),
    "kafka_auth": ("secure.orders", "secure.metrics", "secure.audit", "sec-2001"),
    "kafka_multi_ports": ("orders", "payments.events", "audit.logs", "ord-1001"),
    "zookeeper_default": ("/redposture/app/api_key", "rp-zk-key-2026"),
    "zookeeper_multi_ports": ("/redposture/app/api_key", "rp-zk-key-2026"),
    "keeper_cluster": ("/redposture/app/api_key", "rp-keeper-key-2026", "clickhouse-keeper"),
    "keeper_tls": ("clickhouse-keeper", '"transport": "tls"'),
    "keeper_no4lw": ('"service": "zookeeper-compatible"', '"fingerprint_confidence": "unconfirmed"'),
    "keeper_apache_control": ('"service": "apache-zookeeper"', '"status": "not_keeper"'),
    "proxmox_admin": ("credential_hit", "pve-edge-01", "pve-core-02", "GitLabCloudInit!2026"),
    "registry_extended_tags_metadata": ("redposture/demo-api", "latest"),
    "consul_extended_inventory_filters": ("redposture/kafka/sasl_password", "svc-redposture-api"),
    "postgres_extended_query_privs": (
        "demo_accounts",
        "username",
        "admin | admin",
        "privesc_summary",
        '"critical": 3',
    ),
    "mongodb_extended_document_index_cmd": ("demo_accounts", "username_1"),
    "oracle_extended_schema_sensitive_protocol": ("ACCOUNTS", "REDPOSTURE"),
    "docker_extended_exec_worker": ("root",),
    "clickhouse_extended_query_columns": ("secrets_inventory", "owner"),
    # NB: only the --key query value is deterministic here. The 3-key dump (--dump 3 with
    # batch=2) is per-page sorted, so which 3 keys land in it depends on SCAN cursor order
    # -- asserting on a specific dumped value would be flaky.
    "redis_extended_key_dump_count": ("offlineStocks:city_4949:552400",),
    "etcd_extended_key_dump_count": ("offlineStocks:city_4949:552400",),
    "qdrant_extended_collection_dump_count": ("demo_vectors",),
    "grpc_extended_metadata_invoke": ("grpc.health.v1.Health",),
    "kafka_extended_topic_dump_count": ("orders", "ord-1001"),
    "zookeeper_extended_znode_limits": ("/redposture/app/api_key",),
    "proxmox_extended_add_user_mock": ("rp-matrix@pve",),
    "proxy_exporters_socks4a": ("node_exporter",),
    "proxy_exporters_socks5h": ("node_exporter",),
    "proxy_exporters_http": ("node_exporter",),
    "proxy_exporters_https": ("node_exporter",),
    # P0 additions: assert that runs against seeded lab services actually produced the
    # expected content, not just exit=0. Substrings chosen from real matrix JSON artifacts
    # so they are stable across runs (no per-run-random tokens).
    "redis_default": ("stream_len=", "svc:grafana", "ratelimit:ip", "queue:payments:retry"),
    "redis_multi_ports": ("stream:alerts", "svc:grafana"),
    "redis_extended_defcreds": ("weak_default_creds",),
    "postgres_default": ("valid_credentials", "redposture.demo_accounts"),
    "postgres_extended_defcreds": ("weak_default_creds",),
    "postgres_extended_execute": ("uid=70(postgres)", '"execute_ok": true'),
    "postgres_extended_os_read": ('"os_read_ok": true',),
    "etcd_open": ("/redposture/app/api_key", "/inventory/services/grafana/url"),
    "mongodb_auth": ('"database_count": 5', "redposture"),
    "exporters_collect": ("nats_exporter",),
    # P2.1: forced-paging redis dump must still surface all 16 seeded keys (incl. all 6 types).
    "redis_extended_paged_dump": ("stream_len=", "svc:grafana", '"key_count": 16'),
    # P2.2: forced-paging etcd dump must continuation-cursor through every range page.
    "etcd_extended_paged_dump": ("/redposture/app/api_key", "/inventory/services/grafana/url"),
    # P2.3: 5.5.1 path -- both default credentials are rejected, both rows surfaced.
    # The matrix runs in --format json, so attempted_credentials is the JSON object form
    # rather than the rendered "user:pass" colon syntax; assert both username AND password
    # appear in the structured payload for each default that was tried.
    "postgres_extended_defcreds_both_fail": (
        '"attempted_credentials"',
        '"username": "postgres"',
        '"password": "postgres"',
        '"username": "pgbouncer"',
        '"password": "pgbouncer"',
    ),
    # A: rich-substring for modules that previously had no content check (elastic, kubeapi,
    # grafana). Substrings extracted from real matrix JSON artifacts; verified before use.
    "elastic_open": ('"discover_schema_version": 2', '"discover_findings"', "elastic-prod-api-key-2026"),
    "elastic_auth": (".security-7", "user-observer", '"can_read": true'),
    "elastic_extended_all_actions": (".security-7", '"can_write": true', '"effective_username": "elastic"'),
    "elastic_extended_ports_defcreds": ('"discover_results"',),
    "kubeapi_open": ("v1.31.6+k3s1", '"auth_mode": "none"'),
    "kubeapi_extended_selectors_basic_auth": ('"auth_mode": "basic"', '"can_list_namespaces": true'),
    "grafana_extended_auth_ssrf_controls": (
        # Loose match: grafana lab image is `grafana-oss:latest`, minor patches arrive
        # between runs (saw 13.0.1 → 13.0.2 during 5.5.6 testing). Asserting on the major
        # is enough to prove detection / attempted_credentials reached the audit.
        '"server_version": "13.',
        '"attempted_credentials"',
    ),
    "grafana_default": ('"is_grafana": true', '"datasource_count":'),
    "grafana_url_http": ('"is_grafana": true', '"datasource_count":'),
    # C: URL-variant cases hit the same seeded services as their base cases. Asserting on
    # rich content here means a regression in URL-target parsing or fallback (e.g. proxy
    # rewrites swallowing the host) gets caught instead of slipping past exit-code.
    "registry_url_http": ("redposture/demo-api",),
    "consul_url_hint_http": ('"redposture/env"',),
    "etcd_url_http": ('"/redposture/',),
    "qdrant_url_http": ('"demo_vectors"',),
    "gitlab_url_override_http": ('"is_gitlab"',),
    "elastic_url_hint_https": ('"server_version"',),
    "proxmox_url_override_https": ('"is_proxmox"',),
    "kubeapi_url_override_https": ("v1.31.6",),
    # P4-D idempotency twins must produce capability-bearing output (P3-E covers this
    # already, the explicit substring is a belt-and-suspenders).
    "redis_idempotency": ('"key_count": 16',),
    "postgres_idempotency": ("redposture.demo_accounts",),
    "etcd_idempotency": ("/redposture/app/api_key",),
    "mongodb_idempotency": ('"database_count": 5',),
    "kafka_idempotency": ('"topic_count"',),
    # P4-C: each mutate variant must hit the cap (or fewer when keyspace is smaller).
    # P3-C limit-conformance enforces the upper bound; we add a marker that the run
    # actually reached the deep phase.
    "redis_mutate_show_keys_3": ('"is_redis": true',),
    "redis_mutate_show_keys_100": ('"is_redis": true', '"key_count": 16'),
    "exporters_scan_url_http": ('"exporter":',),
    "exporters_collect_url_http": ('"exporter":',),
    "exporters_trigger_url_http": ('"exporter":',),
}

_RICH_OUTPUT_FORBIDDEN_SUBSTRINGS = {
    "kafka_open": ("<no messages>",),
    "kafka_auth": ("<no messages>",),
    "kafka_multi_ports": ("<no messages>",),
    "kafka_extended_topic_dump_count": ("<no messages>",),
    "qdrant_default": ("<no collections>", "no collections available for dump"),
    "qdrant_multi_instance_urls": ("<no collections>", "no collections available for dump"),
    "qdrant_extended_collection_dump_count": ("<no collections>", "no collections available for dump"),
}

_ZOOKEEPER_MULTI_DUMP_PORTS = {2181, 22181, 22182, 22183, 22184}
_SEEDED_ZNODE_EXPECTATIONS: dict[str, dict[int, tuple[str, str]]] = {
    "zookeeper_default": {2181: ("/redposture/app/api_key", "rp-zk-key-2026")},
    "zookeeper_multi_ports": {
        port: ("/redposture/app/api_key", "rp-zk-key-2026") for port in _ZOOKEEPER_MULTI_DUMP_PORTS
    },
    "zookeeper_extended_znode_limits": {2181: ("/redposture/app/api_key", "rp-zk-key-2026")},
    "keeper_cluster": {
        19181: ("/redposture/app/api_key", "rp-keeper-key-2026"),
        29181: ("/redposture/app/api_key", "rp-keeper-key-2026"),
    },
}


def _render_znode_dump_content(record: dict[str, Any]) -> str:
    """Return actual per-record dump content for bulk and explicit-znode modes."""

    parts: list[str] = []
    values = record.get("znode_values")
    if isinstance(values, list):
        parts.extend(str(value) for value in values)

    query_path = record.get("query_znode")
    query_dump = record.get("query_znode_dump")
    if isinstance(query_path, str) and query_path and query_dump not in {None, ""}:
        parts.extend((query_path, str(query_dump)))
    return "\n".join(parts)


def _parse_status_file(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open(encoding="utf-8") as fh:
        header = fh.readline().strip()
        if header not in {
            "module\tlabel\texit_code\tjson_path\tlog_path",
            "module\tlabel\texpected_exit\texit_code\tjson_path\tlog_path",
        }:
            raise SystemExit("matrix status header is invalid")
        has_expected_exit = header.startswith("module\tlabel\texpected_exit\t")
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            parts = raw.split("\t")
            if has_expected_exit and len(parts) != 6:
                raise SystemExit(f"invalid matrix status row: {raw}")
            if not has_expected_exit and len(parts) != 5:
                raise SystemExit(f"invalid matrix status row: {raw}")
            if has_expected_exit:
                module, label, expected_exit, exit_code, json_path, log_path = parts
            else:
                module, label, exit_code, json_path, log_path = parts
                expected_exit = "0"
            rows.append(
                {
                    "module": module,
                    "label": label,
                    "expected_exit": expected_exit,
                    "exit_code": exit_code,
                    "json_path": json_path,
                    "log_path": log_path,
                }
            )
    return rows


def _validate_expected_exits(rows: list[dict[str, str]]) -> None:
    for row in rows:
        label = row["label"]
        try:
            expected_exit = int(row["expected_exit"])
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"invalid expected_exit for label '{label}': {row['expected_exit']}") from exc
        try:
            exit_code = int(row["exit_code"])
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"invalid exit_code for label '{label}': {row['exit_code']}") from exc
        if exit_code != expected_exit:
            raise SystemExit(f"label '{label}' exit mismatch: expected={expected_exit} actual={exit_code}")


def _expected_labels_for_profile(profile: str) -> tuple[str, ...]:
    if profile == "balanced":
        return _EXPECTED_LABELS
    if profile == "extended":
        return (*_EXPECTED_LABELS, *_EXTENDED_EXPECTED_LABELS)
    raise SystemExit(f"unsupported verifier profile: {profile}")


def _validate_expected_labels(rows: list[dict[str, str]], *, profile: str = "balanced") -> None:
    seen_labels = {row["label"] for row in rows}
    missing = sorted(label for label in _expected_labels_for_profile(profile) if label not in seen_labels)
    if missing:
        raise SystemExit(f"matrix status is missing expected labels: {', '.join(missing)}")


def _validate_json_artifacts(rows: list[dict[str, str]]) -> Counter[str]:
    successful_modules: Counter[str] = Counter()

    for row in rows:
        log_path = Path(row["log_path"])
        if not log_path.exists():
            raise SystemExit(f"missing run log file: {log_path}")

        if row["exit_code"] != "0":
            continue

        json_path = row["json_path"]
        if json_path in {"", "-"}:
            successful_modules[row["module"]] += 1
            continue

        artifact = Path(json_path)
        if not artifact.exists() or artifact.stat().st_size == 0:
            raise SystemExit(f"missing or empty JSON artifact for successful run: {artifact}")

        try:
            with artifact.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
            if not isinstance(payload, (dict, list)):
                raise SystemExit(f"unexpected JSON payload type in {artifact}: {type(payload).__name__}")
        except json.JSONDecodeError:
            # Some module outputs are JSONL streams; treat as valid when each non-empty line is valid JSON.
            # NOTE: must split on "\n" only, not str.splitlines(): exporter response bodies
            # can contain bytes that splitlines() treats as line separators (\r, \x85/NEL,
            # U+2028, etc.), which would shred an otherwise-valid JSONL record into invalid
            # fragments. This was a real flaky-test source in the lab matrix.
            lines = [line for line in artifact.read_text(encoding="utf-8").split("\n") if line.strip()]
            if not lines:
                raise SystemExit(f"empty JSONL artifact for successful run: {artifact}") from None
            for idx, line in enumerate(lines, start=1):
                try:
                    payload_line = json.loads(line)
                except Exception as exc:  # pragma: no cover - surfaced via SystemExit
                    raise SystemExit(f"invalid JSONL artifact {artifact} at line {idx}: {exc}") from exc
                if not isinstance(payload_line, (dict, list)):
                    raise SystemExit(
                        f"unexpected JSONL payload type in {artifact} at line {idx}: {type(payload_line).__name__}"
                    ) from None
        except Exception as exc:  # pragma: no cover - surfaced via SystemExit
            raise SystemExit(f"invalid JSON artifact {artifact}: {exc}") from exc

        successful_modules[row["module"]] += 1

    return successful_modules


def _progress_counts_from_log(text: str) -> list[int]:
    return [int(match.group(1)) for match in _PROGRESS_LINE_RE.finditer(text)]


def _infer_target_count_from_jsonl(text: str) -> int:
    seen: set[tuple[str, int]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = payload.get("host")
        port = payload.get("port")
        if isinstance(host, str) and isinstance(port, int):
            seen.add((host, port))
    return len(seen)


def _combined_run_output(row: dict[str, str]) -> str:
    parts: list[str] = []
    log_path = Path(row["log_path"])
    if log_path.exists():
        parts.append(log_path.read_text(encoding="utf-8", errors="replace"))
    json_path = row.get("json_path") or "-"
    if json_path not in {"", "-"}:
        artifact = Path(json_path)
        if artifact.exists():
            parts.append(artifact.read_text(encoding="utf-8", errors="replace"))
    elif log_path.suffix == ".log":
        text_artifact = log_path.with_suffix(".txt")
        if text_artifact.exists():
            parts.append(text_artifact.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def _iter_json_objects(text: str):
    for raw in text.splitlines():
        line = raw.strip()
        if not line or not line.startswith(("{", "[")):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    yield item


def _validate_rich_lab_outputs(rows: list[dict[str, str]]) -> None:
    for row in rows:
        if row["exit_code"] != "0":
            continue
        label = row["label"]
        output_text = _combined_run_output(row)
        for needle in _RICH_OUTPUT_REQUIRED_SUBSTRINGS.get(label, ()):
            if needle not in output_text:
                raise SystemExit(f"label '{label}' is missing expected seeded lab data: {needle}")
        for needle in _RICH_OUTPUT_FORBIDDEN_SUBSTRINGS.get(label, ()):
            if needle in output_text:
                raise SystemExit(f"label '{label}' contains empty/unseeded lab output: {needle}")

        if label == "oracle_large_file_resume":
            ok = False
            for payload in _iter_json_objects(output_text):
                if payload.get("type") not in {None, "file_results"}:
                    continue
                file_results = payload.get("file_results") or []
                if not isinstance(file_results, list):
                    continue
                for item in file_results:
                    if not isinstance(item, dict):
                        continue
                    if (
                        item.get("action") == "download"
                        and item.get("ok") is True
                        and int(item.get("bytes") or 0) > 0
                        and "redposture_large_file" in str(item.get("path") or "")
                    ):
                        ok = True
                        break
            if not ok:
                raise SystemExit("label 'oracle_large_file_resume' did not complete a non-empty download")

        if label == "oracle_wallet_extract":
            ok = False
            for payload in _iter_json_objects(output_text):
                if payload.get("type") not in {None, "wallet_findings"}:
                    continue
                wallet_findings = payload.get("wallet_findings") or []
                if not isinstance(wallet_findings, list):
                    continue
                for item in wallet_findings:
                    if not isinstance(item, dict):
                        continue
                    if "redposture_wallet_hint" in json.dumps(item, sort_keys=True):
                        ok = True
                        break
            if not ok:
                raise SystemExit("label 'oracle_wallet_extract' did not extract seeded wallet metadata")

        znode_expectations = _SEEDED_ZNODE_EXPECTATIONS.get(label)
        if znode_expectations:
            artifact_text = output_text
            json_path = row.get("json_path") or "-"
            if json_path not in {"", "-"} and Path(json_path).exists():
                artifact_text = Path(json_path).read_text(encoding="utf-8", errors="replace")
            records_by_port: dict[int, list[dict[str, Any]]] = {}
            for item in _iter_json_objects(artifact_text):
                port = item.get("port")
                if isinstance(port, int) and port in znode_expectations:
                    records_by_port.setdefault(port, []).append(item)
            missing_ports: list[int] = []
            empty_ports: list[int] = []
            seed_mismatch_ports: list[int] = []
            for port, needles in znode_expectations.items():
                records = records_by_port.get(port, [])
                if not records:
                    missing_ports.append(port)
                    continue
                for record in records:
                    rendered = _render_znode_dump_content(record)
                    if not rendered:
                        empty_ports.append(port)
                        continue
                    if any(needle not in rendered for needle in needles):
                        seed_mismatch_ports.append(port)
            if missing_ports or empty_ports or seed_mismatch_ports:
                raise SystemExit(
                    f"label '{label}' did not dump seeded znodes for every expected target: "
                    f"missing_ports={sorted(set(missing_ports))} "
                    f"empty_ports={sorted(set(empty_ports))} "
                    f"seed_mismatch_ports={sorted(set(seed_mismatch_ports))}"
                )

        if label in {"exporters_scan", "exporters_collect"}:
            pgbackrest_ports = {
                int(item["port"])
                for item in _iter_json_objects(output_text)
                if item.get("exporter") == "pgbackrest_exporter"
                and isinstance(item.get("port"), int)
                and (item.get("detected") is True or item.get("ok") is True)
            }
            expected_ports = {9854, 19854, 29854}
            if not expected_ports <= pgbackrest_ports:
                raise SystemExit(
                    f"label '{label}' did not cover all pgBackRest exporter ports: "
                    f"expected={sorted(expected_ports)} got={sorted(pgbackrest_ports)}"
                )


# Modules where every successful `--dump` run on the seeded lab is expected to surface
# non-empty data. A run that exits 0 but produces an empty-dump marker is a regression
# (`-o` tee broke, paging-cursor stuck on "0", credential flow silently rejected, ...).
_MODULES_WITH_SEEDED_DUMP = frozenset(
    {
        "redis",
        "postgres",
        "mongodb",
        "etcd",
        "consul",
        "zookeeper",
        "kafka",
        "qdrant",
        "clickhouse",
    }
)

# Markers that indicate an empty dump in the JSON/txt output (per-module aliases).
_EMPTY_DUMP_MARKERS = (
    '"key_values": null',
    '"key_values": []',
    '"key_value_entries": null',
    '"key_value_entries": []',
    '"znode_values": null',
    '"znode_values": []',
    '"table_dumps": []',
    '"topic_messages": []',
    '"collection_dump_items": []',
    '"<no records>"',
    '"<no messages>"',
    '"<no collections>"',
    "no collections available for dump",
)

# Modules where seeded credentials are expected to gate the deep phase. A `status` of
# `auth_required` for a 0-exit successful run in one of these modules indicates a
# credential-flow regression (5.5.1 fix territory) -- the matrix would still pass on
# exit-code alone, so this check is the safety net.
_MODULES_WITH_SEEDED_CREDENTIALS = frozenset({"postgres", "mongodb", "clickhouse", "oracle", "redis"})

# Labels that legitimately exit 0 with `status: "auth_required"` on the current lab
# (e.g. defcreds intentionally fail, or auth_required is the asserted outcome).
_AUTH_REQUIRED_LEGITIMATE = frozenset(
    {
        "mongodb_defcreds",  # defcreds path documents that no defaults match the lab user
        "postgres_extended_defcreds_both_fail",  # the new P2 case asserts both defaults fail
    }
)


def _validate_tee_when_output_set(rows: list[dict[str, str]]) -> None:
    """For each successful run with `--output` (JSON path is non-`-`), the run log must
    contain the same JSON payload that was written to the file. Catches a regression of
    the 5.5.1 tee behaviour where `-o` silently went back to file-only output."""
    for row in rows:
        if row["exit_code"] != "0":
            continue
        json_path = row.get("json_path") or "-"
        if json_path in {"", "-"}:
            continue
        artifact = Path(json_path)
        log_path = Path(row["log_path"])
        if not artifact.exists() or not log_path.exists():
            continue
        json_text = artifact.read_text(encoding="utf-8", errors="replace").strip()
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if not json_text:
            continue
        # Use the first record's leading slice as the tee witness. 80 chars is plenty to
        # be unique without being brittle (avoids per-run timestamps near the end).
        witness = json_text.splitlines()[0][:80]
        if witness and witness not in log_text:
            raise SystemExit(
                f"tee regression for label '{row['label']}': --output set but log does not contain JSON payload"
            )


def _validate_dump_not_empty(rows: list[dict[str, str]]) -> None:
    """For successful runs of seeded-dump modules whose label name indicates a dump
    (`*dump*` or default cases like `redis_default`), forbid empty-dump markers in the
    output. Catches silent regressions where the dump silently returned no data."""
    for row in rows:
        if row["exit_code"] != "0":
            continue
        module = row["module"]
        if module not in _MODULES_WITH_SEEDED_DUMP:
            continue
        label = row["label"]
        # Only inspect labels that should have produced dump content. `*debug_smoke*`
        # and module-specific *non*-dump cases are excluded.
        if "debug_smoke" in label or "auth_required" in label or label.endswith("_defcreds"):
            continue
        if "dump" not in label and not label.endswith("_default") and not label.endswith("_open"):
            continue
        output_text = _combined_run_output(row)
        if not output_text:
            continue
        # If the run never reached the dump phase (auth gate, protocol mismatch, fail),
        # an empty dump is expected. The status-coherence check covers credential regressions
        # separately, and pre-detect failures are caught by exit-code mismatches.
        if any(
            marker in output_text for marker in ('"status": "auth_required"', '"status": "fail"', '"status": "not_')
        ):
            continue
        for marker in _EMPTY_DUMP_MARKERS:
            if marker in output_text:
                raise SystemExit(f"label '{label}' produced an empty-dump marker {marker!r} in seeded {module} run")


def _validate_status_coherence(rows: list[dict[str, str]]) -> None:
    """For seeded-credential modules where the run actually supplied a username AND a
    password (canonical signal: `"provided_credentials": true` in the output), forbid the
    final status from being `auth_required` -- that means the credentials we sent were
    silently rejected even though exit=0. Mirrors the 5.5.1 credential-flow fix as a
    stand-side guard. Defcreds/probe/spray paths intentionally end with `auth_required`
    and are filtered out by the `provided_credentials` gate (they do not set it true)."""
    for row in rows:
        if row["exit_code"] != "0":
            continue
        module = row["module"]
        if module not in _MODULES_WITH_SEEDED_CREDENTIALS:
            continue
        label = row["label"]
        if label in _AUTH_REQUIRED_LEGITIMATE or "debug_smoke" in label:
            continue
        output_text = _combined_run_output(row)
        if not output_text:
            continue
        # Only fire when the run actually carried explicit credentials.
        if '"provided_credentials": true' not in output_text:
            continue
        if '"status": "auth_required"' in output_text:
            raise SystemExit(
                f"credential-flow regression for label '{label}': seeded {module} run returned "
                f"status=auth_required despite explicit credentials"
            )


# Multi-record labels (multi-port / multi-instance-URL) where every record is expected to
# carry the SAME status -- the case targets N replicas of the same seeded service. A run
# that exits 0 but shows a status split (e.g. "3 ok + 2 fail") is a partial-failure
# regression that exit-code + progress-count checks alone would miss.
#
# Exceptions encoded explicitly:
# - `docker_multi_ports`: TLS port is by-design auth_required, others open_no_auth.
_MIXED_STATUS_MULTI_RECORD = frozenset(
    {
        "docker_multi_ports",  # TLS port intentionally diverges from open_no_auth siblings
        "exporters_scan",  # fan-by-check (48 progress events ≠ host record count)
    }
)


def _record_has_meaningful_outcome(record: dict[str, object], *, label: str) -> bool:
    status = str(record.get("status") or "").strip().lower()
    if label == "keeper_apache_control" and status == "not_keeper":
        return (
            str(record.get("service") or "").strip().lower() == "apache-zookeeper" and record.get("is_keeper") is False
        )
    if not status or status == "fail" or status.startswith(("unknown", "not_")):
        return False
    return True


def _validate_meaningful_outcomes(rows: list[dict[str, str]]) -> None:
    """A successful audit must contain an actual per-host outcome.

    Exit code zero only means that the CLI completed. It must not make connection
    failures, protocol mismatches, unknown states, or a zero-record summary look like a
    successful lab audit.
    """

    for row in rows:
        if row["exit_code"] != "0" or row["module"] == "exporters":
            continue
        json_path = row.get("json_path") or "-"
        if json_path in {"", "-"}:
            continue
        records = list(_iter_audit_records_for_row(row))
        if not records:
            raise SystemExit(f"label '{row['label']}' exited 0 without an audit record")
        if not any(_record_has_meaningful_outcome(record, label=row["label"]) for record in records):
            statuses = sorted({str(record.get("status") or "") for record in records})
            raise SystemExit(f"label '{row['label']}' exited 0 without a meaningful outcome: statuses={statuses}")


def _validate_multi_record_consistency(rows: list[dict[str, str]]) -> None:
    for row in rows:
        if row["exit_code"] != "0":
            continue
        label = row["label"]
        expected = _PROGRESS_EXPECTED_TARGETS.get(label)
        if expected is None or expected <= 1:
            continue
        json_path = row.get("json_path") or "-"
        if json_path in {"", "-"}:
            continue
        artifact = Path(json_path)
        if not artifact.exists():
            continue
        text = artifact.read_text(encoding="utf-8", errors="replace")
        # Filter to per-host audit records (one per port). They always have host + port +
        # status; summary / index / debug records (no `host` or no `status`) are skipped.
        records = [
            r
            for r in _iter_json_objects(text)
            if isinstance(r, dict) and r.get("host") and r.get("status") and isinstance(r.get("port"), int)
        ]
        if len(records) != expected:
            raise SystemExit(f"multi-record label '{label}': expected {expected} host records, got {len(records)}")
        invalid_targets = [
            f"{record.get('host')}:{record.get('port')}={record.get('status')}"
            for record in records
            if not _record_has_meaningful_outcome(record, label=label)
        ]
        if invalid_targets:
            raise SystemExit(
                f"multi-record label '{label}' has targets without a meaningful outcome: " + ", ".join(invalid_targets)
            )
        if label in _MIXED_STATUS_MULTI_RECORD:
            continue
        statuses = {str(r.get("status")) for r in records}
        if len(statuses) > 1:
            raise SystemExit(
                f"multi-record label '{label}': inconsistent status across host records {sorted(statuses)} "
                "(partial-failure regression: not all replicas behaved the same)"
            )


# Status values that indicate the audit reached a meaningful outcome (so capability fields
# are expected to be populated). `detected` is included for protocol-only modules like
# gitlab where the public-project case yields detection without further auth flow.
_SUCCESSFUL_AUDIT_STATUSES = frozenset(
    {
        "valid_credentials",
        "weak_default_creds",
        "open_no_auth",
        "anonymous_access",
        "auth_valid",
        "token_ok",
        "valid_token",
        "token_accepted",
        "detected",
        "ok",
    }
)

# Per-module capability fields -- at least one must carry a non-empty value when status
# indicates the deep phase ran. Field names were extracted from real matrix JSON artifacts
# (mix of detection markers like `is_<module>` and content markers like `keys`/`topics`).
_CAPABILITY_FIELDS_BY_MODULE: dict[str, tuple[str, ...]] = {
    "redis": ("key_count", "keys", "key_values"),
    "postgres": ("database_count", "database_names", "table_names", "server_version"),
    "mongodb": ("database_count", "database_names", "collections", "indexes", "server_version"),
    "etcd": ("key_count", "keys", "key_values", "server_version"),
    "consul": ("version", "leader"),
    "zookeeper": ("znode_count", "znodes", "znode_values", "version"),
    "keeper": ("znode_count", "znodes", "znode_values", "version", "fingerprint_confidence"),
    "kafka": ("topic_count", "topics"),
    "qdrant": ("collections_count", "collections", "version"),
    "clickhouse": ("database_names", "table_names", "effective_username", "auth_attempts"),
    "elastic": ("server_version", "discover_results", "cat_endpoints", "cat_plugins", "cluster_health", "users"),
    "oracle": ("connect_service", "capabilities", "credential_attempts"),
    "docker": ("server_version", "api_version", "containers"),
    "kubeapi": ("version", "auth_mode", "can_list_namespaces", "namespaces", "pods", "secrets"),
    "registry": (
        "image_count",
        "images",
        "harbor_projects",
        "gitlab_repositories",
        "nexus_info",
        "nexus_repositories",
        "nexus_assets",
    ),
    "gitlab": ("version", "open_endpoints", "public_projects", "token_projects", "clone_results"),
    "grpc": ("services", "methods", "reflection_enabled", "invoke_result"),
    "proxmox": ("auth_method", "successful_endpoints", "nodes", "users", "added_user"),
    "grafana": ("server_version", "datasource_count", "datasources", "check_results"),
}


def _is_audit_record(record: dict[str, object]) -> bool:
    """An audit record is a per-host audit payload: status is a non-empty STRING (excludes
    exporters scan/collect records where `status` is an HTTP int code), the record is not
    summary/index scaffolding, and it is not an exporter probe/trigger record (which carry
    `exporter`/`source_type` instead of the audit's `module`/`stages` shape)."""
    status = record.get("status")
    if not (isinstance(status, str) and status):
        return False
    if record.get("type") in {"summary", "index"}:
        return False
    # Exporter-shape records (scan probe, collect, trigger callback) carry these markers
    # and are validated by separate logic, not the audit schema.
    if "exporter" in record or record.get("source_type") in {"trigger", "callback"}:
        return False
    return True


def _record_timer_ms(record: dict[str, object]) -> int:
    """Return any non-zero positive timer the record carries. Different modules ship
    different timer fields (legacy `elapsed_ms` vs newer `stage_timing_total_ms`); failed
    audits omit both top-level timers but the per-stage `duration_ms` entries are still
    set. Any of those positive values prove the audit actually ran."""
    for field in ("elapsed_ms", "stage_timing_total_ms"):
        value = record.get(field)
        if isinstance(value, int) and value > 0:
            return value
    stages = record.get("stages")
    if isinstance(stages, list):
        total = sum(
            stage.get("duration_ms", 0)
            for stage in stages
            if isinstance(stage, dict) and isinstance(stage.get("duration_ms"), int)
        )
        if total > 0:
            return int(total)
    return 0


def _iter_audit_records_for_row(row: dict[str, str]):
    """Yield only the per-host audit records from a row's JSON artifact."""
    json_path = row.get("json_path") or "-"
    if json_path in {"", "-"}:
        return
    artifact = Path(json_path)
    if not artifact.exists():
        return
    text = artifact.read_text(encoding="utf-8", errors="replace")
    for payload in _iter_json_objects(text):
        if isinstance(payload, dict) and _is_audit_record(payload):
            yield payload


def _validate_schema_mandatory_fields(rows: list[dict[str, str]]) -> None:
    """P3-A: every audit record must carry the canonical scaffolding fields. Catches
    serialization/refactor regressions where a field silently disappears from the JSON
    payload."""
    for row in rows:
        if row["exit_code"] != "0":
            continue
        for record in _iter_audit_records_for_row(row):
            host = record.get("host")
            port = record.get("port")
            status = record.get("status")
            timestamp = record.get("timestamp")
            stages = record.get("stages")
            if not (isinstance(host, str) and host):
                raise SystemExit(f"schema regression in '{row['label']}': record missing/empty 'host'")
            if not isinstance(port, int):
                raise SystemExit(f"schema regression in '{row['label']}': record missing/non-int 'port'")
            if not (isinstance(status, str) and status):
                raise SystemExit(f"schema regression in '{row['label']}': record missing/empty 'status'")
            if not (isinstance(timestamp, str) and timestamp):
                raise SystemExit(f"schema regression in '{row['label']}': record missing/empty 'timestamp'")
            if not isinstance(stages, list):
                raise SystemExit(f"schema regression in '{row['label']}': record missing 'stages' list")


def _validate_elapsed_sanity(rows: list[dict[str, str]]) -> None:
    """P3-F: when a record reports the audit reached a meaningful outcome, it must carry
    a positive timer (< 60s). Catches stub records (timer never started returning fake-ok)
    or hangs (timer > 60s on a deterministic lab service). Records whose status is `fail`
    or `not_*` are skipped: a network-level rejection legitimately has 0ms timers because
    the audit code itself never ran."""
    for row in rows:
        if row["exit_code"] != "0":
            continue
        for record in _iter_audit_records_for_row(row):
            status = str(record.get("status") or "")
            if status == "fail" or status.startswith("not_"):
                continue
            timer_ms = _record_timer_ms(record)
            if timer_ms <= 0:
                raise SystemExit(
                    f"timer regression in '{row['label']}': status={status!r} record has no positive "
                    f"timer (host={record.get('host')} port={record.get('port')})"
                )
            if timer_ms > 60_000:
                raise SystemExit(
                    f"timer regression in '{row['label']}': audit took {timer_ms}ms on a deterministic "
                    f"lab service (host={record.get('host')} port={record.get('port')}) -- likely hang"
                )


def _validate_capability_sanity(rows: list[dict[str, str]]) -> None:
    """P3-E: when status indicates the deep phase ran (valid_credentials, open_no_auth,
    etc.), at least one module-specific capability field must be non-empty. Catches the
    class of regressions where auth/detect "succeeds" but the data phase silently returned
    nothing useful."""
    for row in rows:
        if row["exit_code"] != "0":
            continue
        module = row["module"]
        capability_fields = _CAPABILITY_FIELDS_BY_MODULE.get(module)
        if capability_fields is None:
            continue
        for record in _iter_audit_records_for_row(row):
            status = str(record.get("status") or "")
            if status not in _SUCCESSFUL_AUDIT_STATUSES:
                continue
            if any(_field_is_populated(record.get(field)) for field in capability_fields):
                continue
            raise SystemExit(
                f"capability regression in '{row['label']}': status={status!r} but none of "
                f"{capability_fields} carries content (host={record.get('host')} port={record.get('port')})"
            )


def _field_is_populated(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, (list, dict, str)):
        return bool(value)
    return True


_ACTION_EXPECTED_VALUES: dict[str, dict[str, object]] = {
    "registry_nexus": {"nexus": True, "assets": True, "is_nexus": True},
    "grafana_default": {"show_datasources": True, "is_grafana": True},
    "grafana_url_http": {"show_datasources": True, "is_grafana": True},
    "grafana_ssrf_edge": {"show_datasources": True, "is_grafana": True},
    "grafana_extended_auth_ssrf_controls": {"show_datasources": True, "is_grafana": True},
    "grafana_multi_instance_urls": {"is_grafana": True},
    "gitlab_url_override_http": {"https": False, "is_gitlab": True},
    "gitlab_extended_token_project_clone": {"https": False, "clone_requested": True, "is_gitlab": True},
    "kubeapi_open": {"show_namespaces": True, "show_pods": True, "is_kubeapi": True},
    "kubeapi_auditor": {
        "show_namespaces": True,
        "show_pods": True,
        "insecure_effective": True,
        "is_kubeapi": True,
    },
    "kubeapi_admin": {"show_secrets": True, "insecure_effective": True, "is_kubeapi": True},
    "kubeapi_url_override_https": {"show_namespaces": True, "https": True, "is_kubeapi": True},
    "kubeapi_extended_selectors_basic_auth": {
        "show_namespaces": True,
        "show_pods": True,
        "exec_pod": "redposture-api",
        "is_kubeapi": True,
    },
    "consul_extended_inventory_filters": {
        "keys_requested": True,
        "services_list_requested": True,
        "agents_list_requested": True,
        "checks_list_requested": True,
        "nodes_list_requested": True,
        "dump_requested": True,
        "kv_key_requested": "redposture/kafka/sasl_password",
        "service_dump_name": "redposture-api",
        "agent_dump_name": "redposture-lab-consul",
        "node_dump_name": "redposture-lab-consul",
        "is_consul": True,
    },
    "consul_extended_ssrf_probe": {
        "ssrf_enabled": True,
        "checks_list_requested": True,
        "is_consul": True,
    },
    "qdrant_extended_ssrf_probe": {
        "ssrf_requested": True,
        "ssrf_collection": "demo_vectors",
        "is_qdrant": True,
    },
    "consul_url_hint_http": {"scheme": "http", "is_consul": True},
    "clickhouse_http_open": {
        "protocol": "http",
        "show_databases": True,
        "show_tables": True,
        "table_dump_enabled": True,
        "is_clickhouse": True,
    },
    "clickhouse_http_auth": {
        "protocol": "http",
        "show_databases": True,
        "show_tables": True,
        "table_dump_enabled": True,
        "is_clickhouse": True,
    },
    "clickhouse_multi_ports": {
        "show_databases": True,
        "is_clickhouse": True,
    },
    "clickhouse_extended_query_columns": {
        "show_databases": True,
        "show_tables": True,
        "show_columns": True,
        "table_dump_enabled": True,
        "sql_attempted": True,
        "sql_ok": True,
        "is_clickhouse": True,
    },
    "clickhouse_extended_execute": {
        "execute_attempted": True,
        "execute_ok": True,
        "is_clickhouse": True,
    },
    "elastic_open": {
        "show_endpoints": True,
        "show_cluster": True,
        "discover": True,
        "is_elastic": True,
    },
    "elastic_auth": {
        "show_endpoints": True,
        "show_cluster": True,
        "show_users": True,
        "discover": True,
        "is_elastic": True,
    },
    "elastic_plugins_edge": {"show_plugins": True, "is_elastic": True},
    "elastic_url_hint_https": {"scheme": "http", "show_endpoints": True, "is_elastic": True},
    "elastic_extended_all_actions": {
        "show_endpoints": True,
        "show_plugins": True,
        "show_cluster": True,
        "show_users": True,
        "discover": True,
        "is_elastic": True,
    },
    "grpc_invoke_health": {"invoke_result.status": "ok", "is_grpc": True},
    "grpc_proto_invoke": {"invoke_result.status": "ok", "is_grpc": True},
    "grpc_protoset_invoke": {"invoke_result.status": "ok", "is_grpc": True},
    "grpc_extended_metadata_invoke": {
        "invoke_result.status": "ok",
        "invoke_result.request.service": "",
        "invoke_result.metadata": [{"key": "x-redposture-matrix", "value": "extended"}],
        "is_grpc": True,
    },
    "keeper_cluster": {"is_keeper": True, "is_zookeeper_compatible": True},
    "proxmox_audit": {"show_nodes": True, "show_users": True, "is_proxmox": True},
    "proxmox_admin": {"show_nodes": True, "show_users": True, "discover_creds": True, "is_proxmox": True},
    "proxmox_url_override_https": {"use_https": True, "show_nodes": True, "is_proxmox": True},
    "proxmox_extended_add_user_mock": {
        "show_users": True,
        "add_user": "rp-matrix@pve",
        "added_user": "rp-matrix@pve",
        "is_proxmox": True,
    },
    "proxmox_extended_defcreds_empty_password": {
        "auth_attempts": [{"username": "root@pam", "source": "provided", "ok": "False"}],
        "is_proxmox": True,
        "use_https": True,
    },
}

_ACTION_NONEMPTY_FIELDS: dict[str, tuple[str, ...]] = {
    "registry_nexus": ("nexus_repositories", "nexus_assets"),
    "grafana_default": ("datasources",),
    "grafana_url_http": ("datasources",),
    "grafana_ssrf_edge": ("datasources", "check_urls", "check_results"),
    "grafana_extended_auth_ssrf_controls": ("datasources", "check_urls", "check_results"),
    "gitlab_extended_token_project_clone": ("clone_results",),
    "kubeapi_open": ("namespaces", "pods"),
    "kubeapi_auditor": ("namespaces", "pods"),
    "kubeapi_admin": ("secrets",),
    "kubeapi_url_override_https": ("namespaces",),
    "kubeapi_extended_selectors_basic_auth": ("namespaces", "pods"),
    "consul_extended_inventory_filters": (
        "kv_dump_items",
        "services_list",
        "service_instances",
        "agents_list",
        "checks_list",
        "nodes_list",
    ),
    "consul_extended_ssrf_probe": ("ssrf_results", "checks_list"),
    "qdrant_extended_ssrf_probe": ("ssrf_results", "ssrf_hits"),
    "clickhouse_http_open": ("database_names", "table_names", "table_dumps"),
    "clickhouse_http_auth": ("database_names", "table_names", "table_dumps"),
    "clickhouse_multi_ports": ("database_names",),
    "clickhouse_extended_query_columns": ("table_columns_info", "table_dumps", "sql_output"),
    "grpc_proto_invoke": ("descriptor_protos_b64",),
    "grpc_protoset_invoke": ("descriptor_protos_b64",),
    "elastic_open": ("cat_endpoints", "cluster_health", "discover_results"),
    "elastic_auth": ("cat_endpoints", "cluster_health", "users", "discover_results"),
    "elastic_extended_all_actions": (
        "cat_endpoints",
        "cluster_health",
        "users",
        "discover_results",
    ),
    "keeper_cluster": ("znode_values",),
    "proxmox_audit": ("nodes", "users"),
    "proxmox_admin": ("nodes", "users", "findings"),
    "proxmox_extended_add_user_mock": ("users",),
}

_ACTION_LIST_CONTAINS: dict[str, dict[str, tuple[object, ...]]] = {
    "grafana_ssrf_edge": {
        "check_urls": ("http://grafana-2:3000/api/health",),
    },
    "grafana_extended_auth_ssrf_controls": {
        "check_urls": ("http://grafana-2:3000/api/health",),
    },
    "gitlab_extended_token_project_clone": {
        "project_filters": ("redposture-lab/public-api",),
    },
    "kubeapi_extended_selectors_basic_auth": {"namespace_filters": ("default",)},
    "clickhouse_extended_query_columns": {
        "table_targets": ("secure.secrets_inventory",),
        "table_columns": ("owner", "value_hint"),
    },
}


_GRAFANA_SSRF_LABELS = frozenset({"grafana_ssrf_edge", "grafana_extended_auth_ssrf_controls"})
_GRAFANA_SSRF_TARGET_URL = "http://grafana-2:3000/api/health"
_CONSUL_SSRF_TARGET_URL = "http://consul:8500/v1/status/leader"


def _single_dict_result(record: dict[str, object], field: str, *, label: str) -> dict[str, object]:
    value = record.get(field)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise SystemExit(f"typed action contract for '{label}' failed: {field} must contain exactly one object")
    return value[0]


def _validate_ssrf_action_contract(label: str, record: dict[str, object]) -> None:
    if label in _GRAFANA_SSRF_LABELS:
        item = _single_dict_result(record, "check_results", label=label)
        if item.get("target_url") != _GRAFANA_SSRF_TARGET_URL:
            raise SystemExit(
                f"typed action contract for '{label}' failed: check_results.target_url="
                f"{item.get('target_url')!r}, expected {_GRAFANA_SSRF_TARGET_URL!r}"
            )
        if item.get("create_ok") is not True or item.get("create_status") not in {200, 201}:
            raise SystemExit(f"typed action contract for '{label}' failed: datasource creation did not succeed")
        if item.get("probe_ok") is not True or item.get("probe_status") != 200 or item.get("probe_error"):
            raise SystemExit(f"typed action contract for '{label}' failed: Grafana SSRF probe was not a clean HTTP 200")
        proxy_path = str(item.get("probe_proxy_path") or "")
        if not proxy_path.startswith("/api/datasources/proxy/uid/") or not proxy_path.endswith("/api/health"):
            raise SystemExit(
                f"typed action contract for '{label}' failed: probe_proxy_path did not use the UID proxy route"
            )
        try:
            sample = json.loads(str(item.get("probe_sample") or ""))
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"typed action contract for '{label}' failed: probe_sample is not Grafana health JSON"
            ) from exc
        if not isinstance(sample, dict) or sample.get("database") != "ok":
            raise SystemExit(f"typed action contract for '{label}' failed: probe_sample did not confirm database=ok")
        if item.get("cleanup_ok") is not True or item.get("cleanup_error"):
            raise SystemExit(f"typed action contract for '{label}' failed: temporary Grafana datasource cleanup failed")
        return

    if label == "consul_extended_ssrf_probe":
        item = _single_dict_result(record, "ssrf_results", label=label)
        if item.get("target_url") != _CONSUL_SSRF_TARGET_URL:
            raise SystemExit(
                f"typed action contract for '{label}' failed: ssrf_results.target_url="
                f"{item.get('target_url')!r}, expected {_CONSUL_SSRF_TARGET_URL!r}"
            )
        if item.get("registered") is not True or item.get("register_error"):
            raise SystemExit(f"typed action contract for '{label}' failed: Consul check registration failed")
        if item.get("status") != "passing" or "200" not in str(item.get("output") or ""):
            raise SystemExit(
                f"typed action contract for '{label}' failed: Consul SSRF check did not reach HTTP 200/passing"
            )
        if item.get("deregistered") is not True or item.get("deregister_error"):
            raise SystemExit(f"typed action contract for '{label}' failed: Consul check cleanup failed")
        return

    if label == "qdrant_extended_ssrf_probe":
        item = _single_dict_result(record, "ssrf_results", label=label)
        target_url = str(item.get("target_url") or "")
        try:
            parsed = urllib.parse.urlsplit(target_url)
            target_port = parsed.port
        except ValueError as exc:
            raise SystemExit(f"typed action contract for '{label}' failed: invalid SSRF target URL") from exc
        if (
            parsed.scheme != "http"
            or parsed.hostname != "host.docker.internal"
            or target_port != 19115
            or not parsed.path.endswith(".snapshot")
        ):
            raise SystemExit(
                f"typed action contract for '{label}' failed: SSRF target is not the host callback snapshot"
            )
        if item.get("collection") != "demo_vectors" or item.get("ok") is not True or item.get("status") != 200:
            raise SystemExit(f"typed action contract for '{label}' failed: Qdrant snapshot recovery did not succeed")
        if item.get("error"):
            raise SystemExit(f"typed action contract for '{label}' failed: Qdrant SSRF result contains an error")
        try:
            response = json.loads(str(item.get("response_raw") or ""))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"typed action contract for '{label}' failed: Qdrant response_raw is not JSON") from exc
        if not isinstance(response, dict) or response.get("status") != "ok" or response.get("result") is not True:
            raise SystemExit(
                f"typed action contract for '{label}' failed: Qdrant response did not confirm restore success"
            )
        hits = record.get("ssrf_hits")
        hit_count = record.get("ssrf_hit_count")
        if record.get("ssrf_listener_started") is not True:
            raise SystemExit(f"typed action contract for '{label}' failed: SSRF callback listener did not start")
        if not isinstance(hit_count, int) or hit_count <= 0 or not isinstance(hits, list) or len(hits) != hit_count:
            raise SystemExit(f"typed action contract for '{label}' failed: ssrf_hits is empty or inconsistent")
        if not any(
            isinstance(hit, dict) and hit.get("method") == "GET" and str(hit.get("path") or "") == parsed.path
            for hit in hits
        ):
            raise SystemExit(f"typed action contract for '{label}' failed: ssrf_hits has no matching snapshot callback")


def _nested_field(record: dict[str, object], path: str) -> object:
    value: object = record
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _validate_action_contracts(rows: list[dict[str, str]]) -> None:
    """Verify that matrix action flags changed the produced typed record.

    Parser/token coverage alone cannot catch the CLI-to-host-stage binding regression:
    these assertions require the canonical booleans/selectors and their resulting data to
    be present in the production JSON record.
    """

    for row in rows:
        if row["exit_code"] != "0":
            continue
        label = row["label"]
        expected_values = _ACTION_EXPECTED_VALUES.get(label)
        nonempty_fields = _ACTION_NONEMPTY_FIELDS.get(label, ())
        list_contains = _ACTION_LIST_CONTAINS.get(label, {})
        if expected_values is None and not nonempty_fields and not list_contains:
            continue
        records = [
            record for record in _iter_audit_records_for_row(row) if _record_has_meaningful_outcome(record, label=label)
        ]
        if not records:
            raise SystemExit(f"typed action contract for '{label}' has no meaningful audit records")
        for record in records:
            for field, expected in (expected_values or {}).items():
                actual = _nested_field(record, field)
                if actual != expected:
                    raise SystemExit(
                        f"typed action contract for '{label}' failed: {field}={actual!r}, expected {expected!r}"
                    )
            for field in nonempty_fields:
                if not _field_is_populated(_nested_field(record, field)):
                    raise SystemExit(f"typed action contract for '{label}' failed: {field} is empty")
            for field, expected_items in list_contains.items():
                actual = _nested_field(record, field)
                if not isinstance(actual, list) or any(item not in actual for item in expected_items):
                    raise SystemExit(
                        f"typed action contract for '{label}' failed: {field} does not contain {list(expected_items)!r}"
                    )
            _validate_ssrf_action_contract(label, record)


# Known stage names that legitimately ship `result="fail"` even when overall status is OK
# (e.g. a stage that probed an optional capability that the lab does not seed).
_STAGE_FAIL_OK_FOR_STATUS: dict[str, frozenset[str]] = {
    # Currently we accept zero such exceptions: if a stage fails, the audit must surface
    # it via status or error. Add entries here only with a documented reason.
}


def _validate_stage_coherence(rows: list[dict[str, str]]) -> None:
    """P3-B: cross-check the final status against the stage trace. Catches "status says
    OK, but a stage internally reported fail with an error" -- a coherence regression that
    would otherwise pass exit-code AND rich-substring checks."""
    for row in rows:
        if row["exit_code"] != "0":
            continue
        for record in _iter_audit_records_for_row(row):
            stages = record.get("stages")
            if not isinstance(stages, list):
                continue
            status = str(record.get("status") or "")
            stage_failures: list[str] = []
            for stage in stages:
                if not isinstance(stage, dict):
                    continue
                result = stage.get("result")
                stage_name = str(stage.get("stage_name") or "<unnamed>")
                error = stage.get("error")
                if result == "fail":
                    if not error:
                        raise SystemExit(
                            f"stage-coherence in '{row['label']}': stage {stage_name!r} has "
                            "result=fail but null/empty error (silent failure)"
                        )
                    stage_failures.append(stage_name)
            allowed = _STAGE_FAIL_OK_FOR_STATUS.get(row["label"], frozenset())
            real_failures = [s for s in stage_failures if s not in allowed]
            if status in _SUCCESSFUL_AUDIT_STATUSES and real_failures:
                raise SystemExit(
                    f"stage-coherence in '{row['label']}': status={status!r} but stages report "
                    f"failures {real_failures} (host={record.get('host')} port={record.get('port')})"
                )


# P3-D cross-case invariants: pairs of labels that target the same lab service must agree
# on the listed fields. Catches port-routing regressions and streaming-dump completeness
# (e.g. 5.5.0 streaming must dump the same number of keys as a plain dump).
_CROSS_CASE_INVARIANTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("redis_default", "redis_extended_paged_dump", ("key_count",)),
    ("etcd_open", "etcd_extended_paged_dump", ("key_count",)),
    ("postgres_default", "postgres_extended_defcreds", ("database_count",)),
    ("mongodb_open", "mongodb_auth", ("database_count",)),
)


def _validate_cross_case_invariants(rows: list[dict[str, str]]) -> None:
    """P3-D: assert that pairs of cases hitting the same lab service produce consistent
    field values. Each pair is enforced only when both cases ran successfully and produced
    a record we can compare."""
    by_label: dict[str, dict[str, object]] = {}
    for row in rows:
        if row["exit_code"] != "0":
            continue
        for record in _iter_audit_records_for_row(row):
            by_label.setdefault(row["label"], record)
            break  # one record per label is enough for the invariants we encode
    for label_a, label_b, fields in _CROSS_CASE_INVARIANTS:
        rec_a = by_label.get(label_a)
        rec_b = by_label.get(label_b)
        if rec_a is None or rec_b is None:
            continue
        for field in fields:
            value_a = rec_a.get(field)
            value_b = rec_b.get(field)
            # Only compare when both sides have a populated value.
            if value_a is None or value_b is None:
                continue
            if value_a != value_b:
                raise SystemExit(
                    f"cross-case invariant violated: '{label_a}'.{field}={value_a!r} but "
                    f"'{label_b}'.{field}={value_b!r} (both target the same lab service)"
                )


# P4-B: per-module identity-contract markers. A regression that drops one of these from
# the JSON payload (refactor, sloppy serialization, schema drift) is caught immediately.
# The selected fields are stable "always-present" markers extracted from real lab data,
# not the full schema (which would be brittle to legitimate optional-field changes).
_MODULE_SCHEMA_REQUIRED: dict[str, tuple[str, ...]] = {
    "redis": ("is_redis", "show_keys", "dump_keys", "defcreds_enabled"),
    "postgres": ("is_postgres", "database", "auth_database", "defcreds_enabled"),
    "mongodb": ("is_mongodb", "auth_db", "show_databases", "defcreds_enabled"),
    "etcd": ("is_etcd", "api_versions", "show_keys", "dump_keys"),
    "clickhouse": ("is_clickhouse", "protocol", "database", "defcreds_enabled"),
    "consul": ("is_consul", "scheme", "auth_mode", "auth_valid"),
    "kafka": ("is_kafka", "show_topics", "dump", "max_messages"),
    "zookeeper": ("is_zookeeper", "max_znodes", "show_znodes", "dump"),
    "keeper": ("is_zookeeper_compatible", "is_keeper", "fingerprint_confidence", "transport"),
    "qdrant": ("is_qdrant", "anonymous_access", "show_collections"),
    "elastic": ("is_elastic", "scheme", "show_endpoints", "show_plugins"),
    "oracle": ("is_oracle", "transport", "transport_mode", "defcreds_enabled"),
    "docker": ("is_docker", "transport", "transport_mode", "tls_required"),
    "kubeapi": ("is_kubeapi", "https", "auth_mode", "insecure_effective"),
    "registry": ("is_registry", "show_images", "show_tags", "docker"),
    "gitlab": ("is_gitlab", "https", "token_provided"),
    "grpc": ("is_grpc", "transport", "transport_mode", "reflection_enabled"),
    "grafana": ("is_grafana", "show_datasources", "defcreds_enabled"),
    "proxmox": ("is_proxmox", "use_https", "show_users", "show_nodes"),
}


# P4-D: pairs of labels that must produce identical normalized JSON (re-run idempotency).
# Convention: a base label and its `_idempotency` sibling run the SAME CLI with the SAME
# flags against the SAME lab. Any divergence in the normalized output (audit code mutated
# state, race, or non-determinism) is a regression.
_IDEMPOTENCY_PAIRS: tuple[tuple[str, str], ...] = (
    ("redis_default", "redis_idempotency"),
    ("postgres_default", "postgres_idempotency"),
    ("etcd_open", "etcd_idempotency"),
    ("mongodb_auth", "mongodb_idempotency"),
    ("kafka_open", "kafka_idempotency"),
)


def _validate_idempotency(rows: list[dict[str, str]]) -> None:
    """P4-D: paired cases that run the same CLI twice must produce the same normalized
    output. Catches state mutation by audit code, race conditions, and non-determinism."""
    by_label = {row["label"]: row for row in rows if row["exit_code"] == "0"}
    for base, twin in _IDEMPOTENCY_PAIRS:
        base_row = by_label.get(base)
        twin_row = by_label.get(twin)
        if base_row is None or twin_row is None:
            continue
        base_text = _golden_text_for_row(base_row)
        twin_text = _golden_text_for_row(twin_row)
        if base_text is None or twin_text is None:
            continue
        if base_text != twin_text:
            try:
                base_obj = json.loads(base_text)
                twin_obj = json.loads(twin_text)
                hint = _first_diff_path(base_obj, twin_obj)
            except json.JSONDecodeError:
                hint = ""
            raise SystemExit(
                f"idempotency regression: '{base}' vs '{twin}' produced different normalized "
                f"output (read-only audit mutated state, race, or non-deterministic order){hint}"
            )


# P4-E: fuzz cases that pass intentionally invalid/edge inputs. The CLI must reject them
# gracefully (non-zero exit, structured error) -- never crash with Python traceback.
# Any label that starts with `fuzz_` is treated as such; the helper below makes membership
# detection trivial without enumerating every variant.

_MISSING_TARGET_MODULES = (
    "registry",
    "grafana",
    "gitlab",
    "consul",
    "kubeapi",
    "postgres",
    "mongodb",
    "oracle",
    "docker",
    "clickhouse",
    "redis",
    "etcd",
    "qdrant",
    "elastic",
    "grpc",
    "kafka",
    "zookeeper",
    "keeper",
    "proxmox",
)

_EXPECTED_FAILURE_OUTPUT_SUBSTRINGS: dict[str, tuple[str, ...]] = {
    "exporters_scan_url_https_reject": ("exporters scan accepts only http://",),
    "exporters_collect_url_https_reject": ("exporters collect accepts only http://",),
    "exporters_trigger_url_https_reject": ("exporters trigger accepts only http://",),
    "registry_url_https_reject": ("registry accepts only http://",),
    "grafana_url_https_reject": ("grafana accepts only http://",),
    "etcd_url_https_reject": ("etcd accepts only http://",),
    "qdrant_url_https_reject": ("qdrant accepts only http://",),
    "mongodb_extended_invalid_document_query": ("--document cannot be combined with --query",),
    "docker_extended_tls_files_pairing_error": ("--tls-cert and --tls-key must be used together",),
    "kafka_extended_dump_max_conflict": ("--dump count cannot conflict with --max-messages",),
    "fuzz_exporters_scan_missing_targets": ("scan requires -t/--targets",),
    "fuzz_exporters_scan_invalid_ports": ("failed to parse --ports",),
    "fuzz_exporters_scan_zero_timeout": ("value must be > 0",),
    "fuzz_exporters_collect_zero_max_inflight": ("value must be > 0",),
    "fuzz_exporters_trigger_missing_callback": ("trigger requires --callback-ip and/or --callback-dns",),
    "fuzz_exporters_trigger_bad_callback_ip": ("--callback-ip must be a valid IP address",),
    "fuzz_exporters_trigger_check_without_listen": ("--check-credentials requires --with-listen",),
    "fuzz_exporters_trigger_json_listen_without_output": ("--format json with --with-listen requires --output",),
    "fuzz_exporters_trigger_negative_listen_seconds": ("--listen-seconds must be > 0",),
    **{f"fuzz_{module}_missing_targets": (f"{module} requires -t/--targets",) for module in _MISSING_TARGET_MODULES},
    "fuzz_registry_username_without_password": ("--username and --password must be set together",),
    "fuzz_registry_token_basic_conflict": ("use either --token or --username/--password, not both",),
    "fuzz_registry_show_tags_without_repository": ("--show-tags requires --repository",),
    "fuzz_registry_metadata_without_tag": ("--metadata requires --repository and --tag",),
    "fuzz_registry_assets_without_nexus": ("--assets requires --nexus",),
    "fuzz_registry_download_without_image": ("--download requires --image",),
    "fuzz_grafana_username_without_password": ("--password is required when --username is set",),
    "fuzz_kubeapi_username_without_password": ("--username and --password must be set together",),
    "fuzz_elastic_username_without_password": ("--username and --password must be set together",),
    "fuzz_grpc_username_without_password": ("--username and --password must be set together",),
    "fuzz_kafka_username_without_password": ("--username and --password must be set together",),
    "fuzz_zookeeper_username_without_password": ("--username and --password must be set together",),
    "fuzz_proxmox_username_without_password": ("--username and --password must be set together",),
    "fuzz_redis_username_without_password": ("--username and --password must be set together",),
    "fuzz_consul_username_without_password": ("--username and --password must be set together",),
    "fuzz_consul_key_without_dump": ("--key requires --dump",),
    "fuzz_consul_service_without_dump": ("--service requires --dump",),
    "fuzz_consul_agent_without_dump": ("--agent requires --dump",),
    "fuzz_consul_node_without_dump": ("--node requires --dump",),
    "fuzz_consul_ssrf_port_without_target": ("--ssrf-port/--ssrf-path require --ssrf-target",),
    "fuzz_consul_delete_without_revshell": ("--delete requires --revshell or --check-id",),
    "fuzz_consul_listen_without_revshell": ("--listen requires --revshell",),
    "fuzz_consul_revshell_missing_lhost": ("--lhost is required when --revshell is set",),
    "fuzz_consul_revshell_bad_lhost": ("--lhost must be a plain IPv4/DNS hostname",),
    "fuzz_consul_revshell_listen_missing_lport": ("--listen requires --lport",),
    "fuzz_qdrant_listen_without_ssrf_target": ("--listen requires --ssrf-target",),
    "fuzz_qdrant_ssrf_without_collection": ("--ssrf-target requires --collection",),
    "fuzz_qdrant_bad_ssrf_port": ("failed to parse SSRF targets/ports",),
    "fuzz_postgres_username_without_password": ("--password is required when --username is set",),
    "fuzz_postgres_show_columns_without_table": ("--show-columns requires --table",),
    "fuzz_postgres_column_without_table": ("--column requires --table",),
    "fuzz_postgres_execute_sql_conflict": ("--execute cannot be combined with --sql-cmd",),
    "fuzz_postgres_execute_os_read_conflict": ("--execute cannot be combined with --os-read",),
    "fuzz_postgres_os_shell_sql_shell_conflict": ("--os-shell cannot be combined with --sql-shell",),
    "fuzz_mongodb_username_without_password": ("--password is required when --username is set",),
    "fuzz_mongodb_invalid_query_json": ("--query must be valid JSON object",),
    "fuzz_mongodb_query_without_collection": ("--query requires --collection",),
    "fuzz_mongodb_document_without_collection": ("--document requires --collection",),
    "fuzz_mongodb_document_query_conflict": ("--document cannot be combined with --query",),
    "fuzz_mongodb_invalid_projection_json": ("--projection must be valid JSON object",),
    "fuzz_mongodb_invalid_nosql_cmd_json": ("--nosql-cmd must be valid JSON object",),
    "fuzz_mongodb_nosql_cmd_shell_conflict": ("--nosql-cmd cannot be combined with --nosql-shell",),
    "fuzz_oracle_username_without_password": ("--password is required when --username is set",),
    "fuzz_oracle_service_sid_conflict": ("--service cannot be combined with --sid",),
    "fuzz_oracle_non_select_query": ("--query must be a read-only SELECT statement",),
    "fuzz_oracle_os_write_bad_syntax": ("--os-write must use local:remote or remote:local syntax",),
    "fuzz_oracle_download_bad_syntax": ("--download must use local:remote or remote:local syntax",),
    "fuzz_docker_container_without_exec": ("--container and --exec-cmd must be used together",),
    "fuzz_docker_exec_without_container": ("--container and --exec-cmd must be used together",),
    "fuzz_docker_tls_cert_without_key": ("--tls-cert and --tls-key must be used together",),
    "fuzz_docker_tls_key_without_cert": ("--tls-cert and --tls-key must be used together",),
    "fuzz_clickhouse_username_without_password": ("--password is required when --username is set",),
    "fuzz_clickhouse_show_columns_without_table": ("--show-columns requires --table",),
    "fuzz_clickhouse_column_without_table": ("--column requires --table",),
    "fuzz_clickhouse_execute_sql_conflict": ("--execute cannot be combined with --sql-cmd",),
    "fuzz_clickhouse_os_shell_sql_shell_conflict": ("--os-shell cannot be combined with --sql-shell",),
    "fuzz_clickhouse_os_shell_execute_conflict": ("--os-shell cannot be combined with --execute",),
    "fuzz_zookeeper_zero_max_znodes": ("value must be > 0",),
    "fuzz_zookeeper_zero_enum_workers": ("value must be > 0",),
    "fuzz_keeper_incomplete_mtls": ("--tls-cert and --tls-key must be used together",),
    "fuzz_keeper_incomplete_mtls_key": ("--tls-cert and --tls-key must be used together",),
    "fuzz_keeper_ca_insecure_conflict": ("--ca-file cannot be combined with --insecure",),
    "fuzz_keeper_removed_tls_flag": ("ambiguous option: --tls",),
    "fuzz_keeper_removed_no_tls_flag": ("unrecognized arguments: --no-tls",),
    "fuzz_redis_invalid_port_negative": ("failed to parse --port", "invalid port range"),
    "fuzz_redis_invalid_port_huge": ("port must be in range",),
    "fuzz_redis_zero_dump": ("value must be > 0",),
    "fuzz_redis_negative_show_keys": ("value must be > 0",),
    "fuzz_redis_invalid_dump_batch": ("value must be > 0",),
    "fuzz_redis_negative_dump_delay": ("value must be >= 0",),
    "fuzz_postgres_empty_credentials": ("--username must not be empty",),
    "fuzz_etcd_garbage_target": ("failed to parse targets",),
    "fuzz_etcd_invalid_dump_batch": ("value must be > 0",),
    "fuzz_etcd_negative_show_keys": ("value must be > 0",),
    "fuzz_mongodb_zero_timeout": ("value must be > 0",),
    "fuzz_mongodb_invalid_workers": ("value must be an integer",),
    "fuzz_mongodb_negative_retries": ("value must be >= 0",),
    "fuzz_kafka_negative_workers": ("value must be > 0",),
    "fuzz_kafka_zero_max_messages": ("value must be > 0",),
    "fuzz_kafka_invalid_port": ("failed to parse --port", "invalid port"),
    "fuzz_registry_malformed_target": ("failed to parse targets",),
    "fuzz_registry_invalid_port": ("failed to parse --port", "invalid port range"),
    "fuzz_grafana_invalid_target": ("failed to parse targets",),
    "fuzz_grafana_huge_port": ("port must be in range",),
    "fuzz_gitlab_invalid_port": ("port must be in range",),
    "fuzz_gitlab_zero_timeout": ("value must be > 0",),
    "fuzz_consul_zero_workers": ("value must be > 0",),
    "fuzz_consul_negative_dump": ("value must be > 0",),
    "fuzz_kubeapi_zero_timeout": ("value must be > 0",),
    "fuzz_kubeapi_huge_port": ("port must be in range",),
    "fuzz_oracle_invalid_port": ("failed to parse --port", "invalid port range"),
    "fuzz_oracle_zero_timeout": ("value must be > 0",),
    "fuzz_docker_invalid_port": ("failed to parse --port", "invalid port"),
    "fuzz_docker_zero_timeout": ("value must be > 0",),
    "fuzz_clickhouse_negative_timeout": ("value must be > 0",),
    "fuzz_clickhouse_invalid_port": ("failed to parse --port", "invalid port range"),
    "fuzz_qdrant_zero_timeout": ("value must be > 0",),
    "fuzz_qdrant_invalid_port": ("failed to parse --port", "invalid port range"),
    "fuzz_elastic_negative_retries": ("value must be >= 0",),
    "fuzz_elastic_invalid_port": ("failed to parse --port", "invalid port"),
    "fuzz_grpc_invalid_port": ("failed to parse --port", "invalid port range"),
    "fuzz_grpc_zero_workers": ("value must be > 0",),
    "fuzz_zookeeper_invalid_port": ("failed to parse --port", "invalid port"),
    "fuzz_zookeeper_zero_workers": ("value must be > 0",),
    "fuzz_proxmox_negative_workers": ("value must be > 0",),
    "fuzz_proxmox_invalid_port": ("failed to parse --port", "invalid port range"),
}


def _is_fuzz_label(label: str) -> bool:
    return label.startswith("fuzz_")


_FUZZ_LABELS = frozenset(label for label in _EXTENDED_EXPECTED_LABELS if _is_fuzz_label(label))


def _expected_int(row: dict[str, str]) -> int:
    return int(row.get("expected_exit") or "0")


def _validate_expected_failure_outputs(rows: list[dict[str, str]]) -> None:
    """Expected-failure matrix rows must fail cleanly and explain why.

    This validates the actual command logs produced by the lab matrix, not a separate
    smoke command. It catches accidental Python tracebacks, silent JSON output from an
    early-failure path, or a command failing for the wrong reason.
    """
    for row in rows:
        if _expected_int(row) == 0:
            continue
        label = row["label"]
        expected_substrings = _EXPECTED_FAILURE_OUTPUT_SUBSTRINGS.get(label)
        if not expected_substrings:
            raise SystemExit(f"expected-failure label '{label}' has no output expectation")

        log_path = Path(row["log_path"])
        if not log_path.exists():
            raise SystemExit(f"missing run log file for expected-failure label '{label}': {log_path}")
        log_text = log_path.read_text(encoding="utf-8", errors="replace")

        missing = [needle for needle in expected_substrings if needle not in log_text]
        if missing:
            raise SystemExit(
                f"expected-failure label '{label}' failed for the wrong reason; missing log substring(s): {missing}"
            )
        if "Traceback (most recent call last)" in log_text:
            raise SystemExit(f"expected-failure label '{label}' crashed with a Python traceback")
        if "Running redposture against" in log_text:
            raise SystemExit(f"expected-failure label '{label}' unexpectedly reached target execution")

        json_path = row.get("json_path") or "-"
        if json_path in {"", "-"}:
            continue
        artifact = Path(json_path)
        if artifact.exists() and artifact.stat().st_size > 0:
            raise SystemExit(f"expected-failure label '{label}' produced a non-empty JSON artifact: {artifact}")


def _validate_fuzz_no_traceback(rows: list[dict[str, str]]) -> None:
    """P4-E: fuzz cases must exit with the expected non-zero code AND must not surface a
    Python traceback in their log. Either signals a missing input validator (which would
    crash on production input)."""
    for row in rows:
        if row["label"] not in _FUZZ_LABELS:
            continue
        log_path = Path(row["log_path"])
        if not log_path.exists():
            continue
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if "Traceback (most recent call last)" in log_text:
            raise SystemExit(
                f"fuzz regression in '{row['label']}': CLI crashed with a Python traceback "
                "(input validator missing or broken)"
            )


_GOLDEN_DIR = Path("tests/fixtures/golden")
# Modules whose audit output legitimately varies run-to-run on the lab (transient health
# checks, container-issued hostnames, exporter cold-start timing). Their per-module schema
# is still enforced by P4-B; golden diff would just be noise.
_GOLDEN_SKIP_MODULES = frozenset(
    {
        "exporters",  # discovery candidate enumeration timing
        "consul",  # transient health checks, run-to-run state
        "redis",  # SCAN-cursor key order is per-page (5.5.0 streaming), not deterministic
        "qdrant",  # scroll cursor IDs change per boot
        "docker",  # network/volume enumeration order depends on docker daemon state
    }
)
# Labels whose specific case mixes deterministic + volatile content unpredictably.
_GOLDEN_SKIP_LABELS = frozenset(
    {
        "postgres_extended_os_read",  # `/etc/hostname` reads docker-assigned random hex
        "registry_extended_tags_metadata",  # mock issues fresh tokens per lab boot
        "registry_gitlab",
        # kafka_extended_defcreds flakes between status=open_no_auth (anonymous worked,
        # no defcred attempts) and status=auth_required (defcreds tried, attempted_credentials
        # list populated). Depends on lab kafka container startup race; the kafka_extended_*
        # tests in tests/test_stage_kafka.py + the multi-record consistency rule still cover
        # the path semantically.
        "kafka_extended_defcreds",
    }
)
# Docker assigns 12-char hex container names (e.g. `7fa9fd7f914d`). Normalize them so
# golden diffs don't trip on every lab reboot.
_GOLDEN_DOCKER_HEX_NAME = re.compile(r"\b[0-9a-f]{12}\b")
# Audit code itself generates random identifiers for one-shot privesc/file operations.
_GOLDEN_AUDIT_RANDOM = re.compile(
    r"REDPOSTURE_(?:JOB|EXT)_[0-9A-Fa-f]+|rp_(?:ext|read|exec)_[0-9a-f]+|\$oid|"
    r"redposture_large_file_[0-9a-f]+|redposture_wallet_hint_[0-9a-f]+"
)
# Docker container Ids are 64-char hex hashes; container names are 12-char (handled above).
_GOLDEN_DOCKER_CONTAINER_ID = re.compile(r"\b[0-9a-f]{64}\b")
# bcrypt password hashes ($2a$/$2b$ + cost + salt + ciphertext): always per-record-random.
_GOLDEN_BCRYPT = re.compile(r"\$2[ab]\$\d{2}\$[A-Za-z0-9./]+")
# Kafka message envelope prefix `pN@offset` (partition/offset assignment varies per topic).
_GOLDEN_KAFKA_OFFSET = re.compile(r"\bp\d+@\d+\b")
# Fields populated by remote services and inherently per-boot/per-connection.
_GOLDEN_VOLATILE_NESTED_FIELDS = frozenset(
    {
        "connectionId",  # mongodb hello: per-connection counter
        "processId",  # mongodb topology: per-boot ObjectId
        "topologyVersion",  # mongodb hello: changes on each step-down
        "localTime",  # mongodb hello
        "Created",  # docker container Unix timestamp
        "State",  # docker container runtime state (Running/Exited toggles)
        "Status",  # docker container status string
        "set",  # mongodb replica set internals
        "primary",  # mongodb replica primary host
        "me",  # mongodb hello current node
        "hosts",  # mongodb cluster topology
        "lastWrite",  # mongodb replication state
        "operationTime",  # mongodb cluster op time
        "$clusterTime",
        "logicalSessionTimeoutMinutes",
        "minWireVersion",
        "maxWireVersion",
        "iso8601",
        "saslSupportedMechs",
        # Mongo aggregations vary on lab activity (fsUsedSize on $fsstat).
        "fsUsedSize",
        "fsTotalSize",
        # Docker container Id / runtime-dependent paths
        "Id",
        "container_id",
        # Docker network driver attaches/detaches between runs depending on cleanup order.
        "Driver",
        "Labels",
        # Audit code generates a random password when probing proxmox add-user capability.
        "added_password",
        "IPAM",  # docker network IPAM config flips between bridge/null on restart
        "Mountpoint",  # docker volume mountpoint paths embed cluster-side identifiers
        # Lab service images use `:latest` tags and quietly upgrade between runs
        # (saw mongodb 7.0.34->7.0.37, grafana 13.0.1+security-01->13.0.2 in 5.5.6).
        # Pinning the tag is the proper fix at infra level; meanwhile, drop the version
        # from goldens so they don't false-fail on every container patch.
        "server_version",
    }
)
# Field names whose values vary every run -- stripped at ANY nesting depth before comparing
# against the golden snapshot. Includes timer durations, debug counters, per-run output
# paths, response body blobs (gzipped/binary), and container-issued IDs/names.
_GOLDEN_VOLATILE_FIELDS = frozenset(
    {
        "timestamp",
        "elapsed_ms",
        "stage_timing_total_ms",
        "stage_durations_ms",
        "stage_attempts",
        "stage_timing_status",
        "stage_failed_at",
        "debug_events",
        "debug_events_streamed",
        "attempts",
        "max_attempts",
        "stage_detect_ms",
        "stage_auth_ms",
        "stage_capabilities_ms",
        "stage_data_ms",
        "stage_attempts_used",
        "auth_ms",
        "connect_ms",
        "dump_ms",
        "enumerate_ms",
        "elapsed",
        "duration_ms",  # per-stage timer (deep)
        "output_path",  # tied to OUT_DIR, varies per matrix invocation
        "path",  # registry download paths under OUT_DIR
        "body",  # exporter HTTP response bodies (binary/gzipped, always variable)
        "token_issued_at",  # gitlab mock issues a fresh token each lab boot
        "token_expires_at",
        "expires_at",
        "created_at",
        "last_login",
        "last_rotated",
        "started_at",
        "finished_at",
        "issued_at",
        "ts",
        "name",  # docker assigns random container names (hex hashes)
        # Per-target run-to-run lab volatility (health check transitions, exporter cold-start
        # behavior, candidate enumeration timing). These are environmental noise, not code
        # contract; stripping them keeps the golden diff focused on real regressions.
        "checks_list",
        "candidate_count",
        "candidates",
        "content_type",
        "content_length",
    }
)
# Module-specific fields whose values describe transient lab runtime state rather than
# the audit contract. Keep this narrow: typed/status assertions above still validate
# these records before golden comparison.
_GOLDEN_MODULE_VOLATILE_FIELDS: dict[str, frozenset[str]] = {
    "keeper": frozenset(
        {
            "connections",  # includes the verifier connection itself
            "latency_ms",  # 4lw timing depends on host load
        }
    ),
}
# Label-specific runtime state. Keeper TLS/no4lw/control cases have stable roles, while
# keeper_cluster intentionally samples only two members of a three-node election.
_GOLDEN_LABEL_VOLATILE_FIELDS: dict[str, frozenset[str]] = {
    "keeper_cluster": frozenset(
        {
            "quorum_status",  # any of the three Keeper members may be elected leader
            "raft",  # leader-only counters disappear when the target is a follower
            "server_state",  # leader/follower assignment changes on every cold start
        }
    ),
    "keeper_force_plaintext": frozenset(
        {
            "quorum_status",  # port 9181 is another member of the same elected cluster
            "raft",
            "server_state",
        }
    ),
    "zookeeper_extended_znode_limits": frozenset(
        {
            # The bounded concurrent traversal may reach a different valid subset before
            # max_znodes=10. Exact count/truncation and the explicit seeded query are
            # asserted separately; only the subset itself is non-deterministic.
            "znode_details",
            "znodes",
        }
    ),
}
# Volatile fields limited to a specific nested result collection.
_GOLDEN_CONTEXT_VOLATILE_FIELDS: dict[tuple[str, str], frozenset[str]] = {
    ("elastic", "cluster_nodes"): frozenset(
        {
            "host",  # Docker network address
            "id",  # Elasticsearch node ID is generated per data volume
            "ip",  # Docker network address
        }
    ),
    ("grafana", "check_results"): frozenset(
        {
            "datasource_id",  # generated for the temporary SSRF probe datasource
            "datasource_uid",  # generated for the temporary SSRF probe datasource
            "probe_elapsed_ms",  # network timing
            "probe_proxy_path",  # embeds the generated datasource UID
            "probe_sample",  # includes Grafana image version/commit; typed contract validates database=ok
        }
    ),
    ("kubeapi", "pods"): frozenset(
        {
            "phase",  # system pods may still be Pending during a cold-start audit
        }
    ),
}
# Regex pattern: matches any per-run /tmp/rp_matrix_run* path that leaked into a string.
_GOLDEN_PATH_NOISE = re.compile(r"/tmp/[a-z_]+_matrix[_a-z0-9-]*")
# ISO 8601 timestamps embedded in string values (e.g. "issued 2026-06-17T15:55:40Z").
_GOLDEN_ISO_NOISE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?")
_MONGODB_UNORDERED_LIST_FIELDS = frozenset({"database_names", "collections", "documents", "indexes"})


def _normalize_string_value(value: str, *, out_dir: Path | None = None) -> str:
    if out_dir is not None:
        candidates = {str(out_dir), str(out_dir.resolve(strict=False))}
        for candidate in sorted((item for item in candidates if item), key=len, reverse=True):
            value = value.replace(candidate, "<OUT_DIR>")
    value = _GOLDEN_PATH_NOISE.sub("<OUT_DIR>", value)
    value = _GOLDEN_ISO_NOISE.sub("<ISO>", value)
    value = _GOLDEN_DOCKER_CONTAINER_ID.sub("<DOCKER_ID>", value)
    value = _GOLDEN_BCRYPT.sub("<BCRYPT>", value)
    value = _GOLDEN_KAFKA_OFFSET.sub("<KAFKA_OFFSET>", value)
    value = _GOLDEN_DOCKER_HEX_NAME.sub("<DOCKER_HEX>", value)
    value = _GOLDEN_AUDIT_RANDOM.sub("<AUDIT_RND>", value)
    return value


def _normalize_for_golden(
    payload: Any,
    *,
    out_dir: Path | None = None,
    module: str | None = None,
    label: str | None = None,
    parent_key: str | None = None,
) -> Any:
    """Recursively strip volatile fields and normalize per-run-variable string content
    (paths, timestamps) so the golden diff catches semantic regressions only."""
    if isinstance(payload, dict):
        effective_module = str(payload.get("module") or module or "").strip() or None
        module_volatile_fields = _GOLDEN_MODULE_VOLATILE_FIELDS.get(effective_module or "", frozenset())
        label_volatile_fields = _GOLDEN_LABEL_VOLATILE_FIELDS.get(label or "", frozenset())
        context_volatile_fields = _GOLDEN_CONTEXT_VOLATILE_FIELDS.get(
            (effective_module or "", parent_key or ""),
            frozenset(),
        )
        kube_generated_data_fields: frozenset[str] = frozenset()
        if effective_module == "kubeapi" and parent_key == "secrets" and payload.get("namespace") == "kube-system":
            secret_name = str(payload.get("name") or "")
            secret_type = str(payload.get("type") or "")
            if secret_name.endswith(".node-password.k3s"):
                kube_generated_data_fields = frozenset({"hash"})
            elif secret_name == "k3s-serving" and secret_type == "kubernetes.io/tls":
                kube_generated_data_fields = frozenset({"tls.crt", "tls.key"})
        result: dict[str, Any] = {}
        for key, value in payload.items():
            if (
                key in _GOLDEN_VOLATILE_FIELDS
                or key in _GOLDEN_VOLATILE_NESTED_FIELDS
                or key in module_volatile_fields
                or key in label_volatile_fields
                or key in context_volatile_fields
            ):
                continue
            if kube_generated_data_fields and key == "data" and isinstance(value, dict):
                result[key] = {
                    str(data_key): (
                        "<KUBE_SYSTEM_SECRET>"
                        if data_key in kube_generated_data_fields
                        else _normalize_for_golden(
                            data_value,
                            out_dir=out_dir,
                            module=effective_module,
                            label=label,
                            parent_key=str(data_key),
                        )
                    )
                    for data_key, data_value in sorted(value.items(), key=lambda item: str(item[0]))
                }
                continue
            result[key] = _normalize_for_golden(
                value,
                out_dir=out_dir,
                module=effective_module,
                label=label,
                parent_key=key,
            )
        return result
    if isinstance(payload, list):
        normalized = [
            _normalize_for_golden(
                item,
                out_dir=out_dir,
                module=module,
                label=label,
                parent_key=parent_key,
            )
            for item in payload
        ]
        if module == "mongodb" and parent_key in _MONGODB_UNORDERED_LIST_FIELDS:
            return sorted(
                normalized,
                key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            )
        return normalized
    if isinstance(payload, str):
        return _normalize_string_value(payload, out_dir=out_dir)
    return payload


def _canonicalize_golden_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return JSONL audit records in a stable order for snapshot comparison."""

    return sorted(
        records,
        key=lambda payload: json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
    )


def _golden_text_for_row(row: dict[str, str]) -> str | None:
    json_path = row.get("json_path") or "-"
    if json_path in {"", "-"}:
        return None
    artifact = Path(json_path)
    if not artifact.exists():
        return None
    text = artifact.read_text(encoding="utf-8", errors="replace")
    out_dir = artifact.parent.parent
    normalized: list[dict[str, Any]] = []
    for payload in _iter_json_objects(text):
        if isinstance(payload, dict):
            normalized.append(
                _normalize_for_golden(
                    payload,
                    out_dir=out_dir,
                    module=str(row.get("module") or "").strip() or None,
                    label=str(row.get("label") or "").strip() or None,
                )
            )
    # Multi-target audits intentionally emit records as futures complete. The
    # completion order is not a semantic part of an audit result: the set of
    # discovered host/port records is. Canonicalize only the outer JSONL
    # record order so golden snapshots still catch a missing or changed target
    # while accepting a different scheduling order.
    normalized = _canonicalize_golden_records(normalized)
    return json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True)


def _validate_golden_snapshots(rows: list[dict[str, str]], *, update: bool = False) -> None:
    """P4-A: every label with a golden snapshot on disk must reproduce its normalized JSON
    (volatile fields stripped). New labels can be initialised with `--update-golden`.
    Catches every semantic regression that no targeted rule covers explicitly."""
    if not _GOLDEN_DIR.exists() and not update:
        return
    if update:
        _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    diffs: list[str] = []
    for row in rows:
        if row["exit_code"] != "0":
            continue
        if row["module"] in _GOLDEN_SKIP_MODULES or row["label"] in _GOLDEN_SKIP_LABELS:
            continue
        current = _golden_text_for_row(row)
        if current is None:
            continue
        golden_path = _GOLDEN_DIR / f"{row['label']}.json"
        if update:
            golden_path.write_text(current + "\n", encoding="utf-8")
            continue
        if not golden_path.exists():
            continue  # new label without a golden yet; covered by --update-golden run
        previous = golden_path.read_text(encoding="utf-8").rstrip("\n")
        try:
            previous_payload = json.loads(previous)
        except json.JSONDecodeError:
            previous_payload = None
        if isinstance(previous_payload, list) and all(isinstance(item, dict) for item in previous_payload):
            previous = json.dumps(
                _canonicalize_golden_records(previous_payload),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        if current != previous:
            # Surface a compact diff hint (first differing field path)
            try:
                cur_obj = json.loads(current)
                old_obj = json.loads(previous)
            except json.JSONDecodeError:
                cur_obj = old_obj = None
            hint = _first_diff_path(old_obj, cur_obj) if cur_obj is not None and old_obj is not None else ""
            diffs.append(f"  - {row['label']}: normalized JSON diverges from golden{hint}")
    if diffs:
        joined = "\n".join(diffs[:10])
        extra = f"\n  (+{len(diffs) - 10} more)" if len(diffs) > 10 else ""
        raise SystemExit(
            f"golden snapshot regression across {len(diffs)} label(s):\n{joined}{extra}\n"
            "  if the change is intentional, re-run verify_postrun with --update-golden."
        )


def _first_diff_path(old: Any, new: Any, path: str = "") -> str:
    """Return a short hint pointing at where two structures first differ."""
    if type(old) is not type(new):
        return f" -- type changed at {path or '<root>'}"
    if isinstance(old, dict):
        for key in sorted(set(old.keys()) | set(new.keys())):
            if key not in old:
                return f" -- new key {path}.{key}"
            if key not in new:
                return f" -- missing key {path}.{key}"
            hint = _first_diff_path(old[key], new[key], f"{path}.{key}" if path else key)
            if hint:
                return hint
        return ""
    if isinstance(old, list):
        if len(old) != len(new):
            return f" -- list length changed at {path or '<root>'}: {len(old)} -> {len(new)}"
        for idx, (a, b) in enumerate(zip(old, new, strict=False)):
            hint = _first_diff_path(a, b, f"{path}[{idx}]")
            if hint:
                return hint
        return ""
    if old != new:
        old_s = json.dumps(old)[:40] if old is not None else "null"
        new_s = json.dumps(new)[:40] if new is not None else "null"
        return f" -- value at {path or '<root>'}: {old_s} -> {new_s}"
    return ""


def _validate_module_schema(rows: list[dict[str, str]]) -> None:
    """P4-B: every audit record must carry its module's identity-contract fields. Catches
    schema drift where a marker silently disappears from the JSON payload (refactor /
    serialization regression)."""
    for row in rows:
        if row["exit_code"] != "0":
            continue
        module = row["module"]
        required = _MODULE_SCHEMA_REQUIRED.get(module)
        if not required:
            continue
        for record in _iter_audit_records_for_row(row):
            if str(record.get("module") or "") != module:
                continue
            missing = [field for field in required if field not in record]
            if missing:
                raise SystemExit(
                    f"schema regression in '{row['label']}': module={module} record missing "
                    f"identity-contract field(s) {missing}"
                )


# P3-C: map CLI flags to the JSON field whose length must be capped at the flag's value.
# (module, flag) -> field name. Verifier reads the CLI invocation from the matrix script
# and asserts `len(record[field]) <= flag_value`.
#
# Only pairs where the documented contract is "limit applies to JSON" are included.
# zookeeper `--show-znodes` is documented as render-only (the JSON cap is `--max-znodes`),
# so it stays excluded by design.
_LIMIT_FLAG_TO_FIELD: dict[tuple[str, str], str] = {
    ("redis", "--show-keys"): "keys",
    ("etcd", "--show-keys"): "keys",
    ("postgres", "--show-columns"): "table_columns_info",
    ("clickhouse", "--show-databases"): "database_names",
    ("clickhouse", "--show-tables"): "table_names",
}


def _validate_limit_conformance(rows: list[dict[str, str]]) -> None:
    """P3-C: for cases that explicitly cap a list with `--show-X N`, assert the
    corresponding JSON field is at most N items long. Catches off-by-one and "limit
    silently ignored" regressions."""
    try:
        from scripts.matrix_flag_coverage import parse_matrix_cases
    except ImportError:
        return  # script path not importable from current cwd; silently skip
    script_path = Path("scripts/run_lab_matrix_sequential.sh")
    if not script_path.exists():
        return
    cases_by_label: dict[str, list[str]] = {}
    for case in parse_matrix_cases(script_path.read_text(encoding="utf-8")):
        cases_by_label[case.label] = list(case.tokens)
    for row in rows:
        if row["exit_code"] != "0":
            continue
        tokens = cases_by_label.get(row["label"])
        if not tokens:
            continue
        module = row["module"]
        for record in _iter_audit_records_for_row(row):
            for (flag_module, flag), field in _LIMIT_FLAG_TO_FIELD.items():
                if flag_module != module or flag not in tokens:
                    continue
                idx = tokens.index(flag)
                if idx + 1 >= len(tokens):
                    continue
                raw_limit = tokens[idx + 1]
                try:
                    limit = int(raw_limit)
                except ValueError:
                    continue  # `--show-keys` without a count is "no cap"
                value = record.get(field)
                if not isinstance(value, list):
                    continue
                if len(value) > limit:
                    raise SystemExit(
                        f"limit regression in '{row['label']}': {flag} {limit} but "
                        f"{field} contains {len(value)} entries"
                    )
            break  # one record per label is enough


def _validate_output_sanity(rows: list[dict[str, str]]) -> None:
    for row in rows:
        log_path = Path(row["log_path"])
        if not log_path.exists():
            raise SystemExit(f"missing run log file: {log_path}")
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        label = row["label"]
        module = row["module"]
        is_debug_run = "debug" in label

        # Non-debug regressions: debug trace markers must not leak into default runs.
        if not is_debug_run and "stage_trace " in log_text:
            raise SystemExit(f"unexpected debug stage_trace in non-debug run log for label '{label}'")

        # Noise regression: agreed modules should not print noisy connection-failed row in successful default runs.
        if row["exit_code"] == "0" and module in {"redis", "etcd", "kafka"} and not is_debug_run:
            if "[!] connection failed err=" in log_text:
                raise SystemExit(f"unexpected noisy connection failed line in non-debug log for label '{label}'")

        expected_targets = _PROGRESS_EXPECTED_TARGETS.get(label)
        if expected_targets is None or row["exit_code"] != "0":
            continue
        counts = _progress_counts_from_log(log_text)
        if not counts:
            # Some json/jsonl flows intentionally stream structured rows without rendering progress.
            inferred_targets = _infer_target_count_from_jsonl(_combined_run_output(row))
            if inferred_targets == expected_targets:
                continue
            raise SystemExit(f"missing progress row in log for label '{label}'")
        if expected_targets not in counts:
            raise SystemExit(
                f"progress target count mismatch for label '{label}': expected {expected_targets}, got {counts}"
            )
        if expected_targets > 1 and 1 in counts:
            raise SystemExit(f"progress regressed to single-target batches in label '{label}': counts={counts}")
        if any(count != expected_targets for count in counts):
            raise SystemExit(
                f"progress target count mismatch for label '{label}': expected {expected_targets}, got {counts}"
            )


def _validate_progress_target_mappings(
    script_path: Path = Path("scripts/run_lab_matrix_sequential.sh"),
) -> None:
    """Keep hard-coded verifier target counts tied to the actual matrix command."""

    if not script_path.exists():
        return
    try:
        from scripts.matrix_flag_coverage import parse_matrix_cases
    except ImportError:
        return
    cases = {case.label: case for case in parse_matrix_cases(script_path.read_text(encoding="utf-8"))}
    for label, expected in _PROGRESS_EXPECTED_TARGETS.items():
        if label == "exporters_scan":
            continue  # port list is supplied through the EXPORTER_PORTS shell variable
        case = cases.get(label)
        if case is None:
            continue
        tokens = list(case.tokens)
        targets_count = 1
        for target_flag in ("-t", "--targets"):
            if target_flag in tokens and tokens.index(target_flag) + 1 < len(tokens):
                target_value = tokens[tokens.index(target_flag) + 1]
                if "$" not in target_value:
                    targets_count = len([item for item in target_value.split(",") if item.strip()])
                break
        ports_count = 1
        if "--ports" in tokens and tokens.index("--ports") + 1 < len(tokens):
            ports_value = tokens[tokens.index("--ports") + 1]
            if "$" not in ports_value:
                ports_count = len([item for item in ports_value.split(",") if item.strip()])
        inferred = targets_count * ports_count
        if inferred != expected:
            raise SystemExit(f"progress target mapping mismatch for '{label}': verifier={expected} matrix={inferred}")


def _validate_openapi_artifacts(out_dir: Path, rows: list[dict[str, str]]) -> None:
    labels = {row["label"] for row in rows if row["exit_code"] == "0"}
    if "grpc_openapi_export" not in labels:
        return
    path = out_dir / "json" / "grpc_openapi.json"
    if not path.exists() or path.stat().st_size == 0:
        raise SystemExit(f"missing grpc OpenAPI artifact: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid grpc OpenAPI artifact {path}: {exc}") from exc
    if document.get("openapi") != "3.1.0":
        raise SystemExit(f"grpc OpenAPI artifact has unexpected version: {document.get('openapi')}")
    paths = document.get("paths")
    if not isinstance(paths, dict) or "/grpc.health.v1.Health/Check" not in paths:
        raise SystemExit("grpc OpenAPI artifact does not contain /grpc.health.v1.Health/Check")
    operation = (
        paths["/grpc.health.v1.Health/Check"].get("post")
        if isinstance(paths.get("/grpc.health.v1.Health/Check"), dict)
        else None
    )
    if not isinstance(operation, dict):
        raise SystemExit("grpc OpenAPI health path does not contain a post operation")
    for key in ("x-grpc-service", "x-grpc-method", "x-grpc-input-type", "x-grpc-output-type", "x-grpc-streaming"):
        if key not in operation:
            raise SystemExit(f"grpc OpenAPI operation is missing {key}")


def _run_cli_check(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "redposture.py", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _cli_smoke_checks() -> None:
    checks = [
        ("--help",),
        ("registry", "-h"),
        ("exporters", "scan", "-h"),
        ("postgres", "-h"),
        ("elastic", "-h"),
        ("grpc", "-h"),
    ]
    for args in checks:
        result = _run_cli_check(*args)
        if result.returncode != 0:
            raise SystemExit(f"cli smoke failed: redposture.py {' '.join(args)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify lab matrix outputs and artifacts.")
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--profile", choices=("balanced", "extended"), default="balanced")
    parser.add_argument(
        "--update-golden",
        action="store_true",
        help="Regenerate the P4-A golden snapshots from the current artifacts instead of comparing.",
    )
    args = parser.parse_args()

    status_path = Path(args.status_file)
    if not status_path.exists():
        raise SystemExit(f"status file not found: {status_path}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    checks_dir = out_dir / "postrun_checks"
    checks_dir.mkdir(parents=True, exist_ok=True)

    rows = _parse_status_file(status_path)
    if not rows:
        raise SystemExit("matrix status file is empty")

    _validate_expected_exits(rows)
    _validate_expected_failure_outputs(rows)
    _validate_expected_labels(rows, profile=args.profile)
    _validate_progress_target_mappings()

    successful_modules = _validate_json_artifacts(rows)
    if not successful_modules:
        raise SystemExit("no successful runs were recorded")

    seen_modules = {row["module"] for row in rows}
    missing_modules = sorted(module for module in _EXPECTED_MODULES if module not in seen_modules)
    if missing_modules:
        raise SystemExit(f"matrix status is missing expected modules: {', '.join(missing_modules)}")

    _validate_output_sanity(rows)
    _validate_rich_lab_outputs(rows)
    _validate_tee_when_output_set(rows)
    _validate_dump_not_empty(rows)
    _validate_status_coherence(rows)
    _validate_meaningful_outcomes(rows)
    _validate_multi_record_consistency(rows)
    _validate_schema_mandatory_fields(rows)
    _validate_module_schema(rows)
    _validate_elapsed_sanity(rows)
    _validate_capability_sanity(rows)
    _validate_action_contracts(rows)
    _validate_stage_coherence(rows)
    _validate_cross_case_invariants(rows)
    _validate_limit_conformance(rows)
    _validate_idempotency(rows)
    _validate_fuzz_no_traceback(rows)
    _validate_golden_snapshots(rows, update=args.update_golden)
    _validate_openapi_artifacts(out_dir, rows)

    missing_success = sorted(module for module in _EXPECTED_MODULES if successful_modules.get(module, 0) == 0)
    if missing_success:
        raise SystemExit(f"no successful run recorded for modules: {', '.join(missing_success)}")

    _cli_smoke_checks()

    summary = {
        "total_rows": len(rows),
        "profile": args.profile,
        "successful_modules": dict(successful_modules),
        "expected_modules": list(_EXPECTED_MODULES),
        "expected_labels": list(_expected_labels_for_profile(args.profile)),
    }
    (checks_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
