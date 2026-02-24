from __future__ import annotations

import pytest

from redposture_core.cli_args import COMMAND_EXPORTERS, COMMAND_SELFCERT, parse_args


def test_parse_args_without_args_shows_help_and_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args([])
    assert exc.value.code == 0


def test_trigger_with_listen_flag_parses_listener_options() -> None:
    args = parse_args(
        [
            "exporters",
            "trigger",
            "-t",
            "10.0.0.1",
            "--callback-ip",
            "10.0.0.2",
            "--redis-port",
            "16379",
            "--postgres-tls",
            "--with-listen",
        ]
    )
    assert args.command == COMMAND_EXPORTERS
    assert args.exporters_action == "trigger"
    assert args.redis_port == 16379
    assert args.postgres_tls is True


def test_exporters_scan_flags_are_parsed() -> None:
    args = parse_args(["exporters", "scan", "-t", "10.0.0.1", "-p", "9100,9115"])
    assert args.command == COMMAND_EXPORTERS
    assert args.exporters_action == "scan"
    assert args.targets == "10.0.0.1"
    assert args.ports == "9100,9115"


def test_trigger_listener_defaults_have_tls_enabled() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2"])
    assert args.postgres_tls is True
    assert args.proxmox_tls is True


def test_scan_flags_are_parsed() -> None:
    args = parse_args(
        [
            "exporters",
            "scan",
            "-t",
            "10.0.0.1,10.0.0.2",
            "--timeout",
            "1.5",
            "-w",
            "12",
            "-r",
            "3",
            "--profiles-file",
            "profiles.json",
            "-f",
            "json",
            "-o",
            "scan.jsonl",
            "-p",
            "9100,9115,9200-9202",
        ]
    )
    assert args.command == COMMAND_EXPORTERS
    assert args.exporters_action == "scan"
    assert args.targets == "10.0.0.1,10.0.0.2"
    assert args.timeout == 1.5
    assert args.workers == 12
    assert args.retries == 3
    assert args.profiles_file == "profiles.json"
    assert args.output_format == "json"
    assert args.output == "scan.jsonl"
    assert args.ports == "9100,9115,9200-9202"


def test_scan_save_alias_is_parsed() -> None:
    args = parse_args(["exporters", "scan", "-t", "10.0.0.1", "--save", "scan.txt"])
    assert args.output == "scan.txt"


def test_log_flag_is_parsed_for_scan() -> None:
    args = parse_args(["exporters", "scan", "-t", "10.0.0.1", "-log", "scan.log"])
    assert args.log == "scan.log"


def test_log_flag_is_parsed_for_implicit_listen() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["-log", "listen.log"])
    assert exc.value.code == 2


def test_listen_rejects_old_selfcert_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["listen", "-selfcert"])
    assert exc.value.code == 2


def test_trigger_rejects_old_selfcert_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "-selfcert"])
    assert exc.value.code == 2


def test_scan_workers_and_retries_defaults() -> None:
    args = parse_args(["exporters", "scan", "-t", "10.0.0.1"])
    assert args.workers == 10
    assert args.retries == 3


def test_trigger_can_parse_without_callback_values() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1"])
    assert args.command == COMMAND_EXPORTERS
    assert args.exporters_action == "trigger"
    assert args.callback_ip is None
    assert args.callback_dns is None


def test_trigger_with_listen_flag_and_listener_defaults() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "--with-listen"])
    assert args.with_listen is True
    assert args.callback_ip == "10.0.0.2"
    assert args.callback_dns is None
    assert args.services == "postgres,redis,proxmox,blackbox"
    assert args.bind == "0.0.0.0"
    assert args.postgres_port == 5432
    assert args.redis_port == 6379
    assert args.proxmox_port == 8006
    assert args.blackbox_port == 9115
    assert args.postgres_tls is True
    assert args.proxmox_tls is True


def test_trigger_workers_and_retries_flags_are_parsed() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "-w", "20", "-r", "2"])
    assert args.workers == 20
    assert args.retries == 2


def test_trigger_output_flag_is_parsed() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "-o", "trigger.txt"])
    assert args.output == "trigger.txt"


def test_trigger_save_alias_is_parsed() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "--save", "trigger.txt"])
    assert args.output == "trigger.txt"


def test_trigger_with_optional_callback_dns_flag() -> None:
    args = parse_args(
        [
            "exporters",
            "trigger",
            "-t",
            "10.0.0.1",
            "--callback-ip",
            "10.0.0.2",
            "--callback-dns",
            "redposture.example.com",
        ]
    )
    assert args.callback_ip == "10.0.0.2"
    assert args.callback_dns == "redposture.example.com"


def test_redis_flags_are_parsed() -> None:
    args = parse_args(
        [
            "redis",
            "-t",
            "10.0.0.7,10.0.0.8",
            "--timeout",
            "0.8",
            "-w",
            "8",
            "-r",
            "1",
            "--port",
            "6380",
            "--ports",
            "6379,6380,16379",
            "--username",
            "redis",
            "--password",
            "redis",
            "--defcreds",
            "--show-keys",
            "--dump",
            "-key",
            "session:admin",
            "-f",
            "json",
            "-o",
            "redis_audit.jsonl",
        ]
    )
    assert args.command == "redis"
    assert args.targets == "10.0.0.7,10.0.0.8"
    assert args.timeout == 0.8
    assert args.workers == 8
    assert args.retries == 1
    assert args.port == 6380
    assert args.ports == "6379,6380,16379"
    assert args.username == "redis"
    assert args.password == "redis"
    assert args.defcreds is True
    assert args.show_keys is True
    assert args.dump is True
    assert args.key == "session:admin"
    assert args.output_format == "json"
    assert args.output == "redis_audit.jsonl"


def test_redis_short_user_password_flags_are_parsed() -> None:
    args = parse_args(["redis", "-t", "10.0.0.7", "-u", "redis", "-p", "redis"])
    assert args.command == "redis"
    assert args.username == "redis"
    assert args.password == "redis"
    assert args.defcreds is False


def test_redis_key_flag_is_parsed() -> None:
    args = parse_args(["redis", "-t", "10.0.0.7", "-key", "app:token"])
    assert args.command == "redis"
    assert args.key == "app:token"


def test_redis_dump_keys_flag_is_parsed() -> None:
    args = parse_args(["redis", "-t", "10.0.0.7", "--dump"])
    assert args.command == "redis"
    assert args.dump is True


def test_redis_dump_keys_legacy_alias_is_parsed() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["redis", "-t", "10.0.0.7", "--dump-keys"])
    assert exc.value.code == 2


def test_redis_defcreds_flag_is_parsed() -> None:
    args = parse_args(["redis", "-t", "10.0.0.7", "--defcreds"])
    assert args.command == "redis"
    assert args.defcreds is True


def test_etcd_flags_are_parsed() -> None:
    args = parse_args(
        [
            "etcd",
            "-t",
            "10.0.0.9,10.0.0.10",
            "--timeout",
            "0.8",
            "-w",
            "8",
            "-r",
            "1",
            "--port",
            "22379",
            "--ports",
            "2379,22379",
            "--show-keys",
            "--dump",
            "-key",
            "/redposture/env",
            "-f",
            "json",
            "-o",
            "etcd_audit.jsonl",
        ]
    )
    assert args.command == "etcd"
    assert args.targets == "10.0.0.9,10.0.0.10"
    assert args.timeout == 0.8
    assert args.workers == 8
    assert args.retries == 1
    assert args.port == 22379
    assert args.ports == "2379,22379"
    assert args.show_keys is True
    assert args.dump is True
    assert args.key == "/redposture/env"
    assert args.output_format == "json"
    assert args.output == "etcd_audit.jsonl"


def test_etcd_dump_keys_flag_is_parsed() -> None:
    args = parse_args(["etcd", "-t", "10.0.0.9", "--dump"])
    assert args.command == "etcd"
    assert args.dump is True


def test_etcd_dump_keys_legacy_alias_is_parsed() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["etcd", "-t", "10.0.0.9", "--dump-keys"])
    assert exc.value.code == 2


def test_etcd_show_keys_flag_is_parsed() -> None:
    args = parse_args(["etcd", "-t", "10.0.0.9", "--show-keys"])
    assert args.command == "etcd"
    assert args.show_keys is True
    assert args.dump is False


def test_registry_flags_are_parsed() -> None:
    args = parse_args(
        [
            "registry",
            "-t",
            "10.0.0.41,10.0.0.42",
            "--timeout",
            "0.9",
            "-w",
            "6",
            "-r",
            "2",
            "--port",
            "5001",
            "--ports",
            "5000,5001,15000-15001",
            "-u",
            "robot$ci",
            "-p",
            "secret",
            "--images",
            "--repository",
            "gitlab/project-api",
            "--show-tags",
            "--tag",
            "latest",
            "--metadata",
            "--harbor",
            "--gitlab",
            "--nexus",
            "--assets",
            "--inspect",
            "--image",
            "library/nginx:latest",
            "--download",
            "--download-dir",
            "./dl",
            "-f",
            "json",
            "-o",
            "registry_audit.jsonl",
        ]
    )
    assert args.command == "registry"
    assert args.targets == "10.0.0.41,10.0.0.42"
    assert args.timeout == 0.9
    assert args.workers == 6
    assert args.retries == 2
    assert args.port == 5001
    assert args.ports == "5000,5001,15000-15001"
    assert args.username == "robot$ci"
    assert args.password == "secret"
    assert args.images is True
    assert args.repository == "gitlab/project-api"
    assert args.show_tags is True
    assert args.tag == "latest"
    assert args.metadata is True
    assert args.harbor is True
    assert args.gitlab is True
    assert args.nexus is True
    assert args.assets is True
    assert args.inspect is True
    assert args.image == "library/nginx:latest"
    assert args.download is True
    assert args.download_dir == "./dl"
    assert args.token is None
    assert args.output_format == "json"
    assert args.output == "registry_audit.jsonl"


def test_registry_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["registry", "-t", "10.0.0.9", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_registry_token_flag_is_parsed() -> None:
    args = parse_args(["registry", "-t", "10.0.0.9", "--token", "token-value"])
    assert args.command == "registry"
    assert args.token == "token-value"
    assert args.gitlab is False
    assert args.nexus is False
    assert args.show_tags is False
    assert args.metadata is False
    assert args.assets is False


def test_registry_port_list_in_port_flag_is_normalized() -> None:
    args = parse_args(["registry", "-t", "10.0.0.9", "--port", "15000,15002"])
    assert args.command == "registry"
    assert args.port == 15000
    assert args.ports == "15000,15002"


def test_registry_port_file_in_port_flag_is_normalized(tmp_path) -> None:
    ports_file = tmp_path / "ports.txt"
    ports_file.write_text("15000\n15002\n", encoding="utf-8")
    args = parse_args(["registry", "-t", "10.0.0.9", "--port", str(ports_file)])
    assert args.command == "registry"
    assert args.port == 5000
    assert args.ports == str(ports_file)


def test_kafka_flags_are_parsed() -> None:
    args = parse_args(
        [
            "kafka",
            "-t",
            "10.0.0.21,10.0.0.22",
            "--timeout",
            "0.8",
            "-w",
            "8",
            "-r",
            "1",
            "--port",
            "19092",
            "--ports",
            "9092,19092,29092",
            "-u",
            "metrics",
            "-p",
            "secret",
            "--show-topics",
            "--topic",
            "orders",
            "--dump",
            "--max-messages",
            "5000",
            "-f",
            "json",
            "-o",
            "kafka_audit.jsonl",
        ]
    )
    assert args.command == "kafka"
    assert args.targets == "10.0.0.21,10.0.0.22"
    assert args.timeout == 0.8
    assert args.workers == 8
    assert args.retries == 1
    assert args.port == 19092
    assert args.ports == "9092,19092,29092"
    assert args.username == "metrics"
    assert args.password == "secret"
    assert args.show_topics is True
    assert args.topic == "orders"
    assert args.dump is True
    assert args.max_messages == 5000
    assert args.output_format == "json"
    assert args.output == "kafka_audit.jsonl"


def test_kafka_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["kafka", "-t", "10.0.0.9", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_kafka_dump_without_topic_is_parsed() -> None:
    args = parse_args(["kafka", "-t", "10.0.0.9", "--dump"])
    assert args.command == "kafka"
    assert args.dump is True
    assert args.topic is None


def test_zookeeper_flags_are_parsed() -> None:
    args = parse_args(
        [
            "zookeeper",
            "-t",
            "10.0.0.31,10.0.0.32",
            "--timeout",
            "0.9",
            "-w",
            "6",
            "-r",
            "2",
            "--port",
            "22181",
            "--ports",
            "2181,22181",
            "--show-znodes",
            "--dump",
            "-znode",
            "/brokers/ids/1",
            "--max-znodes",
            "500",
            "-f",
            "json",
            "-o",
            "zookeeper_audit.jsonl",
        ]
    )
    assert args.command == "zookeeper"
    assert args.targets == "10.0.0.31,10.0.0.32"
    assert args.timeout == 0.9
    assert args.workers == 6
    assert args.retries == 2
    assert args.port == 22181
    assert args.ports == "2181,22181"
    assert args.show_znodes is True
    assert args.dump is True
    assert args.znode == "/brokers/ids/1"
    assert args.max_znodes == 500
    assert args.output_format == "json"
    assert args.output == "zookeeper_audit.jsonl"


def test_zookeeper_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["zookeeper", "-t", "10.0.0.9", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_zookeeper_dump_legacy_alias_is_parsed() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["zookeeper", "-t", "10.0.0.9", "--dump-znodes"])
    assert exc.value.code == 2


def test_grafana_flags_are_parsed() -> None:
    args = parse_args(
        [
            "grafana",
            "-t",
            "10.0.0.11,10.0.0.12",
            "--timeout",
            "0.9",
            "-w",
            "6",
            "-r",
            "2",
            "--port",
            "3001",
            "--ports",
            "3000,3001",
            "-u",
            "admin",
            "-p",
            "secret",
            "--defcreds",
            "--show-datasources",
            "--ssrf-target",
            "http://127.0.0.1/probe",
            "--ssrf-port",
            "8081",
            "--ssrf-path",
            "/debug/vars?x=1",
            "-f",
            "json",
            "-o",
            "grafana_audit.jsonl",
        ]
    )
    assert args.command == "grafana"
    assert args.targets == "10.0.0.11,10.0.0.12"
    assert args.timeout == 0.9
    assert args.workers == 6
    assert args.retries == 2
    assert args.port == 3001
    assert args.ports == "3000,3001"
    assert args.username == "admin"
    assert args.password == "secret"
    assert args.defcreds is True
    assert args.show_datasources is True
    assert args.ssrf_target == "http://127.0.0.1/probe"
    assert args.ssrf_port == "8081"
    assert args.ssrf_path == "/debug/vars?x=1"
    assert args.output_format == "json"
    assert args.output == "grafana_audit.jsonl"


def test_grafana_show_datasource_alias_is_parsed() -> None:
    args = parse_args(["grafana", "-t", "10.0.0.11", "--show-datasource"])
    assert args.command == "grafana"
    assert args.show_datasources is True


def test_grafana_temp_check_flags_are_parsed() -> None:
    args = parse_args(
        ["grafana", "-t", "10.0.0.11", "--ssrf-target", "example.com/path", "--ssrf-port", "8080", "--ssrf-path", "/x"]
    )
    assert args.command == "grafana"
    assert args.ssrf_target == "example.com/path"
    assert args.ssrf_port == "8080"
    assert args.ssrf_path == "/x"


def test_grafana_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["grafana", "-t", "10.0.0.11", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_etcd_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["etcd", "-t", "10.0.0.9", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_collect_save_responses_flag_is_parsed() -> None:
    args = parse_args(["exporters", "collect", "-t", "10.0.0.1", "--save-responses-dir", "collect_raw"])
    assert args.save_responses_dir == "collect_raw"


def test_redis_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["redis", "-t", "10.0.0.7", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_redis_rejects_removed_fetch_keys_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["redis", "-t", "10.0.0.7", "--fetch-keys"])
    assert exc.value.code == 2


def test_postgres_flags_are_parsed() -> None:
    args = parse_args(
        [
            "postgres",
            "-t",
            "10.0.0.7,10.0.0.8",
            "--timeout",
            "0.8",
            "-w",
            "8",
            "-r",
            "1",
            "--port",
            "5433",
            "--ports",
            "5432,5433,15432",
            "--database",
            "appdb",
            "--username",
            "postgres",
            "--password",
            "postgres",
            "--defcreds",
            "--show-databases",
            "--show-tables",
            "--show-columns",
            "--os-shell",
            "--table",
            "public.users",
            "--dump",
            "--table",
            "redposture.demo_accounts,public.audit_log",
            "--column",
            "id,username",
            "--column",
            "created_at",
            "--execute",
            "id",
            "-f",
            "json",
            "-o",
            "postgres_audit.jsonl",
        ]
    )
    assert args.command == "postgres"
    assert args.targets == "10.0.0.7,10.0.0.8"
    assert args.timeout == 0.8
    assert args.workers == 8
    assert args.retries == 1
    assert args.port == 5433
    assert args.ports == "5432,5433,15432"
    assert args.database == "appdb"
    assert args.username == "postgres"
    assert args.password == "postgres"
    assert args.defcreds is True
    assert args.show_databases is True
    assert args.show_tables is True
    assert args.show_columns is True
    assert args.os_shell is True
    assert args.tables == ["public.users", "redposture.demo_accounts,public.audit_log"]
    assert args.dump is True
    assert args.columns == ["id,username", "created_at"]
    assert args.execute == "id"
    assert args.output_format == "json"
    assert args.output == "postgres_audit.jsonl"


def test_postgres_short_user_password_flags_are_parsed() -> None:
    args = parse_args(
        [
            "postgres",
            "-t",
            "10.0.0.7",
            "-u",
            "postgres",
            "-p",
            "postgres",
            "-d",
            "appdb",
            "--table",
            "public.users",
            "-x",
            "whoami",
        ]
    )
    assert args.command == "postgres"
    assert args.username == "postgres"
    assert args.password == "postgres"
    assert args.database == "appdb"
    assert args.defcreds is False
    assert args.show_databases is False
    assert args.show_tables is False
    assert args.show_columns is False
    assert args.os_shell is False
    assert args.tables == ["public.users"]
    assert args.dump is False
    assert args.columns is None
    assert args.execute == "whoami"


def test_postgres_columns_alias_is_parsed() -> None:
    args = parse_args(["postgres", "-t", "10.0.0.7", "--table", "public.users", "--columns", "id"])
    assert args.command == "postgres"
    assert args.tables == ["public.users"]
    assert args.columns == ["id"]


def test_postgres_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["postgres", "-t", "10.0.0.7", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_postgres_defcreds_flag_is_parsed() -> None:
    args = parse_args(["postgres", "-t", "10.0.0.7", "--defcreds"])
    assert args.command == "postgres"
    assert args.defcreds is True


def test_postgres_debug_flag_is_long_only() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["postgres", "-t", "10.0.0.7", "-d"])
    assert exc.value.code == 2

    args = parse_args(["postgres", "-t", "10.0.0.7", "--debug"])
    assert args.debug is True


def test_version_flag_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["--version"])
    assert exc.value.code == 0


def test_selfcert_command_defaults_are_parsed() -> None:
    args = parse_args(["--selfcert"])
    assert args.command == COMMAND_SELFCERT
    assert args.cert_out == "cert.pem"
    assert args.key_out == "key.pem"
    assert args.force is False
    assert args.log is None


def test_selfcert_log_flag_is_parsed() -> None:
    args = parse_args(["--selfcert", "-log", "selfcert.log"])
    assert args.command == COMMAND_SELFCERT
    assert args.log == "selfcert.log"


def test_global_selfcert_alias_is_parsed() -> None:
    args = parse_args(["--selfcert", "--cert-out", "tls/cert.pem", "--key-out", "tls/key.pem", "--force"])
    assert args.command == COMMAND_SELFCERT
    assert args.cert_out == "tls/cert.pem"
    assert args.key_out == "tls/key.pem"
    assert args.force is True


def test_legacy_short_selfcert_alias_is_parsed() -> None:
    args = parse_args(["-selfcert"])
    assert args.command == COMMAND_SELFCERT


def test_selfcert_subcommand_is_not_supported() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args([COMMAND_SELFCERT])
    assert exc.value.code == 2


def test_collect_deep_flags_are_parsed() -> None:
    args = parse_args(
        ["exporters", "collect", "-t", "10.0.0.1", "--deep", "--pprof-seconds", "9", "--trace-seconds", "3"]
    )
    assert args.deep is True
    assert args.pprof_seconds == 9
    assert args.trace_seconds == 3


def test_collect_validation_flags_removed_from_collect() -> None:
    args = parse_args(["exporters", "collect", "-t", "10.0.0.1"])
    assert args.deep is False
    assert args.pprof_seconds == 5
    assert args.trace_seconds == 2
    assert not hasattr(args, "validate")
    assert not hasattr(args, "validate_show")
    assert not hasattr(args, "validate_max_lines")
    assert not hasattr(args, "validate_fail_on_creds")


def test_collect_rejects_removed_validate_flags() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["exporters", "collect", "-t", "10.0.0.1", "--validate"])
    assert exc.value.code == 2


def test_direct_scan_trigger_collect_are_rejected() -> None:
    for argv in (
        ["scan", "-t", "10.0.0.1"],
        ["trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2"],
        ["collect", "-t", "10.0.0.1"],
    ):
        with pytest.raises(SystemExit) as exc:
            parse_args(argv)
        assert exc.value.code == 2
