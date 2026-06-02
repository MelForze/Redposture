"""Static constants used across RedPosture modules."""

POSTGRES_SSL_REQUEST_CODE = 80877103
POSTGRES_AUTH_CLEAR_TEXT = 3

BLACKBOX_DEFAULT_MODULE = "http_2xx"
BLACKBOX_COMPAT_MODULES = {
    "http_2xx",
    "http_post_2xx",
    "tcp_connect",
    "icmp",
    "ssh_banner",
    "dns",
}

SUPPORTED_SERVICES = {"postgres", "redis", "proxmox", "blackbox"}

SCAN_EXPORTERS = (
    {
        "name": "redis_exporter",
        "port": 9121,
        "detect_path": "/metrics",
        "markers": ("redis_exporter_build_info", "redis_up"),
        "trigger_path": "/scrape",
        "target_fmt": "{our_host}:6379",
    },
    {
        "name": "postgres_exporter",
        "port": 9187,
        "detect_path": "/metrics",
        "markers": ("postgres_exporter_build_info", "pg_up"),
        "trigger_path": "/probe",
        "target_fmt": "{our_host}:5432",
    },
    {
        "name": "blackbox_exporter",
        "port": 9115,
        "detect_path": "/metrics",
        "markers": ("blackbox_exporter_build_info",),
        "trigger_path": "/probe",
        "target_fmt": "http://{our_host}",
    },
    {
        "name": "proxmox_exporter",
        "port": 9221,
        "detect_path": "/metrics",
        "markers": ("proxmox_", "pve_"),
        "trigger_path": "/pve",
        "target_fmt": "{our_host}:8006",
    },
)

DISCOVERY_EXPORTERS = (
    {
        "name": "nats_exporter",
        "port": 7777,
        "markers": ("nats_exporter_build_info", "nats_up"),
        "strong_markers": ("nats_exporter_build_info", "nats_up"),
        "weak_markers": ("nats_", "gnatsd_"),
        "fingerprint_vars": ("nats", "nats://", "nats_password", "nats_username"),
        "fingerprint_cmdline": ("nats_exporter", "--nats.url=", "--nats.user=", "--nats.password="),
    },
    {
        "name": "statsd_exporter",
        "port": 9102,
        "markers": ("statsd_exporter_build_info", "statsd_exporter_lines_total"),
        "strong_markers": ("statsd_exporter_build_info", "statsd_exporter_lines_total"),
        "weak_markers": ("statsd_exporter_", "statsd_"),
        "fingerprint_vars": ("statsd", "mapping_config", "listen_udp"),
        "fingerprint_cmdline": ("statsd_exporter", "--statsd.listen-udp=", "--statsd.mapping-config="),
    },
    {
        "name": "mysqld_exporter",
        "port": 9104,
        "markers": ("mysqld_exporter_build_info", "mysql_up"),
        "strong_markers": ("mysqld_exporter_build_info", "mysql_up"),
        "weak_markers": ("mysql_", "mysqld_"),
        "negative_markers": ("postgres_exporter_build_info",),
        "fingerprint_vars": ("mysql", "data_source_name", "mysql_password", "mysql_username"),
        "fingerprint_cmdline": ("mysqld_exporter", "--mysqld.username=", "--mysqld.password="),
    },
    {
        "name": "blackbox_exporter",
        "port": 9115,
        "markers": ("blackbox_exporter_build_info", "blackbox_exporter_scrapes_total"),
        "strong_markers": ("blackbox_exporter_build_info", "blackbox_exporter_scrapes_total"),
        "weak_markers": ("blackbox_exporter_", "probe_duration_seconds", "probe_success"),
        "fingerprint_vars": ("blackbox", "modules", "prober", "blackbox_password", "blackbox_username"),
        "fingerprint_cmdline": ("blackbox_exporter", "--config.file=", "--web.config.file="),
    },
    {
        "name": "elasticsearch_exporter",
        "port": 9114,
        "markers": ("elasticsearch_exporter_build_info", "elasticsearch_cluster_health_status"),
        "strong_markers": ("elasticsearch_exporter_build_info", "elasticsearch_cluster_health_status"),
        "weak_markers": ("elasticsearch_", "es_"),
        "fingerprint_vars": ("elasticsearch", "api_key", "es.internal"),
        "fingerprint_cmdline": ("elasticsearch_exporter", "--es.uri=", "--es.api-key="),
    },
    {
        "name": "nginx_exporter",
        "port": 9113,
        "markers": ("nginx_exporter_build_info", "nginx_connections_active"),
        "strong_markers": ("nginx_exporter_build_info", "nginx_connections_active"),
        "weak_markers": ("nginx_",),
        "fingerprint_vars": ("nginx", "scrape_uri", "nginx_password", "nginx_username"),
        "fingerprint_cmdline": ("nginx_exporter", "--nginx.scrape-uri=", "--nginx.ssl-verify="),
    },
    {
        "name": "haproxy_exporter",
        "port": 9101,
        "markers": ("haproxy_exporter_build_info", "haproxy_up"),
        "strong_markers": ("haproxy_exporter_build_info", "haproxy_up"),
        "weak_markers": ("haproxy_",),
        "negative_markers": ("node_exporter_build_info", "node_uname_info"),
        "fingerprint_vars": ("haproxy", "stats_uri", "haproxy_password", "haproxy_username"),
        "fingerprint_cmdline": ("haproxy_exporter", "--haproxy.scrape-uri=", "--haproxy.user=", "--haproxy.pass="),
    },
    {
        "name": "kafka_exporter",
        "port": 9308,
        "markers": ("kafka_brokers", "kafka_exporter_build_info"),
        "strong_markers": ("kafka_brokers", "kafka_exporter_build_info"),
        "weak_markers": ("kafka_", "kafka_topic_", "kafka_consumergroup_"),
        "fingerprint_vars": ("kafka", "brokers", "sasl", "kafka_username", "kafka_password"),
        "fingerprint_cmdline": ("kafka_exporter", "--kafka.server=", "--sasl.enabled", "--sasl.username="),
    },
    {
        "name": "node_exporter",
        "port": 9100,
        "markers": (
            "node_exporter_build_info",
            "node_uname_info",
            "node_cpu_seconds_total",
            "node_boot_time_seconds",
        ),
        "strong_markers": (
            "node_exporter_build_info",
            "node_uname_info",
            "node_cpu_seconds_total",
            "node_boot_time_seconds",
        ),
        "weak_markers": (
            "node_filesystem_size_bytes",
            "node_filesystem_avail_bytes",
            "node_memory_MemAvailable_bytes",
            "node_memory_MemTotal_bytes",
            "node_network_receive_bytes_total",
            "node_network_transmit_bytes_total",
            "node_time_seconds",
            "node_load1",
            "node_context_switches_total",
            "node_scrape_collector_duration_seconds",
            "node_scrape_collector_success",
            "node_netstat_Tcp_CurrEstab",
            "node_",
        ),
        "negative_markers": ("haproxy_exporter_build_info", "haproxy_up", "haproxy_frontend_"),
        "fingerprint_vars": ("runtime_config", "node_exporter", "service_discovery", "node_filesystem", "node_cpu"),
        "fingerprint_cmdline": (
            "node_exporter",
            "--collector.",
            "--web.config.file=",
            "--path.rootfs=",
            "--path.procfs=",
        ),
    },
    {
        "name": "node_exporter",
        "port": 9101,
        "markers": (
            "node_exporter_build_info",
            "node_uname_info",
            "node_cpu_seconds_total",
            "node_boot_time_seconds",
        ),
        "strong_markers": (
            "node_exporter_build_info",
            "node_uname_info",
            "node_cpu_seconds_total",
            "node_boot_time_seconds",
        ),
        "weak_markers": (
            "node_filesystem_size_bytes",
            "node_filesystem_avail_bytes",
            "node_memory_MemAvailable_bytes",
            "node_memory_MemTotal_bytes",
            "node_network_receive_bytes_total",
            "node_network_transmit_bytes_total",
            "node_time_seconds",
            "node_load1",
            "node_context_switches_total",
            "node_scrape_collector_duration_seconds",
            "node_scrape_collector_success",
            "node_netstat_Tcp_CurrEstab",
            "node_",
        ),
        "negative_markers": ("haproxy_exporter_build_info", "haproxy_up", "haproxy_frontend_"),
        "fingerprint_vars": ("runtime_config", "node_exporter", "service_discovery", "node_filesystem", "node_cpu"),
        "fingerprint_cmdline": (
            "node_exporter",
            "--collector.",
            "--web.config.file=",
            "--path.rootfs=",
            "--path.procfs=",
        ),
    },
    {
        "name": "memcached_exporter",
        "port": 9150,
        "markers": ("memcached_exporter_build_info", "memcached_up"),
        "strong_markers": ("memcached_exporter_build_info", "memcached_up"),
        "weak_markers": ("memcached_",),
        "fingerprint_vars": ("memcached", "memcached_address", "memcached_password", "memcached_username"),
        "fingerprint_cmdline": ("memcached_exporter", "--memcached.address=", "--memcached.username="),
    },
    {
        "name": "postgres_exporter",
        "port": 9187,
        "markers": ("postgres_exporter_build_info", "pg_up"),
        "strong_markers": ("postgres_exporter_build_info", "pg_up"),
        "weak_markers": ("pg_stat_", "pg_database_", "pg_postmaster_", "postgres_"),
        "fingerprint_vars": ("postgres", "data_source_name", "datasource", "postgres_password", "postgres_username"),
        "fingerprint_cmdline": ("postgres_exporter", "DATA_SOURCE_NAME", "--collector.", "--web.config.file="),
    },
    {
        "name": "redis_exporter",
        "port": 9121,
        "markers": ("redis_exporter_build_info", "redis_up"),
        "strong_markers": ("redis_exporter_build_info", "redis_up"),
        "weak_markers": ("redis_memory_", "redis_connected_", "redis_keyspace_", "redis_commands_"),
        "fingerprint_vars": ("redis", "redis.addr", "redis_password", "redis_username", "tile38"),
        "fingerprint_cmdline": ("redis_exporter", "--redis.addr=", "--redis.password=", "--namespace="),
    },
    {
        "name": "clickhouse_exporter",
        "port": 9116,
        "markers": ("clickhouse_",),
        "strong_markers": ("clickhouse_exporter_build_info", "clickhouse_up"),
        "weak_markers": ("clickhouse_",),
        "fingerprint_vars": ("clickhouse", "scrape_uri", "clickhouse_password", "clickhouse_username"),
        "fingerprint_cmdline": ("clickhouse_exporter", "--clickhouse.url=", "--scrape.uri="),
    },
    {
        "name": "snmp_exporter",
        "port": 9117,
        "markers": ("snmp_exporter_build_info", "snmp_scrape_duration_seconds"),
        "strong_markers": ("snmp_exporter_build_info", "snmp_scrape_duration_seconds"),
        "weak_markers": ("snmp_",),
        "negative_markers": ("apache_exporter_build_info", "apache_up"),
        "fingerprint_vars": ("snmp", "auth_password", "priv_password", "snmp_metrics"),
        "fingerprint_cmdline": ("snmp_exporter", "--snmp.module=", "--snmp.auth-password="),
    },
    {
        "name": "apache_exporter",
        "port": 9117,
        "markers": ("apache_exporter_build_info", "apache_up"),
        "strong_markers": ("apache_exporter_build_info", "apache_up"),
        "weak_markers": ("apache_",),
        "negative_markers": ("snmp_exporter_build_info", "snmp_scrape_duration_seconds"),
        "fingerprint_vars": ("apache", "scrape_uri", "apache_password", "apache_username"),
        "fingerprint_cmdline": ("apache_exporter", "--apache.scrape_uri=", "--apache.user=", "--apache.password="),
    },
    {
        "name": "bind_exporter",
        "port": 9119,
        "markers": ("bind_exporter_build_info", "bind_up"),
        "strong_markers": ("bind_exporter_build_info", "bind_up"),
        "weak_markers": ("bind_",),
        "fingerprint_vars": ("bind", "named", "rndc_key", "bind_password"),
        "fingerprint_cmdline": ("bind_exporter", "--bind.stats-url=", "--bind.rndc-key="),
    },
    {
        "name": "mongodb_exporter",
        "port": 9216,
        "markers": ("mongodb_",),
        "strong_markers": ("mongodb_exporter_build_info", "mongodb_up"),
        "weak_markers": ("mongodb_",),
        "fingerprint_vars": ("mongodb", "mongodb_uri", "mongodb_password", "mongodb_username"),
        "fingerprint_cmdline": ("mongodb_exporter", "--mongodb.uri=", "--mongodb.user=", "--mongodb.password="),
    },
    {
        "name": "pgbouncer_exporter",
        "port": 9127,
        "markers": ("pgbouncer_",),
        "strong_markers": ("pgbouncer_up",),
        "weak_markers": ("pgbouncer_",),
        "fingerprint_vars": ("pgbouncer", "pgbouncer_uri", "pgbouncer_password", "pgbouncer_username"),
        "fingerprint_cmdline": ("pgbouncer_exporter", "--pgBouncer.connectionString=", "--web.config.file="),
    },
    {
        "name": "ceph_exporter",
        "port": 9128,
        "markers": ("ceph_exporter_build_info", "ceph_health_status"),
        "strong_markers": ("ceph_exporter_build_info", "ceph_health_status"),
        "weak_markers": ("ceph_",),
        "fingerprint_vars": ("ceph", "rados", "ceph_username", "ceph_password"),
        "fingerprint_cmdline": ("ceph_exporter", "--ceph.config=", "--ceph.user=", "--ceph.password="),
    },
    {
        "name": "varnish_exporter",
        "port": 9131,
        "markers": ("varnish_exporter_build_info", "varnish_up"),
        "strong_markers": ("varnish_exporter_build_info", "varnish_up"),
        "weak_markers": ("varnish_",),
        "fingerprint_vars": ("varnish", "varnishadm", "varnish_secret"),
        "fingerprint_cmdline": ("varnish_exporter", "--varnish.uri=", "--varnish.secret-file="),
    },
    {
        "name": "windows_exporter",
        "port": 9182,
        "markers": ("windows_exporter_build_info", "windows_cs_hostname"),
        "strong_markers": ("windows_exporter_build_info", "windows_cs_hostname"),
        "weak_markers": ("windows_",),
        "fingerprint_vars": ("windows_exporter", "collectors", "windows_password", "windows_username"),
        "fingerprint_cmdline": ("windows_exporter", "--collectors.enabled=", "--web.config.file="),
    },
    {
        "name": "gobgp_exporter",
        "port": 9349,
        "markers": ("gobgp_",),
        "strong_markers": ("gobgp_peer_session_up",),
        "weak_markers": ("gobgp_",),
        "fingerprint_vars": ("gobgp", "bgp", "router_id"),
        "fingerprint_cmdline": ("gobgp_exporter", "--gobgp.addr=", "--gobgp.password="),
    },
    {
        "name": "frr_exporter",
        "port": 9342,
        "markers": ("frr_",),
        "strong_markers": ("frr_bgp_peer_up", "frr_exporter_build_info"),
        "weak_markers": ("frr_",),
        "fingerprint_vars": ("frr", "vtysh", "bgpd"),
        "fingerprint_cmdline": ("frr_exporter", "--frr.socket=", "--frr.password="),
    },
    {
        "name": "named_process_exporter",
        "port": 9256,
        "markers": ("namedprocess_",),
        "strong_markers": ("namedprocess_namegroup_num_procs",),
        "weak_markers": ("namedprocess_",),
        "fingerprint_vars": ("named_process", "process_names", "cmdline_re"),
        "fingerprint_cmdline": ("named_process_exporter", "--config.path=", "--procfs="),
    },
    {
        "name": "ping_exporter",
        "port": 9427,
        "markers": ("ping_",),
        "strong_markers": ("ping_exporter_build_info", "ping_loss_ratio"),
        "weak_markers": ("ping_",),
        "fingerprint_vars": ("ping", "targets", "icmp"),
        "fingerprint_cmdline": ("ping_exporter", "--config.file=", "--ping.timeout="),
    },
    {
        "name": "rabbitmq_exporter",
        "port": 9419,
        "markers": ("rabbitmq_exporter_build_info", "rabbitmq_up"),
        "strong_markers": ("rabbitmq_exporter_build_info", "rabbitmq_up"),
        "weak_markers": ("rabbitmq_",),
        "fingerprint_vars": ("rabbitmq", "amqp", "rabbitmq_password", "rabbitmq_username"),
        "fingerprint_cmdline": ("rabbitmq_exporter", "--rabbit.url=", "--rabbit.user=", "--rabbit.password="),
    },
    {
        "name": "ipmi_exporter",
        "port": 9290,
        "markers": ("ipmi_exporter_build_info", "ipmi_scrape_duration_seconds"),
        "strong_markers": ("ipmi_exporter_build_info", "ipmi_scrape_duration_seconds"),
        "weak_markers": ("ipmi_",),
        "fingerprint_vars": ("ipmi", "bmc", "ipmi_password", "ipmi_username"),
        "fingerprint_cmdline": ("ipmi_exporter", "--config.file=", "--ipmi.username=", "--ipmi.password="),
    },
    {
        "name": "sql_exporter",
        "port": 9399,
        "markers": ("sql_exporter_build_info", "sql_exporter_scrape_duration_seconds"),
        "strong_markers": ("sql_exporter_build_info", "sql_exporter_scrape_duration_seconds"),
        "weak_markers": ("sql_exporter_", "sql_"),
        "fingerprint_vars": ("sql", "target_dsn", "query_config", "sql_password", "sql_username"),
        "fingerprint_cmdline": ("sql_exporter", "--config.file=", "--target.dsn="),
    },
    {
        "name": "pgbackrest_exporter",
        "port": 9854,
        "markers": ("pgbackrest_exporter_build_info", "pgbackrest_info"),
        "strong_markers": ("pgbackrest_exporter_build_info", "pgbackrest_info"),
        "weak_markers": ("pgbackrest_", "pgbackrest_exporter_"),
        "fingerprint_vars": ("pgbackrest", "stanza", "repo", "postgresql"),
        "fingerprint_cmdline": ("pgbackrest_exporter", "--web.listen-address=", "--config.file="),
    },
    {
        "name": "victoriametrics_exporter",
        "port": 8428,
        "markers": ("vm_app_version", "vm_build_info"),
        "strong_markers": ("vm_app_version", "vm_build_info"),
        "weak_markers": ("vm_", "victoriametrics_"),
        "fingerprint_vars": ("victoriametrics", "vmagent", "vmalert", "vmstorage"),
        "fingerprint_cmdline": ("victoria-metrics", "victoriametrics", "vmagent", "vmalert"),
    },
    {
        "name": "victoriametrics_exporter",
        "port": 8429,
        "markers": ("vm_app_version", "vm_build_info"),
        "strong_markers": ("vm_app_version", "vm_build_info"),
        "weak_markers": ("vm_", "victoriametrics_"),
        "fingerprint_vars": ("victoriametrics", "vmagent", "vmalert", "vmstorage"),
        "fingerprint_cmdline": ("victoria-metrics", "victoriametrics", "vmagent", "vmalert"),
    },
    {
        "name": "proxmox_exporter",
        "port": 9221,
        "markers": ("proxmox_", "pve_"),
        "strong_markers": ("proxmox_up", "pve_up"),
        "weak_markers": ("proxmox_", "pve_"),
        "fingerprint_vars": ("proxmox", "pve", "token_name", "token_value", "verify_ssl"),
        "fingerprint_cmdline": ("proxmox_exporter", "--config.file=", "--pve.user=", "--pve.token-name="),
    },
)

COLLECT_EXPORTERS = (
    {"name": "nats_exporter", "port": 7777},
    {"name": "statsd_exporter", "port": 9102},
    {"name": "mysqld_exporter", "port": 9104},
    {"name": "blackbox_exporter", "port": 9115},
    {"name": "elasticsearch_exporter", "port": 9114},
    {"name": "nginx_exporter", "port": 9113},
    {"name": "haproxy_exporter", "port": 9101},
    {"name": "kafka_exporter", "port": 9308},
    {"name": "node_exporter", "port": 9100},
    {"name": "node_exporter", "port": 9101},
    {"name": "memcached_exporter", "port": 9150},
    {"name": "postgres_exporter", "port": 9187},
    {"name": "redis_exporter", "port": 9121},
    {"name": "clickhouse_exporter", "port": 9116},
    {"name": "snmp_exporter", "port": 9117},
    {"name": "apache_exporter", "port": 9117},
    {"name": "bind_exporter", "port": 9119},
    {"name": "mongodb_exporter", "port": 9216},
    {"name": "pgbouncer_exporter", "port": 9127},
    {"name": "ceph_exporter", "port": 9128},
    {"name": "varnish_exporter", "port": 9131},
    {"name": "windows_exporter", "port": 9182},
    {"name": "ipmi_exporter", "port": 9290},
    {"name": "gobgp_exporter", "port": 9349},
    {"name": "frr_exporter", "port": 9342},
    {"name": "named_process_exporter", "port": 9256},
    {"name": "sql_exporter", "port": 9399},
    {"name": "pgbackrest_exporter", "port": 9854},
    {"name": "victoriametrics_exporter", "port": 8428},
    {"name": "victoriametrics_exporter", "port": 8429},
    {"name": "ping_exporter", "port": 9427},
    {"name": "rabbitmq_exporter", "port": 9419},
    {"name": "proxmox_exporter", "port": 9221},
)

COLLECT_DEFAULT_ENDPOINTS = (
    "/debug/vars",
    "/debug/pprof/",
    "/debug/pprof/goroutine?debug=1",
    "/debug/pprof/cmdline?debug=1",
    "/debug/pprof/heap?debug=1",
    "/metrics",
)

COLLECT_DEEP_ENDPOINT_TEMPLATES = (
    "/debug/pprof/goroutine?debug=2",
    "/debug/pprof/heap",
    "/debug/pprof/allocs",
    "/debug/pprof/block",
    "/debug/pprof/mutex",
    "/debug/pprof/threadcreate",
    "/debug/pprof/profile?seconds={pprof_seconds}",
    "/debug/pprof/trace?seconds={trace_seconds}",
)

# Backward compatibility alias for profile defaults.
COLLECT_DEBUG_ENDPOINTS = COLLECT_DEFAULT_ENDPOINTS

HTTP_METHOD_PREFIXES = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"PATCH ",
    b"DELETE ",
    b"OPTIONS ",
    b"TRACE ",
    b"CONNECT ",
)

DEFAULT_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUDYgH0n3N8QYXMfeIDzbpCc5bXtQwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIcG9zdGdyZXMwHhcNMjYwMjE3MjA1OTI5WhcNMzYwMjE1
MjA1OTI5WjATMREwDwYDVQQDDAhwb3N0Z3JlczCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALNFh0Sgg1rRvZeLhe0edSbG7tyXE74F/TNegcBbojbKI9Mj
BVRNdbW5tsk6lQIeuY2loYN4E6uu/xdFLY5itRo6Y6mjVYB86J24yFD8+A1+Sy/0
TKmtBLp/7qWJNDN/RPwKcQkVj31WYBwfl2lH3WdssglUgIzFG2dTKAcKJ0i8r5Ow
uF8QuhWhZSvuvHG9zH4z/rxLFzoHb+iLjn1htcfacu3mp75YF33ClfmIo6B4t1T/
BpXlnFrQnp1kuaY5srcgsFVN8Is4pjC9RTyc7zapg0qvnZejtIhErVjRFBnC0sDl
my/lsJ+mGUeOrVK/Tg62o8ObSrR/ZJF+6lb6VxkCAwEAAaNTMFEwHQYDVR0OBBYE
FGzXPMd4P4BPAmf301tv5CBXrngaMB8GA1UdIwQYMBaAFGzXPMd4P4BPAmf301tv
5CBXrngaMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEoAAxsY
edf9e3e4x/0z8eQErg5K0pV8gYea890yCc6FXe/quWHfDnEi9cW/cGWFQie4eajW
OkW+CtWewykRzmfrKEcJZmrt2I62wRyX9l1dAkBBBeZ+yrySPQLYITNwQslwEwFK
vJzS/UnoxL7+/oN7Y3ZkL379sZNhzCEQMia3gyx1YpLz/qdL4rZHgglcGoWE3rMw
hkly5MTgmrssDjzg8IEgpt9n1/rYmk2KyFCwN67PpHr1tIRADzRIxgLVWn6XTEeX
vpYhpRVKkEg+687HaiA1qeTzL4UUMpa+PUHoHynryB57QWYbzsgTlKwC7yUV6Jyo
ua9cjNJehWQ081o=
-----END CERTIFICATE-----
"""

DEFAULT_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzRYdEoINa0b2X
i4XtHnUmxu7clxO+Bf0zXoHAW6I2yiPTIwVUTXW1ubbJOpUCHrmNpaGDeBOrrv8X
RS2OYrUaOmOpo1WAfOiduMhQ/PgNfksv9EyprQS6f+6liTQzf0T8CnEJFY99VmAc
H5dpR91nbLIJVICMxRtnUygHCidIvK+TsLhfELoVoWUr7rxxvcx+M/68Sxc6B2/o
i459YbXH2nLt5qe+WBd9wpX5iKOgeLdU/waV5Zxa0J6dZLmmObK3ILBVTfCLOKYw
vUU8nO82qYNKr52Xo7SIRK1Y0RQZwtLA5Zsv5bCfphlHjq1Sv04OtqPDm0q0f2SR
fupW+lcZAgMBAAECggEAEluXuiE6Rkf1Y2IKI0Gj00ZakjwFzWcZWkPuo0s26aeq
Qr4itvLuL39urn1ZYjPRgkXwa9E1aXa0gFZpD3w/6alKSKY1VKCl5PXVzIZVI/OX
gTgCDDuPoQYGAw1Ra0cYgjtS/zBGJvp8AdFB3On7LBLDSgWNWuz5zQtEzXC+nFnq
qaPruCO+/m66gn+J2OjQKx8J3wLIsXjU2WxLSYhx9T8sdHFYhQTi1MvN7GMWZD5d
npLPxxVkWnDtCxW9cXeoKBd7BGH9f3HdOzEuNbW20SHEd4PG4YD/kloxDC29VkMH
NANGMgubUnJyRFtWB9FTiJB1z6i1MCFZobMT9lDM4QKBgQD7wU9aKBkKXAChqqwk
edVBe9AFJVjeID5qKEmoqlR8LBM9R9RBtmTBfNwvr154jSsbkbuudcZNYMeRPMT3
g6D8QFR5kWUEJlgpcs3U/jdJTwNK8UEqvUPZJt/VrGTsO4CHu4tV3oeyg2FKA33v
f/UMuEa/bdgXAVc+zTbPnO6MIQKBgQC2S1iww6jPfSO+XtYuHcV0onmak5kGqs8l
mjiD9EISRK6S+Ohs7lgYAVLvPoZuj7qnJZJb6SEA7Xcbk6R9+a55kIuoaTpYUyT7
BVZ1jg/z8nhLNgv+eDYYGrvBnbJlQQSxqN/L3AsmcU3gF0EyDBcZuQsycDmttInE
N4pJIBqr+QKBgDOypKrs5Qd9kRuhwqvS4PoLhNIpszAaCvcdwtKB98tv+Ztx7qJ3
5ATfsQ+RwaKbyqhkqtfOk6Q8JX8rrX7uZtamFzLHqqjJfv0z+BSvB4dkVFbFaA5w
w0gKdZiZSDhCl8hHuPsvMUp1NDtQsEHIUvgDt3OECQXgXpwk5AaKQWpBAoGAf4Dd
7O09krsVmB7fMexS4syNv6eC/h3Uu5lN9EWRPRPbAyOj9iUTat7qMjqKbqSLSkPG
RhEeq3Zsu9Yd1JsiBRcsB8RqMcMd95F5MsoFsHwk1X5dD0TnmR6But/hGl9KuDTF
K+KhzeasMJQzXp0EP1KlWUcToMLJJXwvdgxFe4kCgYEAi8csZzKPTt3cyrMzv0cM
5zIPn8vZXI6mLOcgjYT+6DkQ3jpLzlKoikKFfCP6C/C8UNWJ780+/jaigyOr+5F6
aVRfBfSMV/qd3xJqC8QHdp7D5QDPLdVu3Bk7iHMFW+qt6/x4+nTrDjSHCxpfzK/8
e8U+LhLGsFmbcWVQPKBvm0U=
-----END PRIVATE KEY-----
"""
