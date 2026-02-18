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
)

DISCOVERY_EXPORTERS = (
    {"name": "blackbox_exporter", "port": 9115, "markers": ("blackbox_exporter_build_info",)},
    {"name": "kafka_exporter", "port": 9308, "markers": ("kafka_brokers", "kafka_exporter_build_info")},
    {"name": "node_exporter", "port": 9100, "markers": ("node_exporter_build_info", "node_uname_info")},
    {"name": "postgres_exporter", "port": 9187, "markers": ("postgres_exporter_build_info", "pg_up")},
    {"name": "redis_exporter", "port": 9121, "markers": ("redis_exporter_build_info", "redis_up")},
    {"name": "clickhouse_exporter", "port": 9116, "markers": ("clickhouse_",)},
    {"name": "mongodb_exporter", "port": 9216, "markers": ("mongodb_",)},
    {"name": "pgbouncer_exporter", "port": 9127, "markers": ("pgbouncer_",)},
    {"name": "gobgp_exporter", "port": 9349, "markers": ("gobgp_",)},
    {"name": "frr_exporter", "port": 9342, "markers": ("frr_",)},
    {"name": "named_process_exporter", "port": 9256, "markers": ("namedprocess_",)},
    {"name": "ping_exporter", "port": 9427, "markers": ("ping_",)},
    {"name": "proxmox_exporter", "port": 9221, "markers": ("proxmox_",)},
)

COLLECT_EXPORTERS = (
    {"name": "blackbox_exporter", "port": 9115},
    {"name": "kafka_exporter", "port": 9308},
    {"name": "node_exporter", "port": 9100},
    {"name": "postgres_exporter", "port": 9187},
    {"name": "redis_exporter", "port": 9121},
    {"name": "clickhouse_exporter", "port": 9116},
    {"name": "mongodb_exporter", "port": 9216},
    {"name": "pgbouncer_exporter", "port": 9127},
    {"name": "gobgp_exporter", "port": 9349},
    {"name": "frr_exporter", "port": 9342},
    {"name": "named_process_exporter", "port": 9256},
    {"name": "ping_exporter", "port": 9427},
    {"name": "proxmox_exporter", "port": 9221},
)

COLLECT_DEBUG_ENDPOINTS = (
    "/debug/vars",
    "/debug/pprof/cmdline?debug=1",
)

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
