from __future__ import annotations

from types import SimpleNamespace

from redposture_core.audit_config import AuditConfig


def test_from_namespace_defaults_for_missing_fields() -> None:
    cfg = AuditConfig.from_namespace(SimpleNamespace())
    assert cfg.timeout == 5.0
    assert cfg.retries == 0
    assert cfg.workers == 1
    assert cfg.proxy is None
    assert cfg.output is None
    assert cfg.output_format == "txt"
    assert cfg.debug is False
    assert cfg.no_color is False
    assert cfg.username is None
    assert cfg.token is None


def test_from_namespace_reads_provided_values() -> None:
    args = SimpleNamespace(
        timeout=2.5,
        retries=3,
        workers=8,
        proxy="socks5://127.0.0.1:9050",
        output="/tmp/out.txt",
        output_format="json",
        debug=True,
        no_color=True,
        username="admin",
        password="",
        database="postgres",
        defcreds=True,
        cert_file="/c.pem",
        key_file="/k.pem",
    )
    cfg = AuditConfig.from_namespace(args)
    assert cfg.timeout == 2.5
    assert cfg.retries == 3
    assert cfg.workers == 8
    assert cfg.proxy == "socks5://127.0.0.1:9050"
    assert cfg.output == "/tmp/out.txt"
    assert cfg.output_format == "json"
    assert cfg.debug is True
    assert cfg.no_color is True
    assert cfg.username == "admin"
    assert cfg.password == ""  # empty string preserved (credential-file marker)
    assert cfg.database == "postgres"
    assert cfg.defcreds is True
    assert cfg.cert_file == "/c.pem"


def test_from_namespace_coercions_match_legacy_getattr() -> None:
    # workers floored to >=1; falsy output_format -> "txt"; token falls back to api_token
    cfg = AuditConfig.from_namespace(SimpleNamespace(workers=0, output_format="", api_token="tok"))
    assert cfg.workers == 1
    assert cfg.output_format == "txt"
    assert cfg.token == "tok"

    cfg2 = AuditConfig.from_namespace(SimpleNamespace(token="primary", api_token="secondary"))
    assert cfg2.token == "primary"


def test_config_is_frozen() -> None:
    cfg = AuditConfig.from_namespace(SimpleNamespace())
    try:
        cfg.timeout = 1.0  # type: ignore[misc]
    except AttributeError:
        return
    raise AssertionError("AuditConfig should be frozen")
