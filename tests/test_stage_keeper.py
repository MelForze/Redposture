from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import redposture_core.stage_keeper as keeper_facade
from redposture_core import stage_runtime
from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.clients.zookeeper import (
    ZkImplementationFingerprint,
    ZkKeeperVirtualProbe,
    ZkTransportConfig,
)
from redposture_core.modules.keeper import stage as keeper_stage
from redposture_core.modules.zookeeper import engine as implementation_engine
from redposture_core.stage_runtime import (
    AuditCommandResult,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
)


def _protocol_detect(ctx, _options):
    ctx.lifecycle_state.selected_transport_config = ZkTransportConfig(mode="plaintext")
    return {
        "host": ctx.host,
        "port": ctx.port,
        "service": "zookeeper",
        "status": "open_no_auth",
        "auth_required": False,
        "is_zookeeper": True,
        "error": None,
        "stages": [],
    }


def _detect_record(
    monkeypatch: pytest.MonkeyPatch,
    fingerprint: ZkImplementationFingerprint,
) -> tuple[object, AuditRecord]:
    args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None
    assert spec.detect is not None
    state = spec.lifecycle_state_factory(None)
    monkeypatch.setattr(implementation_engine.zookeeper_actions, "detect_zookeeper", _protocol_detect)
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: fingerprint,
    )
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    return spec, spec.detect(ctx)


def test_keeper_plan_uses_only_keeper_default_ports_and_keeper_credentials() -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1", "--defcreds"])
    plan = keeper_stage.build_keeper_plan(args)

    assert plan.ports == (9181, 19181, 29181)
    assert keeper_stage._DEFAULT_CREDENTIALS == keeper_stage.KEEPER_DIGEST_DEFAULT_CREDENTIALS
    assert tuple((item.username, item.password) for item in plan.credential_runs) == tuple(
        sorted(keeper_stage._DEFAULT_CREDENTIALS, key=lambda pair: (pair[0].lower(), pair[1].lower()))
    )
    assert ("keeper", "keeper") in keeper_stage._DEFAULT_CREDENTIALS
    assert ("clickhouse", "clickhouse") in keeper_stage._DEFAULT_CREDENTIALS
    assert all(item.username not in {"hadoop", "solr", "zookeeper"} for item in plan.credential_runs)


def test_keeper_accepts_only_confirmed_keeper(monkeypatch: pytest.MonkeyPatch) -> None:
    spec, record = _detect_record(
        monkeypatch,
        ZkImplementationFingerprint("clickhouse-keeper", True, "confirmed", version="v25.3.3.42"),
    )
    payload = record.to_dict()

    assert spec.is_detected is not None and spec.is_detected(record) is True
    assert payload["module"] == "keeper"
    assert payload["service"] == "keeper"
    assert payload["implementation"] == "clickhouse-keeper"
    assert payload["is_keeper"] is True
    assert payload["status"] == "open_no_auth"


@pytest.mark.parametrize(
    ("read_error", "create_error", "expected", "created"),
    [
        (0, 0, "Write", True),
        (0, -102, "Read", True),
        (-102, 0, "Write", True),
        (-102, -102, "Denied", True),
        (-101, None, "Absent", False),
        (-122, None, "Unknown", False),
    ],
)
def test_keeper_default_ddl_probe_uses_only_non_task_ephemeral_marker(
    monkeypatch: pytest.MonkeyPatch,
    read_error: int,
    create_error: int | None,
    expected: str,
    created: bool,
) -> None:
    calls: list[tuple[object, ...]] = []

    class Client:
        def get_children2(self, path: str):
            calls.append(("read", path))
            return ([], read_error, None)

        def create(self, path: str, data: bytes = b"", flags: int = 1):
            calls.append(("create", path, data, flags))
            return create_error

        def delete(self, path: str, version: int = -1):
            calls.append(("delete", path, version))
            return 0

    client = Client()
    args = parse_args(["keeper", "-t", "127.0.0.1:9181", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.detect is not None
    state = spec.lifecycle_state_factory(None)

    def fake_detect(ctx, _options):
        ctx.lifecycle_state.zookeeper_state.anonymous_client = client
        return {
            "host": ctx.host,
            "port": ctx.port,
            "service": "keeper",
            "status": "open_no_auth",
            "auth_required": False,
            "is_zookeeper": True,
            "is_keeper": True,
            "transport": "plaintext",
            "version": "v24.8.14.39",
        }

    monkeypatch.setattr(implementation_engine, "detect_zookeeper_implementation", fake_detect)
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    payload = spec.detect(ctx).to_dict()

    assert payload["ddl_access"] == expected
    assert calls[0] == ("read", "/clickhouse/task_queue/ddl")
    create_calls = [call for call in calls if call[0] == "create"]
    assert bool(create_calls) is created
    if create_error == 0:
        assert len(create_calls) == 1
        marker_path = str(create_calls[0][1])
        assert marker_path.startswith("/clickhouse/task_queue/ddl/redposture-probe-")
        assert "/query-" not in marker_path
        assert create_calls[0][2:] == (b"", 1)
        assert ("delete", marker_path, -1) in calls
    else:
        assert not any(call[0] == "delete" for call in calls)
    rendered = keeper_stage.render._format_detect_record(payload, "txt")
    assert f"(auth required:False) (ddl access:{expected}) (transport:plaintext)" in rendered


def test_keeper_denied_ddl_path_becomes_digest_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.keeper import actions as keeper_actions

    args = parse_args(["keeper", "-t", "127.0.0.1:9181", "--defcreds", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.detect is not None
    state = spec.lifecycle_state_factory(None)
    state.zookeeper_state.anonymous_client = object()
    state.zookeeper_state.credential_verification_status = "unavailable"
    monkeypatch.setattr(keeper_actions, "probe_ddl_access", lambda _client: ("Denied", None))
    monkeypatch.setattr(
        implementation_engine,
        "detect_zookeeper_implementation",
        lambda _ctx, _options: {
            "host": "127.0.0.1",
            "port": 9181,
            "service": "keeper",
            "status": "open_no_auth",
            "is_zookeeper": True,
            "is_keeper": True,
            "credential_verification_requested": True,
            "credential_verification_status": "unavailable",
        },
    )
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )

    payload = spec.detect(ctx).to_dict()

    assert payload["credential_verification_status"] == "available"
    assert payload["credential_verification_path"] == keeper_actions._DDL_QUEUE
    assert state.zookeeper_state.anonymous_auth_probe_results[keeper_actions._DDL_QUEUE] == -102


def test_keeper_digest_uses_closed_ddl_path_to_verify_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.keeper import actions as keeper_actions
    from redposture_core.modules.zookeeper import actions as protocol_actions

    args = parse_args(["keeper", "-t", "127.0.0.1:9181", "--defcreds", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.auth is not None
    state = spec.lifecycle_state_factory(None)
    state.fingerprint = ZkImplementationFingerprint("clickhouse-keeper", True, "confirmed")
    verifier = state.zookeeper_state
    verifier.root_err = 0
    verifier.auth_required = False
    verifier.credential_verification_status = "available"
    verifier.credential_verification_path = keeper_actions._DDL_QUEUE
    verifier.anonymous_auth_probe_results = {"/": 0, keeper_actions._DDL_QUEUE: -102}

    class Client:
        def connect(self) -> None:
            return None

        def close(self) -> None:
            return None

        def auth_digest(self, _user: str, _password: str) -> tuple[bool, None]:
            return True, None

        def get_children2(self, path: str):
            return [], 0 if path in {"/", keeper_actions._DDL_QUEUE} else -101, {}

    monkeypatch.setattr(protocol_actions, "_zookeeper_lifecycle_client", lambda *_args, **_kwargs: Client())
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(username="known", password="secret", source="default"),
        lifecycle_state=state,
    )
    detect_record = AuditRecord.from_mapping(
        {"host": "127.0.0.1", "port": 9181, "status": "open_no_auth", "is_keeper": True},
        module="keeper",
        service="keeper",
    )

    record = spec.auth(ctx, detect_record).to_dict()

    assert record["provided_credentials_ok"] is True
    assert record["credential_verdict"] == "valid"
    assert record["credential_auth_probe_results"][keeper_actions._DDL_QUEUE] == "ok"


def test_keeper_credential_renderer_shows_every_attempt_and_skipped_count() -> None:
    record = {
        "module": "keeper",
        "host": "127.0.0.1",
        "port": 9181,
        "credential_verification_status": "available",
        "credential_attempts_skipped": 2,
        "attempted_credentials": [
            {"username": "bad", "password": "bad", "credential_verdict": "rejected"},
            {"username": "unknown", "password": "unknown", "credential_verdict": "unverified"},
            {"username": "good", "password": "good", "credential_verdict": "valid", "provided_credentials_ok": True},
        ],
    }
    lines = keeper_stage.render._format_credential_attempts_records(record, "txt")
    assert any("[-] bad:bad" in line for line in lines)
    assert any("1 credential check(s) inconclusive" in line for line in lines)
    assert any("[+] good:good" in line for line in lines)
    assert any("2 credential pair(s) not attempted" in line for line in lines)
    assert keeper_stage.render._format_credential_attempts_records(record, "json") == []


def test_keeper_unknown_credential_color_and_plain_output(capsys: pytest.CaptureFixture[str]) -> None:
    from redposture_core.console import Console

    line = "KEEPER\t127.0.0.1\t9181\t [*] 1 credential check(s) inconclusive; see --debug/JSON"

    class PaintedConsole:
        def __init__(self) -> None:
            self.colors: list[tuple[str, str]] = []

        def _paint(self, text: str, color: str, _stream: object) -> str:
            self.colors.append((text, color))
            return text

        def plain(self, _line: str) -> None:
            return None

    painted = PaintedConsole()
    assert keeper_stage.render._render_colored_keeper_line(painted, line)
    assert ("[*]", "white") in painted.colors
    assert ("1 credential check(s) inconclusive; see --debug/JSON", "orange") in painted.colors
    assert keeper_stage.render._render_colored_keeper_line(painted, "KEEPER\t127.0.0.1\t9181\t [+] admin:secret")
    assert ("admin:secret", "true_red") in painted.colors
    assert keeper_stage.render._render_colored_keeper_line(painted, "KEEPER\t127.0.0.1\t9181\t [-] admin:wrong")
    assert ("admin:wrong", "bright_green") in painted.colors
    denied_line = "KEEPER\t127.0.0.1\t9181\t [-] admin:wrong (no access to tested znodes)"
    assert keeper_stage.render._render_colored_keeper_line(painted, denied_line)
    assert ("admin:wrong", "bright_green") in painted.colors
    assert keeper_stage.render._render_colored_keeper_line(Console(no_color=True), line)
    assert keeper_stage.render._render_colored_keeper_line(Console(no_color=True), denied_line)
    assert capsys.readouterr().out == f"{line}\n{denied_line}\n"
    assert "\x1b[" not in denied_line


def test_keeper_default_ddl_probe_is_not_run_on_foreign_zookeeper(monkeypatch: pytest.MonkeyPatch) -> None:
    spec, record = _detect_record(
        monkeypatch,
        ZkImplementationFingerprint("apache-zookeeper", False, "confirmed", version="3.9.5"),
    )
    assert spec.is_detected is not None and spec.is_detected(record) is False
    assert "ddl_access" not in record.to_dict()


def test_keeper_ddl_probe_closes_ephemeral_session_if_delete_is_denied() -> None:
    from redposture_core.modules.keeper import actions as keeper_actions

    calls: list[str] = []

    class Client:
        def get_children2(self, _path: str):
            return [], 0, None

        def create(self, path: str, _data: bytes, *, flags: int):
            calls.append(f"create:{path}:{flags}")
            return 0

        def delete(self, path: str, _version: int):
            calls.append(f"delete:{path}")
            return -102

        def close(self):
            calls.append("close")

        def connect(self):
            calls.append("reconnect")

    access, detail = keeper_actions.probe_ddl_access(Client())
    assert access == "Write"
    assert "NOAUTH" in str(detail)
    assert calls[-2:] == ["close", "reconnect"]


def test_keeper_ddl_probe_ambiguous_create_closes_session_before_reuse() -> None:
    from redposture_core.modules.keeper import actions as keeper_actions

    calls: list[str] = []

    class Client:
        def get_children2(self, _path: str):
            return [], 0, None

        def create(self, _path: str, _data: bytes, *, flags: int):
            calls.append(f"create:{flags}")
            raise TimeoutError("response lost")

        def close(self):
            calls.append("close")

        def connect(self):
            calls.append("reconnect")

    access, detail = keeper_actions.probe_ddl_access(Client())
    assert access == "Read"
    assert "response lost" in str(detail)
    assert calls == ["create:1", "close", "reconnect"]


def test_keeper_ddl_probe_malformed_read_result_does_not_hide_service() -> None:
    from redposture_core.modules.keeper import actions as keeper_actions

    class Client:
        def get_children2(self, _path: str):
            return [], None, None

    assert keeper_actions.probe_ddl_access(Client())[0] == "Unknown"


@pytest.mark.parametrize(
    ("status", "color"),
    [
        ("Write", "red"),
        ("Read", "orange"),
        ("Denied", "bright_green"),
        ("Absent", "bright_green"),
        ("Unknown", "orange"),
    ],
)
def test_keeper_ddl_access_colors_match_status(status: str, color: str) -> None:
    class Console:
        paint_calls: list[tuple[str, str]] = []

        def _paint(self, text: str, selected: str, _stream) -> str:
            self.paint_calls.append((text, selected))
            return text

        def plain(self, _text: str, color: str | None = None) -> None:
            del color

    console = Console()
    assert keeper_stage.render._render_colored_keeper_line(
        console,
        f"KEEPER\t127.0.0.1\t9181\t [*] ClickHouse Keeper (auth required:False) (ddl access:{status})",
    )
    assert (f"ddl access:{status}", color) in console.paint_calls


@pytest.mark.parametrize(
    ("payload", "fragment", "color"),
    [
        ("[*] DDL Clusters (clusters:2)", "DDL Clusters (", "white"),
        ("[*] DDL Clusters (clusters:2)", "clusters:2", "true_red"),
        ("[*] DDL Clusters (clusters:0)", "clusters:0", "bright_green"),
        ("[*] DDL Worker Hosts (hosts:3)", "DDL Worker Hosts (", "white"),
        ("[*] DDL Worker Hosts (hosts:3)", "hosts:3", "true_red"),
        ("[*] DDL Worker Hosts (hosts:0)", "hosts:0", "bright_green"),
        ('[*] Cluster="qa"', '"qa"', "orange"),
        ('[*] Cluster="qa" Host="clickhouse:9000"', '"clickhouse:9000"', "orange"),
        ('[+] ClickHouse user "audituser" created (cluster:qa) (hosts:1:ch-a:9000)', '"audituser"', "orange"),
        ('[+] ClickHouse user "audituser" created (cluster:qa) (hosts:1:ch-a:9000)', "created", "true_red"),
        (
            '[-] ClickHouse user "audituser" partially created (cluster:qa) (hosts:1:ch-a:9000)',
            "partially created",
            "orange",
        ),
        ('[-] ClickHouse user "audituser" not created (cluster:qa) (hosts:1:ch-a:9000)', "not created", "bright_green"),
        (
            '[-] ClickHouse user "audituser" creation unverified (cluster:qa) (hosts:1:ch-a:9000)',
            "creation unverified",
            "orange",
        ),
        ("[+] Administration rights granted (cluster:qa) (hosts:1:ch-a:9000)", "granted", "true_red"),
        ("[-] Administration rights partially granted (cluster:qa) (hosts:1:ch-a:9000)", "partially granted", "orange"),
        ("[-] Administration rights not granted (cluster:qa) (hosts:1:ch-a:9000)", "not granted", "bright_green"),
        ("[-] Administration rights grant unverified (cluster:qa) (hosts:1:ch-a:9000)", "grant unverified", "orange"),
        ('[+] ClickHouse user "audituser" created (cluster:qa) (hosts:1:ch-a:9000)', "qa", "orange"),
        ('[+] ClickHouse user "audituser" created (cluster:qa) (hosts:1:ch-a:9000)', "ch-a:9000", "orange"),
        ("[-] DDL topology unavailable", "unavailable", "orange"),
    ],
)
def test_keeper_ddl_output_uses_airflow_color_semantics(payload: str, fragment: str, color: str) -> None:
    class Console:
        def __init__(self) -> None:
            self.paint_calls: list[tuple[str, str]] = []

        def _paint(self, text: str, selected: str, _stream: object) -> str:
            self.paint_calls.append((text, selected))
            return text

        def plain(self, _text: str, color: str | None = None) -> None:
            del color

    console = Console()
    assert keeper_stage.render._render_colored_keeper_line(console, f"KEEPER\t127.0.0.1\t9181\t {payload}")
    assert (fragment, color) in console.paint_calls


def test_keeper_ddl_output_respects_no_color(capsys: pytest.CaptureFixture[str]) -> None:
    from redposture_core.console import Console

    payload = 'KEEPER\t127.0.0.1\t9181\t [*] Cluster="qa" Host="clickhouse:9000"'
    assert keeper_stage.render._render_colored_keeper_line(Console(no_color=True), payload)
    assert capsys.readouterr().out == f"{payload}\n"


def test_keeper_ddl_topology_render_keeps_plain_text_and_json_contract() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9181,
        "service": "keeper",
        "ddl_topology_requested": {"clusters": True, "hosts": True},
        "ddl_topology": {
            "status": "ok",
            "clusters": {
                "zeta": ["worker-b:9000"],
                "alpha": ["worker-a:9000", "worker-c:9000"],
            },
        },
    }
    rendered = keeper_stage.render._format_ddl_topology_records(record, "txt")
    assert [line.split("\t", 3)[-1].strip() for line in rendered] == [
        "[*] DDL Clusters (clusters:2)",
        '[*] Cluster="alpha"',
        '[*] Cluster="zeta"',
        "[*] DDL Worker Hosts (hosts:3)",
        '[*] Cluster="alpha" Host="worker-a:9000"',
        '[*] Cluster="alpha" Host="worker-c:9000"',
        '[*] Cluster="zeta" Host="worker-b:9000"',
    ]
    assert keeper_stage.render._format_ddl_topology_records(record, "json") == []


def test_keeper_ddl_topology_render_handles_absent_and_unavailable() -> None:
    base = {"host": "127.0.0.1", "port": 9181, "service": "keeper"}
    assert keeper_stage.render._format_ddl_topology_records(base, "txt") == []
    record = {
        **base,
        "ddl_topology_requested": {"clusters": True, "hosts": True},
        "ddl_topology": {"status": "unavailable", "reason": "read denied"},
    }
    assert keeper_stage.render._format_ddl_topology_records(record, "txt")[0].endswith("[-] DDL topology unavailable")
    assert keeper_stage.render._format_ddl_topology_records(record, "txt", debug=True)[0].endswith(
        "[-] DDL topology read denied"
    )


def test_keeper_ddl_topology_render_skips_invalid_host_collections() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9181,
        "service": "keeper",
        "ddl_topology_requested": {"clusters": False, "hosts": True},
        "ddl_topology": {"status": "ok", "clusters": {"broken": None, "empty": []}},
    }
    rendered = keeper_stage.render._format_ddl_topology_records(record, "txt")
    assert len(rendered) == 1
    assert rendered[0].endswith("[*] DDL Worker Hosts (hosts:0)")


def test_keeper_report_lists_topology_before_ddl_creation_result() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 9181,
        "module": "keeper",
        "service": "keeper",
        "ddl_topology_requested": {"clusters": True, "hosts": True},
        "ddl_topology": {"status": "ok", "clusters": {"qa": ["clickhouse:9000"]}},
        "ddl_user_creation": {
            "username": "audituser",
            "status": "created",
            "admin_status": "not_requested",
            "cluster": "qa",
            "hosts": ["clickhouse:9000"],
        },
    }
    plan = stage_runtime.build_render_plan(keeper_stage.render)
    lines = stage_runtime.render_with_plan(plan, record, "txt")
    topology_index = next(index for index, line in enumerate(lines) if "DDL Clusters" in line)
    creation_index = next(index for index, line in enumerate(lines) if 'ClickHouse user "audituser"' in line)
    assert topology_index < creation_index


def test_keeper_help_explains_default_ddl_write_probe(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["keeper", "--help"])
    assert exc.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "DDL queue" in help_text
    assert "by default" in help_text
    assert "Without this flag the audit is read-only" not in help_text


def test_keeper_rejects_apache_before_auth_or_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    spec, record = _detect_record(
        monkeypatch,
        ZkImplementationFingerprint("apache-zookeeper", False, "confirmed", version="3.9.5"),
    )
    payload = record.to_dict()

    assert spec.is_detected is not None and spec.is_detected(record) is False
    assert payload["status"] == "not_keeper"
    assert payload["is_zookeeper"] is True
    assert payload["is_keeper"] is False
    assert "does not match keeper module" in str(payload["error"])


def test_keeper_virtual_znode_fallback_confirms_no4lw_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class AnonymousClient:
        def probe_keeper_virtual_nodes(self) -> ZkKeeperVirtualProbe:
            return ZkKeeperVirtualProbe(True, api_version=2, children=("api_version", "feature_flags"))

        def close(self) -> None:
            return None

    def fake_detect(ctx, options):
        result = _protocol_detect(ctx, options)
        ctx.lifecycle_state.anonymous_client = AnonymousClient()
        return result

    args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.detect is not None
    state = spec.lifecycle_state_factory(None)
    monkeypatch.setattr(implementation_engine.zookeeper_actions, "detect_zookeeper", fake_detect)
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: ZkImplementationFingerprint("zookeeper-compatible", None, "unconfirmed"),
    )
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=39181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )

    payload = spec.detect(ctx).to_dict()

    assert payload["is_keeper"] is True
    assert payload["implementation"] == "clickhouse-keeper"
    assert payload["implementation_evidence"] == "keeper_virtual_znodes"
    assert payload["keeper_virtual_probe"]["api_version"] == 2


def test_unconfirmed_keeper_is_hidden_in_txt_but_preserved_in_json(monkeypatch: pytest.MonkeyPatch) -> None:
    class AnonymousClient:
        def probe_keeper_virtual_nodes(self) -> ZkKeeperVirtualProbe:
            return ZkKeeperVirtualProbe(False, reason="virtual markers unavailable")

        def close(self) -> None:
            return None

    def fake_detect(ctx, options):
        result = _protocol_detect(ctx, options)
        ctx.lifecycle_state.anonymous_client = AnonymousClient()
        return result

    monkeypatch.setattr(implementation_engine.zookeeper_actions, "detect_zookeeper", fake_detect)
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: ZkImplementationFingerprint("zookeeper-compatible", None, "unconfirmed"),
    )
    auth_calls = 0

    def fail_auth(*_args, **_kwargs):
        nonlocal auth_calls
        auth_calls += 1
        raise AssertionError("auth must not run for unconfirmed implementation")

    monkeypatch.setattr(implementation_engine, "authenticate_zookeeper_implementation", fail_auth)

    txt_args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"])
    txt_lines: list[str] = []
    txt_runner = AuditCommandRunner(
        args=txt_args,
        spec=keeper_stage.build_keeper_spec(txt_args),
        emit_line=txt_lines.append,
    )
    txt_result = txt_runner.run_plan(keeper_stage.build_keeper_plan(txt_args))

    assert txt_result.detected_count == 0
    assert auth_calls == 0
    assert not any("ClickHouse Keeper" in line for line in txt_lines)

    json_args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0", "--format", "json"])
    json_lines: list[str] = []
    json_runner = AuditCommandRunner(
        args=json_args,
        spec=keeper_stage.build_keeper_spec(json_args),
        emit_line=json_lines.append,
    )
    json_runner.run_plan(keeper_stage.build_keeper_plan(json_args))
    records = [json.loads(line) for line in json_lines]

    assert any(item.get("status") == "not_keeper_unconfirmed" for item in records)
    assert any(item.get("implementation") == "zookeeper-compatible" for item in records)


def test_keeper_spec_adapts_shared_auth_data_and_capability_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None
    state = spec.lifecycle_state_factory(None)
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(username="keeper", password="keeper", source="provided"),
        lifecycle_state=state,
    )
    record = AuditRecord.from_mapping(
        {
            "host": "127.0.0.1",
            "port": 9181,
            "status": "open_no_auth",
            "is_zookeeper": True,
            "is_keeper": True,
        },
        module="keeper",
        service="keeper",
    )

    monkeypatch.setattr(
        implementation_engine,
        "authenticate_zookeeper_implementation",
        lambda *_args, **_kwargs: {**record.to_dict(), "provided_credentials_ok": True},
    )
    monkeypatch.setattr(
        implementation_engine,
        "collect_zookeeper_implementation_data",
        lambda *_args, **_kwargs: {**record.to_dict(), "znode_count": 2},
    )
    monkeypatch.setattr(
        implementation_engine,
        "probe_zookeeper_implementation_capabilities",
        lambda *_args, **_kwargs: {**record.to_dict(), "can_create_znode": False},
    )

    assert spec.auth is not None and spec.auth(ctx, record).extra["provided_credentials_ok"] is True
    assert spec.data is not None and spec.data(ctx, record).extra["znode_count"] == 2
    assert spec.capabilities is not None and spec.capabilities(ctx, record).extra["can_create_znode"] is False
    assert spec.credential_gate is not None
    assert spec.credential_gate(ctx.credential, spec.auth(ctx, record))[0] is True
    assert spec.credential_gate(AuditCredentialRun(source="anonymous"), record)[0] is True
    assert spec.is_detected is not None and spec.is_detected(record) is True
    assert spec.lifecycle_state_close is not None
    spec.lifecycle_state_close(state)


def test_run_keeper_stage_debug_success_and_error_paths(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = AuditCommandResult(records=[], detected_count=0, emitted_lines=0, typed_records=[])
    monkeypatch.setattr(AuditCommandRunner, "run_plan", lambda *_args, **_kwargs: result)
    args = parse_args(["keeper", "-t", "127.0.0.1", "--debug", "-u", " keeper ", "-p", ""])

    assert keeper_stage.run_keeper_stage(args, logger=None) == 0
    assert args.username == "keeper"
    assert args.password == ""
    output = capsys.readouterr().out
    assert "keeper audit started" in output
    assert "no target confirmed as ClickHouse Keeper" in output

    invalid = parse_args(["keeper", "-t", "127.0.0.1", "-u", "keeper"])
    assert keeper_stage.run_keeper_stage(invalid, logger=None) == 2

    valid = parse_args(["keeper", "-t", "127.0.0.1"])
    monkeypatch.setattr(keeper_stage, "build_keeper_plan", lambda _args: (_ for _ in ()).throw(ValueError("bad plan")))
    assert keeper_stage.run_keeper_stage(valid, logger=None) == 2


def test_run_keeper_stage_handles_output_error(monkeypatch: pytest.MonkeyPatch) -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1"])
    monkeypatch.setattr(
        AuditCommandRunner, "run_plan", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk"))
    )
    assert keeper_stage.run_keeper_stage(args, logger=None) == 2


def test_keeper_compatibility_facade_forwards_runtime_and_stage_attributes(monkeypatch: pytest.MonkeyPatch) -> None:
    assert keeper_facade.collect_scan_ports is stage_runtime.collect_scan_ports
    with pytest.raises(AttributeError):
        keeper_facade.__getattr__("missing_keeper_attribute")

    def runtime_sentinel(*_args, **_kwargs):
        return (9181,)

    monkeypatch.setattr(keeper_facade, "collect_scan_ports", runtime_sentinel)
    assert stage_runtime.collect_scan_ports is runtime_sentinel

    stage_sentinel = SimpleNamespace(name="keeper-stage")
    monkeypatch.setattr(keeper_facade, "run_keeper_stage", stage_sentinel)
    assert keeper_stage.run_keeper_stage is stage_sentinel
