"""Regression tests for the G-batch (consistency sweeps).

G1 — DISCOVERY_EXPORTERS: no un-declared port collisions among exporters.
G2 — E3 opt-in expansion to mongodb/postgres/qdrant/etcd/registry/zookeeper/kubeapi.
G3 — Every module that accepts `-u`/`-p` also accepts `--username`/`--password`,
     and no module opts out of `--save`.
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

# ---------------------------------------------------------------------------
# G1 — No un-declared port collisions
# ---------------------------------------------------------------------------


def test_fix_g1_exporter_port_collisions_all_have_negative_markers() -> None:
    """Every port shared by multiple exporters in DISCOVERY_EXPORTERS must
    carry `negative_markers` on both sides so `discover.py`'s B4/B5 gate can
    veto cross-labelled hits."""
    from redposture_core.constants import DISCOVERY_EXPORTERS

    by_port: dict[int, list[dict]] = {}
    for e in DISCOVERY_EXPORTERS:
        by_port.setdefault(int(e["port"]), []).append(e)

    collisions = {port: exps for port, exps in by_port.items() if len(exps) > 1}
    # If more exporters get added, this asserts the invariant on ALL of them.
    for port, exps in collisions.items():
        for e in exps:
            assert e.get("negative_markers"), (
                f"port {port}: exporter {e['name']} shares the port but has no negative_markers"
            )


# ---------------------------------------------------------------------------
# G2 — E3 opt-in expansion
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module",
    [
        "redis",
        "docker",
        "elastic",
        "clickhouse",
        "grpc",
        "mongodb",
        "postgres",
        "qdrant",
        "etcd",
        "registry",
        "zookeeper",
        "kubeapi",
    ],
)
def test_fix_g2_module_opts_into_keep_anonymous_open_no_auth(module: str) -> None:
    """These modules opt into the anon-open fast-path so `--defcreds` with a
    confirmed anonymous access doesn't run the credential loop redundantly."""
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    build_spec = getattr(stage, f"build_{module}_spec")
    spec = build_spec(SimpleNamespace())
    assert getattr(spec, "keep_anonymous_open_no_auth", False) is True, (
        f"{module} spec did not opt in to keep_anonymous_open_no_auth"
    )


@pytest.mark.parametrize(
    "module",
    ["consul", "proxmox", "gitlab", "oracle", "kafka"],
)
def test_fix_g2_module_stays_opted_out_of_keep_anonymous_open_no_auth(module: str) -> None:
    """These modules stay opted OUT — their auth model doesn't cleanly
    guarantee that a confirmed 'anonymous' probe makes creds redundant.
    Kafka in particular uses its own hardcoded fast-path in
    `_should_keep_anonymous_detect_record`, so the spec flag is False."""
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    build_spec = getattr(stage, f"build_{module}_spec")
    spec = build_spec(SimpleNamespace())
    assert getattr(spec, "keep_anonymous_open_no_auth", False) is False, (
        f"{module} spec unexpectedly opted in to keep_anonymous_open_no_auth"
    )


# ---------------------------------------------------------------------------
# G3 — Flag consistency sweeps
# ---------------------------------------------------------------------------

# Modules that expose --username/--password. Enumerated by hand because argparse
# doesn't expose subcommand groups in a convenient introspection API.
_AUTH_MODULES = [
    "clickhouse",
    "elastic",
    "kubeapi",
    "mongodb",
    "oracle",
    "postgres",
    "redis",
    "registry",
    "zookeeper",
    "kafka",
    "etcd",
]


@pytest.mark.parametrize("module", _AUTH_MODULES)
def test_fix_g3_every_auth_module_accepts_both_short_and_long_username_password(module: str) -> None:
    """No module may accept only `-u`/`-p` (short) without also accepting
    `--username`/`--password` (long) — batch scripts should not need to
    special-case any single module."""
    from redposture_core.cli_args import parse_args

    argv = [module, "-t", "127.0.0.1", "--username", "test-user", "--password", "test-pass"]
    args = parse_args(argv)
    assert args.username == "test-user"
    assert args.password == "test-pass"


# Modules that accept a file output. Includes the four (postgres/mongo/docker/
# oracle) that previously rejected `--save`.
_SAVE_MODULES = [
    "clickhouse",
    "docker",
    "elastic",
    "etcd",
    "kafka",
    "mongodb",
    "oracle",
    "postgres",
    "redis",
    "registry",
    "zookeeper",
    "consul",
    "grafana",
    "qdrant",
]


@pytest.mark.parametrize("module", _SAVE_MODULES)
def test_fix_g3_every_module_accepts_save_alias(module: str) -> None:
    from redposture_core.cli_args import parse_args

    argv = [module, "-t", "127.0.0.1", "--save", "out.txt"]
    if module == "docker":
        argv += ["--containers"]
    if module == "oracle":
        argv += ["-u", "system", "-p", "oracle"]
    args = parse_args(argv)
    assert args.output == "out.txt", f"module {module} did not honor --save alias"
