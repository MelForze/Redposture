"""Command registry for CLI parser construction and runtime dispatch."""

from __future__ import annotations

import argparse
import importlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .cli_modules.clickhouse import configure_clickhouse_parser
from .cli_modules.consul import configure_consul_parser
from .cli_modules.datastores import configure_etcd_parser, configure_kafka_parser, configure_redis_parser
from .cli_modules.docker_engine import configure_docker_parser
from .cli_modules.elastic import configure_elastic_parser
from .cli_modules.exporters import configure_collect_parser, configure_scan_parser, configure_trigger_parser
from .cli_modules.gitlab import configure_gitlab_parser
from .cli_modules.grafana import configure_grafana_parser
from .cli_modules.grpc import configure_grpc_parser
from .cli_modules.kubeapi import configure_kubeapi_parser
from .cli_modules.mongodb import MongoDBHelpFormatter, configure_mongodb_parser
from .cli_modules.oracle import configure_oracle_parser
from .cli_modules.postgres import PostgresHelpFormatter, configure_postgres_parser
from .cli_modules.proxmox import configure_proxmox_parser
from .cli_modules.qdrant import configure_qdrant_parser
from .cli_modules.registry import configure_registry_parser
from .cli_modules.zookeeper import configure_zookeeper_parser

COMMAND_LISTEN = "listen"
COMMAND_SCAN = "scan"
COMMAND_TRIGGER = "trigger"
COMMAND_COLLECT = "collect"
COMMAND_REDIS = "redis"
COMMAND_REGISTRY = "registry"
COMMAND_POSTGRES = "postgres"
COMMAND_CLICKHOUSE = "clickhouse"
COMMAND_ETCD = "etcd"
COMMAND_PROXMOX = "proxmox"
COMMAND_GRAFANA = "grafana"
COMMAND_GITLAB = "gitlab"
COMMAND_CONSUL = "consul"
COMMAND_QDRANT = "qdrant"
COMMAND_KUBEAPI = "kubeapi"
COMMAND_KAFKA = "kafka"
COMMAND_ZOOKEEPER = "zookeeper"
COMMAND_ELASTIC = "elastic"
COMMAND_GRPC = "grpc"
COMMAND_MONGODB = "mongodb"
COMMAND_DOCKER = "docker"
COMMAND_ORACLE = "oracle"
COMMAND_SELFCERT = "selfcert"
COMMAND_EXPORTERS = "exporters"


@dataclass(frozen=True)
class ParserHelperSet:
    add_output_flags: Callable[..., None]
    add_log_flag: Callable[..., None]
    add_scan_host_flags: Callable[..., None]
    add_multi_ports_flag: Callable[..., None]
    add_save_flag: Callable[..., None]
    add_listener_flags: Callable[..., None]
    append_selected_defaults: Callable[..., None]
    mirror_group_actions: Callable[..., None]
    # `--port` now accepts either a single int (returned as int for backward
    # compatibility) or a list/range/file spec (returned as str and merged
    # with `args.ports` downstream). See `_port_spec` in cli_args.py.
    port_type: Callable[[str], int | str]
    positive_int: Callable[[str], int]


@dataclass(frozen=True)
class CommandSpec:
    name: str
    help: str
    runner_attr: str
    configure_parser: Callable[[argparse.ArgumentParser, ParserHelperSet], None]
    description: str | None = None
    formatter_class: type[argparse.HelpFormatter] | None = argparse.ArgumentDefaultsHelpFormatter
    runner_module: str | None = None


@dataclass(frozen=True)
class ExportersActionSpec:
    name: str
    help: str
    runner_attr: str
    configure_parser: Callable[[argparse.ArgumentParser, ParserHelperSet], None]
    runner_module: str | None = None


RuntimeCommandSpec = CommandSpec | ExportersActionSpec


_STAGE_RUNNER_MODULES: dict[str, str] = {
    COMMAND_SCAN: "redposture_core.stage_scan",
    COMMAND_TRIGGER: "redposture_core.stage_trigger",
    COMMAND_COLLECT: "redposture_core.stage_collect",
    COMMAND_REDIS: "redposture_core.modules.redis.stage",
    COMMAND_REGISTRY: "redposture_core.modules.registry.stage",
    COMMAND_POSTGRES: "redposture_core.modules.postgres.stage",
    COMMAND_CLICKHOUSE: "redposture_core.modules.clickhouse.stage",
    COMMAND_ETCD: "redposture_core.modules.etcd.stage",
    COMMAND_PROXMOX: "redposture_core.modules.proxmox.stage",
    COMMAND_GRAFANA: "redposture_core.modules.grafana.stage",
    COMMAND_GITLAB: "redposture_core.modules.gitlab.stage",
    COMMAND_CONSUL: "redposture_core.modules.consul.stage",
    COMMAND_QDRANT: "redposture_core.modules.qdrant.stage",
    COMMAND_KUBEAPI: "redposture_core.modules.kubeapi.stage",
    COMMAND_KAFKA: "redposture_core.modules.kafka.stage",
    COMMAND_ZOOKEEPER: "redposture_core.modules.zookeeper.stage",
    COMMAND_ELASTIC: "redposture_core.modules.elastic.stage",
    COMMAND_GRPC: "redposture_core.modules.grpc.stage",
    COMMAND_MONGODB: "redposture_core.modules.mongodb.stage",
    COMMAND_DOCKER: "redposture_core.modules.docker.stage",
    COMMAND_ORACLE: "redposture_core.modules.oracle.stage",
    COMMAND_SELFCERT: "redposture_core.stage_selfcert",
}


# Canonical list of audit-module command names (those whose runner lives under
# `redposture_core.modules.<name>`). Single source of truth for tests and tools
# that need to enumerate the audit modules instead of hard-coding the list.
AUDIT_MODULE_NAMES: tuple[str, ...] = tuple(
    name for name, target in _STAGE_RUNNER_MODULES.items() if target.startswith("redposture_core.modules.")
)


def resolve_command_runner(spec: RuntimeCommandSpec) -> Callable[..., int]:
    """Resolve a registered command runner lazily.

    Lazy resolution keeps `cli.py` independent from stage-module imports. It
    also makes tests patch the registry boundary instead of relying on
    `cli.py` exporting every runner function as an accidental API.
    """

    module_name = spec.runner_module or _STAGE_RUNNER_MODULES.get(spec.name)
    if not module_name:
        raise LookupError(f"no runner module registered for command {spec.name!r}")
    try:
        module = importlib.import_module(module_name)
    except (ModuleNotFoundError, ImportError) as exc:
        raise LookupError(
            f"cannot import module {module_name!r} for command {spec.name!r}: {exc}; try reinstalling the package"
        ) from exc
    runner = getattr(module, spec.runner_attr, None)
    if not callable(runner):
        raise LookupError(f"runner {module_name}:{spec.runner_attr} is not callable")
    return runner


# Helper sets reused across modules. Names must match both the `ParserHelperSet`
# fields and the keyword parameters of the underlying `configure_*_parser`.
_HTTP_MODULE_HELPERS: tuple[str, ...] = (
    "add_output_flags",
    "add_log_flag",
    "add_scan_host_flags",
    "add_multi_ports_flag",
    "add_save_flag",
    "port_type",
)
_HTTP_MODULE_HELPERS_WITH_MIRROR: tuple[str, ...] = (*_HTTP_MODULE_HELPERS, "mirror_group_actions")
_DATASTORE_HELPERS: tuple[str, ...] = (
    "add_scan_host_flags",
    "add_multi_ports_flag",
    "add_save_flag",
    "add_log_flag",
    "add_output_flags",
    "append_selected_defaults",
    "port_type",
)
_DATASTORE_HELPERS_WITH_POSITIVE_INT: tuple[str, ...] = (*_DATASTORE_HELPERS, "positive_int")


def _make_configurator(
    configure_fn: Callable[..., None],
    helper_names: tuple[str, ...],
) -> Callable[[argparse.ArgumentParser, ParserHelperSet], None]:
    """Build a parser configurator that forwards the named helpers as keyword
    arguments. This replaces a wall of near-identical wrapper functions with a
    single data-driven dispatch; `helper_names` is the per-command contract of
    which `ParserHelperSet` fields the module's `configure_*_parser` expects."""

    def _configure(parser: argparse.ArgumentParser, helpers: ParserHelperSet) -> None:
        configure_fn(parser, **{name: getattr(helpers, name) for name in helper_names})

    return _configure


EXPORTERS_ACTION_SPECS: tuple[ExportersActionSpec, ...] = (
    ExportersActionSpec(
        name=COMMAND_SCAN,
        help="Discover observability endpoints and write scan report.",
        runner_attr="run_scan_stage",
        configure_parser=_make_configurator(
            configure_scan_parser,
            ("add_output_flags", "add_log_flag", "add_scan_host_flags", "add_save_flag"),
        ),
    ),
    ExportersActionSpec(
        name=COMMAND_COLLECT,
        help="Collect debug/runtime endpoints from a target service list.",
        runner_attr="run_collect_stage",
        configure_parser=_make_configurator(
            configure_collect_parser,
            ("add_output_flags", "add_log_flag", "add_scan_host_flags", "add_save_flag", "positive_int"),
        ),
    ),
    ExportersActionSpec(
        name=COMMAND_TRIGGER,
        help="Trigger discovered endpoints/exporters to your callback target.",
        runner_attr="run_trigger_stage",
        configure_parser=_make_configurator(
            configure_trigger_parser,
            ("add_output_flags", "add_log_flag", "add_scan_host_flags", "add_save_flag", "add_listener_flags"),
        ),
    ),
)


COMMAND_SPECS: tuple[CommandSpec, ...] = (
    CommandSpec(
        name=COMMAND_REGISTRY,
        help="Audit Docker Registry v2 / Harbor / GitLab / Nexus exposure and image metadata.",
        description=(
            "Registry audit supports four modes: generic Docker Registry v2/OCI, Harbor, "
            "GitLab Container Registry, and Nexus Repository. By default it performs minimal "
            "detection and prints only the detected type + basic access status. "
            "Use --harbor/--gitlab/--nexus for vendor API parsing, and use shared Docker/OCI "
            "flags (--repository/--show-tags/--tag/--metadata/--inspect/--download) to inspect "
            "image tags and config metadata on any compatible v2 registry endpoint."
        ),
        runner_attr="run_registry_stage",
        configure_parser=_make_configurator(configure_registry_parser, _HTTP_MODULE_HELPERS_WITH_MIRROR),
    ),
    CommandSpec(
        name=COMMAND_GRAFANA,
        help="Audit Grafana auth exposure and datasource access.",
        runner_attr="run_grafana_stage",
        configure_parser=_make_configurator(configure_grafana_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_PROXMOX,
        help="Audit Proxmox API with PVE API token and search leaked credentials in API responses.",
        runner_attr="run_proxmox_stage",
        configure_parser=_make_configurator(configure_proxmox_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_GITLAB,
        help="Audit GitLab public/unprotected endpoints, public projects, token access, and cloning.",
        description=(
            "GitLab module checks login-page presence alongside public/unprotected endpoints, "
            "enumerates public projects by default, optionally validates PAT/GAT token API access "
            "and per-project capabilities (repo/issues/members), and can clone selected or all "
            "accessible repositories."
        ),
        runner_attr="run_gitlab_stage",
        configure_parser=_make_configurator(configure_gitlab_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_CONSUL,
        help="Audit Consul API exposure, anonymous access, and agent SSRF via health checks.",
        description=(
            "Consul module detects Consul agents/servers by API responses, checks anonymous access to KV, services, "
            "agent members, and health checks, inspects script-check settings (EnableLocalScriptChecks / "
            "EnableRemoteScriptChecks), and can perform SSRF probes via temporary agent HTTP checks."
        ),
        runner_attr="run_consul_stage",
        configure_parser=_make_configurator(configure_consul_parser, _HTTP_MODULE_HELPERS_WITH_MIRROR),
    ),
    CommandSpec(
        name=COMMAND_KUBEAPI,
        help="Audit Kubernetes API exposure, auth requirements, and resource visibility.",
        description=(
            "Kubernetes API module checks whether the cluster API is reachable without authentication, "
            "supports Bearer token or Basic auth, and can enumerate namespaces, pods, and secrets "
            "visible to the current access level."
        ),
        runner_attr="run_kubeapi_stage",
        configure_parser=_make_configurator(configure_kubeapi_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_POSTGRES,
        help="Audit Postgres auth exposure and risky privileges.",
        runner_attr="run_postgres_stage",
        configure_parser=_make_configurator(configure_postgres_parser, _DATASTORE_HELPERS_WITH_POSITIVE_INT),
        formatter_class=PostgresHelpFormatter,
    ),
    CommandSpec(
        name=COMMAND_MONGODB,
        help="Audit MongoDB auth exposure, database/collection visibility, and document dumps.",
        runner_attr="run_mongodb_stage",
        configure_parser=_make_configurator(configure_mongodb_parser, _DATASTORE_HELPERS_WITH_POSITIVE_INT),
        formatter_class=MongoDBHelpFormatter,
    ),
    CommandSpec(
        name=COMMAND_DOCKER,
        help="Audit exposed Docker Engine TCP API endpoints and inventory visibility.",
        description=(
            "Docker module detects Docker Engine API over plaintext/TLS TCP, checks auth/TLS requirements, "
            "optionally inventories containers/images/networks/volumes/system data, and can run an explicit "
            "Docker exec command in a selected existing container."
        ),
        runner_attr="run_docker_stage",
        configure_parser=_make_configurator(configure_docker_parser, _DATASTORE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_ORACLE,
        help="Audit Oracle listener, auth, PDB/CDB visibility, privileges, and explicit post-auth actions.",
        description=(
            "Oracle module detects TNS listener/database exposure, enumerates SID/service targets, "
            "checks credentials/defaults, and can run explicit enumeration, privesc, RCE/file/exfil actions."
        ),
        runner_attr="run_oracle_stage",
        configure_parser=_make_configurator(configure_oracle_parser, _DATASTORE_HELPERS_WITH_POSITIVE_INT),
    ),
    CommandSpec(
        name=COMMAND_CLICKHOUSE,
        help="Audit ClickHouse auth exposure and privileges.",
        runner_attr="run_clickhouse_stage",
        configure_parser=_make_configurator(configure_clickhouse_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_REDIS,
        help="Audit Redis auth exposure and default credentials.",
        runner_attr="run_redis_stage",
        configure_parser=_make_configurator(configure_redis_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_ETCD,
        help="Audit etcd API exposure and auth requirements.",
        runner_attr="run_etcd_stage",
        configure_parser=_make_configurator(configure_etcd_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_QDRANT,
        help="Audit Qdrant collections exposure, dump collection info, and snapshot-recover SSRF.",
        description=(
            "Qdrant module checks anonymous access to /collections, lists and dumps collection metadata, "
            "probes collection update reachability with a no-op PATCH {} request, and can test SSRF "
            "via collection snapshot restore from a supplied URL."
        ),
        runner_attr="run_qdrant_stage",
        configure_parser=_make_configurator(configure_qdrant_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_ELASTIC,
        help="Audit Elasticsearch exposure, auth, cluster/users endpoints, and secret discovery.",
        description=(
            "Elastic module detects Elasticsearch/OpenSearch API exposure, supports Basic/API key auth checks, "
            "collects _cat endpoints, cluster health/nodes, security users, and performs mapping-aware "
            "document/configuration discovery for potential secret leaks."
        ),
        runner_attr="run_elastic_stage",
        configure_parser=_make_configurator(configure_elastic_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_GRPC,
        help="Audit gRPC services with transport/auth/reflection/health checks.",
        description=(
            "gRPC module fingerprints service transport (TLS/plaintext), auth requirements, and Reflection. "
            "Use --analyze to enumerate services/method descriptors and run per-service Health checks."
        ),
        runner_attr="run_grpc_stage",
        configure_parser=_make_configurator(configure_grpc_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_KAFKA,
        help="Audit Kafka broker auth exposure and topic visibility.",
        runner_attr="run_kafka_stage",
        configure_parser=_make_configurator(configure_kafka_parser, _HTTP_MODULE_HELPERS),
    ),
    CommandSpec(
        name=COMMAND_ZOOKEEPER,
        help="Audit ZooKeeper and ClickHouse Keeper exposure, auth, transport, and znodes.",
        description=(
            "ZooKeeper module auto-detects plaintext/TLS ZooKeeper-compatible services, classifies Apache "
            "ZooKeeper and ClickHouse Keeper, and audits digest auth and znode visibility."
        ),
        runner_attr="run_zookeeper_stage",
        configure_parser=_make_configurator(configure_zookeeper_parser, (*_HTTP_MODULE_HELPERS, "positive_int")),
    ),
)

COMMAND_SPECS_BY_NAME: dict[str, CommandSpec] = {spec.name: spec for spec in COMMAND_SPECS}
EXPORTERS_ACTION_SPECS_BY_NAME: dict[str, ExportersActionSpec] = {spec.name: spec for spec in EXPORTERS_ACTION_SPECS}

DIRECT_RUNTIME_SPECS_BY_NAME: dict[str, ExportersActionSpec] = {
    COMMAND_SCAN: EXPORTERS_ACTION_SPECS_BY_NAME[COMMAND_SCAN],
    COMMAND_COLLECT: EXPORTERS_ACTION_SPECS_BY_NAME[COMMAND_COLLECT],
    COMMAND_TRIGGER: EXPORTERS_ACTION_SPECS_BY_NAME[COMMAND_TRIGGER],
    COMMAND_SELFCERT: ExportersActionSpec(
        name=COMMAND_SELFCERT,
        help="Generate self-signed certificate material.",
        runner_attr="run_selfcert_stage",
        configure_parser=lambda _parser, _helpers: None,
    ),
}


def command_names_for_error() -> str:
    names = [COMMAND_EXPORTERS, *(spec.name for spec in COMMAND_SPECS), "--selfcert"]
    return ", ".join(names)


def configure_cli_subcommands(
    subparsers: argparse._SubParsersAction[Any],
    *,
    parser_class: type[argparse.ArgumentParser],
    helpers: ParserHelperSet,
) -> None:
    exporters_parser = subparsers.add_parser(
        COMMAND_EXPORTERS,
        help="Unified exporter workflows: scan/collect/trigger.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    exporters_subparsers = exporters_parser.add_subparsers(
        dest="exporters_action",
        required=True,
        parser_class=parser_class,
    )
    for action_spec in EXPORTERS_ACTION_SPECS:
        child = exporters_subparsers.add_parser(
            action_spec.name,
            help=action_spec.help,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        action_spec.configure_parser(child, helpers)

    for spec in COMMAND_SPECS:
        parser_kwargs: dict[str, Any] = {
            "help": spec.help,
            "formatter_class": spec.formatter_class or argparse.ArgumentDefaultsHelpFormatter,
        }
        if spec.description is not None:
            parser_kwargs["description"] = spec.description
        module_parser = subparsers.add_parser(spec.name, **parser_kwargs)
        spec.configure_parser(module_parser, helpers)


__all__ = [
    "COMMAND_CLICKHOUSE",
    "COMMAND_COLLECT",
    "COMMAND_CONSUL",
    "COMMAND_DOCKER",
    "COMMAND_ELASTIC",
    "COMMAND_ETCD",
    "COMMAND_EXPORTERS",
    "COMMAND_GITLAB",
    "COMMAND_GRAFANA",
    "COMMAND_GRPC",
    "COMMAND_KAFKA",
    "COMMAND_KUBEAPI",
    "COMMAND_LISTEN",
    "COMMAND_MONGODB",
    "COMMAND_ORACLE",
    "COMMAND_POSTGRES",
    "COMMAND_PROXMOX",
    "COMMAND_QDRANT",
    "COMMAND_REDIS",
    "COMMAND_REGISTRY",
    "COMMAND_SCAN",
    "COMMAND_SELFCERT",
    "COMMAND_TRIGGER",
    "COMMAND_ZOOKEEPER",
    "AUDIT_MODULE_NAMES",
    "COMMAND_SPECS",
    "COMMAND_SPECS_BY_NAME",
    "CommandSpec",
    "DIRECT_RUNTIME_SPECS_BY_NAME",
    "EXPORTERS_ACTION_SPECS",
    "EXPORTERS_ACTION_SPECS_BY_NAME",
    "ExportersActionSpec",
    "ParserHelperSet",
    "resolve_command_runner",
    "command_names_for_error",
    "configure_cli_subcommands",
]
