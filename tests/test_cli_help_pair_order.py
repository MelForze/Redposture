"""List and selector options should be adjacent in command help."""

from __future__ import annotations

import re

import pytest

from redposture_core.cli_args import build_parser


def _option_rows(command: str) -> list[str]:
    parser = build_parser()
    subparsers = parser._subparsers._group_actions[0]
    help_text = subparsers.choices[command].format_help()
    return [line.strip() for line in help_text.splitlines() if re.match(r"^  (?:--[a-z]|-[a-z])", line)]


def _position(rows: list[str], option: str) -> int:
    pattern = rf"(?<![\w-]){re.escape(option)}(?=[\s,]|$)"
    return next(index for index, row in enumerate(rows) if re.search(pattern, row.partition("  ")[0]))


@pytest.mark.parametrize("command", ["nexus", "docker-registry", "harbor", "gitlab"])
def test_oci_help_lists_before_selectors(command: str) -> None:
    rows = _option_rows(command)
    if command == "nexus":
        assert _position(rows, "--show-repositories") + 1 == _position(rows, "--repository")
        assert _position(rows, "--repository") + 1 == _position(rows, "--show-images")
        assert _position(rows, "--image") + 1 == _position(rows, "--show-tags")
    else:
        assert not any("--show-repositories" in row for row in rows)
        assert _position(rows, "--image") + 1 == _position(rows, "--repository")
        assert _position(rows, "--repository") + 1 == _position(rows, "--show-tags")
    assert _position(rows, "--show-images") + 1 == _position(rows, "--image")
    assert _position(rows, "--show-tags") + 1 == _position(rows, "--tag")
    assert _position(rows, "--tag") + 1 == _position(rows, "--show-manifest")
    assert _position(rows, "--show-manifest") + 1 == _position(rows, "--show-metadata")
    if command == "nexus":
        assert _position(rows, "--show-metadata") + 1 == _position(rows, "--show-assets")
        assert _position(rows, "--show-assets") + 1 == _position(rows, "--asset")
        assert _position(rows, "--asset") + 1 == _position(rows, "--download")
    else:
        assert _position(rows, "--show-metadata") + 1 == _position(rows, "--download")
    assert _position(rows, "--download") + 1 == _position(rows, "--download-dir")


@pytest.mark.parametrize(
    ("command", "pairs"),
    [
        ("airflow", (("--show-dags", "--dag"), ("--show-keys", "--key"), ("--show-connections", "--connection"))),
        ("keycloak", (("--show-realms", "--realm"),)),
        ("oracle", (("--show-schemas", "--schema"), ("--show-tables", "--table"))),
        ("redis", (("--show-keys", "--key"),)),
        ("etcd", (("--show-keys", "--key"),)),
        ("kafka", (("--show-topics", "--topic"),)),
        ("zookeeper", (("--show-znodes", "--znode"),)),
        ("keeper", (("--show-znodes", "--znode"),)),
        ("minio", (("--show-buckets", "--bucket"), ("--show-objects", "--object"))),
        (
            "mongodb",
            (("--show-databases", "--database"), ("--show-collections", "--collection"), ("--show-indexes", "--index")),
        ),
        (
            "postgres",
            (("--show-databases", "--database"), ("--show-tables", "--table"), ("--show-columns", "--column")),
        ),
        (
            "clickhouse",
            (("--show-databases", "--database"), ("--show-tables", "--table"), ("--show-columns", "--column")),
        ),
        ("qdrant", (("--collections", "--collection"),)),
        (
            "consul",
            (("--keys", "--key"), ("--services", "--service"), ("--agents", "--agent"), ("--nodes", "--node")),
        ),
    ],
)
def test_other_help_list_selector_pairs_are_adjacent(command: str, pairs: tuple[tuple[str, str], ...]) -> None:
    rows = _option_rows(command)
    for show, selector in pairs:
        assert _position(rows, show) + 1 == _position(rows, selector), (command, show, selector)
