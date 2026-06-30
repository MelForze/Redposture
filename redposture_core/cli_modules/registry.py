"""Registry CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_registry_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    mirror_group_actions: Callable[..., None],
    port_type: Callable[[str], int],
) -> None:
    common = parser.add_argument_group("Common")
    auth = parser.add_argument_group("Auth")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=(
            "Docker Registry port spec: single port, list/range, or file "
            "(examples: 5000, 5000,15000-15002, ./ports.txt). "
            "If omitted, scans 5000, 15000."
        ),
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Registry audit output format for stdout/file.",
    )

    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Registry/Harbor/GitLab/Nexus username or credential file for Basic auth.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Registry/Harbor/GitLab/Nexus password for Basic auth.",
    )
    auth.add_argument(
        "--token",
        dest="token",
        default=None,
        metavar="value",
        help="Optional Bearer token for Registry/Harbor/GitLab API auth.",
    )

    docker = parser.add_argument_group(
        "Docker / OCI (Registry v2)",
        (
            "Shared OCI content operations. These flags work with plain Docker Registry v2 and "
            "also with vendor-backed Docker registry endpoints (Harbor/GitLab/Nexus Docker)."
        ),
    )
    docker.add_argument(
        "--docker",
        action="store_true",
        help="Enable explicit Docker Registry v2/OCI mode (for clarity with vendor-specific flags).",
    )
    images_action = docker.add_argument(
        "--images",
        action="store_true",
        help="List repositories/images from /v2/_catalog and tags (when accessible).",
    )
    repository_action = docker.add_argument(
        "--repository",
        dest="repository",
        default=None,
        metavar="name",
        help="Repository name for targeted tag listing/metadata (example: gitlab/project-api).",
    )
    show_tags_action = docker.add_argument(
        "--show-tags",
        dest="show_tags",
        action="store_true",
        help="Show tags for --repository.",
    )
    tag_action = docker.add_argument(
        "--tag",
        dest="tag",
        default=None,
        metavar="name",
        help="Tag name used with --repository for --metadata.",
    )
    metadata_action = docker.add_argument(
        "--metadata",
        dest="metadata",
        action="store_true",
        help="Show config metadata (ENV/LABELS/CMD) for --repository + --tag.",
    )
    inspect_action = docker.add_argument(
        "--inspect",
        action="store_true",
        help="Inspect image metadata (ENV, exposed ports, labels, history).",
    )
    image_action = docker.add_argument(
        "--image",
        dest="image",
        default=None,
        metavar="name",
        help="Image reference for --inspect/--download (example: library/nginx:latest).",
    )
    download_action = docker.add_argument(
        "--download",
        action="store_true",
        help="Download image blobs for --image (asks confirmation when image size exceeds 100MB).",
    )
    download_dir_action = docker.add_argument(
        "--download-dir",
        dest="download_dir",
        default="./registry_downloads",
        metavar="dir",
        help="Output directory for --download files.",
    )

    harbor = parser.add_argument_group(
        "Harbor",
        (
            "Harbor API deep parsing for projects/repositories/artifacts. Combine with shared "
            "Docker/OCI flags above (--repository/--show-tags/--tag/--metadata) to inspect specific image tags."
        ),
    )
    harbor.add_argument("--harbor", action="store_true", help="Enable Harbor API deep parsing.")

    gitlab = parser.add_argument_group(
        "GitLab Container Registry",
        (
            "GitLab registry challenge/token endpoint probing and repository enumeration. "
            "Combine with shared Docker/OCI flags above for tags/metadata on a selected repo."
        ),
    )
    gitlab.add_argument(
        "--gitlab",
        action="store_true",
        help="Enable GitLab Container Registry deep parsing.",
    )

    nexus = parser.add_argument_group(
        "Nexus Repository",
        ("Nexus REST API deep parsing for repositories/components. Use --assets to print downloadUrl + checksums."),
    )
    nexus.add_argument("--nexus", action="store_true", help="Enable Nexus Repository deep parsing.")
    nexus.add_argument(
        "--assets",
        dest="assets",
        action="store_true",
        help="With --nexus, show asset downloadUrl and checksums for repository components.",
    )

    for vendor_group in (harbor, gitlab, nexus):
        mirror_group_actions(
            vendor_group,
            images_action,
            repository_action,
            show_tags_action,
            tag_action,
            metadata_action,
            inspect_action,
            image_action,
            download_action,
            download_dir_action,
        )


__all__ = ["configure_registry_parser"]
