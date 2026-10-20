"""Product-specific OCI registry CLI parsers."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def add_oci_content_flags(group: argparse._ArgumentGroup, *, product: str) -> None:
    if product == "nexus":
        group.add_argument(
            "--show-repositories",
            action="store_true",
            help="List Nexus storage repositories with their format and type.",
        )
        group.add_argument(
            "--repository",
            metavar="name",
            help="Nexus storage for --show-images, or Docker image repository for tags and metadata.",
        )
    group.add_argument(
        "--show-images",
        "--images",
        dest="images",
        action="store_true",
        help="List accessible Docker image names and tags.",
    )
    group.add_argument("--image", metavar="name", help="Image reference for --show-manifest or --download.")
    if product != "nexus":
        group.add_argument(
            "--repository", metavar="name", help="Docker image repository for targeted tag or metadata checks."
        )
    group.add_argument(
        "--show-tags",
        action="store_true",
        help="Show tags for every accessible Docker image repository, or only --repository.",
    )
    group.add_argument("--tag", metavar="name", help="Tag for --repository and --show-metadata.")
    group.add_argument(
        "--show-manifest",
        "--inspect",
        dest="inspect",
        action="store_true",
        help="Inspect an image manifest and config.",
    )
    group.add_argument(
        "--show-metadata",
        "--metadata",
        dest="metadata",
        action="store_true",
        help="Show image config metadata for --repository and --tag.",
    )
    if product == "nexus":
        group.add_argument(
            "--show-assets", "--assets", dest="assets", action="store_true", help="Show Nexus asset URLs and checksums."
        )
        group.add_argument(
            "--asset", metavar="path-or-url", help="Show one Nexus asset by its exact path or download URL."
        )
    group.add_argument("--download", action="store_true", help="Download blobs for --image.")
    group.add_argument(
        "--download-dir",
        default="./registry_downloads",
        metavar="dir",
        help="Blob output root; endpoint/image identity directories preserve existing downloads.",
    )


def configure_oci_registry_parser(
    parser: argparse.ArgumentParser,
    *,
    product: str,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[[str], int | str],
) -> None:
    common = parser.add_argument_group("Common")
    auth = parser.add_argument_group("Auth")
    actions = parser.add_argument_group("Nexus repositories / OCI images" if product == "nexus" else "OCI images")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    defaults = {"docker-registry": "5000,15000,25000", "harbor": "80,443", "nexus": "8081"}
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=f"Port, list/range or file. Default ports: {defaults[product]}.",
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument("-f", "--format", dest="output_format", choices=("json", "txt"), default="txt")
    auth.add_argument("-u", "--username", metavar="name", help="Basic username or credentials file.")
    auth.add_argument("-p", "--password", metavar="value", help="Basic password.")
    auth.add_argument("--token", metavar="value", help="Registry Bearer token.")
    auth.add_argument("--defcreds", action="store_true", help="Check a small catalog of weak Basic pairs.")
    add_oci_content_flags(actions, product=product)


def configure_docker_registry_parser(parser: argparse.ArgumentParser, **kwargs: object) -> None:
    configure_oci_registry_parser(parser, product="docker-registry", **kwargs)  # type: ignore[arg-type]


def configure_harbor_parser(parser: argparse.ArgumentParser, **kwargs: object) -> None:
    configure_oci_registry_parser(parser, product="harbor", **kwargs)  # type: ignore[arg-type]


def configure_nexus_parser(parser: argparse.ArgumentParser, **kwargs: object) -> None:
    configure_oci_registry_parser(parser, product="nexus", **kwargs)  # type: ignore[arg-type]
