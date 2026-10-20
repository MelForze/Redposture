"""Jupyter Server output follows the Airflow color convention."""

from typing import Any

from ..token_render import colorize, credential, detect, inventory


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    return detect("jupyter", "Jupyter Server", record, output_format)


def _format_record(record: dict[str, Any], output_format: str) -> str:
    return credential("jupyter", record, output_format)


def _format_inventory_records(record: dict[str, Any], output_format: str) -> list[str]:
    return inventory("jupyter", record, output_format)


def _render_colored_jupyter_line(console: Any, line: str) -> bool:
    return colorize(console, line, "jupyter")
