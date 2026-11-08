"""Minimal DOM controls derived from actual local product pages, not title-only stubs."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path


def application_page(product: str, version: str | None = None, *, include_title: bool = True) -> str:
    rows = json.loads((Path(__file__).parent / "fixtures/detection_pages/application-markup.json").read_text())
    row = next(item for item in rows if item["product"] == product and (version is None or item["version"] == version))
    title = f"<title>{escape(row['title'])}</title>" if include_title else ""
    styles = "".join(f'<link rel="stylesheet" href="{escape(path, quote=True)}">' for path in row["styles"])
    scripts = "".join(f'<script src="{escape(path, quote=True)}"></script>' for path in row["scripts"])
    body = " ".join(f'{escape(key)}="{escape(value, quote=True)}"' for key, value in row["body"].items())
    roots = "".join(f'<div id="{escape(value, quote=True)}"></div>' for value in row["ids"])
    return f"<html><head>{title}{styles}</head><body {body}>{roots}{scripts}</body></html>"
