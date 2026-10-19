"""Render helpers for the mongodb audit module."""

from __future__ import annotations

from .actions import (
    _format_collections_detail_records,
    _format_credential_attempts_records,
    _format_databases_detail_records,
    _format_detect_record,
    _format_documents_detail_records,
    _format_indexes_detail_records,
    _format_nosql_command_detail_records,
    _format_partial_operation_records,
    _format_query_detail_records,
    _format_record,
    _nxc_prefix,
    _render_colored_mongodb_line,
)


def _format_grouped_inventory_detail_records(record: dict, output_format: str) -> list[str]:
    """Show documents under their collection, retaining global show limits."""
    databases = _format_databases_detail_records(record, output_format)
    collections = _format_collections_detail_records(record, output_format)
    indexes = _format_indexes_detail_records(record, output_format)
    documents = _format_documents_detail_records(record, output_format)
    if output_format != "txt" or not collections:
        return databases + collections + indexes + documents

    collection_rows = record.get("collections")
    if not isinstance(collection_rows, list):
        return databases + collections + indexes + documents
    limit = record.get("show_collections_limit")
    displayed_rows = (
        collection_rows[:limit] if isinstance(limit, int) and not isinstance(limit, bool) else collection_rows
    )
    document_rows = record.get("documents")
    document_rows = document_rows if isinstance(document_rows, list) else []
    index_rows = record.get("indexes")
    index_rows = index_rows if isinstance(index_rows, list) else []
    index_limit = record.get("show_indexes_limit")
    if isinstance(index_limit, int) and not isinstance(index_limit, bool):
        index_rows = index_rows[:index_limit]
    indexes_by_collection: dict[tuple[object, object], list[tuple[int, dict]]] = {}
    documents_by_collection: dict[tuple[object, object], list[tuple[int, dict]]] = {}
    for row_index, row in enumerate(index_rows):
        if isinstance(row, dict):
            indexes_by_collection.setdefault((row.get("database"), row.get("collection")), []).append((row_index, row))
    for row_index, row in enumerate(document_rows):
        if isinstance(row, dict):
            documents_by_collection.setdefault((row.get("database"), row.get("collection")), []).append(
                (row_index, row)
            )
    lines = databases[:1] + collections[:1] + indexes[:1] + documents[:1]
    rendered_collections: set[int] = set()
    rendered_indexes: set[int] = set()
    rendered_documents: set[int] = set()

    def append_collection(index: int, item: dict) -> None:
        rendered_collections.add(index)
        lines.extend(
            _format_collections_detail_records(
                {**record, "collections": [item], "show_collections_limit": None}, "txt"
            )[1:]
        )
        identity = (item.get("database"), item.get("collection"))
        for row_index, row in indexes_by_collection.get(identity, []):
            if row_index not in rendered_indexes:
                lines.extend(
                    _format_indexes_detail_records({**record, "indexes": [row], "show_indexes_limit": None}, "txt")[1:]
                )
                rendered_indexes.add(row_index)
        for row_index, row in documents_by_collection.get(identity, []):
            if row_index not in rendered_documents:
                lines.extend(_format_documents_detail_records({**record, "documents": [row]}, "txt")[1:])
                rendered_documents.add(row_index)

    db_names = record.get("database_names")
    db_limit = record.get("show_databases_limit")
    if isinstance(db_names, list) and databases:
        displayed_dbs = (
            db_names[:db_limit] if isinstance(db_limit, int) and not isinstance(db_limit, bool) else db_names
        )
        for db_line, db_name in zip(databases[1:], displayed_dbs, strict=False):
            lines.append(db_line)
            for index, item in enumerate(displayed_rows):
                if index not in rendered_collections and isinstance(item, dict) and item.get("database") == db_name:
                    append_collection(index, item)
    for index, item in enumerate(displayed_rows):
        if index not in rendered_collections and isinstance(item, dict):
            append_collection(index, item)
    for index, row in enumerate(index_rows):
        if index not in rendered_indexes and isinstance(row, dict):
            lines.extend(
                _format_indexes_detail_records({**record, "indexes": [row], "show_indexes_limit": None}, "txt")[1:]
            )
    for index, row in enumerate(document_rows):
        if index not in rendered_documents and isinstance(row, dict):
            lines.extend(_format_documents_detail_records({**record, "documents": [row]}, "txt")[1:])
    return lines


__all__ = [
    "_nxc_prefix",
    "_format_detect_record",
    "_format_record",
    "_format_credential_attempts_records",
    "_format_grouped_inventory_detail_records",
    "_format_query_detail_records",
    "_format_nosql_command_detail_records",
    "_format_partial_operation_records",
    "_render_colored_mongodb_line",
]
