"""Read-only ClickHouse catalog inventory with permission-aware fallbacks."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .models import ColumnInventory, TableInventory

QueryRows = Callable[[str], tuple[list[list[Any]] | None, str | None]]


def quote_identifier(value: str) -> str:
    return "`" + value.replace("`", "``") + "`"


def quote_literal(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _integer(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _catalog_inventory(query_rows: QueryRows) -> tuple[list[TableInventory] | None, list[str]]:
    errors: list[str] = []
    table_rows, error = query_rows(
        "SELECT database,name,engine,partition_key,sorting_key,primary_key,total_rows,total_bytes "
        "FROM system.tables ORDER BY database,name"
    )
    if error or table_rows is None:
        return None, [f"system.tables: {error or 'unavailable'}"]

    tables: dict[tuple[str, str], TableInventory] = {}
    for row in table_rows:
        if len(row) < 2:
            continue
        database, name = str(row[0]), str(row[1])
        tables[(database, name)] = TableInventory(
            database=database,
            name=name,
            engine=str(row[2] or "") if len(row) > 2 else "",
            partition_key=str(row[3] or "") if len(row) > 3 else "",
            sorting_key=str(row[4] or "") if len(row) > 4 else "",
            primary_key=str(row[5] or "") if len(row) > 5 else "",
            total_rows=_integer(row[6]) if len(row) > 6 else None,
            total_bytes=_integer(row[7]) if len(row) > 7 else None,
        )

    column_rows, error = query_rows(
        "SELECT database,table,name,type,position,data_compressed_bytes,data_uncompressed_bytes "
        "FROM system.columns ORDER BY database,table,position"
    )
    if error or column_rows is None:
        errors.append(f"system.columns: {error or 'unavailable'}")
        for table in tables.values():
            description, description_error = query_rows(
                f"DESCRIBE TABLE {quote_identifier(table.database)}.{quote_identifier(table.name)}"
            )
            if description_error or description is None:
                table.inventory_errors.append(description_error or "columns unavailable")
                continue
            for position, row in enumerate(description, 1):
                if len(row) >= 2:
                    table.columns.append(
                        ColumnInventory(table.database, table.name, str(row[0]), str(row[1]), position)
                    )
    else:
        for row in column_rows:
            if len(row) < 5:
                continue
            found_table = tables.get((str(row[0]), str(row[1])))
            if found_table is None:
                continue
            found_table.columns.append(
                ColumnInventory(
                    database=found_table.database,
                    table=found_table.name,
                    name=str(row[2]),
                    type_name=str(row[3]),
                    position=int(row[4] or 0),
                    compressed_bytes=int(row[5] or 0) if len(row) > 5 else 0,
                    uncompressed_bytes=int(row[6] or 0) if len(row) > 6 else 0,
                )
            )

    part_column_rows, error = query_rows(
        "SELECT database,table,column,sum(column_data_compressed_bytes),sum(column_data_uncompressed_bytes) "
        "FROM system.parts_columns WHERE active GROUP BY database,table,column ORDER BY database,table,column"
    )
    if error or part_column_rows is None:
        errors.append(f"system.parts_columns: {error or 'unavailable'}")
    else:
        part_sizes = {
            (str(row[0]), str(row[1]), str(row[2])): (int(row[3] or 0), int(row[4] or 0))
            for row in part_column_rows
            if len(row) >= 5
        }
        for table in tables.values():
            table.columns = [
                ColumnInventory(
                    column.database,
                    column.table,
                    column.name,
                    column.type_name,
                    column.position,
                    *part_sizes.get(
                        (column.database, column.table, column.name),
                        (column.compressed_bytes, column.uncompressed_bytes),
                    ),
                )
                for column in table.columns
            ]

    part_rows, error = query_rows(
        "SELECT database,table,partition_id,sum(rows),sum(bytes_on_disk),min(min_block_number),max(max_block_number) "
        "FROM system.parts WHERE active GROUP BY database,table,partition_id ORDER BY database,table,partition_id"
    )
    if error or part_rows is None:
        errors.append(f"system.parts: {error or 'unavailable'}")
    else:
        for row in part_rows:
            if len(row) < 5:
                continue
            found_table = tables.get((str(row[0]), str(row[1])))
            if found_table is None:
                continue
            found_table.partitions.append(
                {
                    "partition_id": str(row[2]),
                    "rows": int(row[3] or 0),
                    "bytes": int(row[4] or 0),
                    "min_block": _integer(row[5]) if len(row) > 5 else None,
                    "max_block": _integer(row[6]) if len(row) > 6 else None,
                }
            )
    return list(tables.values()), errors


def _fallback_inventory(query_rows: QueryRows) -> tuple[list[TableInventory], list[str]]:
    errors: list[str] = []
    database_rows, error = query_rows("SHOW DATABASES")
    if error or database_rows is None:
        return [], [f"SHOW DATABASES: {error or 'unavailable'}"]
    tables: list[TableInventory] = []
    for database_row in database_rows:
        if not database_row:
            continue
        database = str(database_row[0])
        table_rows, table_error = query_rows(f"SHOW TABLES FROM {quote_identifier(database)}")
        if table_error or table_rows is None:
            errors.append(f"{database}: {table_error or 'tables unavailable'}")
            continue
        for table_row in table_rows:
            if not table_row:
                continue
            table = TableInventory(database=database, name=str(table_row[0]))
            description, description_error = query_rows(
                f"DESCRIBE TABLE {quote_identifier(database)}.{quote_identifier(table.name)}"
            )
            if description_error or description is None:
                table.inventory_errors.append(description_error or "columns unavailable")
            else:
                for position, row in enumerate(description, 1):
                    if len(row) >= 2:
                        table.columns.append(ColumnInventory(database, table.name, str(row[0]), str(row[1]), position))
            tables.append(table)
    return tables, errors


def collect_inventory(query_rows: QueryRows) -> tuple[list[TableInventory], list[str]]:
    tables, errors = _catalog_inventory(query_rows)
    if tables is not None:
        return tables, errors
    fallback, fallback_errors = _fallback_inventory(query_rows)
    return fallback, errors + fallback_errors


def is_content_type(type_name: str) -> bool:
    """Return whether a ClickHouse type can contain searchable text."""

    normalized = "".join(type_name.split()).lower()
    if any(token in normalized for token in ("string", "json", "object(", "dynamic", "map(", "variant(")):
        return True
    return False


__all__ = ["collect_inventory", "is_content_type", "quote_identifier", "quote_literal"]
