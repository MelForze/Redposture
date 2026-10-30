"""Bounded native column decoding using SDK type factories and scalar codecs.

Composite offsets, null maps, dictionaries and values are stored on disk. No
server JSON conversion is used: native numbers/dates/tuples keep their types.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from ....discovery_bytes import SpoolBytes
from .native_values import NativeRows, NativeValues, _Sequence


class PartialColumn(Exception):
    def __init__(self, values: _Sequence, error: Exception) -> None:
        self.values, self.error = values, error
        super().__init__(str(error))


@dataclass
class NativeReadState:
    remaining: int = 0
    delivered: int = 0
    buffered: NativeRows | None = None

    def take_remaining(self, *, include_current: bool = False) -> NativeRows | None:
        if self.buffered is None:
            return None
        start = len(self.buffered) - self.remaining - int(include_current)
        self.remaining = 0
        return self.buffered[max(0, start) :]


class NativeBlock:
    def __init__(
        self,
        columns: list[tuple[str, str]],
        data: list[_Sequence],
        info: Any,
        declared_columns: int,
        owner: NativeValues,
        error: Exception | None = None,
    ) -> None:
        self.columns_with_types = columns
        self.data, self.info, self.error = data, info, error
        self.declared_columns = declared_columns
        self.owner = owner
        self.read_state: NativeReadState | None = None

    @property
    def num_rows(self) -> int:
        return min(map(len, self.data), default=0) if len(self.data) == self.declared_columns else 0

    @property
    def num_columns(self) -> int:
        return len(self.data)

    def get_columns(self) -> list[_Sequence]:
        return self.data

    def get_column_by_index(self, index: int) -> _Sequence:
        return self.data[index]

    def row_view(self) -> NativeRows:
        return NativeRows(self.owner, tuple(column.node for column in self.data), range(self.num_rows))

    def get_rows(self) -> Iterator[Any]:
        if len(self.data) == self.declared_columns:
            for row in self.row_view():
                if self.read_state is not None:
                    self.read_state.remaining -= 1
                    self.read_state.delivered += 1
                yield row
        if self.error is not None:
            raise self.error


def _offsets(owner: NativeValues, count: int, buf: Any) -> _Sequence:
    offsets = owner.sequence()
    previous = 0
    for _ in range(count):
        buf._check()
        value = struct.unpack("<Q", buf.read(8))[0]
        if value < previous:
            raise ValueError("non-monotonic native offsets")
        offsets.append(value)
        previous = value
    return offsets


def _nulls(count: int, buf: Any) -> SpoolBytes:
    result = SpoolBytes()
    remaining = count
    while remaining:
        buf._check()
        part = buf.read(min(65536, remaining))
        if not part:
            raise EOFError("truncated native null map")
        if any(value not in (0, 1) for value in part):
            raise ValueError("invalid native null map")
        result.write(part)
        remaining -= len(part)
    return result


def _array(column: Any, count: int, buf: Any, owner: NativeValues) -> _Sequence:
    result = owner.sequence()
    try:
        offsets = _offsets(owner, count, buf)
        total = offsets[-1] if offsets else 0
        error = None
        try:
            values = read_data(column.nested_column, total, buf, owner)
        except PartialColumn as exc:
            values, error = exc.values, exc.error
        start = 0
        for end in offsets:
            buf._check()
            array = owner.sequence()
            for index in range(start, min(end, len(values))):
                buf._check()
                array.append_node(values.node_at(index))
            if end <= len(values) or len(array):
                result.append_node(array.node)
            if end > len(values):
                break
            start = end
        if error is not None:
            raise PartialColumn(result, error)
        return result

    except PartialColumn:
        raise
    except Exception as exc:
        raise PartialColumn(result, exc) from exc


def _map(column: Any, count: int, buf: Any, owner: NativeValues) -> _Sequence:
    result = owner.sequence()
    try:
        offsets = _offsets(owner, count, buf)
        total = offsets[-1] if offsets else 0
        pending_keys = [column.key_column]
        while pending_keys:
            key_schema = pending_keys.pop()
            if hasattr(key_schema, "names"):
                key_schema._native_key_tuple = True
                pending_keys.extend(key_schema.nested_columns)
            for attr in ("nested_column", "key_column", "value_column"):
                nested = getattr(key_schema, attr, None)
                if nested is not None:
                    pending_keys.append(nested)
        try:
            keys = read_data(column.key_column, total, buf, owner)
        except PartialColumn as exc:
            # Keys alone are not completed map entries; do not expose them as rows.
            raise PartialColumn(result, exc.error) from exc
        error = None
        try:
            values = read_data(column.value_column, total, buf, owner)
        except PartialColumn as exc:
            values, error = exc.values, exc.error
        start = 0
        for end in offsets:
            buf._check()
            item = owner.mapping()
            for index in range(start, min(end, len(values))):
                buf._check()
                owner.put(item.node, keys.node_at(index), values.node_at(index), preserve_entries=True)
            if end <= len(values) or len(item):
                result.append_node(item.node)
            if end > len(values):
                break
            start = end
        if error is not None:
            raise PartialColumn(result, error)
        return result

    except PartialColumn:
        raise
    except Exception as exc:
        raise PartialColumn(result, exc) from exc


def _tuple(column: Any, count: int, buf: Any, owner: NativeValues) -> _Sequence:
    result = owner.sequence()
    try:
        children: list[_Sequence] = []
        error = None
        for child in column.nested_columns:
            try:
                children.append(read_data(child, count, buf, owner))
            except PartialColumn as exc:
                children.append(exc.values)
                error = exc.error
                break
        if len(children) == len(column.nested_columns):
            size = min(map(len, children), default=count)
            for index in range(size):
                buf._check()
                if column.names[0] and not getattr(column, "_native_key_tuple", False):
                    item = owner.mapping()
                    for name, child in zip(column.names, children, strict=True):
                        buf._check()
                        owner.put(item.node, owner.scalar(name), child.node_at(index))
                else:
                    sequence_item = owner.sequence(tuple_value=True)
                    for child in children:
                        buf._check()
                        sequence_item.append_node(child.node_at(index))
                    result.append_node(sequence_item.node)
                    continue
                result.append_node(item.node)
        if error is not None:
            raise PartialColumn(result, error)
        return result

    except PartialColumn:
        raise
    except Exception as exc:
        raise PartialColumn(result, exc) from exc


def _low_cardinality(column: Any, count: int, buf: Any, owner: NativeValues) -> _Sequence:
    result = owner.sequence()
    if not count:
        return result
    from clickhouse_driver.reader import read_binary_uint64

    flags = read_binary_uint64(buf)
    key_type = flags & 0xFF
    if key_type not in column.int_types or flags & (1 << 8):
        raise ValueError("unsupported native LowCardinality dictionary flags")
    size = read_binary_uint64(buf)
    child = column.nested_column
    nullable = child.nullable
    child.nullable = False
    try:
        values = read_data(child, size, buf, owner)
    finally:
        child.nullable = nullable
    if read_binary_uint64(buf) != count:
        raise ValueError("native LowCardinality key count mismatch")
    keys_column = column.int_types[key_type](**column.init_kwargs)
    try:
        for _ in range(count):
            buf._check()
            key = keys_column.read_items(1, buf)[0]
            if nullable and key == 0:
                result.append(None)
            else:
                result.append_node(values.node_at(key))
    except Exception as exc:
        raise PartialColumn(result, exc) from exc
    return result


def _sparse(column: Any, count: int, buf: Any, owner: NativeValues) -> tuple[int, _Sequence | None]:
    from clickhouse_driver.columns.base import SparseSerialization
    from clickhouse_driver.varint import read_varint

    if not isinstance(column.serialization, SparseSerialization):
        return count, None
    indices = owner.sequence()
    total = 0
    while True:
        buf._check()
        group = read_varint(buf)
        last = bool(group & (1 << 62))
        total += (group & ~(1 << 62)) + 1
        if total - 1 > count:
            raise ValueError("native sparse length overflow")
        if last:
            break
        indices.append(total - 1)
    if total - 1 != count:
        raise ValueError("native sparse length mismatch")
    return len(indices), indices


def _expand_sparse(
    column: Any,
    count: int,
    values: _Sequence,
    positions: _Sequence,
    buf: Any,
    owner: NativeValues,
    *,
    partial: bool = False,
) -> _Sequence:
    expanded = owner.sequence()
    default = column.null_value
    if column.after_read_items:
        default = column.after_read_items([default])[0]
    if isinstance(default, bytes):
        default = default.decode("utf-8", errors="replace")
    default_node = owner.scalar(default)
    indices = iter(positions)
    next_position = next(indices, count)
    stop = positions[len(values)] if partial and len(values) < len(positions) else count
    element = 0
    try:
        for index in range(stop):
            buf._check()
            if index == next_position:
                expanded.append_node(values.node_at(element))
                element += 1
                next_position = next(indices, count)
            else:
                expanded.append_node(default_node)
    except Exception as exc:
        raise PartialColumn(expanded, exc) from exc
    return expanded


def read_data(column: Any, count: int, buf: Any, owner: NativeValues) -> _Sequence:
    from clickhouse_driver.columns.arraycolumn import ArrayColumn
    from clickhouse_driver.columns.jsoncolumn import JsonColumn
    from clickhouse_driver.columns.lowcardinalitycolumn import LowCardinalityColumn
    from clickhouse_driver.columns.mapcolumn import MapColumn
    from clickhouse_driver.columns.stringcolumn import ByteFixedString, ByteString, FixedString, String
    from clickhouse_driver.columns.tuplecolumn import TupleColumn
    from clickhouse_driver.reader import read_binary_str, read_binary_uint8
    from clickhouse_driver.varint import read_varint

    result = owner.sequence()
    sparse = None
    expanding = False
    try:
        if isinstance(column, ArrayColumn):
            return _array(column, count, buf, owner)
        if isinstance(column, TupleColumn):
            return _tuple(column, count, buf, owner)
        encoded_count, sparse = _sparse(column, count, buf, owner)
        nulls = _nulls(encoded_count, buf) if column.nullable else None
        if isinstance(column, MapColumn):
            result = _map(column, encoded_count, buf, owner)
        elif isinstance(column, LowCardinalityColumn):
            result = _low_cardinality(column, encoded_count, buf, owner)
        elif isinstance(column, JsonColumn):
            read_binary_uint8(buf)
            child = column.column_by_spec_getter(read_binary_str(buf))
            child.read_state_prefix(buf)
            result = read_data(child, encoded_count, buf, owner)
        else:
            for index in range(encoded_count):
                buf._check()
                if isinstance(column, String):
                    length = column.length if isinstance(column, FixedString) else read_varint(buf)
                    encoding = None if isinstance(column, (ByteString, ByteFixedString)) else column.encoding
                    value = buf._value(length, encoding, fixed=isinstance(column, FixedString))
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="replace")
                else:
                    items = column._read_data(1, buf, nulls_map=[bool(nulls[index])] if nulls is not None else None)
                    value = items[0]
                result.append(None if nulls is not None and nulls[index] else value)
        if sparse is not None:
            expanding = True
            return _expand_sparse(column, count, result, sparse, buf, owner)
        return result
    except PartialColumn as exc:
        if sparse is not None and not expanding:
            prefix = _expand_sparse(column, count, exc.values, sparse, buf, owner, partial=True)
            raise PartialColumn(prefix, exc.error) from exc
        raise
    except Exception as exc:
        if sparse is not None:
            result = _expand_sparse(column, count, result, sparse, buf, owner, partial=True)
        raise PartialColumn(result, exc) from exc


def read_block(stream: Any, owner: NativeValues) -> NativeBlock:
    from clickhouse_driver import defines
    from clickhouse_driver.block import BlockInfo
    from clickhouse_driver.columns.service import get_column_by_spec
    from clickhouse_driver.reader import read_binary_str, read_binary_uint8
    from clickhouse_driver.varint import read_varint

    buf = stream.fin
    info = BlockInfo()
    revision = stream.context.server_info.used_revision
    if revision >= defines.DBMS_MIN_REVISION_WITH_BLOCK_INFO:
        info.read(buf)
    column_count, row_count = read_varint(buf), read_varint(buf)
    columns: list[tuple[str, str]] = []
    data: list[_Sequence] = []
    error: Exception | None = None
    for _ in range(column_count):
        try:
            name, spec = read_binary_str(buf), read_binary_str(buf)
            columns.append((name, spec))
            custom = (
                bool(read_binary_uint8(buf))
                if revision >= defines.DBMS_MIN_REVISION_WITH_CUSTOM_SERIALIZATION
                else False
            )
            if row_count:
                column = get_column_by_spec(
                    spec, {"context": stream.context, "has_custom_serialization": custom}, use_numpy=False
                )
                column.read_state_prefix(buf)
                data.append(read_data(column, row_count, buf, owner))
        except PartialColumn as exc:
            data.append(exc.values)
            error = exc.error
            break
        except Exception as exc:
            error = exc
            break
    return NativeBlock(columns, data, info, column_count if row_count else 0, owner, error)
