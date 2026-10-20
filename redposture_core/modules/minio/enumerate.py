"""Streaming, bounded enumeration of MinIO buckets and objects.

Pagination and limits are applied *while fetching* (generators) — a bucket with
millions of objects is never materialised in memory.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree

from ...clients.minio_api import MinioClient


@dataclass(frozen=True)
class BucketInfo:
    name: str
    creation_date: str | None = None


@dataclass(frozen=True)
class ObjectInfo:
    bucket: str
    key: str
    size: int
    last_modified: str | None = None
    etag: str | None = None
    version_id: str | None = None
    content_type: str | None = None


def _tag(elem: Any) -> str:
    return elem.tag.split("}")[-1]


def iter_buckets(
    client: MinioClient, *, limit: int | None = None, on_error: Callable[[str], None] | None = None
) -> Iterator[BucketInfo]:
    """Yield buckets. `limit=None` (default) lists all of them (buckets are few)."""
    if limit is not None and limit <= 0:
        return
    resp = client.get_service_root(signed=True)
    if resp.transport_error or resp.http_status != 200:
        if on_error is not None:
            on_error(f"ListBuckets: {resp.transport_error or f'HTTP {resp.http_status}'}")
        return
    if getattr(resp, "truncated", False):
        if on_error is not None:
            on_error("ListBuckets: truncated XML response")
        return
    try:
        root = ElementTree.fromstring(resp.body or b"")
    except ElementTree.ParseError:
        if on_error is not None:
            on_error("ListBuckets: invalid XML response")
        return
    if _tag(root) != "ListAllMyBucketsResult":
        if on_error is not None:
            on_error("ListBuckets: unexpected XML response")
        return
    count = 0
    for bucket in root.iter():
        if _tag(bucket) != "Bucket":
            continue
        name = None
        created = None
        for child in bucket:
            if _tag(child) == "Name":
                name = (child.text or "").strip()
            elif _tag(child) == "CreationDate":
                created = (child.text or "").strip() or None
        if name:
            yield BucketInfo(name=name, creation_date=created)
            count += 1
            if limit is not None and count >= limit:
                return


def _parse_page(bucket: str, body: bytes) -> tuple[list[ObjectInfo], str | None]:
    try:
        root = ElementTree.fromstring(body or b"")
    except ElementTree.ParseError as exc:
        raise ValueError("invalid XML response") from exc
    if _tag(root) != "ListBucketResult":
        raise ValueError("unexpected XML response")
    objects: list[ObjectInfo] = []
    next_token: str | None = None
    for elem in root:
        tag = _tag(elem)
        if tag == "NextContinuationToken":
            next_token = (elem.text or "").strip() or None
        elif tag == "Contents":
            key = size = mtime = etag = None
            for child in elem:
                ctag = _tag(child)
                if ctag == "Key":
                    key = child.text or ""
                elif ctag == "Size":
                    size = child.text
                elif ctag == "LastModified":
                    mtime = (child.text or "").strip() or None
                elif ctag == "ETag":
                    etag = (child.text or "").strip().strip('"') or None
            if key:
                objects.append(
                    ObjectInfo(
                        bucket=bucket,
                        key=key,
                        size=int(size) if size and str(size).isdigit() else 0,
                        last_modified=mtime,
                        etag=etag,
                    )
                )
    truncated = next(
        (str(elem.text or "").strip().lower() == "true" for elem in root if _tag(elem) == "IsTruncated"), False
    )
    if truncated and not next_token:
        raise ValueError("truncated listing without continuation token")
    return objects, next_token


def iter_objects(
    client: MinioClient,
    bucket: str,
    *,
    limit: int | None = None,
    page_size: int = 1000,
    on_error: Callable[[str], None] | None = None,
) -> Iterator[ObjectInfo]:
    """Stream objects with continuation-token pagination.

    Fetches one page at a time; never accumulates the whole listing. `limit=None`
    (default) streams the entire bucket — the caller consumes lazily so memory
    stays bounded to one page (~page_size).
    """
    if limit is not None and limit <= 0:
        return
    yielded = 0
    token: str | None = None
    seen_tokens: set[str] = set()
    while True:
        request_page_size = max(1, int(page_size))
        if limit is not None:
            request_page_size = min(request_page_size, limit - yielded)
        resp = client.list_objects_v2(
            bucket,
            max_keys=request_page_size,
            continuation_token=token,
            signed=True,
        )
        if resp.transport_error or resp.http_status != 200:
            if on_error is not None:
                on_error(f"ListObjects {bucket}: {resp.transport_error or f'HTTP {resp.http_status}'}")
            return
        try:
            if getattr(resp, "truncated", False):
                raise ValueError("truncated XML response")
            objects, next_token = _parse_page(bucket, resp.body or b"")
            if next_token and next_token in seen_tokens:
                raise ValueError("repeated continuation token")
        except ValueError as exc:
            if on_error is not None:
                on_error(f"ListObjects {bucket}: {exc}")
            return
        token = next_token
        if token:
            seen_tokens.add(token)
        for obj in objects:
            yield obj
            yielded += 1
            if limit is not None and yielded >= limit:
                return
        if not token:
            return


def iter_objects_multi(
    client: MinioClient,
    buckets: Any,
    *,
    limit: int | None = None,
    page_size: int = 1000,
    on_error: Callable[[str], None] | None = None,
) -> Iterator[ObjectInfo]:
    """Stream objects across several buckets.

    Used when the operator did not target a single `--bucket`. `limit=None`
    (default) streams every bucket fully; an int spreads that shared budget across
    buckets in order, so a huge first bucket cannot starve the rest.
    """
    if limit is None:
        for bucket in buckets:
            yield from iter_objects(client, str(bucket), limit=None, page_size=page_size, on_error=on_error)
        return
    remaining = max(0, limit)
    for bucket in buckets:
        if remaining <= 0:
            return
        for obj in iter_objects(client, str(bucket), limit=remaining, page_size=page_size, on_error=on_error):
            yield obj
            remaining -= 1
            if remaining <= 0:
                return


__all__ = ["BucketInfo", "ObjectInfo", "iter_buckets", "iter_objects", "iter_objects_multi"]
