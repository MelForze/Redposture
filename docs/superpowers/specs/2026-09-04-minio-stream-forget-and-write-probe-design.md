# MinIO: stream-forget object listing + active write-probe — design

Date: 2026-09-04
Status: approved in chat, implementing.

Two independent features for the `minio` module, both crossing existing
boundaries (shared runtime emission; the module's read-only stance).

## Part A — stream-forget object listing (removes `--limit`)

### Problem
`--show-objects` materialises every object into `record["objects"]`
(`[asdict(o) for o in ...]`) and the runtime renders the whole list at the end.
On a bucket with millions of objects this holds the entire listing in memory. The
user wants: list **all** objects, but never hold more than one page (~1000) in
memory — "read 1000, emit, forget, read the next 1000".

### Why not stream lazily at emit time
`_close_lifecycle_state` runs in a `finally` immediately after the phases
(`stage_runtime.py` ~L2291), **before** the record is emitted. The pool is dead by
emit time, so a lazy factory closing over the pool cannot re-iterate MinIO at
emit time.

### Approach: buffer to a temp file during the data phase, stream at emit
- `data_record` streams `iter_objects_multi(..., limit=None)` page by page (memory
  O(page_size)=1000) into a temp file, writing one **pre-formatted** output line
  per object and counting as it goes. It stores on the record:
  - `_stream_lines_file` = temp file path (generic runtime key; redacted from JSON)
  - `objects_count` = total written
  - `objects_streamed = True`
  - it does **not** set `objects`.
- The temp file holds final lines ready to emit:
  - TXT: `"{prefix} {bucket}/{key} (size:{n})"` (+ `(ctype:..)` when present) — the
    bare orange item, uncolored (the sink's colorize hook paints it on emit).
  - JSON: `json.dumps({"type":"object","host":..,"port":..,"bucket":..,"key":..,"size":..})`
    (NDJSON — one object per line).
- Runtime (`stage_runtime`), generic:
  - `LineOutputSink.emit_stream_file(path)` — iterate the file lazily, emit each
    line through the same colored emit under the lock; never materialise the file.
  - `_emit_record`: after the static lines (TXT) or the record JSON, if
    `record.extra["_stream_lines_file"]` is set, stream that file then delete it.
    For JSON, pop `_stream_lines_file` from the payload first. Always delete the
    temp file if present (even for suppressed records) — best-effort cleanup.
- Render (`render.py`):
  - `_format_record`: `(objects:N)` uses `objects_count` (known from the count) —
    still shown. `(buckets:N)` unchanged.
  - `_format_minio_detail_records`: for objects emit **only** the header
    `[*] Show Objects (Count:{objects_count})`; the object lines come from the temp
    file. Buckets unchanged (header + bare items).
- `enumerate.py`: `iter_objects` / `iter_objects_multi` accept `limit: int | None`
  (None = unbounded).
- CLI: remove `--limit`. Matrix `minio_enum` case: drop `--limit 5`.

### JSON contract change (approved)
minio JSON becomes NDJSON when `--show-objects`: the main record line (carrying
`objects_count`, no `objects` array) followed by one JSON object per line.

## Part B — active write-probe (`--probe-write`)

Crosses the module's read-only stance: it PUTs and DELETEs a canary. Opt-in only.

- `clients/minio_api.py`:
  - `_request` gains `body: bytes | None`; passes it to `pool.request(..., body=body)`.
  - `put_object(bucket, key, body, *, signed=True)` — PUT, SigV4 signed with the
    real payload hash `sha256(body)`.
  - `delete_object(bucket, key, *, signed=True)` — DELETE, empty payload hash.
  - `s3_sigv4.sign_request` already accepts `payload_hash`.
- `actions.probe_write_capability(client, buckets)`:
  - Per bucket: canary key `.redposture-probe-<rand>`, PUT a tiny body.
    - 200/204 → `write: True`, then DELETE → `cleanup: ok|failed`.
    - 403 / AccessDenied → `write: False`.
    - otherwise → `write: unknown`.
  - If the PUT succeeded but DELETE failed, record `leftover = bucket/key`.
  - Returns `{bucket: {write, cleanup?, leftover?}}`.
  - Runs in `data_record` when `args.probe_write`; enumerates buckets if needed
    (respects `--bucket`; otherwise all enumerated buckets — buckets are few).
  - Stores `merged["write_probe"]` and `merged["write_probe_leftovers"]`.
- Render:
  - `_format_minio_detail_records`: when `write_probe` present, append
    `(write:True|False|unknown)` to each bucket's bare line; emit
    `[!] canary left behind: <bucket>/<key>` per leftover.
  - Color: `BooleanColorRule("write")` — write access is exposure → red on True.

### Safety
Only with `--probe-write`. Random canary name. DELETE always attempted after a
successful PUT. Leftovers surfaced so the operator can remove them.

## Testing (TDD)
- enumerate: `iter_objects*` unbounded (`limit=None`).
- data_record: streams objects to a temp file, sets `objects_count` /
  `_stream_lines_file`, no `objects`; write-probe path builds `write_probe`.
- render: object header-only + `(objects:N)` from count; bucket `(write:...)`;
  leftover line.
- client: `put_object` signs with body hash + sends body; `delete_object`.
- runtime: `emit_stream_file` streams + deletes; `_emit_record` TXT and JSON paths.
- CLI: `--limit` removed (SystemExit); `--probe-write` still parses.
- Live: full listing streamed against the lab `bulk` bucket; write-probe on lab.
