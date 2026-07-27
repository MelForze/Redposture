from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from google.protobuf import (
    any_pb2,
    descriptor_pb2,
    duration_pb2,
    empty_pb2,
    field_mask_pb2,
    struct_pb2,
    timestamp_pb2,
    wrappers_pb2,
)

from redposture_core.cli_args import parse_args
from redposture_core.clients import grpc as grpc_client
from redposture_core.modules.grpc import stage as grpc_stage
from redposture_core.stage_runtime import AuditCommandResult, AuditRecord, render_record_with_module


def _add_field(
    message: descriptor_pb2.DescriptorProto,
    *,
    name: str,
    number: int,
    field_type: int,
    label: int = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
    type_name: str = "",
    oneof_index: int | None = None,
    proto3_optional: bool = False,
) -> descriptor_pb2.FieldDescriptorProto:
    field = message.field.add(name=name, number=number, type=field_type, label=label)
    if type_name:
        field.type_name = type_name
    if oneof_index is not None:
        field.oneof_index = oneof_index
    field.proto3_optional = proto3_optional
    return field


def _rich_openapi_descriptors() -> list[bytes]:
    file_proto = descriptor_pb2.FileDescriptorProto(name="rich.proto", package="demo", syntax="proto3")
    file_proto.dependency.extend(
        [
            "google/protobuf/any.proto",
            "google/protobuf/duration.proto",
            "google/protobuf/empty.proto",
            "google/protobuf/field_mask.proto",
            "google/protobuf/struct.proto",
            "google/protobuf/timestamp.proto",
            "google/protobuf/wrappers.proto",
        ]
    )
    request = file_proto.message_type.add(name="Request")
    map_entry = request.nested_type.add(name="LabelsEntry")
    map_entry.options.map_entry = True
    _add_field(
        map_entry,
        name="key",
        number=1,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
    )
    _add_field(
        map_entry,
        name="value",
        number=2,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_INT64,
    )
    numeric_map_entry = request.nested_type.add(name="CountsEntry")
    numeric_map_entry.options.map_entry = True
    _add_field(
        numeric_map_entry,
        name="key",
        number=1,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_INT64,
    )
    _add_field(
        numeric_map_entry,
        name="value",
        number=2,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
    )
    request.oneof_decl.add(name="choice")
    request.oneof_decl.add(name="_note")
    _add_field(
        request,
        name="labels",
        number=1,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
        type_name=".demo.Request.LabelsEntry",
    )
    _add_field(
        request,
        name="total_count",
        number=2,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_INT64,
    )
    _add_field(
        request,
        name="name",
        number=3,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
        oneof_index=0,
    )
    _add_field(
        request,
        name="id",
        number=4,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_INT32,
        oneof_index=0,
    )
    _add_field(
        request,
        name="note",
        number=5,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
        oneof_index=1,
        proto3_optional=True,
    )
    for number, name, type_name in (
        (6, "created_at", ".google.protobuf.Timestamp"),
        (7, "ttl", ".google.protobuf.Duration"),
        (8, "payload", ".google.protobuf.Any"),
        (9, "data", ".google.protobuf.Struct"),
        (10, "wrapped_count", ".google.protobuf.Int64Value"),
        (11, "mask", ".google.protobuf.FieldMask"),
        (13, "wrapped_ratio", ".google.protobuf.DoubleValue"),
    ):
        _add_field(
            request,
            name=name,
            number=number,
            field_type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
            type_name=type_name,
        )
    _add_field(
        request,
        name="counts",
        number=12,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
        type_name=".demo.Request.CountsEntry",
    )
    _add_field(
        request,
        name="ratio",
        number=14,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE,
    )
    service = file_proto.service.add(name="API")
    service.method.add(
        name="Call",
        input_type=".demo.Request",
        output_type=".google.protobuf.Empty",
    )
    dependencies = [
        any_pb2.DESCRIPTOR.serialized_pb,
        duration_pb2.DESCRIPTOR.serialized_pb,
        empty_pb2.DESCRIPTOR.serialized_pb,
        field_mask_pb2.DESCRIPTOR.serialized_pb,
        struct_pb2.DESCRIPTOR.serialized_pb,
        timestamp_pb2.DESCRIPTOR.serialized_pb,
        wrappers_pb2.DESCRIPTOR.serialized_pb,
    ]
    return [*dependencies, file_proto.SerializeToString()]


def _single_method_descriptor(file_name: str, package: str) -> bytes:
    file_proto = descriptor_pb2.FileDescriptorProto(name=file_name, package=package, syntax="proto3")
    file_proto.message_type.add(name="Request")
    file_proto.message_type.add(name="Response")
    service = file_proto.service.add(name="API")
    service.method.add(
        name="Call",
        input_type=f".{package}.Request",
        output_type=f".{package}.Response",
    )
    return file_proto.SerializeToString()


def _encoded_descriptors(*blobs: bytes) -> list[str]:
    return [base64.b64encode(blob).decode("ascii") for blob in blobs]


def test_openapi_models_proto_json_maps_int64_oneof_optional_and_well_known_types() -> None:
    document = grpc_client._generate_openapi_document(_rich_openapi_descriptors())

    assert document["paths"]["/demo.API/Call"]["post"]["operationId"] == "demo_API_Call"
    request_schema = document["components"]["schemas"]["demo.Request"]
    properties = request_schema["properties"]
    assert properties["labels"] == {
        "type": "object",
        "additionalProperties": {
            "type": "string",
            "pattern": r"^-?[0-9]+$",
            "x-protobuf-type": "int64",
        },
        "x-protobuf-map-key-type": "string",
    }
    assert properties["totalCount"]["type"] == "string"
    assert properties["totalCount"]["x-protobuf-field-name"] == "total_count"
    assert properties["counts"]["propertyNames"] == {"pattern": r"^-?[0-9]+$"}
    assert properties["counts"]["x-protobuf-map-key-type"] == "int64"
    assert request_schema["x-protobuf-oneofs"] == {"choice": ["name", "id"]}
    assert len(request_schema["oneOf"]) == 3
    assert properties["note"]["x-protobuf-optional"] is True
    assert "x-protobuf-oneof" not in properties["note"]

    schemas = document["components"]["schemas"]
    assert schemas["google.protobuf.Timestamp"]["format"] == "date-time"
    assert schemas["google.protobuf.Duration"]["type"] == "string"
    assert schemas["google.protobuf.Any"]["required"] == ["@type"]
    assert schemas["google.protobuf.Empty"]["additionalProperties"] is False
    assert schemas["google.protobuf.Struct"]["additionalProperties"] == {
        "$ref": "#/components/schemas/google.protobuf.Value"
    }
    assert schemas["google.protobuf.ListValue"]["items"] == {"$ref": "#/components/schemas/google.protobuf.Value"}
    assert schemas["google.protobuf.Int64Value"]["type"] == ["string", "null"]
    assert {variant.get("type") for variant in schemas["google.protobuf.DoubleValue"]["oneOf"]} == {
        "number",
        "string",
        "null",
    }
    assert schemas["google.protobuf.FieldMask"]["type"] == "string"
    assert {variant["type"] for variant in properties["ratio"]["oneOf"]} == {"number", "string"}


def test_openapi_servers_use_discovered_urls_without_localhost() -> None:
    document = grpc_client._generate_openapi_document(
        [_single_method_descriptor("servers.proto", "servers")],
        server_urls=[
            "https://10.17.216.154:50053",
            "http://[2001:db8::3]:50051",
            "https://10.17.216.154:50053",
        ],
    )

    assert document["servers"] == [
        {"url": "http://[2001:db8::3]:50051"},
        {"url": "https://10.17.216.154:50053"},
    ]
    assert "localhost" not in json.dumps(document["servers"])


def test_openapi_reports_conflicting_same_name_descriptor_variants() -> None:
    first = _single_method_descriptor("shared.proto", "first")
    second = _single_method_descriptor("shared.proto", "second")

    document = grpc_client._generate_openapi_document([first, second])
    reversed_document = grpc_client._generate_openapi_document([second, first])

    assert document["paths"] == reversed_document["paths"]
    assert grpc_client._dedup_descriptor_bytes([first, second]) == grpc_client._dedup_descriptor_bytes([second, first])
    conflicts = document["x-redposture"]["descriptor_conflicts"]
    assert conflicts == reversed_document["x-redposture"]["descriptor_conflicts"]
    assert len(conflicts) == 1
    assert conflicts[0]["file"] == "shared.proto"
    assert len(conflicts[0]["variants"]) == 2
    assert conflicts[0]["selection_policy"] == "lowest_normalized_sha256"
    assert conflicts[0]["selected_sha256"] == min(item["sha256"] for item in conflicts[0]["variants"])
    descriptor_digests: dict[str, str] = {}
    for package, blob in (("first", first), ("second", second)):
        file_proto = descriptor_pb2.FileDescriptorProto()
        file_proto.ParseFromString(blob)
        descriptor_digests[package] = hashlib.sha256(grpc_client._normalized_descriptor_bytes(file_proto)).hexdigest()
    selected_package = min(descriptor_digests, key=descriptor_digests.__getitem__)
    assert set(document["paths"]) == {f"/{selected_package}.API/Call"}


def test_openapi_ignores_source_locations_when_comparing_descriptor_variants() -> None:
    first = descriptor_pb2.FileDescriptorProto()
    first.ParseFromString(_single_method_descriptor("shared.proto", "demo"))
    with_source_info = descriptor_pb2.FileDescriptorProto()
    with_source_info.CopyFrom(first)
    location = with_source_info.source_code_info.location.add()
    location.path.extend([4, 0])
    location.span.extend([1, 0, 1, 10])

    document = grpc_client._generate_openapi_document([first.SerializeToString(), with_source_info.SerializeToString()])

    assert document["x-redposture"]["descriptor_count"] == 1
    assert "descriptor_conflicts" not in document["x-redposture"]


def test_explicit_protosets_preserve_same_name_variants_for_openapi_diagnostics(tmp_path: Path) -> None:
    first = descriptor_pb2.FileDescriptorProto()
    first.ParseFromString(_single_method_descriptor("shared.proto", "first"))
    second = descriptor_pb2.FileDescriptorProto()
    second.ParseFromString(_single_method_descriptor("shared.proto", "second"))
    first_path = tmp_path / "first.protoset"
    second_path = tmp_path / "second.protoset"
    first_path.write_bytes(descriptor_pb2.FileDescriptorSet(file=[first]).SerializeToString())
    second_path.write_bytes(descriptor_pb2.FileDescriptorSet(file=[second]).SerializeToString())

    descriptors = grpc_client._load_explicit_descriptor_bytes(
        None,
        None,
        [str(second_path), str(first_path)],
    )
    document = grpc_client._generate_openapi_document(descriptors)

    assert len(descriptors) == 2
    assert len(document["x-redposture"]["descriptor_conflicts"]) == 1


def test_openapi_reports_malformed_descriptor_bytes() -> None:
    valid = _single_method_descriptor("valid.proto", "valid")
    malformed = b"\xff"
    missing_name = b"\x08\x01"

    document = grpc_client._generate_openapi_document([valid, malformed, malformed, missing_name])

    malformed_digest = hashlib.sha256(malformed).hexdigest()
    missing_name_digest = hashlib.sha256(missing_name).hexdigest()
    assert set(document["paths"]) == {"/valid.API/Call"}
    assert document["x-redposture"]["descriptor_count"] == 1
    assert set(document["x-redposture"]["descriptor_errors"]) == {
        f"invalid descriptor sha256={malformed_digest}: malformed FileDescriptorProto",
        f"invalid descriptor sha256={missing_name_digest}: missing file name",
    }


def test_openapi_reports_cross_file_duplicate_protobuf_symbols() -> None:
    first_proto = descriptor_pb2.FileDescriptorProto()
    first_proto.ParseFromString(_single_method_descriptor("first.proto", "shared"))
    second_proto = descriptor_pb2.FileDescriptorProto()
    second_proto.ParseFromString(_single_method_descriptor("second.proto", "shared"))
    for file_proto in (first_proto, second_proto):
        enum = file_proto.enum_type.add(name="Mode")
        enum.value.add(name="MODE_UNSPECIFIED", number=0)

    first_bytes = first_proto.SerializeToString()
    second_bytes = second_proto.SerializeToString()
    document = grpc_client._generate_openapi_document([second_bytes, first_bytes])
    reversed_document = grpc_client._generate_openapi_document([first_bytes, second_bytes])

    assert document == reversed_document
    conflicts = document["x-redposture"]["descriptor_symbol_conflicts"]
    assert {item["symbol"] for item in conflicts} == {
        "shared.API",
        "shared.Mode",
        "shared.Request",
        "shared.Response",
    }
    assert all(item["files"] == ["first.proto", "second.proto"] for item in conflicts)
    assert all("duplicate protobuf symbol shared." in error for error in document["x-redposture"]["descriptor_errors"])


def test_openapi_component_keys_do_not_collide_when_packages_contain_underscores() -> None:
    first = _single_method_descriptor("first.proto", "a.b_c")
    second = _single_method_descriptor("second.proto", "a_b.c")

    document = grpc_client._generate_openapi_document([first, second])

    schemas = document["components"]["schemas"]
    assert "a.b_c.Request" in schemas
    assert "a_b.c.Request" in schemas
    assert document["paths"]["/a.b_c.API/Call"]["post"]["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/a.b_c.Request"
    }
    assert document["paths"]["/a_b.c.API/Call"]["post"]["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/a_b.c.Request"
    }
    operation_ids = {operation["post"]["operationId"] for operation in document["paths"].values()}
    assert len(operation_ids) == 2


def test_openapi_stage_aggregates_and_deduplicates_all_target_descriptors(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    first = _single_method_descriptor("first.proto", "first")
    second = _single_method_descriptor("second.proto", "second")

    def _run_plan(_self: Any, _plan: Any) -> AuditCommandResult:
        return AuditCommandResult(
            records=[
                {
                    "host": "10.0.0.1",
                    "port": 50051,
                    "is_grpc": True,
                    "transport_mode": "plaintext",
                    "descriptor_protos_b64": _encoded_descriptors(first),
                },
                {
                    "host": "10.0.0.2",
                    "port": 50052,
                    "is_grpc": True,
                    "transport_mode": "tls",
                    "descriptor_protos_b64": _encoded_descriptors(first, second),
                },
                {
                    "host": "2001:db8::3",
                    "port": 50053,
                    "is_grpc": True,
                    "transport_mode": "plaintext",
                    "descriptor_protos_b64": None,
                },
            ],
            detected_count=3,
            emitted_lines=0,
            typed_records=[],
        )

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", _run_plan)
    output_path = tmp_path / "grpc.openapi.json"
    args = parse_args(["grpc", "-t", "127.0.0.1", "--openapi", str(output_path)])

    assert grpc_stage.run_grpc_stage(args, SimpleNamespace(log=lambda *_args, **_kwargs: None)) == 0

    document = json.loads(output_path.read_text(encoding="utf-8"))
    assert set(document["paths"]) == {"/first.API/Call", "/second.API/Call"}
    assert document["servers"] == [
        {"url": "http://10.0.0.1:50051"},
        {"url": "http://[2001:db8::3]:50053"},
        {"url": "https://10.0.0.2:50052"},
    ]
    assert document["x-redposture"] == {
        "descriptor_count": 2,
        "descriptor_errors": [],
        "descriptor_targets": {
            "10.0.0.1:50051": True,
            "10.0.0.2:50052": True,
            "[2001:db8::3]:50053": False,
        },
        "descriptors_obtained": True,
        "targets_without_descriptors": ["[2001:db8::3]:50053"],
    }
    output = capsys.readouterr().out
    assert "descriptors were not obtained for targets: [2001:db8::3]:50053" in output
    assert f"gRPC OpenAPI exported: {output_path} (2 operations)" in output


def test_openapi_without_path_uses_endpoint_filename_and_compact_rendering(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    descriptor = _single_method_descriptor("auto.proto", "auto")

    def _run_plan(_self: Any, _plan: Any) -> AuditCommandResult:
        return AuditCommandResult(
            records=[
                {
                    "host": "10.17.216.154",
                    "port": 50053,
                    "is_grpc": True,
                    "transport_mode": "tls",
                    "descriptor_protos_b64": _encoded_descriptors(descriptor),
                }
            ],
            detected_count=1,
            emitted_lines=1,
            typed_records=[],
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", _run_plan)
    args = parse_args(["grpc", "-t", "10.17.216.154", "--port", "50053", "--openapi"])

    assert grpc_stage.run_grpc_stage(args, SimpleNamespace(log=lambda *_args, **_kwargs: None)) == 0

    output_path = tmp_path / "openapi_10.17.216.154_50053.json"
    assert output_path.is_file()
    document = json.loads(output_path.read_text(encoding="utf-8"))
    assert set(document["paths"]) == {"/auto.API/Call"}
    assert document["servers"] == [{"url": "https://10.17.216.154:50053"}]
    assert "gRPC OpenAPI exported: openapi_10.17.216.154_50053.json (1 operation)" in capsys.readouterr().out

    record = AuditRecord.from_mapping(
        {
            "host": "10.17.216.154",
            "port": 50053,
            "status": "detected",
            "is_grpc": True,
            "transport_mode": "tls",
            "protocol_flavor": "grpc",
            "reflection_enabled": True,
            "analysis_performed": True,
            "services": ["auto.API"],
        },
        module="grpc",
        service="grpc",
    )
    compact_lines = render_record_with_module(grpc_stage.build_grpc_spec(args).render_module, record, "txt")
    assert any("gRPC Service" in line for line in compact_lines)
    assert not any("Services" in line or "service=auto.API" in line for line in compact_lines)

    analyzed_args = parse_args(["grpc", "-t", "10.17.216.154", "--port", "50053", "--analyze", "--openapi"])
    analyzed_lines = render_record_with_module(
        grpc_stage.build_grpc_spec(analyzed_args).render_module,
        record,
        "txt",
    )
    assert any("service=auto.API" in line for line in analyzed_lines)


def test_openapi_without_path_uses_merged_filename_for_multiple_targets() -> None:
    args = parse_args(["grpc", "-t", "10.0.0.1,10.0.0.2", "--openapi"])
    plan = grpc_stage.build_grpc_plan(args)

    assert grpc_stage._resolve_openapi_path(args, plan) == "openapi_merged.json"


def test_openapi_stage_writes_empty_artifact_and_reports_missing_descriptors(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    def _run_plan(_self: Any, _plan: Any) -> AuditCommandResult:
        return AuditCommandResult(
            records=[
                {
                    "host": "10.0.0.1",
                    "port": 50051,
                    "is_grpc": True,
                    "transport_mode": "plaintext",
                    "descriptor_protos_b64": None,
                }
            ],
            detected_count=1,
            emitted_lines=0,
            typed_records=[],
        )

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", _run_plan)
    output_path = tmp_path / "grpc.openapi.json"
    args = parse_args(["grpc", "-t", "127.0.0.1", "--openapi", str(output_path)])

    assert grpc_stage.run_grpc_stage(args, SimpleNamespace(log=lambda *_args, **_kwargs: None)) == 0

    document = json.loads(output_path.read_text(encoding="utf-8"))
    assert document["paths"] == {}
    assert document["servers"] == [{"url": "http://10.0.0.1:50051"}]
    assert document["x-redposture"]["descriptors_obtained"] is False
    assert document["x-redposture"]["targets_without_descriptors"] == ["10.0.0.1:50051"]
    assert "descriptors were not obtained from any target" in capsys.readouterr().out


def test_openapi_stage_preserves_cross_target_descriptor_conflicts(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    first = _single_method_descriptor("shared.proto", "first")
    second = _single_method_descriptor("shared.proto", "second")

    def _run_plan(_self: Any, _plan: Any) -> AuditCommandResult:
        return AuditCommandResult(
            records=[
                {
                    "host": "10.0.0.1",
                    "port": 50051,
                    "is_grpc": True,
                    "transport_mode": "plaintext",
                    "descriptor_protos_b64": _encoded_descriptors(first),
                },
                {
                    "host": "10.0.0.2",
                    "port": 50052,
                    "is_grpc": True,
                    "transport_mode": "tls",
                    "descriptor_protos_b64": _encoded_descriptors(second),
                },
            ],
            detected_count=2,
            emitted_lines=0,
            typed_records=[],
        )

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", _run_plan)
    output_path = tmp_path / "grpc.openapi.json"
    args = parse_args(["grpc", "-t", "127.0.0.1", "--openapi", str(output_path)])

    assert grpc_stage.run_grpc_stage(args, SimpleNamespace(log=lambda *_args, **_kwargs: None)) == 0

    document = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(document["paths"]) == 1
    conflicts = document["x-redposture"]["descriptor_conflicts"]
    assert len(conflicts) == 1
    assert conflicts[0]["file"] == "shared.proto"
    assert len(conflicts[0]["variants"]) == 2
    assert conflicts[0]["selected_sha256"] == min(item["sha256"] for item in conflicts[0]["variants"])
