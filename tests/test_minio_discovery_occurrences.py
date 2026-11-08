"""MinIO combines equal values while preserving all object/field locations."""

from redposture_core.clients.minio_api import MinioResponse
from redposture_core.modules.minio.discover import discover_secrets
from redposture_core.modules.minio.enumerate import ObjectInfo


def test_minio_equal_value_across_objects_has_all_places_and_one_live_value():
    body = b'password="inactive-minio-repeated-password"\n'

    class Client:
        def get_object_range(self, _bucket, _key, *, start, length, signed):
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    objects = [ObjectInfo("qa", f"config-{n}.env", len(body)) for n in range(150)]
    emitted = []
    result = discover_secrets(Client(), [*objects, objects[0]], on_finding=emitted.append)
    assert result.coverage_complete, result.partial_reasons
    assert len(result.findings) == len(emitted) == 1
    finding = result.findings[0]
    assert finding["value"] == "inactive-minio-repeated-password"
    assert finding["occurrence_count"] == len(finding["locations"]) == 150
    assert {place["key"] for place in finding["locations"]} == {obj.key for obj in objects}


def test_duplicate_archive_filenames_keep_separate_physical_places():
    import io
    import warnings
    import zipfile

    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w") as archive:
            for _ in range(2):
                archive.writestr("config.env", 'password="inactive-duplicate-member-password"\n')
    body = stream.getvalue()

    class Client:
        def get_object_range(self, _bucket, _key, *, start, length, signed):
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    result = discover_secrets(Client(), [ObjectInfo("qa", "configs.zip", len(body))])
    assert result.coverage_complete, result.partial_reasons
    assert len(result.findings) == 1
    row = result.findings[0]
    assert row["occurrence_count"] == len(row["locations"]) == 2
    assert len({location["object_path"] for location in row["locations"]}) == 2


def test_equal_values_in_consecutive_json_documents_keep_document_ordinals():
    body = b'{"password":"inactive-json-document-password"}\n' * 3

    class Client:
        def get_object_range(self, _bucket, _key, *, start, length, signed):
            return MinioResponse(http_status=206, headers={}, body=body[start : start + length])

    result = discover_secrets(Client(), [ObjectInfo("qa", "configs.jsonl", len(body))])
    assert result.coverage_complete, result.partial_reasons
    assert len(result.findings) == 1
    row = result.findings[0]
    assert row["occurrence_count"] == len(row["locations"]) == 3
    assert [location["document_ordinal"] for location in row["locations"]] == [0, 1, 2]
