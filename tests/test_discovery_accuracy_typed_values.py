"""Accuracy gates must distinguish a credential object from JSON-looking text."""

from scripts.discovery_accuracy import expected_rows, measure


def test_lossless_fixture_decoding_does_not_invoke_detector(tmp_path):
    import base64
    import hashlib
    import json

    from scripts.discovery_accuracy import _load_locked

    def encode(value):
        return base64.b64encode(json.dumps(value).encode()).decode()

    body = {"oauth": {"client_id": "qa", "client_secret": "inactive!42"}}
    raw = json.dumps(
        {
            "cases": [
                {
                    "id": "one",
                    "body_json_base64": encode(body),
                    "expected": [
                        {"type": "oauth_credentials", "path": "$.oauth", "value_json_base64": encode(body["oauth"])}
                    ],
                    "status": "complete",
                }
            ]
        }
    ).encode()
    path = tmp_path / "fixture.json"
    path.write_bytes(raw)
    loaded = _load_locked(path, hashlib.sha256(raw).hexdigest())["cases"][0]
    assert loaded["body"] == body
    assert loaded["expected"][0]["value"] == body["oauth"]


def test_measure_rejects_stringified_credential_object():
    expected = [
        {
            "type": "oauth_credentials",
            "path": "$.oauth",
            "value": '{"client_id":"qa","client_secret":"inactive!42"}',
            "value_kind": "object",
        }
    ]
    assert measure(expected, expected)["tp"] == 1
    result = measure(expected, [{**expected[0], "value_kind": "string"}])
    assert result["fn"] == result["fp"] == 1


def test_expected_object_is_canonical_and_keeps_type():
    case = {
        "expected": [
            {
                "type": "oauth_credentials",
                "path": "$.oauth",
                "value": {"client_secret": "inactive!42", "client_id": "qa"},
            }
        ]
    }
    row = expected_rows(case, "common")[0]
    assert row["value"] == '{"client_id":"qa","client_secret":"inactive!42"}'
    assert row["value_kind"] == "object"
