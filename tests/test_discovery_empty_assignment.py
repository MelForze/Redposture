"""An empty line assignment must not borrow a value from the next line."""

import pytest

from scripts.discovery_accuracy import scan


@pytest.mark.parametrize("route", ["common", "disk-json", "stream-json", "elastic"])
@pytest.mark.parametrize(
    "text",
    ["# password=\n# use environment configuration\n", "password: \r\nnot-a-secret", "token=\nnext_setting=value"],
)
def test_empty_assignment_does_not_capture_next_line(route, text):
    rows, status = scan(route, {"message": text}, portion=7)
    assert status == "complete"
    assert rows == []


@pytest.mark.parametrize("route", ["common", "disk-json", "stream-json", "elastic"])
@pytest.mark.parametrize(
    "text,value",
    [
        ('password="#"', "#"),
        ("# password=real-inactive!42", "real-inactive!42"),
        ('"password":\n"multi-line-inactive!42"', "multi-line-inactive!42"),
        ('password="first\nsecond"', "first\nsecond"),
    ],
)
def test_real_assignments_keep_complete_value(route, text, value):
    rows, status = scan(route, {"message": text}, portion=7)
    assert status == "complete"
    assert [(r["type"], r["value"]) for r in rows] == [("password", value)]
