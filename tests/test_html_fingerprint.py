"""DOM evidence retains actual fields, excluding scripts and inert templates."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from redposture_core.html_fingerprint import document_title, markup_evidence, set_cookie_names


def test_form_fields_belong_to_their_form_and_examples_are_ignored():
    page = markup_evidence(
        '<form action="/one"><input name="username"></form>'
        '<template><form action="/fake"><input name="password"></form></template>'
        '<form action="/two"><input name="password"></form>'
        '<script id="actual-metadata">const example=`<input name="hidden">`</script>'
    )
    assert page is not None
    assert [(form.action, form.inputs) for form in page.forms] == [
        ("/one", {"username"}),
        ("/two", {"password"}),
    ]
    assert page.identifiers == {"actual-metadata"}
    assert all(not {"username", "password"}.issubset(form.inputs) for form in page.forms)


def test_capture_uses_first_real_element_and_ignores_comment_version():
    body = '<!-- <span class="version">99.0.0</span> --><span class="version"><b>3.5</b>.6</span>'
    body += '<span class="version">88.0.0</span>'
    page = markup_evidence(body, capture=("span", "version"))
    assert page is not None and page.capture_finished
    assert "".join(page.captured) == "3.5.6"


@pytest.mark.parametrize("body", ["<![", "<![CDATA[", "<!--", "<title>unfinished", '<script>"<title>Hidden</title>"'])
def test_damaged_markup_does_not_make_a_title(body):
    assert document_title(body) == ""


def test_cookie_names_respect_header_boundaries_and_attributes():
    assert set_cookie_names('first="x;y"; Path=/\nsecond=z; Expires=Wed, 01 Jan 2030 00:00:00 GMT') == {
        "first",
        "second",
    }
    assert set_cookie_names("first=x; second=z") == {"first"}
    assert set_cookie_names("no-cookie\n=bad\nfoo:bar=x") == set()


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=2000))
def test_arbitrary_markup_and_cookies_never_raise(body):
    page = markup_evidence(body)
    assert isinstance(document_title(body), str)
    assert page is None or isinstance(page.title, str)
    assert isinstance(set_cookie_names(body), set)
