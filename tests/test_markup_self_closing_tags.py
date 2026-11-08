"""HTML's slash on a non-void element does not make its contents active markup."""

import pytest

from redposture_core.html_fingerprint import document_title, markup_evidence
from tests.test_markup_detection_contracts import PAGES, _proof


@pytest.mark.parametrize(
    "tag", ["script", "style", "template", "noscript", "textarea", "xmp", "iframe", "noembed", "noframes", "plaintext"]
)
@pytest.mark.parametrize("product", PAGES)
def test_self_closing_html_inert_tag_does_not_expose_example(tag, product):
    assert _proof(product, f"<{tag}/>" + PAGES[product] + f"</{tag}>") is False


@pytest.mark.parametrize("tag", ["script", "style", "textarea", "xmp", "iframe", "noembed", "noframes"])
def test_self_closing_raw_text_ends_at_real_matching_close(tag):
    assert document_title(f'<{tag}/>const fake="<title>Hidden</title>";</{tag}><title>Actual</title>') == "Actual"


def test_html_form_self_closing_slash_keeps_real_inputs_in_form():
    page = markup_evidence('<form action="/login"/><input name="username"><input name="password"></form>')
    assert page is not None
    assert page.forms[0].inputs == {"username", "password"}


@pytest.mark.parametrize("foreign", ["svg", "math"])
def test_foreign_self_closing_container_does_not_hide_next_real_html_title(foreign):
    assert document_title(f"<{foreign}/><title>Actual</title>") == "Actual"


def test_plaintext_never_exposes_a_later_html_title():
    assert document_title("<plaintext/><title>Hidden</title></plaintext><title>Also text</title>") == ""
