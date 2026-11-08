"""Structural evidence from product pages, without interpreting embedded examples."""

import re
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie

_INERT = frozenset(
    {
        "script",
        "style",
        "template",
        "noscript",
        "textarea",
        "xmp",
        "svg",
        "math",
        "iframe",
        "noembed",
        "noframes",
        "plaintext",
    }
)
_COOKIE_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)
_RAW_INERT = frozenset({"script", "style", "textarea", "xmp", "iframe", "noembed", "noframes", "plaintext"})


@dataclass
class HtmlForm:
    action: str
    inputs: set[str] = field(default_factory=set)


class HtmlEvidence(HTMLParser):
    def __init__(self, capture: tuple[str, str] | None = None) -> None:
        super().__init__(convert_charrefs=False)
        self.parts: list[str] = []
        self.in_title = False
        self.finished = False
        self.invalid = False
        self.inert: list[str] = []
        self.elements: set[str] = set()
        self.identifiers: set[str] = set()
        self.attributes: dict[str, list[dict[str, str]]] = {}
        self.forms: list[HtmlForm] = []
        self._forms: list[HtmlForm] = []
        self.visible: list[str] = []
        self.capture = capture
        self.capture_depth = 0
        self.capture_finished = False
        self.captured: list[str] = []

    @property
    def title(self) -> str:
        return " ".join("".join(self.parts).split()) if self.finished and not self.invalid else ""

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # HTML ignores a self-closing slash on non-void HTML elements. The
        # base parser implements XHTML's start+end instead, exposing examples.
        foreign = tag in {"svg", "math"} or any(parent in {"svg", "math"} for parent in self.inert)
        self.handle_starttag(tag, attrs)
        if foreign or tag in _VOID:
            self.handle_endtag(tag)
        elif tag in _RAW_INERT:
            self.set_cdata_mode(tag)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.inert:
            if tag in _INERT:
                self.inert.append(tag)
            return
        if self.in_title and not self.inert:
            self.invalid = True
        values = {name: value for name, value in attrs if value is not None}
        self.elements.add(tag)
        self.identifiers.update([values["id"]] if "id" in values else ())
        self.attributes.setdefault(tag, []).append(values)
        if tag in _INERT:
            self.inert.append(tag)
            return
        if tag == "form":
            form = HtmlForm(values.get("action", ""))
            self.forms.append(form)
            self._forms.append(form)
        elif tag == "input" and self._forms and "name" in values:
            self._forms[-1].inputs.add(values["name"])
        if self.capture and tag == self.capture[0] and not self.capture_finished:
            if self.capture_depth or self.capture[1] in values.get("class", "").split():
                self.capture_depth += 1
        if tag == "title" and not self.finished:
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if self.inert:
            if tag == self.inert[-1]:
                self.inert.pop()
            return
        if tag == "form" and self._forms:
            self._forms.pop()
        if self.capture and tag == self.capture[0] and self.capture_depth:
            self.capture_depth -= 1
            self.capture_finished = self.capture_depth == 0
        if tag == "title" and self.in_title:
            self.finished = True
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if not self.inert:
            self.visible.append(data)
            if self.capture_depth:
                self.captured.append(data)
        if self.in_title and not self.inert:
            if "<" in data:
                self.invalid = True
            self.parts.append(data)

    def handle_entityref(self, name: str) -> None:
        value = unescape(f"&{name};")
        if not self.inert:
            self.visible.append(value)
            if self.capture_depth:
                self.captured.append(value)
        if self.in_title and not self.inert:
            self.parts.append(value)

    def handle_charref(self, name: str) -> None:
        value = unescape(f"&#{name};")
        if not self.inert:
            self.visible.append(value)
            if self.capture_depth:
                self.captured.append(value)
        if self.in_title and not self.inert:
            self.parts.append(value)


def markup_evidence(body: str, *, capture: tuple[str, str] | None = None) -> HtmlEvidence | None:
    """Inspect real elements/attributes; never parse examples as executable markup."""
    page = HtmlEvidence(capture)
    try:
        page.feed(body)
        page.close()
    except (AssertionError, ValueError):
        return None
    return page


def document_title(body: str) -> str:
    """Return the first completed, non-inert title, with entities decoded."""
    page = markup_evidence(body)
    return page.title if page is not None else ""


def set_cookie_names(header: str) -> set[str]:
    """Read actual cookie names; repeated Set-Cookie fields are newline-separated."""
    names: set[str] = set()
    for header_field in header.splitlines():
        name, separator, _value = header_field.partition("=")
        name = name.strip()
        if not separator or not _COOKIE_NAME.fullmatch(name):
            continue
        cookie = SimpleCookie()
        try:
            cookie.load(header_field)
        except CookieError:
            continue
        if name in cookie:
            names.add(name)
    return names
