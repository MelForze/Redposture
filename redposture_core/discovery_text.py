"""Incremental text values with field context and bounded temporary storage."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from .discovery_entities import EntityTextStream
from .discovery_values import DiskBackedText
from .secret_detection import SecretMatch, _is_secret_sentinel, is_secret_field_name

_ASSIGNMENT = re.compile(r"""(?i)(?<![\w.])(?:--)?([A-Za-z][A-Za-z0-9._-]{0,127})["']?\s*(?:=>|[:=])""")
_ATOMIC = re.compile(r"(?<![\w-])(?:eyJ|glsa_|sk-|dop_v1_|shpat_|dckr_pat_|pypi-AgEI)")
_END = re.compile(r"""[\s,;"'&<>]""")
_QUOTED = re.compile(r"""\\.|["']""", re.S)
_AUTH = re.compile(r"(?i)\b(bearer|basic)\s+")
_SQL_PASSWORD = re.compile(r"(?i)\b(?:WITH\s+)?PASSWORD\s+([\"'])")
_BEARER_END = re.compile(r"[^A-Za-z0-9._~+/=-]")
_BASIC_END = re.compile(r"[^A-Za-z0-9+/]")
_XML_HEAD = re.compile(r"<([A-Za-z][\w:.-]{0,79})(?=[\s/>])")
_XML_HEADER_CHAR = re.compile(r"[\"'>]")
_PEM = re.compile(r"-----BEGIN ((?:[A-Z0-9 ]+ )?PRIVATE KEY|CERTIFICATE)-----")
_SINGLE_ASSIGNMENT_LINE = re.compile(
    r"[ \t]*(?:--)?([A-Za-z][A-Za-z0-9._-]{0,127})[ \t]*(?:=>|[:=])[ \t]*"
    r"""(?:"(?:[^"\\\r\n]|\\[^\r\n])*"|'(?:[^'\\\r\n]|\\[^\r\n])*')[ \t]*\r?\n"""
)


class _Value:
    def __init__(self, limit: int, *, entities: bool = False) -> None:
        self.limit = limit
        self.entities = EntityTextStream() if entities else None
        self.nonspace = False
        self.text = ""
        self.length = 0
        self.disk: DiskBackedText | None = None

    def append(self, text: str) -> None:
        self._append(self.entities.feed(text) if self.entities is not None else text)

    def append_literal(self, text: str) -> None:
        if self.entities is not None:
            self._append(self.entities.finish())
        self._append(text)

    def _append(self, text: str) -> None:
        self.nonspace |= bool(text.strip())
        self.length += len(text)
        if self.disk is None:
            if len(self.text) + len(text) <= self.limit:
                self.text += text
                return
            self.disk = DiskBackedText()
            self.disk.append_text(self.text)
            self.text = ""
        self.disk.append_text(text)

    def finish(self) -> str | DiskBackedText:
        if self.entities is not None:
            self._append(self.entities.finish())
        if self.disk is None:
            return self.text
        value, self.disk = self.disk, None
        value.finish()
        return value

    def close(self) -> None:
        if self.disk is not None:
            self.disk.close()
            self.disk = None
        self.text = ""


class DiscoveryTextStream:
    """Publish completed text/assignment values; discard an interrupted value.

    Recognizing a field starts capture before its value arrives, so quotes,
    whitespace and portion boundaries cannot detach a value from its name.
    The consumer performs classification and owns completed disk references.
    """

    def __init__(
        self,
        emit: Callable[[Any], Any],
        partial: Callable[[str], Any],
        *,
        portion: int = 65_536,
        _attributes: bool | str = False,
    ) -> None:
        self.emit = emit
        self.attributes = _attributes
        self.xml_name = ""
        self.xml_quote = ""
        self.xml_tail = ""
        self.xml_attributes: DiscoveryTextStream | None = None
        self.xml_input: dict[str, Any] = {}
        self.partial = partial
        self.limit = max(64, min(portion, 65_536))
        self.pending = ""
        self.value: _Value | None = None
        self.key: str | None = None
        self.mode = ""
        self.quote = ""
        self.escaped = False
        self.pem_end = ""
        self.detector: str | None = None
        self.minimum = 0
        self.auth_body_length = 0
        self.padding = 0
        self.finished = False

    def _xml_attribute(self, item: Any) -> None:
        if self.xml_name.lower() == "input" and isinstance(item, dict):
            key = next(iter(item)).lower()
            if key in {"name", "value"}:
                previous = self.xml_input.get(key)
                if isinstance(previous, DiskBackedText):
                    previous.close()
                self.xml_input[key] = next(iter(item.values()))
                return
        self.emit(item)

    def _finish_xml_input(self) -> None:
        name = self.xml_input.get("name")
        value = self.xml_input.get("value")
        if isinstance(name, str) and is_secret_field_name(name) and value is not None:
            self.emit({name: value})
            self.xml_input.pop("value", None)
        elif isinstance(name, DiskBackedText):
            self.partial("unsupported_long_input_name")
        elif value is not None:
            self.emit({"value": value})
            self.xml_input.pop("value", None)
        self._close_xml_input()

    def _close_xml_input(self) -> None:
        for item in self.xml_input.values():
            if isinstance(item, DiskBackedText):
                item.close()
        self.xml_input.clear()

    def _complete(self) -> None:
        assert self.value is not None
        length = self.auth_body_length if self.detector == "basic_auth" else self.value.length
        value = self.value.finish()
        self.value = None
        key, self.key = self.key, None
        detector, self.detector = self.detector, None
        minimum, self.minimum = self.minimum, 0
        self.auth_body_length = self.padding = 0
        self.mode = ""
        self.quote = ""
        self.escaped = False
        self.pem_end = ""
        if detector is not None:
            placeholder = value.obvious_placeholder if isinstance(value, DiskBackedText) else _is_secret_sentinel(value)
            if length < minimum or placeholder:
                if isinstance(value, DiskBackedText):
                    value.close()
                return
            self.emit(SecretMatch(detector, "high", "", value))
        else:
            self.emit({key: value} if key is not None else value)

    def _begin_xml(self, match: re.Match[str]) -> None:
        if match.start():
            self.emit(self.pending[: match.start()])
        self.xml_name = match.group(1)
        self.xml_quote = self.xml_tail = ""
        self.xml_attributes = DiscoveryTextStream(
            self._xml_attribute,
            self.partial,
            portion=self.limit,
            _attributes="input" if self.xml_name.lower() == "input" else True,
        )
        self.mode = "xml_header"
        self.pending = self.pending[match.end() :]

    def _drain(self) -> None:
        while self.pending:
            if (
                not self.mode
                and self.value is None
                and not self.attributes
                and len(self.pending) <= self.limit
                and self.pending.endswith("\n")
                and "<" not in self.pending
                and "-----BEGIN" not in self.pending
            ):
                line_match = _SINGLE_ASSIGNMENT_LINE.fullmatch(self.pending)
                if line_match is not None and is_secret_field_name(line_match.group(1)):
                    # The normal state machine emits exactly this one closed
                    # line. Keep multi-line batches and contextual syntax on
                    # that path so callback order and partials stay identical.
                    completed, self.pending = self.pending, ""
                    self.emit(completed)
                    continue
            if self.mode == "xml_header":
                end = -1
                for marker in _XML_HEADER_CHAR.finditer(self.pending):
                    char = marker.group()
                    if self.xml_quote:
                        if char == self.xml_quote:
                            self.xml_quote = ""
                    elif char in "\"'":
                        self.xml_quote = char
                    else:
                        end = marker.start()
                        break
                assert self.xml_attributes is not None
                if end < 0:
                    self.xml_attributes.feed(self.pending)
                    self.xml_tail = (self.xml_tail + self.pending)[-1:]
                    self.pending = ""
                    return
                prefix, self.pending = self.pending[:end], self.pending[end + 1 :]
                self.xml_attributes.feed(prefix)
                self.xml_attributes.finish()
                self.xml_attributes.close()
                self.xml_attributes = None
                self._finish_xml_input()
                local_name = self.xml_name.rsplit(":", 1)[-1]
                self_closing = (self.xml_tail + prefix).rstrip().endswith("/")
                if is_secret_field_name(local_name) and not self_closing:
                    self.key = local_name
                    self.value = _Value(self.limit, entities=True)
                    self.mode = "xml_body"
                else:
                    self.mode = ""
                self.xml_quote = self.xml_tail = ""
                continue
            if self.value is not None:
                if self.mode == "xml_close":
                    self.pending = self.pending.lstrip()
                    if not self.pending:
                        return
                    if self.pending.startswith(">"):
                        self.pending = self.pending[1:]
                        self._complete()
                    else:
                        self.partial("invalid_xml_secret_end")
                        self.value.close()
                        self.value = None
                        self.key = None
                        self.mode = ""
                    continue
                if self.mode == "xml_cdata":
                    end = self.pending.find("]]>")
                    if end < 0:
                        if len(self.pending) > 2:
                            self.value.append_literal(self.pending[:-2])
                            self.pending = self.pending[-2:]
                        return
                    self.value.append_literal(self.pending[:end])
                    self.pending = self.pending[end + 3 :]
                    self.mode = "xml_body"
                    continue
                if self.mode == "xml_body":
                    end = self.pending.find("<")
                    if end < 0:
                        self.value.append(self.pending)
                        self.pending = ""
                        return
                    self.value.append(self.pending[:end])
                    self.pending = self.pending[end:]
                    close = f"</{self.xml_name}"
                    cdata = "<![CDATA["
                    if close.startswith(self.pending) or cdata.startswith(self.pending):
                        return
                    if self.pending.startswith(close) and (
                        len(self.pending) == len(close) or self.pending[len(close)] in " \t\r\n>"
                    ):
                        self.pending = self.pending[len(close) :]
                        self.mode = "xml_close"
                    elif self.pending.startswith(cdata):
                        self.pending = self.pending[len(cdata) :]
                        self.mode = "xml_cdata"
                    else:
                        if self.value.nonspace:
                            self.partial("mixed_xml_secret_value")
                        self.value.close()
                        self.value = None
                        self.key = None
                        self.mode = ""
                    continue
                if self.mode == "basic_padding":
                    count = 0
                    while count < len(self.pending) and self.pending[count] == "=" and count < 2 - self.padding:
                        count += 1
                    self.value.append(self.pending[:count])
                    self.padding += count
                    self.pending = self.pending[count:]
                    if self.padding == 2 or self.pending:
                        self._complete()
                        continue
                    return
                if self.mode in {"bearer", "basic"}:
                    end_pattern = _BEARER_END if self.mode == "bearer" else _BASIC_END
                    boundary = end_pattern.search(self.pending)
                    if boundary is None:
                        self.value.append(self.pending)
                        self.auth_body_length += len(self.pending)
                        self.pending = ""
                        return
                    self.value.append(self.pending[: boundary.start()])
                    self.auth_body_length += boundary.start()
                    self.pending = self.pending[boundary.start() :]
                    if self.mode == "basic" and self.pending.startswith("="):
                        self.mode = "basic_padding"
                    else:
                        self._complete()
                    continue
                if self.mode == "pem":
                    end = self.pending.find(self.pem_end)
                    if end >= 0:
                        end += len(self.pem_end)
                        self.value.append(self.pending[:end])
                        self.pending = self.pending[end:]
                        self._complete()
                        continue
                    keep = len(self.pem_end) - 1
                    if len(self.pending) > keep:
                        self.value.append(self.pending[:-keep])
                        self.pending = self.pending[-keep:]
                    return
                if self.mode == "start":
                    self.pending = self.pending.lstrip()
                    if not self.pending:
                        return
                    if self.pending[0] in "\"'":
                        self.quote = self.pending[0]
                        self.pending = self.pending[1:]
                        self.mode = "quoted"
                    else:
                        self.mode = "unquoted"
                    continue
                if self.mode == "quoted":
                    start = int(self.escaped)
                    end = (
                        self.pending.find(self.quote)
                        if self.attributes
                        else next(
                            (m.start() for m in _QUOTED.finditer(self.pending, start) if m.group() == self.quote), -1
                        )
                    )
                    if end < 0:
                        text, self.pending = self.pending, ""
                        self.value.append(text)
                        tail = text[start:]
                        self.escaped = (len(tail) - len(tail.rstrip("\\"))) % 2 == 1
                        return
                    self.value.append(self.pending[:end])
                    self.pending = self.pending[end + 1 :]
                    self._complete()
                    continue
                boundary = _END.search(self.pending)
                if boundary is None:
                    self.value.append(self.pending)
                    self.pending = ""
                    return
                self.value.append(self.pending[: boundary.start()])
                self.pending = self.pending[boundary.end() :]
                self._complete()
                continue
            xml = None if self.attributes else _XML_HEAD.search(self.pending)
            if xml is not None and xml.start() <= self.limit:
                # A field assignment or PEM header cannot cross '<'. Only
                # the prefix can precede this tag. Avoid searching all later
                # attributes again for every neutral tag in a dense document.
                prefix_end = xml.start()
                if _PEM.search(self.pending, 0, prefix_end) is None and not any(
                    is_secret_field_name(match.group(1)) for match in _ASSIGNMENT.finditer(self.pending, 0, prefix_end)
                ):
                    self._begin_xml(xml)
                    continue
            assignment = next(
                (
                    m
                    for m in _ASSIGNMENT.finditer(self.pending)
                    if self.attributes == "input" or is_secret_field_name(m.group(1))
                ),
                None,
            )
            pem = _PEM.search(self.pending)
            if (
                xml is not None
                and xml.start() <= self.limit
                and (assignment is None or xml.start() <= assignment.start())
                and (pem is None or xml.start() < pem.start())
            ):
                self._begin_xml(xml)
                continue
            auth = _AUTH.search(self.pending)
            sql_password = _SQL_PASSWORD.search(self.pending)
            contextual = auth
            if sql_password is not None and (contextual is None or sql_password.start() < contextual.start()):
                contextual = sql_password
            if (
                contextual is not None
                and contextual.start() <= self.limit
                and (assignment is None or contextual.start() < assignment.start())
                and (pem is None or contextual.start() < pem.start())
            ):
                if contextual.start():
                    self.emit(self.pending[: contextual.start()])
                self.value = _Value(self.limit)
                self.key = None
                self.pending = self.pending[contextual.end() :]
                if contextual is sql_password:
                    self.detector = "password"
                    self.minimum = 4
                    self.mode = "quoted"
                    self.quote = contextual.group(1)
                else:
                    self.mode = contextual.group(1).lower()
                    self.detector = "bearer_token" if self.mode == "bearer" else "basic_auth"
                    self.minimum = 12 if self.mode == "bearer" else 8
                    self.auth_body_length = self.padding = 0
                continue
            newline = self.pending.rfind("\n", 0, self.limit)
            if pem is not None and pem.start() <= self.limit and (newline < 0 or pem.start() <= newline):
                if pem.start():
                    self.emit(self.pending[: pem.start()])
                self.value = _Value(self.limit)
                self.value.append(pem.group())
                self.pem_end = f"-----END {pem.group(1)}-----"
                self.key = None
                self.mode = "pem"
                self.pending = self.pending[pem.end() :]
                continue
            multiline = False
            if newline >= 0:
                for candidate in _ASSIGNMENT.finditer(self.pending, 0, newline):
                    if not is_secret_field_name(candidate.group(1)):
                        continue
                    head = self.pending[candidate.end() : newline].lstrip()
                    if head.startswith(('"', "'")) and not any(m.group() == head[0] for m in _QUOTED.finditer(head, 1)):
                        assignment = candidate
                        multiline = True
                        break
            if 0 <= newline < self.limit and not multiline:
                line, self.pending = self.pending[: newline + 1], self.pending[newline + 1 :]
                self.emit(line)
                continue
            if len(self.pending) <= self.limit and not multiline and not (self.attributes and assignment is not None):
                return
            atomic = _ATOMIC.search(self.pending) if not multiline else None
            match = assignment
            if atomic is not None and (match is None or atomic.start() < match.start()):
                match = atomic
            newline = self.pending.rfind("\n", 0, self.limit)
            if match is not None and match.start() <= self.limit and (newline < 0 or match.start() <= newline):
                if match.start():
                    self.emit(self.pending[: match.start()])
                self.value = _Value(self.limit, entities=bool(self.attributes))
                if match is assignment:
                    self.key = match.group(1)
                    self.mode = "start"
                    self.pending = self.pending[match.end() :]
                else:
                    self.key = None
                    self.mode = "unquoted"
                    self.pending = self.pending[match.start() :]
                continue
            if 0 <= newline < self.limit:
                line, self.pending = self.pending[: newline + 1], self.pending[newline + 1 :]
                self.emit(line)
                continue
            if len(self.pending) <= self.limit:
                return
            cut = max(self.pending.rfind(char, 0, self.limit) for char in " \t\r\n,;\"'&<>")
            if cut >= 0:
                part, self.pending = self.pending[: cut + 1], self.pending[cut + 1 :]
                self.emit(part)
            else:
                self.key = None
                self.value = _Value(self.limit)
                self.mode = "unquoted"

    def feed(self, text: str) -> None:
        if self.finished:
            raise RuntimeError("text discovery stream is finished")
        for position in range(0, len(text), self.limit):
            self.pending += text[position : position + self.limit]
            self._drain()

    def finish(self) -> None:
        if self.finished:
            raise RuntimeError("text discovery stream is finished")
        self._drain()
        self.finished = True
        if self.xml_attributes is not None:
            self.xml_attributes.close()
            self.xml_attributes = None
            self.partial("unterminated_xml_tag")
            self.pending = ""
            self._close_xml_input()
        if self.value is not None:
            if self.mode in {"quoted", "pem", "xml_body", "xml_close", "xml_cdata"}:
                self.partial(
                    "unterminated_pem"
                    if self.mode == "pem"
                    else "unterminated_xml_secret"
                    if self.mode.startswith("xml_")
                    else "unterminated_secret_value"
                )
                self.pending = ""
                self.value.close()
                self.value = None
            elif self.mode == "start":
                self.value.close()
                self.value = None
            else:
                self._complete()
        if self.pending:
            self.emit(self.pending)
            self.pending = ""

    def close(self) -> None:
        self._close_xml_input()
        if self.xml_attributes is not None:
            self.xml_attributes.close()
            self.xml_attributes = None
        if self.value is not None:
            self.value.close()
            self.value = None
        self.pending = ""
        self.finished = True
