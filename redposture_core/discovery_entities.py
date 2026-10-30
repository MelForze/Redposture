"""Bounded entity decoding for streamed XML/HTML text values."""

from __future__ import annotations

import html


class EntityTextStream:
    def __init__(self) -> None:
        self.pending = ""
        self.numeric = False
        self.base = 10
        self.number = 0
        self.digits = False

    def _flush(self) -> str:
        if self.numeric and self.digits:
            result = html.unescape(f"&#{self.number};")
        else:
            result = html.unescape(self.pending)
        self.pending = ""
        self.numeric = self.digits = False
        self.base = 10
        self.number = 0
        return result

    def feed(self, text: str) -> str:
        parts: list[str] = []
        position = 0
        while position < len(text):
            if not self.pending:
                start = text.find("&", position)
                if start < 0:
                    parts.append(text[position:])
                    break
                parts.append(text[position:start])
                self.pending = "&"
                position = start + 1
                continue
            char = text[position]
            if self.pending == "&" and char == "#":
                self.pending = "&#"
                self.numeric = True
                position += 1
                continue
            if self.numeric:
                if self.pending == "&#" and not self.digits and char in "xX":
                    self.pending += char
                    self.base = 16
                    position += 1
                    continue
                allowed = "0123456789abcdefABCDEF" if self.base == 16 else "0123456789"
                if char in allowed:
                    self.digits = True
                    self.number = min(0x110000, self.number * self.base + int(char, self.base))
                    position += 1
                    continue
                valid_numeric = self.digits
                parts.append(self._flush())
                if char == ";" and valid_numeric:
                    position += 1
                continue
            if char == ";":
                self.pending += char
                parts.append(self._flush())
                position += 1
            elif char.isalnum() and len(self.pending) <= 33:
                self.pending += char
                position += 1
            else:
                parts.append(self._flush())
        return "".join(parts)

    def finish(self) -> str:
        return self._flush() if self.pending else ""
