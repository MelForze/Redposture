"""Small DIGEST-MD5 SASL client for ZooKeeper's password-based login.

Only qop=auth is supported.  A successful exchange is still followed by a
protected znode read in the audit module before a credential is called valid.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

_DIRECTIVE = re.compile(rb'\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^,\s]+))\s*(?:,|$)')
_DIGEST_URI = "zookeeper/zk-sasl-md5"


def _md5(data: bytes) -> bytes:
    return hashlib.md5(data, usedforsecurity=False).digest()


def _directives(token: bytes) -> dict[str, bytes]:
    if len(token) > 4096:
        raise ValueError("oversized SASL challenge")
    values: dict[str, bytes] = {}
    offset = 0
    while offset < len(token):
        match = _DIRECTIVE.match(token, offset)
        if match is None:
            raise ValueError("malformed SASL challenge")
        key = match.group(1).decode("ascii").lower()
        if key in values:
            raise ValueError("duplicate SASL directive")
        value = match.group(2) if match.group(2) is not None else match.group(3)
        values[key] = re.sub(rb"\\(.)", rb"\1", value or b"")
        offset = match.end()
    return values


def _quoted(value: str) -> bytes:
    raw = value.encode("utf-8")
    if b"\r" in raw or b"\n" in raw or b"\x00" in raw:
        raise ValueError("invalid SASL identity")
    return b'"' + raw.replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


class DigestMd5Client:
    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.expected_rspauth: bytes | None = None

    def response(self, challenge: bytes) -> bytes:
        fields = _directives(challenge)
        nonce = fields.get("nonce")
        if not nonce or len(nonce) > 1024:
            raise ValueError("SASL challenge has no usable nonce")
        if fields.get("algorithm", b"md5-sess").lower() != b"md5-sess":
            raise ValueError("unsupported SASL algorithm")
        if fields.get("charset", b"utf-8").lower() != b"utf-8":
            raise ValueError("unsupported SASL charset")
        if b"auth" not in (item.strip().lower() for item in fields.get("qop", b"auth").split(b",")):
            raise ValueError("unsupported SASL quality of protection")
        realm = fields.get("realm", b"")
        realm_text = realm.decode("utf-8")
        nonce_text = nonce.decode("utf-8")
        cnonce = secrets.token_hex(16).encode("ascii")
        nc = b"00000001"
        a1 = _md5(self.username.encode("utf-8") + b":" + realm + b":" + self.password.encode("utf-8"))
        a1 = a1 + b":" + nonce + b":" + cnonce
        ha1 = _md5(a1).hex().encode("ascii")
        tail = b":" + nonce + b":" + nc + b":" + cnonce + b":auth:"

        def digest(a2: bytes) -> bytes:
            return _md5(ha1 + tail + _md5(a2).hex().encode("ascii")).hex().encode("ascii")

        digest_uri = _DIGEST_URI.encode("ascii")
        self.expected_rspauth = digest(b":" + digest_uri)
        response = b",".join(
            (
                b"username=" + _quoted(self.username),
                b"realm=" + _quoted(realm_text),
                b"nonce=" + _quoted(nonce_text),
                b"cnonce=" + _quoted(cnonce.decode("ascii")),
                b"nc=" + nc,
                b"qop=auth",
                b"digest-uri=" + _quoted(_DIGEST_URI),
                b"response=" + digest(b"AUTHENTICATE:" + digest_uri),
                b"charset=utf-8",
            )
        )
        if len(response) >= 4096:
            raise ValueError("oversized SASL response")
        return response

    def verify_server(self, challenge: bytes) -> None:
        fields = _directives(challenge)
        received = fields.get("rspauth")
        if (
            self.expected_rspauth is None
            or received is None
            or not hmac.compare_digest(received, self.expected_rspauth)
        ):
            raise ValueError("SASL server proof mismatch")
