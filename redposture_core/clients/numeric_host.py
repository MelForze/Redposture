"""Bounded memo of numeric address families; never performs DNS resolution."""

from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache


@lru_cache(maxsize=4096)
def numeric_host_family(host: str) -> int:
    address = ipaddress.ip_address(host)
    return socket.AF_INET6 if address.version == 6 else socket.AF_INET
