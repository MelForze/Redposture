"""Seed only the isolated loopback Portainer fixture; never use a host socket."""

from __future__ import annotations

import json
import ssl
import time
from pathlib import Path
from urllib.request import Request, urlopen

BASE = "https://127.0.0.1:29443"


def request(path: str, data: bytes | None = None, **headers: str):
    with urlopen(
        Request(BASE + path, data=data, headers=headers), context=ssl._create_unverified_context(), timeout=10
    ) as response:
        return json.load(response)


def main() -> None:
    deadline = time.monotonic() + 45
    while True:
        try:
            status = request("/api/system/status")
            if isinstance(status, dict) and isinstance(status.get("Version"), str):
                break
        except (OSError, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise SystemExit("Portainer did not become ready on the isolated QA port")
        time.sleep(0.5)
    password = Path(__file__).with_name("password.txt").read_text().strip()
    auth = request(
        "/api/auth",
        json.dumps({"Username": "admin", "Password": password}).encode(),
        **{"Content-Type": "application/json"},
    )
    headers = {"Authorization": "Bearer " + auth["jwt"]}
    endpoints = request("/api/endpoints", **headers)
    if not any(item["Name"] == "qa-engine" for item in endpoints):
        boundary = "redposture-qa-form"
        fields = {"Name": "qa-engine", "EndpointCreationType": "1", "URL": "tcp://engine:2375", "TLS": "false"}
        body = (
            "".join(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'
                for key, value in fields.items()
            )
            + f"--{boundary}--\r\n"
        )
        request(
            "/api/endpoints", body.encode(), **headers, **{"Content-Type": "multipart/form-data; boundary=" + boundary}
        )
    print("Isolated qa-engine environment ready.")


if __name__ == "__main__":
    main()
