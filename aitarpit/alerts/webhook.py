"""Webhook alert sink (JSON POST/PUT) with optional authentication.

Auth types:
  none    - no authentication
  bearer  - ``Authorization: Bearer <token>``
  basic   - HTTP basic (username/password)
  header  - arbitrary ``<header>: <value>`` (API-key style)
  hmac    - ``X-AITarpit-Timestamp`` + ``X-AITarpit-Signature: sha256=<hex>`` where the
            signature is HMAC-SHA256(secret, "<timestamp>.<raw body>")

Uses only the standard library (urllib) so alerting has no extra dependency.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ssl
import time
import urllib.error
import urllib.request

from aitarpit import __version__
from aitarpit.alerts.base import Sink, event_payload
from aitarpit.events import Event


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


class WebhookSink(Sink):
    def __init__(self, cfg: dict):
        super().__init__(cfg.get("name", "webhook"), cfg.get("min_severity", "medium"))
        self.url = cfg["url"]
        self.method = cfg.get("method", "POST")
        self.headers = dict(cfg.get("headers") or {})
        self.auth = dict(cfg.get("auth") or {"type": "none"})
        self.timeout = float(cfg.get("timeout", 10.0))
        self.retries = int(cfg.get("retries", 3))
        self._ssl = None if cfg.get("verify_tls", True) else ssl._create_unverified_context()  # noqa: S323 - opt-in

    def build_request(self, event: Event) -> urllib.request.Request:
        body = json.dumps(event_payload(event), default=str, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": f"aitarpit/{__version__}"}
        headers.update(self.headers)
        kind = self.auth.get("type", "none")
        if kind == "bearer":
            headers["Authorization"] = f"Bearer {self.auth['token']}"
        elif kind == "basic":
            cred = base64.b64encode(f"{self.auth['username']}:{self.auth['password']}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"
        elif kind == "header":
            headers[self.auth["header"]] = self.auth["value"]
        elif kind == "hmac":
            ts = str(int(time.time()))
            headers["X-AITarpit-Timestamp"] = ts
            headers["X-AITarpit-Signature"] = sign(self.auth["secret"], ts, body)
        return urllib.request.Request(self.url, data=body, headers=headers, method=self.method)

    def send(self, event: Event) -> None:
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            req = self.build_request(event)  # rebuilt each time: fresh HMAC timestamp
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl) as resp:
                    if 200 <= resp.status < 300:
                        return
                    last_exc = RuntimeError(f"HTTP {resp.status}")
            except urllib.error.HTTPError as exc:
                last_exc = exc
                if 400 <= exc.code < 500 and exc.code not in (408, 429):
                    break  # client error: retrying will not help
            except (urllib.error.URLError, OSError) as exc:
                last_exc = exc
            if attempt < self.retries:
                time.sleep(min(2 ** attempt, 30))
        raise RuntimeError(f"webhook {self.name} failed: {last_exc}")
