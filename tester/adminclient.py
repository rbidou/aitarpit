"""Admin API client for the test tool.

Optional: when the operator passes ``--admin URL --token T``, the checker and the
agent runner use this to verify emitted events and to correlate agent activity
with honeypot state (techniques engaged, time held).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class AdminClient:
    """Read-only client for the AI Tarpit admin API."""

    base_url: str
    token: str
    timeout: float = 10.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")

    def _get(self, path: str, params: dict | None = None) -> dict:
        resp = requests.get(f"{self.base_url}{path}", params=params or {},
                            headers={"X-Admin-Token": self.token}, timeout=self.timeout)
        body = resp.json()
        return body.get("data", {}) if body.get("status") else {}

    def status(self) -> dict[str, Any]:
        """Return the admin status payload (stats, persona, techniques)."""
        return self._get("/api/admin/status")

    def events(self, min_severity: str = "info", limit: int = 1000) -> list[dict]:
        """Return recent events at or above a severity."""
        return self._get("/api/admin/events", {"min_severity": min_severity, "limit": limit}).get("events", [])

    def config(self) -> dict[str, Any]:
        """Return the active configuration (for resolving technique paths)."""
        return self._get("/api/admin/config").get("config", {})

    def report(self) -> dict[str, Any]:
        """Return the activity report dict."""
        resp = requests.post(f"{self.base_url}/api/admin/report", json={"format": "json"},
                             headers={"X-Admin-Token": self.token}, timeout=self.timeout)
        body = resp.json()
        return body.get("data", {}).get("report", {}) if body.get("status") else {}
