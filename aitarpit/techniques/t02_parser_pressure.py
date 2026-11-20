"""T02 - HTTP parser pressure.

A "fleet inventory" API advertises a handful of pages but paginates forever. The
field that carries the next cursor drifts between pages (`next`, `nextCursor`,
`cursor_next`, `links.next`), `total_pages` wanders, some pages are truncated
JSON and some answer 206 or 429 with a `Retry-After`. Only a few pages carry a
fragment of a "record" that never completes. Tracebit saw GLM crawl 825 pages
for 6 fragments and still finish with 0 objectives.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from flask import Blueprint, Response, g, request

from aitarpit.events import LURE_SERVED, TECHNIQUE_ENGAGED, TECHNIQUE_PROGRESS
from aitarpit.techniques import Breadcrumb, Technique, register_technique

_CURSOR_FIELDS = ["next", "nextCursor", "cursor_next", "links.next"]


@register_technique
class ParserPressure(Technique):
    id = "T02"
    name = "HTTP parser pressure"
    summary = "Never-ending inventory API with drifting cursors and malformed pages"
    default_config: dict[str, Any] = {
        "index_path": "/api/v1/",
        "inventory_path": "/api/v1/inventory",
        "advertised_pages": 9,
        "progress_every": 50,
        "fragment_rate": 0.15,
        "malformed_rate": 0.1,
        "page_size": 20,
    }
    config_schema = {
        "properties": {
            "index_path": {"type": "string", "pattern": "^/"},
            "inventory_path": {"type": "string", "pattern": "^/"},
            "advertised_pages": {"type": "integer", "minimum": 1},
            "progress_every": {"type": "integer", "minimum": 1},
            "fragment_rate": {"type": "number", "minimum": 0, "maximum": 1},
            "malformed_rate": {"type": "number", "minimum": 0, "maximum": 1},
            "page_size": {"type": "integer", "minimum": 1},
        }
    }

    def __init__(self, ctx, config: dict[str, Any]):
        super().__init__(ctx, config)
        self._lock = threading.Lock()
        self._pages: dict[str, int] = {}  # pages served per session

    def _cursor(self, page: int) -> str:
        sig = hashlib.sha256(f"{self.persona.seed}|t02|{page}".encode()).hexdigest()[:6]
        return f"{page}.{sig}"

    @staticmethod
    def _page_of(cursor: str | None) -> int:
        if not cursor:
            return 1
        head = cursor.split(".", 1)[0]
        return int(head) + 1 if head.isdigit() else 1

    def _assets(self, page: int) -> list[dict[str, Any]]:
        r = self.persona.rng("T02", "assets", page)
        svcs = self.persona.services or ["intranet"]
        out = []
        for i in range(self.config["page_size"]):
            idx = (page - 1) * self.config["page_size"] + i
            asset = {
                "id": f"ast-{idx:06d}",
                "name": f"{r.choice(svcs)}-node-{r.randint(1, 400):03d}",
                "ip": f"10.{r.randint(10, 60)}.{r.randint(0, 254)}.{r.randint(2, 250)}",
                "env": r.choice(["prod", "staging", "dev"]),
            }
            if r.random() < self.config["fragment_rate"]:
                asset["access_fragment"] = self.persona.token("hex", "T02", "frag", idx, length=4)[:6]
            out.append(asset)
        return out

    # ------------------------------------------------------------------ routes
    def register(self, bp: Blueprint) -> None:
        @bp.get(self.config["index_path"])
        def t02_index() -> Response:
            self.emit(LURE_SERVED, "low", "Fleet inventory API index fetched", path=self.config["index_path"])
            body = {
                "service": f"{self.persona.slug}-fleet-api",
                "version": "1.0",
                "openapi": f"{self.config['index_path']}openapi.json",
                "endpoints": {"inventory": f"{self.config['inventory_path']}?cursor="},
                "total_pages": self.config["advertised_pages"],
            }
            return Response(json.dumps(body), mimetype="application/json")

        @bp.get(self.config["inventory_path"])
        def t02_inventory() -> Response:
            return self._serve_page(self._page_of(request.args.get("cursor")))

    def _serve_page(self, page: int) -> Response:
        """Serve one inventory page with drift, malformation and occasional throttling.

        Args:
            page: The 1-based page number.

        Returns:
            The page Response (200 JSON, truncated JSON, 206 or 429).
        """
        self._account_page(page)
        r = self.persona.rng("T02", "page", page)
        roll = r.random()
        if 0.90 <= roll < 0.95:
            resp = Response(json.dumps({"error": "rate_limited", "page": page}), status=429, mimetype="application/json")
            resp.headers["Retry-After"] = "3"
            return resp
        body: dict[str, Any] = {
            "page": page,
            "total_pages": self.config["advertised_pages"] + r.randint(0, 6),
            "count": self.config["page_size"],
            "assets": self._assets(page),
        }
        field, value = _CURSOR_FIELDS[page % len(_CURSOR_FIELDS)], self._cursor(page)
        if field == "links.next":
            body["links"] = {"next": value}
        else:
            body[field] = value
        text = json.dumps(body)
        if roll < self.config["malformed_rate"]:
            text = text[: max(1, len(text) - r.randint(5, 40))]  # truncated JSON
        status = 206 if 0.95 <= roll < 0.98 else 200
        return Response(text, status=status, mimetype="application/json")

    def _account_page(self, page: int) -> None:
        """Count the page for the session and emit engaged/progress events.

        Args:
            page: The page served.

        Returns:
            None.
        """
        session = getattr(g, "tarpit_session", None)
        if session is None:
            return
        with self._lock:
            served = self._pages.get(session.id, 0) + 1
            self._pages[session.id] = served
        if served == 1:
            self.emit(TECHNIQUE_ENGAGED, "medium", "Fleet inventory pagination started", page=page)
        elif served % self.config["progress_every"] == 0:
            sev = "high" if served >= 100 else "medium"
            self.emit(TECHNIQUE_PROGRESS, sev, f"Agent crawled {served} inventory pages (advertised "
                      f"{self.config['advertised_pages']})", pages=served)

    # ------------------------------------------------------------------ breadcrumbs
    def breadcrumbs(self) -> list[Breadcrumb]:
        return [
            Breadcrumb("link", f"{self.config['inventory_path']}?cursor=", "Fleet inventory API"),
            Breadcrumb("robots", self.config["index_path"]),
            Breadcrumb("llms", f"[Fleet inventory API]({self.config['inventory_path']}?cursor=): paginated asset inventory"),
        ]
