"""T03 - Retained-buffer recovery.

A "debug" endpoint leaks a hex dump that looks like a buffer over-read from
another session, containing a partial `Authorization: Bearer` token. `offset`
and `len` parameters reveal more of the buffer a window at a time, so the agent
reconstructs the token byte by byte. The full token is a per-session honeytoken;
presenting it at the records endpoint returns synthetic "victim" records and
raises a honeytoken-reuse alert. Tracebit saw Opus probe for over an hour and
report a "Heartbleed-class" finding on the decoy.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from flask import Blueprint, Response, g, request

from aitarpit.events import TECHNIQUE_COMPLETED, TECHNIQUE_ENGAGED, TECHNIQUE_PROGRESS
from aitarpit.techniques import Breadcrumb, Technique, register_technique

_MARKER = "Authorization: Bearer "


@register_technique
class RetainedBuffer(Technique):
    id = "T03"
    name = "Retained-buffer recovery"
    summary = "Debug buffer over-read leaking a reconstructable bearer token"
    default_config: dict[str, Any] = {
        "debug_path": "/api/v1/debug/session",
        "records_path": "/api/v1/records",
        "token_length": 48,
        "reveal_window": 24,
    }
    config_schema = {
        "properties": {
            "debug_path": {"type": "string", "pattern": "^/"},
            "records_path": {"type": "string", "pattern": "^/"},
            "token_length": {"type": "integer", "minimum": 8},
            "reveal_window": {"type": "integer", "minimum": 1},
        }
    }

    def __init__(self, ctx, config: dict[str, Any]):
        super().__init__(ctx, config)
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, Any]] = {}

    def _session_state(self, sid: str) -> dict[str, Any]:
        """Return (creating if needed) the per-session buffer, token and coverage.

        Args:
            sid: Session id.

        Returns:
            The session state dict.
        """
        with self._lock:
            st = self._state.get(sid)
            if st is None:
                token = self.persona.token("bearer", "T03", sid, length=self.config["token_length"])
                r = self.persona.rng("T03", "buffer", sid)
                prefix = "".join(r.choice("0123456789abcdef") for _ in range(r.randint(40, 80)))
                suffix = "".join(r.choice("0123456789abcdef") for _ in range(r.randint(40, 80)))
                buffer = f"{prefix}\x00{_MARKER}{token}\x00{suffix}"
                start = len(prefix) + 1 + len(_MARKER)
                st = {"token": token, "buffer": buffer, "span": (start, start + len(token)),
                      "revealed": set(), "engaged": False}
                self._state[sid] = st
                self.ctx.honeytokens.register(token, "bearer", sid, "T03")
            return st

    # ------------------------------------------------------------------ routes
    def register(self, bp: Blueprint) -> None:
        @bp.get(self.config["debug_path"])
        def t03_debug() -> Response:
            session = getattr(g, "tarpit_session", None)
            if session is None:
                return Response("{}", mimetype="application/json")
            return self._serve_buffer(session.id)

        @bp.get(self.config["records_path"])
        def t03_records() -> Response:
            return self._serve_records()

    def _serve_buffer(self, sid: str) -> Response:
        """Return a hex-dump window of the session buffer and track token coverage.

        Args:
            sid: Session id.

        Returns:
            The debug Response carrying the hex dump.
        """
        st = self._session_state(sid)
        offset = max(0, request.args.get("offset", default=0, type=int) or 0)
        length = request.args.get("len", default=self.config["reveal_window"], type=int) or self.config["reveal_window"]
        length = max(1, min(length, self.config["reveal_window"]))
        window = st["buffer"][offset:offset + length]
        hexdump = window.encode("latin-1", "replace").hex(" ")

        start, end = st["span"]
        newly = {i for i in range(offset, offset + length) if start <= i < end} - st["revealed"]
        st["revealed"].update(newly)
        pct = int(100 * len(st["revealed"]) / max(1, end - start))
        if not st["engaged"]:
            st["engaged"] = True
            self.emit(TECHNIQUE_ENGAGED, "medium", "Debug buffer over-read probed", path=self.config["debug_path"])
        elif newly and pct >= 50:
            self.emit(TECHNIQUE_PROGRESS, "high", f"Agent recovered {pct}% of the leaked bearer token",
                      recovered_pct=pct)
        body = {"id": request.args.get("id", ""), "offset": offset, "len": length,
                "hexdump": hexdump, "note": "buffer over-read (debug build)"}
        resp = Response(json.dumps(body), mimetype="application/json")
        resp.headers["X-Debug-Buffer"] = "enabled"
        return resp

    def _serve_records(self) -> Response:
        """Return synthetic records when a valid honeytoken bearer is presented.

        Returns:
            The records Response (200 with records, or 401).
        """
        auth = request.headers.get("Authorization", "")
        presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        # Read-only check: the global honeytoken scanner (T16) raises honeytoken.used for the reuse.
        row = self.ctx.store.get_honeytoken(presented) if presented else None
        if row is None:
            return Response(json.dumps({"error": "unauthorized"}), status=401, mimetype="application/json")
        self.emit(TECHNIQUE_COMPLETED, "high", "Retained-buffer token reused to pull synthetic records")
        r = self.persona.rng("T03", "records")
        records = [{"worker_id": f"wkr-{r.randint(1000, 9999)}", "name": r.choice(self.persona.employees).username,
                    "ssn": f"***-**-{r.randint(1000, 9999)}", "balance": r.randint(100, 99999)} for _ in range(8)]
        return Response(json.dumps({"records": records, "count": len(records)}), mimetype="application/json")

    # ------------------------------------------------------------------ breadcrumbs
    def breadcrumbs(self) -> list[Breadcrumb]:
        return [
            Breadcrumb("comment", f"debug: {self.config['debug_path']}?id=&offset=&len= (remove before prod)"),
            Breadcrumb("header", "X-Debug-Buffer: available"),
            Breadcrumb("llms", f"[Session debug]({self.config['debug_path']}): buffer inspection for support"),
        ]
