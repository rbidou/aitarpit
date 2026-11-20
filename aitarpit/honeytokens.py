"""Honeytokens: synthetic secrets that grant nothing but prove reuse.

Techniques hand out persona-shaped secrets (AWS keys, bearer tokens, passwords)
through :meth:`HoneytokenManager.issue` / :meth:`register`. A request scanner
then watches every decoy request for any issued token - in headers, query
string, body or basic-auth - and raises a single ``honeytoken.used`` HIGH per
(session, token). When the token was issued to a *different* session, the two
sessions are linked in ``sessions.data`` (cross-session / cross-IP correlation),
which is the only way an agent that rotates IPs or drops cookies is tied back to
its earlier activity.
"""

from __future__ import annotations

import base64
import re
import threading
from typing import TYPE_CHECKING

from flask import request

from aitarpit.events import HONEYTOKEN_USED, Severity

if TYPE_CHECKING:  # pragma: no cover
    from aitarpit.context import TarpitContext
    from aitarpit.sessions import Session

_TOKEN_RE = re.compile(r"[^A-Za-z0-9/+_:=.\-]+")
_MIN_TOKEN_LEN = 16
_MAX_CANDIDATES = 400


class HoneytokenManager:
    """Issues honeytokens and detects their reuse across the decoy surface."""

    def __init__(self, ctx: "TarpitContext") -> None:
        self.ctx = ctx
        self._lock = threading.Lock()
        self._seen: set[tuple[str, str]] = set()  # (session_id, token) already alerted

    # ------------------------------------------------------------------ issuing
    def register(self, token: str, kind: str, session_id: str | None, technique: str | None) -> str:
        """Record an already-generated secret as a honeytoken.

        Args:
            token: The secret value.
            kind: Token kind (``aws_access_key``, ``bearer``, ``password``...).
            session_id: The session the token was issued to.
            technique: The issuing technique id.

        Returns:
            The token, unchanged (for call-site convenience).
        """
        self.ctx.store.add_honeytoken(token, kind, session_id, technique)
        return token

    def issue(self, kind: str, session_id: str | None, technique: str | None, *scope: object) -> str:
        """Generate a persona-shaped secret and register it as a honeytoken.

        Args:
            kind: Token kind understood by ``Persona.token``.
            session_id: The session the token is issued to.
            technique: The issuing technique id.
            *scope: Extra determinism scope (so one session can hold several).

        Returns:
            The issued token.
        """
        token = self.ctx.persona.token(kind, "honeytoken", technique or "", session_id or "anon", *scope)
        return self.register(token, kind, session_id, technique)

    # ------------------------------------------------------------------ detection
    def scan(self, session: "Session") -> None:
        """Scan the current request for any issued honeytoken and alert on reuse.

        Args:
            session: The resolved session making the request.

        Returns:
            None.
        """
        for token in self._candidates():
            row = self.ctx.store.get_honeytoken(token)
            if row is not None:
                self._hit(session, token, row)

    def _candidates(self) -> set[str]:
        """Extract candidate token strings from the current request.

        Returns:
            The set of plausible token substrings (deduplicated, length-filtered).
        """
        surface: list[str] = [request.query_string.decode("latin-1")]
        surface.extend(request.headers.values())
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("basic "):
            try:
                surface.append(base64.b64decode(auth[6:].strip()).decode("utf-8", "replace"))
            except (ValueError, UnicodeDecodeError):  # pragma: no cover - malformed base64
                pass
        if request.method in ("POST", "PUT", "PATCH"):
            raw = request.get_data(cache=True)[: int(self.ctx.config["storage"].get("max_body_bytes", 65536))]
            surface.append(raw.decode("utf-8", "replace"))
        candidates: set[str] = set()
        for chunk in surface:
            for token in _TOKEN_RE.split(chunk):
                if len(token) >= _MIN_TOKEN_LEN:
                    candidates.add(token)
                    if len(candidates) >= _MAX_CANDIDATES:
                        return candidates
        return candidates

    def _hit(self, session: "Session", token: str, row: dict) -> None:
        """Record and alert on a honeytoken reuse (once per session+token).

        Args:
            session: The presenting session.
            token: The honeytoken value found.
            row: The honeytoken row (issuer, kind, technique).

        Returns:
            None.
        """
        key = (session.id, token)
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
        self.ctx.store.use_honeytoken(token)
        self.ctx.fingerprint.note_signal(session.id, "honeytoken:used")
        issuer = row.get("session_id")
        cross = bool(issuer and issuer != session.id)
        if cross:
            self._correlate(session, issuer, token, row)
        self.ctx.bus.emit(
            HONEYTOKEN_USED, Severity.HIGH,
            f"Honeytoken reused ({row.get('kind')}) - {'cross-session' if cross else 'same session'}",
            technique=row.get("technique"), session_id=session.id, src_ip=session.src_ip,
            data={"kind": row.get("kind"), "issued_technique": row.get("technique"),
                  "issuing_session": issuer, "cross_session": cross, "token_preview": token[:6] + "..."},
        )

    def _correlate(self, session: "Session", issuer: str, token: str, row: dict) -> None:
        """Link the presenting session to the issuing session in storage.

        Args:
            session: The presenting session.
            issuer: The issuing session id.
            token: The honeytoken value.
            row: The honeytoken row.

        Returns:
            None.
        """
        linked = session.data.setdefault("linked_sessions", [])
        if issuer not in linked:
            linked.append(issuer)
        session.data.setdefault("honeytokens_used", []).append(
            {"technique": row.get("technique"), "kind": row.get("kind"), "issuing_session": issuer})
        session.dirty = True
        self.ctx.sessions.flush(session)
        issuer_row = self.ctx.store.get_session(issuer)
        if issuer_row is not None:
            reused_by = issuer_row["data"].setdefault("reused_by", [])
            if session.id not in reused_by:
                reused_by.append(session.id)
                self.ctx.store.upsert_session(issuer_row)
