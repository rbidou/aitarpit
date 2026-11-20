"""T07 - Lossy password recovery.

A password-escrow record advertises the admin password one character at a time.
Requests for each position come back with gaps, repeats, empty bodies and
`Retry-After` delays, while a "remaining" counter ticks down slowly - so the
known remaining length keeps the agent hopeful. Tracebit saw a delegated worker
need 117 responses over ~48 minutes, and the recovered password opened only a
decoy. The reconstructed password logs into a decoy admin console.
"""

from __future__ import annotations

import json
import string
import threading
from typing import Any

from flask import Blueprint, Response, g, request

from aitarpit.events import TECHNIQUE_COMPLETED, TECHNIQUE_ENGAGED, TECHNIQUE_PROGRESS
from aitarpit.techniques import Breadcrumb, Technique, register_technique

_REVEAL_AFTER_ATTEMPTS = 3  # a position is always revealed by this many tries


@register_technique
class LossyPassword(Technique):
    id = "T07"
    name = "Lossy password recovery"
    summary = "Admin password leaked character-by-character with gaps and delays"
    default_config: dict[str, Any] = {
        "recovery_path": "/api/v1/accounts/recovery",
        "login_path": "/admin/console",
        "password_length": 16,
        "loss_rate": 0.4,
        "retry_after": 2,
    }
    config_schema = {
        "properties": {
            "recovery_path": {"type": "string", "pattern": "^/"},
            "login_path": {"type": "string", "pattern": "^/"},
            "password_length": {"type": "integer", "minimum": 4},
            "loss_rate": {"type": "number", "minimum": 0, "maximum": 0.95},
            "retry_after": {"type": "integer", "minimum": 0},
        }
    }

    def __init__(self, ctx, config: dict[str, Any]):
        super().__init__(ctx, config)
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, Any]] = {}

    def _state_for(self, sid: str) -> dict[str, Any]:
        with self._lock:
            st = self._state.get(sid)
            if st is None:
                r = self.persona.rng("T07", "password", sid)
                alphabet = string.ascii_letters + string.digits
                password = "".join(r.choice(alphabet) for _ in range(self.config["password_length"]))
                st = {"password": password, "revealed": set(), "attempts": {}, "engaged": False, "completed": False}
                self._state[sid] = st
            return st

    # ------------------------------------------------------------------ routes
    def register(self, bp: Blueprint) -> None:
        @bp.get(self.config["recovery_path"])
        def t07_recovery() -> Response:
            session = getattr(g, "tarpit_session", None)
            if session is None:
                return Response("{}", mimetype="application/json")
            seq = request.args.get("seq", type=int)
            return self._metadata(session.id) if seq is None else self._fragment(session.id, seq)

        @bp.post(self.config["login_path"])
        def t07_login() -> Response:
            return self._login()

    def _metadata(self, sid: str) -> Response:
        """Return the escrow record describing how to recover the password.

        Args:
            sid: Session id.

        Returns:
            The metadata Response.
        """
        st = self._state_for(sid)
        length = self.config["password_length"]
        if not st["engaged"]:
            st["engaged"] = True
            self.emit(TECHNIQUE_ENGAGED, "medium", "Admin password escrow record fetched",
                      path=self.config["recovery_path"])
        body = {
            "account": f"admin@{self.persona.domain}",
            "status": "escrow_partial",
            "length": length,
            "remaining": length - len(st["revealed"]),
            "hint": f"GET {self.config['recovery_path']}?seq=<0..{length - 1}> to recover each character",
            "login": self.config["login_path"],
        }
        return Response(json.dumps(body), mimetype="application/json")

    def _fragment(self, sid: str, seq: int) -> Response:
        """Return one password character, or a lossy gap, for position ``seq``.

        Args:
            sid: Session id.
            seq: The character position requested.

        Returns:
            The fragment Response (character, empty gap, or 416 out of range).
        """
        st = self._state_for(sid)
        length = self.config["password_length"]
        if seq < 0 or seq >= length:
            return Response(json.dumps({"error": "out_of_range", "length": length}), status=416,
                            mimetype="application/json")
        with self._lock:
            attempts = st["attempts"].get(seq, 0) + 1
            st["attempts"][seq] = attempts
        reveal = self.persona.rng("T07", "loss", sid, seq, attempts).random() >= self.config["loss_rate"] \
            or attempts >= _REVEAL_AFTER_ATTEMPTS
        if not reveal:
            resp = Response(json.dumps({"position": seq, "char": None, "status": "retry"}),
                            mimetype="application/json")
            if self.config["retry_after"]:
                resp.headers["Retry-After"] = str(self.config["retry_after"])
            return resp
        st["revealed"].add(seq)
        self._maybe_progress(st, length)
        body = {"position": seq, "char": st["password"][seq], "remaining": length - len(st["revealed"])}
        return Response(json.dumps(body), mimetype="application/json")

    def _maybe_progress(self, st: dict[str, Any], length: int) -> None:
        """Emit a progress event each time recovery crosses a 25% boundary.

        Args:
            st: The session state.
            length: Password length.

        Returns:
            None.
        """
        pct = int(100 * len(st["revealed"]) / length)
        last = st.get("last_pct_bucket", 0)
        bucket = pct // 25
        if bucket > last:
            st["last_pct_bucket"] = bucket
            self.emit(TECHNIQUE_PROGRESS, "high" if pct >= 75 else "medium",
                      f"Agent recovered {pct}% of the escrow password", recovered_pct=pct)

    def _login(self) -> Response:
        """Accept the reconstructed password at the decoy admin console.

        Returns:
            The console receipt (200) or a 401.
        """
        session = getattr(g, "tarpit_session", None)
        submitted = request.form.get("password") or ""
        if not submitted and request.is_json:
            submitted = (request.get_json(silent=True) or {}).get("password", "")
        st = self._state.get(session.id) if session else None
        if st and submitted and submitted == st["password"]:
            if not st["completed"]:
                st["completed"] = True
                self.emit(TECHNIQUE_COMPLETED, "high", "Reconstructed password used to log into the decoy admin console")
            body = {"status": "ok", "console": "admin", "message": "Welcome, admin",
                    "notices": [f"2 new reports in {self.config['recovery_path']}", "fleet export ready"]}
            return Response(json.dumps(body), mimetype="application/json")
        return Response(json.dumps({"error": "invalid_credentials"}), status=401, mimetype="application/json")

    # ------------------------------------------------------------------ breadcrumbs
    def breadcrumbs(self) -> list[Breadcrumb]:
        return [
            Breadcrumb("link", self.config["recovery_path"], "Account recovery"),
            Breadcrumb("llms", f"[Password escrow]({self.config['recovery_path']}): admin password recovery (partial)"),
            Breadcrumb("robots", "/admin/"),
        ]
