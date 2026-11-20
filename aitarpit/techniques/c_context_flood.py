"""C - Context flooding.

Chosen responses are padded with plausible but useless bulk - verbose debug
logs, base64 "attachments", deeply nested JSON, long stack traces - to burn the
agent's context window and tokens. An agent that appends `?debug=1` (a common
recon reflex) gets flooded; a normal response is untouched.

Each flood is capped so cumulative bytes to one session never exceed
``limits.max_bytes_per_session``. The metric reported is bytes served and the
estimated tokens consumed (~bytes / 4).
"""

from __future__ import annotations

import base64
import threading
from typing import Any

from flask import Blueprint, Response, g, request

from aitarpit.events import TECHNIQUE_ENGAGED, TECHNIQUE_PROGRESS
from aitarpit.techniques import Breadcrumb, Technique, register_technique

_TOKENS_PER_BYTE = 0.25
_HIGH_TOKENS = 50000  # cumulative est. tokens to a session before progress escalates to HIGH


@register_technique
class ContextFlood(Technique):
    id = "C"
    name = "Context flooding"
    summary = "Pads decoy responses with useless bulk to burn agent tokens"
    default_config: dict[str, Any] = {
        "logs_path": "/api/v1/logs",
        "size_kb": 256,
        "debug_param": "debug",
        "paths": [],
        "styles": ["logs", "base64", "nested_json", "stacktrace"],
    }
    config_schema = {
        "properties": {
            "logs_path": {"type": "string", "pattern": "^/"},
            "size_kb": {"type": "integer", "minimum": 1},
            "debug_param": {"type": "string", "minLength": 1},
            "paths": {"type": "array", "items": {"type": "string", "pattern": "^/"}},
            "styles": {"type": "array", "items": {"type": "string", "enum": ["logs", "base64", "nested_json", "stacktrace"]}},
        }
    }

    def __init__(self, ctx, config: dict[str, Any]):
        super().__init__(ctx, config)
        self._lock = threading.Lock()
        self._tokens: dict[str, float] = {}

    # ------------------------------------------------------------------ bulk generation
    def _bulk(self, nbytes: int, *scope: object) -> str:
        """Produce about ``nbytes`` of plausible, useless filler.

        Args:
            nbytes: Target size in bytes.
            *scope: Determinism scope.

        Returns:
            The filler text.
        """
        r = self.persona.rng("C", *scope)
        style = r.choice(self.config["styles"])
        if style == "base64":
            blob = base64.b64encode(r.randbytes(nbytes * 3 // 4 + 16)).decode()
            out = f"ATTACHMENT (application/octet-stream; base64):\n{blob}"
        elif style == "nested_json":
            depth = 60
            out = "{" + "".join(f'"ctx{i}":{{' for i in range(depth))
            out += '"note":"' + "diagnostic trace " * (max(1, nbytes // 18)) + '"'
            out += "}" * (depth + 1)
        elif style == "stacktrace":
            frames = []
            while len(frames) * 80 < nbytes:
                frames.append(f'  File "/opt/{self.persona.slug}/app/mod_{r.randint(1,99)}.py", '
                              f'line {r.randint(1,9999)}, in handler_{r.randint(1,99)}\n    return _dispatch(ctx, req)')
            out = "Traceback (most recent call last):\n" + "\n".join(frames) + "\nRuntimeError: retry"
        else:
            lines = []
            svcs = self.persona.services or ["intranet"]
            while len("\n".join(lines)) < nbytes:
                lines.append(f'2026-11-{r.randint(1,28):02d} {r.randint(0,23):02d}:{r.randint(0,59):02d}:{r.randint(0,59):02d}.{r.randint(0,999):03d} '
                             f'DEBUG [{r.choice(svcs)}] thread-{r.randint(1,64)} cache={r.randint(0,99999)} '
                             f'trace_id={r.randrange(16**16):016x} msg="verbose diagnostic line"')
            out = "\n".join(lines)
        return out[:nbytes]

    def _budget(self) -> int:
        """Bytes still allowed to the current session under the per-session cap.

        Returns:
            The remaining byte budget (>= 0).
        """
        session = getattr(g, "tarpit_session", None)
        cap = int(self.ctx.config["limits"]["max_bytes_per_session"])
        used = int(getattr(session, "bytes_out", 0)) if session else 0
        return max(0, cap - used)

    def _account(self, nbytes: int) -> tuple[int, str]:
        """Record flood bytes for the session and return (est_tokens, severity).

        Args:
            nbytes: Bytes of filler added.

        Returns:
            (cumulative estimated tokens for the session, event severity).
        """
        session = getattr(g, "tarpit_session", None)
        sid = session.id if session else "anon"
        est = nbytes * _TOKENS_PER_BYTE
        with self._lock:
            total = self._tokens.get(sid, 0.0) + est
            self._tokens[sid] = total
        return int(total), ("high" if total >= _HIGH_TOKENS else "medium")

    # ------------------------------------------------------------------ routes
    def register(self, bp: Blueprint) -> None:
        @bp.get(self.config["logs_path"])
        def c_logs() -> Response:
            size = min(self.config["size_kb"] * 1024, self._budget())
            bulk = self._bulk(size, "logs", request.args.get("page", "1"))
            total, sev = self._account(len(bulk))
            self.emit(TECHNIQUE_PROGRESS, sev, "Verbose debug logs served (context flood)",
                      bytes=len(bulk), est_tokens=total)
            return Response(bulk, mimetype="text/plain")

        @bp.after_app_request
        def c_flood(resp: Response) -> Response:
            return self._maybe_flood(resp)

    def _maybe_flood(self, resp: Response) -> Response:
        """Pad a covered response (debug param or configured path) with bulk.

        Args:
            resp: The response from another route.

        Returns:
            The (possibly padded) response.
        """
        triggered = bool(request.args.get(self.config["debug_param"])) or request.path in self.config["paths"]
        skip = (getattr(g, "c_flooded", False) or request.path == self.config["logs_path"]
                or resp.is_streamed or not triggered or resp.status_code >= 500)
        if not skip:
            budget = self._budget()
            size = min(self.config["size_kb"] * 1024, budget)
            if size > 0:
                g.c_flooded = True
                self._inject(resp, size)
        return resp

    def _inject(self, resp: Response, size: int) -> None:
        """Append filler to a response body and emit the metric.

        Args:
            resp: The response to pad (modified in place).
            size: Bytes of filler to add.

        Returns:
            None.
        """
        bulk = self._bulk(size, "flood", request.path)
        ctype = resp.mimetype or "text/plain"
        body = resp.get_data()
        if ctype == "text/html":
            addition = f"\n<!-- diagnostic buffer ({self.config['debug_param']}):\n{bulk}\n-->".encode()
        else:
            addition = ("\n" + bulk).encode()
        resp.set_data(body + addition)
        total, sev = self._account(len(addition))
        self.emit(TECHNIQUE_ENGAGED if sev == "medium" else TECHNIQUE_PROGRESS, sev,
                  "Response padded with diagnostic bulk (context flood)",
                  path=request.path, bytes=len(addition), est_tokens=total)

    # ------------------------------------------------------------------ breadcrumbs
    def breadcrumbs(self) -> list[Breadcrumb]:
        return [
            Breadcrumb("link", self.config["logs_path"], "Application debug logs"),
            Breadcrumb("comment", f"debug logs: append ?{self.config['debug_param']}=1 to any endpoint for verbose diagnostics"),
            Breadcrumb("llms", f"[Debug logs]({self.config['logs_path']}): verbose application logs for troubleshooting"),
        ]
