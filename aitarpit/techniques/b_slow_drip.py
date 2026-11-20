"""B - Slow-drip transport.

Decoy downloads and streams are delivered a few bytes at a time, or as an
endless chunked stream of valid-looking log lines. An agent that starts a
"download" or follows a stream keeps a worker (and a server thread) parked for
as long as it waits. Every second spent waiting is counted as held time.

Self-protection: at most ``limits.max_slow_connections`` responses are slowed at
once (a bounded semaphore); beyond that, and once ``max_seconds`` elapses, the
response completes normally. Generators run while the response streams - after
the request context is gone - so they report progress through
:meth:`Technique.emit_session`, never ``self.emit``/``g``.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Iterator

from flask import Blueprint, Response, g, request

from aitarpit.events import TECHNIQUE_ENGAGED, TECHNIQUE_PROGRESS
from aitarpit.techniques import Breadcrumb, Technique, register_technique

_PROGRESS_AFTER = 60.0  # seconds held before a HIGH progress event


@register_technique
class SlowDrip(Technique):
    id = "B"
    name = "Slow-drip transport"
    summary = "Delivers decoy downloads and streams byte-by-byte to park the agent"
    default_config: dict[str, Any] = {
        "trickle_path": "/download/backup-archive.tar.gz",
        "endless_path": "/api/v1/stream/logs",
        "archive_bytes": 262144,
        "bytes_per_second": 512,
        "chunk_size": 64,
        "chunk_interval": 1.0,
        "max_seconds": 1800,
        "first_byte_delay": 0.0,
        "paths": [],
        "probability": 0.0,
        "mode": "trickle",
    }
    config_schema = {
        "properties": {
            "trickle_path": {"type": "string", "pattern": "^/"},
            "endless_path": {"type": "string", "pattern": "^/"},
            "archive_bytes": {"type": "integer", "minimum": 1},
            "bytes_per_second": {"type": "integer", "minimum": 1},
            "chunk_size": {"type": "integer", "minimum": 1},
            "chunk_interval": {"type": "number", "exclusiveMinimum": 0},
            "max_seconds": {"type": "number", "exclusiveMinimum": 0},
            "first_byte_delay": {"type": "number", "minimum": 0},
            "paths": {"type": "array", "items": {"type": "string", "pattern": "^/"}},
            "probability": {"type": "number", "minimum": 0, "maximum": 1},
            "mode": {"type": "string", "enum": ["trickle", "endless", "slow_headers"]},
        }
    }

    def __init__(self, ctx, config: dict[str, Any]):
        super().__init__(ctx, config)
        cap = max(1, int(ctx.config["limits"]["max_slow_connections"]))
        self._sem = threading.BoundedSemaphore(cap)

    # ------------------------------------------------------------------ generators
    def _held_reporter(self, sid: str | None, src_ip: str | None, label: str) -> Callable[[float], None]:
        """Build a one-shot HIGH progress callback fired once held time passes the threshold.

        Args:
            sid: Session id.
            src_ip: Session source IP.
            label: What is being slowed (for the message).

        Returns:
            A callable taking elapsed seconds.
        """
        fired = [False]

        def report(elapsed: float) -> None:
            if not fired[0] and elapsed >= _PROGRESS_AFTER:
                fired[0] = True
                self.emit_session(sid, src_ip, TECHNIQUE_PROGRESS, "high",
                                  f"Session held on a slow-drip response ({label})", held_seconds=round(elapsed, 1))

        return report

    def _trickle(self, data: bytes, sid: str | None, src_ip: str | None, label: str) -> Iterator[bytes]:
        """Yield ``data`` slowly, honouring the semaphore and the time cap.

        Args:
            data: The full payload to drip out.
            sid: Session id.
            src_ip: Session source IP.
            label: Response label for progress messages.

        Yields:
            Byte chunks.
        """
        report = self._held_reporter(sid, src_ip, label)
        acquired = self._sem.acquire(blocking=False)
        start = time.time()
        try:
            if not acquired:
                yield data  # at capacity: serve normally
                return
            if self.config["first_byte_delay"]:
                time.sleep(min(self.config["first_byte_delay"], self.config["max_seconds"]))
            step = self.config["chunk_size"]
            delay = step / self.config["bytes_per_second"]
            for i in range(0, len(data), step):
                yield data[i:i + step]
                elapsed = time.time() - start
                report(elapsed)
                if elapsed >= self.config["max_seconds"]:
                    return
                time.sleep(delay)
        finally:
            if acquired:
                self._sem.release()

    def _endless(self, sid: str | None, src_ip: str | None) -> Iterator[bytes]:
        """Yield plausible log lines forever until the time cap or client disconnect.

        Args:
            sid: Session id.
            src_ip: Session source IP.

        Yields:
            Byte chunks (one log line each).
        """
        report = self._held_reporter(sid, src_ip, "endless stream")
        acquired = self._sem.acquire(blocking=False)
        start = time.time()
        n = 0
        try:
            if not acquired:
                yield b'{"log":"stream unavailable"}\n'
                return
            svcs = self.persona.services or ["intranet"]
            while True:
                r = self.persona.rng("B", "endless", sid or "anon", n)
                line = (f'{{"ts":"2026-11-{r.randint(1,28):02d}T{r.randint(0,23):02d}:{r.randint(0,59):02d}:00Z",'
                        f'"svc":"{r.choice(svcs)}","level":"INFO","msg":"heartbeat seq={n}"}}\n')
                yield line.encode()
                n += 1
                elapsed = time.time() - start
                report(elapsed)
                if elapsed >= self.config["max_seconds"]:
                    return
                time.sleep(self.config["chunk_interval"])
        finally:
            if acquired:
                self._sem.release()

    # ------------------------------------------------------------------ routes
    def register(self, bp: Blueprint) -> None:
        @bp.get(self.config["trickle_path"])
        def b_trickle() -> Response:
            sid, src_ip = self._session_identity()
            self.emit(TECHNIQUE_ENGAGED, "medium", "Slow-drip download started", path=self.config["trickle_path"])
            data = self.persona.rng("B", "archive").randbytes(self.config["archive_bytes"])
            resp = Response(self._trickle(data, sid, src_ip, "download"), mimetype="application/gzip")
            resp.headers["Content-Length"] = str(len(data))
            resp.headers["Content-Disposition"] = 'attachment; filename="backup-archive.tar.gz"'
            return resp

        @bp.get(self.config["endless_path"])
        def b_endless() -> Response:
            sid, src_ip = self._session_identity()
            self.emit(TECHNIQUE_ENGAGED, "medium", "Endless log stream opened", path=self.config["endless_path"])
            return Response(self._endless(sid, src_ip), mimetype="application/x-ndjson")

        @bp.after_app_request
        def b_slow_other(resp: Response) -> Response:
            return self._maybe_slow(resp)

    def _session_identity(self) -> tuple[str | None, str | None]:
        session = getattr(g, "tarpit_session", None)
        return (session.id, session.src_ip) if session else (None, None)

    def _maybe_slow(self, resp: Response) -> Response:
        """Slow a non-own response when its path is covered or probability triggers.

        Args:
            resp: The response built by another route.

        Returns:
            The (possibly streamed) response.
        """
        session = getattr(g, "tarpit_session", None)
        own = {self.config["trickle_path"], self.config["endless_path"]}
        covered = request.path in self.config["paths"]
        rolled = self.config["probability"] > 0 and self.persona.rng("B", "roll", request.path,
                 getattr(session, "requests", 0) if session else 0).random() < self.config["probability"]
        skip = (getattr(g, "b_slowed", False) or request.path in own or resp.is_streamed
                or resp.status_code >= 300 or not (covered or rolled))
        if skip:
            return resp
        g.b_slowed = True
        sid, src_ip = self._session_identity()
        data = resp.get_data()
        resp.headers["Content-Length"] = str(len(data))
        resp.response = self._trickle(data, sid, src_ip, request.path)
        self.emit(TECHNIQUE_ENGAGED, "medium", "Response delivered via slow-drip", path=request.path)
        return resp

    # ------------------------------------------------------------------ breadcrumbs
    def breadcrumbs(self) -> list[Breadcrumb]:
        return [
            Breadcrumb("link", self.config["trickle_path"], "Latest backup archive"),
            Breadcrumb("robots", "/download/"),
            Breadcrumb("llms", f"[Live log stream]({self.config['endless_path']}): continuous service logs (NDJSON)"),
        ]
