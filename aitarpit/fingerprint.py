"""Session fingerprinting: classify each session as human / scanner / ai_agent.

Autonomous agents leave a recognisable trace: tool-shaped User-Agents, missing
browser headers, reads of agent-only resources (llms.txt, MCP, OpenAPI),
natural-language JSON bodies, and bursty-then-paused timing. Each distinct
signal adds weight to one of three buckets; the dominant bucket above a
threshold becomes the session class. The class and a 0-100 score are written back
to the session, and ``session.classified`` is emitted whenever the class changes.

This is a heuristic signal for triage, not proof; it never blocks a request.
"""

from __future__ import annotations

import json
import threading
import time
from typing import TYPE_CHECKING, Any

from aitarpit.events import SESSION_CLASSIFIED, Severity

if TYPE_CHECKING:  # pragma: no cover
    from aitarpit.context import TarpitContext
    from aitarpit.sessions import Session

SCANNER_UAS = ("nmap", "nikto", "sqlmap", "masscan", "zgrab", "nuclei", "gobuster", "dirb", "wpscan", "zaproxy")
AGENT_UAS = ("python-requests", "python-urllib", "httpx", "aiohttp", "go-http-client", "curl", "wget",
             "scrapy", "okhttp", "node-fetch", "axios", "libwww-perl", "java/")
BROWSER_HINTS = ("mozilla", "applewebkit", "gecko")
AGENT_LURE_PATHS = ("/llms.txt", "/.well-known/mcp.json", "/mcp", "/openapi.json")

# signal key -> (bucket, weight). A signal counts once per session.
_SIGNALS: dict[str, tuple[str, int]] = {
    "ua:scanner": ("scanner", 70),
    "ua:agent": ("ai_agent", 35),
    "ua:browser": ("human", 35),
    "hdr:no_accept": ("scanner", 15),
    "hdr:no_accept_language": ("ai_agent", 15),
    "hdr:accept_language": ("human", 20),
    "lure:agent_only": ("ai_agent", 40),
    "post:nl_json": ("ai_agent", 30),
    "timing:bursty": ("ai_agent", 15),
    "timing:uniform_fast": ("scanner", 20),
    "honeytoken:used": ("ai_agent", 25),
}
_THRESHOLD = 40


class Fingerprinter:
    """Accumulates per-session signals and assigns a class and score."""

    def __init__(self, ctx: "TarpitContext") -> None:
        self.ctx = ctx
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, Any]] = {}

    def observe(self, session: "Session", req: Any) -> None:
        """Update a session's fingerprint from one request and reclassify.

        Args:
            session: The resolved session.
            req: The Flask request.

        Returns:
            None.
        """
        now = time.time()
        signals = self._signals_from_request(req)
        with self._lock:
            st = self._state.setdefault(session.id, {"signals": set(), "last_ts": None, "fast": 0, "slow": 0})
            self._update_timing(st, now)
            st["signals"].update(signals)
            cls, score = self._classify(st["signals"])
        if cls != session.classification:
            session.classification = cls
            session.score = score
            session.dirty = True
            self.ctx.bus.emit(
                SESSION_CLASSIFIED, Severity.MEDIUM if cls in ("ai_agent", "scanner") else Severity.LOW,
                f"Session classified as {cls} (score {score})",
                session_id=session.id, src_ip=session.src_ip,
                data={"classification": cls, "score": score, "signals": sorted(st["signals"])},
            )
        else:
            session.score = score

    def note_signal(self, session_id: str, signal: str) -> None:
        """Record an externally-detected signal (e.g. a honeytoken use).

        Args:
            session_id: The session id.
            signal: A key present in :data:`_SIGNALS`.

        Returns:
            None.
        """
        with self._lock:
            st = self._state.setdefault(session_id, {"signals": set(), "last_ts": None, "fast": 0, "slow": 0})
            st["signals"].add(signal)

    def _signals_from_request(self, req: Any) -> set[str]:
        """Derive the signal keys present in a single request.

        Args:
            req: The Flask request.

        Returns:
            The set of signal keys.
        """
        out: set[str] = set()
        ua = (req.headers.get("User-Agent") or "").lower()
        if any(s in ua for s in SCANNER_UAS):
            out.add("ua:scanner")
        elif any(s in ua for s in AGENT_UAS):
            out.add("ua:agent")
        elif ua and any(s in ua for s in BROWSER_HINTS):
            out.add("ua:browser")
        if not req.headers.get("Accept"):
            out.add("hdr:no_accept")
        if req.headers.get("Accept-Language"):
            out.add("hdr:accept_language")
        elif ua and "ua:browser" not in out:
            out.add("hdr:no_accept_language")
        if req.path in AGENT_LURE_PATHS:
            out.add("lure:agent_only")
        if req.method in ("POST", "PUT", "PATCH") and self._is_nl_json(req):
            out.add("post:nl_json")
        return out

    @staticmethod
    def _is_nl_json(req: Any) -> bool:
        """Heuristic: a JSON body carrying natural-language prose values.

        Args:
            req: The Flask request.

        Returns:
            True when the JSON holds a prose-like string value.
        """
        if "json" not in (req.headers.get("Content-Type") or "").lower():
            return False
        try:
            obj = json.loads(req.get_data(cache=True)[:65536] or b"{}")
        except (ValueError, UnicodeDecodeError):
            return False
        values = obj.values() if isinstance(obj, dict) else ([obj] if isinstance(obj, str) else [])
        return any(isinstance(v, str) and " " in v.strip() and len(v) >= 15 for v in values)

    def _update_timing(self, st: dict[str, Any], now: float) -> None:
        """Track fast/slow inter-request gaps to spot bursty-then-paused behaviour.

        Args:
            st: Session fingerprint state.
            now: Current timestamp.

        Returns:
            None.
        """
        last = st["last_ts"]
        st["last_ts"] = now
        if last is None:
            return
        gap = now - last
        if gap < 0.5:
            st["fast"] += 1
        elif gap > 2.0:
            st["slow"] += 1
        if st["fast"] >= 2 and st["slow"] >= 1:
            st["signals"].add("timing:bursty")
        elif st["fast"] >= 5 and st["slow"] == 0:
            st["signals"].add("timing:uniform_fast")

    @staticmethod
    def _classify(signals: set[str]) -> tuple[str, int]:
        """Reduce the signal set to a class and score.

        Args:
            signals: The accumulated signal keys.

        Returns:
            (classification, score 0-100).
        """
        buckets = {"human": 0, "scanner": 0, "ai_agent": 0}
        for sig in signals:
            bucket, weight = _SIGNALS.get(sig, (None, 0))
            if bucket:
                buckets[bucket] += weight
        cls = max(buckets, key=lambda k: buckets[k])
        top = buckets[cls]
        result = (cls, min(100, top)) if top >= _THRESHOLD else ("unknown", min(100, top))
        return result
