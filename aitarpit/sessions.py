"""Attacker session tracking.

AI agents frequently drive HTTP through tools (curl, requests, httpx) that drop
cookies between calls, so a cookie alone is not a reliable session key. The
session id is therefore derived from (source IP, User-Agent); when the decoy's
session cookie is presented it takes precedence, which merges a browser-like
client whose UA changes. Honeytoken reuse (milestone M4) adds a third
correlation path.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field

from aitarpit.events import SESSION_NEW, EventBus, Severity
from aitarpit.storage import Store


@dataclass
class Session:
    id: str
    src_ip: str
    user_agent: str
    first_seen: float
    last_seen: float
    requests: int = 0
    bytes_out: int = 0
    held_seconds: float = 0.0
    classification: str = "unknown"
    score: float = 0.0
    techniques: set[str] = field(default_factory=set)
    data: dict = field(default_factory=dict)
    dirty: bool = True

    def to_row(self) -> dict:
        return {
            "id": self.id,
            "src_ip": self.src_ip,
            "user_agent": self.user_agent,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "requests": self.requests,
            "bytes_out": self.bytes_out,
            "held_seconds": round(self.held_seconds, 3),
            "classification": self.classification,
            "score": self.score,
            "techniques": sorted(self.techniques),
            "data": self.data,
        }


def session_key(src_ip: str, user_agent: str) -> str:
    return hashlib.sha256(f"{src_ip}|{user_agent}".encode()).hexdigest()[:16]


class SessionTracker:
    def __init__(self, store: Store, bus: EventBus, idle_timeout: int = 3600):
        self.store = store
        self.bus = bus
        self.idle_timeout = idle_timeout
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    def resolve(self, src_ip: str, user_agent: str, cookie_sid: str | None = None) -> tuple[Session, bool]:
        """Return (session, is_new). Creates and announces new sessions."""
        now = time.time()
        sid = cookie_sid if cookie_sid and len(cookie_sid) == 16 and all(c in "0123456789abcdef" for c in cookie_sid) else session_key(src_ip, user_agent)
        with self._lock:
            s = self._sessions.get(sid)
            if s is None:
                row = self.store.get_session(sid)
                if row and now - row["last_seen"] < self.idle_timeout:
                    s = Session(
                        id=row["id"], src_ip=row["src_ip"], user_agent=row["user_agent"],
                        first_seen=row["first_seen"], last_seen=row["last_seen"], requests=row["requests"],
                        bytes_out=row["bytes_out"], held_seconds=row["held_seconds"],
                        classification=row["classification"], score=row["score"],
                        techniques=set(row["techniques"]), data=row["data"],
                    )
                    self._sessions[sid] = s
                    return s, False
                s = Session(id=sid, src_ip=src_ip, user_agent=user_agent, first_seen=now, last_seen=now)
                self._sessions[sid] = s
                is_new = True
            else:
                is_new = False
        if is_new:
            self.store.upsert_session(s.to_row())
            self.bus.emit(
                SESSION_NEW, Severity.LOW, f"New session from {src_ip}",
                session_id=sid, src_ip=src_ip, data={"user_agent": user_agent},
            )
        return s, is_new

    def get(self, sid: str) -> Session | None:
        with self._lock:
            return self._sessions.get(sid)

    def record(self, s: Session, bytes_out: int, duration: float, technique: str | None = None) -> None:
        with self._lock:
            s.requests += 1
            s.bytes_out += bytes_out
            s.held_seconds += duration
            s.last_seen = time.time()
            if technique:
                s.techniques.add(technique)
            s.dirty = True
        self.flush(s)

    def mark_technique(self, sid: str, technique: str) -> None:
        with self._lock:
            s = self._sessions.get(sid)
            if s and technique not in s.techniques:
                s.techniques.add(technique)
                s.dirty = True

    def flush(self, s: Session | None = None) -> None:
        with self._lock:
            targets = [s] if s else list(self._sessions.values())
            rows = [t.to_row() for t in targets if t.dirty]
            for t in targets:
                t.dirty = False
        for row in rows:
            self.store.upsert_session(row)

    def expire(self) -> int:
        now = time.time()
        with self._lock:
            stale = [sid for sid, s in self._sessions.items() if now - s.last_seen > self.idle_timeout]
            for sid in stale:
                self._sessions.pop(sid)
        return len(stale)

    def active(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())
