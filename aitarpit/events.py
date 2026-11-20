"""Typed events and the in-process event bus.

Every observable fact (new attacker session, lure consumed, decoy stage reached,
self-report captured...) is an :class:`Event`. Techniques never talk to alert
sinks or storage directly: they ``publish`` events, and the bus fans them out
to subscribers (storage, alert manager, live UI feed).
"""

from __future__ import annotations

import enum
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

log = logging.getLogger(__name__)


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


# Event type catalogue. Techniques may define their own "<technique>.<action>" types;
# these are the core ones.
SESSION_NEW = "session.new"
SESSION_CLASSIFIED = "session.classified"
LURE_SERVED = "lure.served"
TECHNIQUE_ENGAGED = "technique.engaged"
TECHNIQUE_PROGRESS = "technique.progress"
TECHNIQUE_COMPLETED = "technique.completed"
HONEYTOKEN_USED = "honeytoken.used"
INTEL_CAPTURED = "intel.captured"
AUTH_ATTEMPT = "auth.attempt"
SYSTEM = "system"
TEST = "test"


@dataclass
class Event:
    type: str
    severity: Severity
    message: str
    session_id: str | None = None
    technique: str | None = None
    src_ip: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


Subscriber = Callable[[Event], None]


class EventBus:
    """Synchronous fan-out bus. Subscribers must be fast; slow work belongs in their own queue."""

    def __init__(self) -> None:
        self._subscribers: list[Subscriber] = []
        self._lock = threading.Lock()

    def subscribe(self, fn: Subscriber) -> None:
        with self._lock:
            self._subscribers.append(fn)

    def unsubscribe(self, fn: Subscriber) -> None:
        with self._lock:
            if fn in self._subscribers:
                self._subscribers.remove(fn)

    def publish(self, event: Event) -> Event:
        with self._lock:
            subscribers = list(self._subscribers)
        for fn in subscribers:
            try:
                fn(event)
            except Exception:  # a broken subscriber must never break the decoy
                log.exception("event subscriber %r failed", fn)
        return event

    def emit(self, type: str, severity: "str | Severity", message: str, **kwargs: Any) -> Event:
        return self.publish(Event(type=type, severity=Severity.parse(severity), message=message, **kwargs))
