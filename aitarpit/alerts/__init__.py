"""Alert manager: filters events by severity and dispatches them to sinks.

The console sink runs synchronously in the publishing thread. Network sinks
(syslog, webhooks) are fed through a bounded queue drained by one background
worker so a slow collector never delays the decoy's responses. When the queue
is full the oldest alert is dropped and a counter incremented.
"""

from __future__ import annotations

import logging
import queue
import threading

from aitarpit.alerts.base import Sink, event_payload
from aitarpit.alerts.console import ConsoleSink
from aitarpit.alerts.syslog import SyslogSink
from aitarpit.alerts.webhook import WebhookSink
from aitarpit.events import Event

log = logging.getLogger(__name__)

__all__ = ["AlertManager", "Sink", "ConsoleSink", "SyslogSink", "WebhookSink", "event_payload"]

_STOP = object()


class AlertManager:
    def __init__(self, sinks: list[Sink], queue_size: int = 10000, show_requests: bool = False):
        self.sinks = sinks
        self.show_requests = show_requests
        self._queue: "queue.Queue[object]" = queue.Queue(maxsize=queue_size)
        self._worker: threading.Thread | None = None
        self.dropped = 0
        self.failures: dict[str, int] = {}
        self.sent: dict[str, int] = {}

    @classmethod
    def from_config(cls, cfg: dict) -> "AlertManager":
        a = cfg.get("alerts", {})
        sinks: list[Sink] = []
        con = a.get("console", {})
        if con.get("enabled", True):
            sinks.append(ConsoleSink(con.get("min_severity", "low"), con.get("color", True)))
        for s in a.get("syslog", []):
            if s.get("enabled", True):
                sinks.append(SyslogSink(s))
        for w in a.get("webhooks", []):
            if w.get("enabled", True):
                sinks.append(WebhookSink(w))
        return cls(sinks, show_requests=con.get("show_requests", False))

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._worker is None and any(not s.synchronous for s in self.sinks):
            self._worker = threading.Thread(target=self._run, name="aitarpit-alerts", daemon=True)
            self._worker.start()

    def stop(self, timeout: float = 5.0) -> None:
        if self._worker is not None:
            self._queue.put(_STOP)
            self._worker.join(timeout)
            self._worker = None
        for s in self.sinks:
            try:
                s.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ dispatch
    def dispatch(self, event: Event) -> None:
        for s in self.sinks:
            if s.synchronous and s.accepts(event):
                self._deliver(s, event)
        if self._worker is None:
            # not started (tests / one-shot CLI): deliver async sinks inline
            for s in self.sinks:
                if not s.synchronous and s.accepts(event):
                    self._deliver(s, event)
            return
        if any(not s.synchronous and s.accepts(event) for s in self.sinks):
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    pass
                self.dropped += 1
                self._queue.put_nowait(event)

    def _deliver(self, sink: Sink, event: Event) -> bool:
        try:
            sink.send(event)
            self.sent[sink.name] = self.sent.get(sink.name, 0) + 1
            return True
        except Exception as exc:
            self.failures[sink.name] = self.failures.get(sink.name, 0) + 1
            log.warning("alert sink %s failed: %s", sink.name, exc)
            return False

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            assert isinstance(item, Event)
            for s in self.sinks:
                if not s.synchronous and s.accepts(item):
                    self._deliver(s, item)

    def test(self, event: Event) -> dict[str, str]:
        """Send ``event`` to every sink synchronously, ignoring severity filters. Returns per-sink status."""
        results = {}
        for s in self.sinks:
            ok = self._deliver(s, event)
            results[s.name] = "ok" if ok else "failed"
        return results

    def status(self) -> dict:
        return {
            "sinks": [{"name": s.name, "type": type(s).__name__, "min_severity": s.min_severity.label} for s in self.sinks],
            "sent": dict(self.sent),
            "failures": dict(self.failures),
            "dropped": self.dropped,
            "queued": self._queue.qsize(),
        }

