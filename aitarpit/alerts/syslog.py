"""Syslog alert sink over UDP or TCP (RFC 5424 / CEF / JSON payloads).

TCP framing follows RFC 6587: octet-counting (default) or newline (LF)
delimited. The TCP connection is kept open and re-established on failure.
"""

from __future__ import annotations

import json
import socket
import threading

from aitarpit.alerts.base import Sink, event_payload, format_cef, format_rfc5424, SYSLOG_FACILITY, SYSLOG_SEVERITY
from aitarpit.events import Event


class SyslogSink(Sink):
    def __init__(self, cfg: dict):
        super().__init__(cfg.get("name", "syslog"), cfg.get("min_severity", "low"))
        self.host = cfg["host"]
        self.port = int(cfg["port"])
        self.protocol = cfg.get("protocol", "udp")
        self.framing = cfg.get("framing", "octet-counting")
        self.facility = cfg.get("facility", "local0")
        self.app_name = cfg.get("app_name", "aitarpit")
        self.fmt = cfg.get("format", "rfc5424")
        self.timeout = float(cfg.get("timeout", 5.0))
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()

    def render(self, event: Event) -> str:
        if self.fmt == "rfc5424":
            return format_rfc5424(event, self.facility, self.app_name)
        pri = SYSLOG_FACILITY[self.facility] * 8 + SYSLOG_SEVERITY[event.severity]
        body = format_cef(event) if self.fmt == "cef" else json.dumps(event_payload(event), default=str, separators=(",", ":"))
        # RFC 5424 header (no structured data) around CEF/JSON bodies so collectors still parse PRI/app
        msgid = event.type.replace(" ", "_")[:32] or "-"
        return f"<{pri}>1 {_ts(event)} {socket.gethostname() or '-'} {self.app_name} - {msgid} - {body}"

    def _connect(self) -> socket.socket:
        family = socket.AF_INET6 if ":" in self.host and not self.host.count(".") else socket.AF_INET
        if self.protocol == "udp":
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            return s
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        return s

    def send(self, event: Event) -> None:
        data = self.render(event).encode("utf-8")
        with self._lock:
            if self.protocol == "udp":
                if self._sock is None:
                    self._sock = self._connect()
                self._sock.sendto(data[:65000], (self.host, self.port))
                return
            frame = (str(len(data)).encode() + b" " + data) if self.framing == "octet-counting" else data + b"\n"
            for attempt in (1, 2):
                try:
                    if self._sock is None:
                        self._sock = self._connect()
                    self._sock.sendall(frame)
                    return
                except OSError:
                    self._close_socket()
                    if attempt == 2:
                        raise

    def _close_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def close(self) -> None:
        with self._lock:
            self._close_socket()


def _ts(event: Event) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(event.ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
