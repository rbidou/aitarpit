"""Alert sink contract and shared formatters."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone

from aitarpit import __version__
from aitarpit.events import Event, Severity

# syslog severities (RFC 5424 section 6.2.1) mapped from our scale
SYSLOG_SEVERITY = {
    Severity.INFO: 6,      # informational
    Severity.LOW: 5,       # notice
    Severity.MEDIUM: 4,    # warning
    Severity.HIGH: 3,      # error
    Severity.CRITICAL: 2,  # critical
}
SYSLOG_FACILITY = {
    "kern": 0, "user": 1, "daemon": 3, "auth": 4, "authpriv": 10, "security": 13,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}
CEF_SEVERITY = {Severity.INFO: 1, Severity.LOW: 3, Severity.MEDIUM: 5, Severity.HIGH: 8, Severity.CRITICAL: 10}


class Sink:
    """An alert destination. ``send`` may raise; the manager handles retries and logging."""

    name: str = "sink"
    synchronous: bool = False  # True: called in the publishing thread (console only)

    def __init__(self, name: str, min_severity: "str | Severity" = Severity.LOW):
        self.name = name
        self.min_severity = Severity.parse(min_severity)

    def accepts(self, event: Event) -> bool:
        return event.severity >= self.min_severity

    def send(self, event: Event) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        pass


def event_payload(event: Event) -> dict:
    """The canonical JSON alert document (webhooks, JSON syslog, exports)."""
    return {
        "source": "aitarpit",
        "version": __version__,
        "id": event.id,
        "timestamp": datetime.fromtimestamp(event.ts, tz=timezone.utc).isoformat(timespec="milliseconds"),
        "type": event.type,
        "severity": event.severity.label,
        "message": event.message,
        "technique": event.technique,
        "session_id": event.session_id,
        "src_ip": event.src_ip,
        "data": event.data,
    }


def _sd_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_rfc5424(event: Event, facility: str, app_name: str, hostname: str | None = None) -> str:
    pri = SYSLOG_FACILITY[facility] * 8 + SYSLOG_SEVERITY[event.severity]
    ts = datetime.fromtimestamp(event.ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    host = (hostname or socket.gethostname() or "-")[:255]
    msgid = event.type.replace(" ", "_")[:32] or "-"
    sd_params = {
        "id": event.id,
        "severity": event.severity.label,
        "technique": event.technique or "",
        "session": event.session_id or "",
        "src": event.src_ip or "",
    }
    sd = "[aitarpit@32473 " + " ".join(f'{k}="{_sd_escape(str(v))}"' for k, v in sd_params.items()) + "]"
    msg = event.message
    if event.data:
        msg += " " + json.dumps(event.data, default=str, separators=(",", ":"))
    return f"<{pri}>1 {ts} {host} {app_name} - {msgid} {sd} {msg}"


def _cef_escape_header(v: str) -> str:
    return v.replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_ext(v: str) -> str:
    return v.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def format_cef(event: Event) -> str:
    ext = {
        "rt": str(int(event.ts * 1000)),
        "src": event.src_ip or "",
        "cs1Label": "technique", "cs1": event.technique or "",
        "cs2Label": "session", "cs2": event.session_id or "",
        "cs3Label": "eventId", "cs3": event.id,
        "msg": event.message,
    }
    if event.data:
        ext["cs4Label"] = "data"
        ext["cs4"] = json.dumps(event.data, default=str, separators=(",", ":"))[:4000]
    header = "|".join([
        "CEF:0", "AITarpit", "AITarpit", __version__,
        _cef_escape_header(event.type), _cef_escape_header(event.message[:128]), str(CEF_SEVERITY[event.severity]),
    ])
    return header + "|" + " ".join(f"{k}={_cef_escape_ext(v)}" for k, v in ext.items() if v != "")
