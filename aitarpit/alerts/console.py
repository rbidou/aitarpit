"""Terminal alert sink (coloured, one line per event, extra details indented)."""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime
from typing import TextIO

from aitarpit.alerts.base import Sink
from aitarpit.events import Event, Severity

_COLORS = {
    Severity.INFO: "\033[90m",      # grey
    Severity.LOW: "\033[36m",       # cyan
    Severity.MEDIUM: "\033[33m",    # yellow
    Severity.HIGH: "\033[31m",      # red
    Severity.CRITICAL: "\033[1;97;41m",  # bold white on red
}
_RESET = "\033[0m"
_DIM = "\033[2m"


def _enable_windows_ansi() -> None:
    if os.name == "nt":  # pragma: no cover - Windows only
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass


class ConsoleSink(Sink):
    synchronous = True

    def __init__(self, min_severity="low", color: bool = True, stream: TextIO | None = None):
        super().__init__("console", min_severity)
        self.stream = stream or sys.stdout
        self.color = color and hasattr(self.stream, "isatty") and self.stream.isatty()
        self._lock = threading.Lock()
        if self.color:
            _enable_windows_ansi()

    def format(self, event: Event) -> str:
        ts = datetime.fromtimestamp(event.ts).strftime("%Y-%m-%d %H:%M:%S")
        sev = f"{event.severity.label.upper():<8}"
        tech = f"[{event.technique}]" if event.technique else "[core]"
        who = f"{event.src_ip or '-'} {(event.session_id or '-')[:8]}"
        line = f"{ts} {sev} {tech:<7} {who:<26} {event.message}"
        details = ""
        if event.data:
            details = "\n" + "\n".join(
                f"    {k}: {v if isinstance(v, str) else json.dumps(v, default=str)}" for k, v in event.data.items()
            )
        if self.color:
            c = _COLORS[event.severity]
            line = f"{_DIM}{ts}{_RESET} {c}{sev}{_RESET} {tech:<7} {who:<26} {event.message}"
            if details:
                details = f"{_DIM}{details}{_RESET}"
        return line + details

    def send(self, event: Event) -> None:
        text = self.format(event)
        with self._lock:
            try:
                self.stream.write(text + "\n")
                self.stream.flush()
            except (ValueError, OSError):  # closed stream
                pass
