"""Admin engine: business logic behind the admin API and (from M5) the Web UI.

Pure methods: one ``params`` dict in, a ``(result, message, data)`` tuple out,
no Flask imports (design system section 7.4).
"""

from __future__ import annotations

import time

from aitarpit import __version__
from aitarpit.events import TEST, Event, Severity
from aitarpit.techniques import registry


def make_function_result(result: bool, message: str, data: dict) -> tuple:
    """Build the standard engine return tuple.

    Args:
        result: True on success.
        message: User-facing error message, empty on success.
        data: Result payload.

    Returns:
        The (result, message, data) tuple.
    """
    return (result, message, data)


class AdminEngine:
    """Business logic for the AI Tarpit admin surface."""

    def __init__(self, ctx) -> None:
        """Bind the engine to a runtime context.

        Args:
            ctx: The TarpitContext.

        Returns:
            None.
        """
        self.ctx = ctx
        self.started = time.time()

    def health(self, params: dict) -> tuple:
        """Report liveness and version.

        Args:
            params: Unused.

        Returns:
            Tuple of (result, message, data).
        """
        return make_function_result(True, "", {"version": __version__, "uptime": round(time.time() - self.started, 1)})

    def status(self, params: dict) -> tuple:
        """Report global statistics, alert sink health and enabled techniques.

        Args:
            params: Optional 'since' (epoch seconds).

        Returns:
            Tuple of (result, message, data).
        """
        since = params.get("since")
        data = {
            "version": __version__,
            "uptime": round(time.time() - self.started, 1),
            "persona": self.ctx.persona.describe(),
            "stats": self.ctx.store.stats(float(since) if since else None),
            "active_sessions": len(self.ctx.sessions.active()),
            "alerts": self.ctx.alerts.status(),
            "techniques": [
                {**cls.describe(), "enabled": tid in self.ctx.techniques}
                for tid, cls in registry.all().items()
            ],
        }
        return make_function_result(True, "", data)

    def sessions(self, params: dict) -> tuple:
        """List attacker sessions, most recent first.

        Args:
            params: Optional 'since' (epoch seconds) and 'limit' (int).

        Returns:
            Tuple of (result, message, data).
        """
        since = params.get("since")
        limit = int(params.get("limit") or 200)
        self.ctx.sessions.flush()
        rows = self.ctx.store.list_sessions(float(since) if since else None, min(limit, 5000))
        return make_function_result(True, "", {"sessions": rows})

    def session(self, params: dict) -> tuple:
        """Return one session with its requests, events and submissions.

        Args:
            params: 'id' (session id).

        Returns:
            Tuple of (result, message, data).
        """
        sid = str(params.get("id") or "")
        if not sid:
            return make_function_result(False, "Missing session id", {})
        self.ctx.sessions.flush()
        row = self.ctx.store.get_session(sid)
        if row is None:
            return make_function_result(False, f"Unknown session {sid}", {})
        data = {
            "session": row,
            "requests": self.ctx.store.list_requests(sid),
            "events": self.ctx.store.list_events(session_id=sid, limit=2000),
            "submissions": self.ctx.store.list_submissions(sid),
        }
        return make_function_result(True, "", data)

    def events(self, params: dict) -> tuple:
        """List events, most recent first.

        Args:
            params: Optional 'since', 'session_id', 'min_severity', 'limit'.

        Returns:
            Tuple of (result, message, data).
        """
        try:
            min_sev = Severity.parse(params.get("min_severity") or "info")
        except ValueError as exc:
            return make_function_result(False, str(exc), {})
        since = params.get("since")
        rows = self.ctx.store.list_events(
            since=float(since) if since else None,
            session_id=params.get("session_id") or None,
            min_severity=min_sev,
            limit=min(int(params.get("limit") or 500), 5000),
        )
        return make_function_result(True, "", {"events": rows})

    def config_get(self, params: dict) -> tuple:
        """Return the active configuration (runtime-only keys stripped).

        Args:
            params: Unused.

        Returns:
            Tuple of (result, message, data) with the config and its file path.
        """
        cfg = {k: v for k, v in self.ctx.config.items() if not k.startswith("_")}
        return make_function_result(True, "", {"config": cfg, "path": self.ctx.config.get("_path")})

    def config_validate(self, params: dict) -> tuple:
        """Validate a candidate configuration without saving it.

        Args:
            params: The candidate configuration (a JSON object).

        Returns:
            Tuple of (result, message, data); on failure data has 'errors'.
        """
        from aitarpit.config import ConfigError, build_config

        try:
            build_config(params)
        except ConfigError as exc:
            return make_function_result(False, "Invalid configuration", {"errors": exc.errors})
        return make_function_result(True, "Configuration is valid", {"errors": []})

    def config_save(self, params: dict) -> tuple:
        """Validate and persist a configuration to the active config file.

        Args:
            params: The full configuration (a JSON object) to write.

        Returns:
            Tuple of (result, message, data). Changes apply on restart.
        """
        import json
        import shutil
        from pathlib import Path

        from aitarpit.config import ConfigError, build_config

        path = self.ctx.config.get("_path")
        if not path:
            return make_function_result(False, "No config file is loaded; start the server with -c FILE to enable saving", {})
        try:
            build_config(params)
        except ConfigError as exc:
            return make_function_result(False, "Invalid configuration", {"errors": exc.errors})
        target = Path(path)
        if target.exists():
            shutil.copy2(target, target.with_suffix(target.suffix + ".bak"))
        target.write_text(json.dumps(params, indent=2) + "\n", encoding="utf-8")
        return make_function_result(True, "Configuration saved. Restart the honeypot to apply.",
                                    {"path": str(target), "restart_required": True})

    def report(self, params: dict) -> tuple:
        """Build an activity report, optionally rendered in a given format.

        Args:
            params: Optional 'since' (epoch seconds) and 'format'
                (text|json|csv|html; default json -> dict only).

        Returns:
            Tuple of (result, message, data) with the report dict and, for
            non-json formats, a 'rendered' string.
        """
        from aitarpit import report as report_mod

        fmt = str(params.get("format") or "json").lower()
        if fmt not in report_mod.FORMATS:
            return make_function_result(False, f"Unknown format '{fmt}'", {})
        since = params.get("since")
        self.ctx.sessions.flush()
        built = report_mod.build_report(self.ctx.store, float(since) if since else None)
        data = {"report": built, "format": fmt}
        if fmt != "json":
            data["rendered"] = report_mod.render(built, fmt)
        return make_function_result(True, "", data)

    def testalert(self, params: dict) -> tuple:
        """Send a test alert to every configured sink, bypassing severity filters.

        Args:
            params: Optional 'severity' and 'message'.

        Returns:
            Tuple of (result, message, data) with per-sink status.
        """
        try:
            sev = Severity.parse(params.get("severity") or "medium")
        except ValueError as exc:
            return make_function_result(False, str(exc), {})
        event = Event(type=TEST, severity=sev, message=params.get("message") or "AI Tarpit test alert")
        results = self.ctx.alerts.test(event)
        ok = all(v == "ok" for v in results.values())
        return make_function_result(ok, "" if ok else "One or more sinks failed", {"sinks": results})
