"""Run the decoy and admin listeners.

Production server: waitress (pure Python, Windows/Linux/Docker, streams
iterator responses chunk by chunk - required by slow-drip and endless
responses). When waitress is not installed the Werkzeug threaded server is
used with a warning (development only).
"""

from __future__ import annotations

import logging
import secrets
import signal
import threading
from dataclasses import dataclass
from typing import Any

from flask import Flask

from aitarpit import __version__

log = logging.getLogger(__name__)

# Housekeeping cadence (flush/expire sessions, tick techniques) and the shorter
# poll used so the main thread returns to a signal-check point quickly - Ctrl-C
# is then acted on within POLL_INTERVAL_S instead of up to HOUSEKEEPING_INTERVAL_S.
HOUSEKEEPING_INTERVAL_S = 30.0
POLL_INTERVAL_S = 0.5

BANNER = r"""
    _    ___   _____                _ _
   / \  |_ _| |_   _|_ _ _ __ _ __ (_) |_
  / _ \  | |    | |/ _` | '__| '_ \| | __|
 / ___ \ | |    | | (_| | |  | |_) | | |_
/_/   \_\___|   |_|\__,_|_|  | .__/|_|\__|
                             |_|
"""

try:  # pragma: no cover - depends on environment
    import waitress
    from waitress.server import create_server as _waitress_create

    HAVE_WAITRESS = True
except ImportError:  # pragma: no cover
    HAVE_WAITRESS = False


@dataclass
class Listener:
    name: str
    host: str
    port: int
    server: Any
    thread: threading.Thread | None = None

    def start(self) -> None:
        """Start serving in a daemon thread.

        Returns:
            None.
        """
        target = self.server.run if HAVE_WAITRESS else self.server.serve_forever
        self.thread = threading.Thread(target=target, name=f"aitarpit-{self.name}", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        """Stop serving.

        Returns:
            None.
        """
        try:
            if HAVE_WAITRESS:
                self.server.close()
            else:
                self.server.shutdown()
        except Exception:  # pragma: no cover
            log.exception("error stopping %s listener", self.name)


def make_listener(name: str, app: Flask, host: str, port: int, threads: int = 16, ident: str = "") -> Listener:
    """Create (bind) a listener for ``app``.

    Args:
        name: Listener label for logs.
        app: The WSGI application.
        host: Bind address.
        port: Bind port.
        threads: Worker threads (waitress) - each held slow connection uses one.
        ident: Server header value advertised by waitress.

    Returns:
        A bound, not yet started, Listener.
    """
    if HAVE_WAITRESS:
        server = _waitress_create(
            app, host=host, port=port, threads=threads, ident=ident or None,
            channel_timeout=3600, cleanup_interval=30, connection_limit=max(100, threads * 4),
            clear_untrusted_proxy_headers=True,
        )
    else:
        from werkzeug.serving import make_server

        log.warning("waitress not installed: using the Werkzeug development server for %s", name)
        server = make_server(host, port, app, threaded=True)
    return Listener(name=name, host=host, port=port, server=server)


def resolve_admin_token(cfg: dict) -> tuple[str, bool]:
    """Return the admin token, generating an ephemeral one when none is configured.

    Args:
        cfg: The merged configuration.

    Returns:
        (token, generated) where generated is True for an ephemeral token.
    """
    token = cfg["admin"].get("token") or ""
    generated = False
    if not token:
        token = secrets.token_urlsafe(32)
        generated = True
    return token, generated


def print_startup_banner(decoy_url: str, admin_url: str | None, technique_ids: list[str]) -> None:
    """Print the ASCII banner and the running configuration to the terminal.

    Args:
        decoy_url: The tarpit (decoy) base URL.
        admin_url: The admin/UI base URL, or None when the UI is not running.
        technique_ids: Identifiers of the enabled techniques.

    Returns:
        None.
    """
    art = BANNER.strip("\n").split("\n")
    width = max(len(line) for line in art)
    tag = f"v{__version__}"
    art[-1] = art[-1].ljust(width - len(tag)) + tag
    techniques = ", ".join(technique_ids) or "none"
    lines = [
        "",
        *art,
        "",
        f"  Tarpit     : {decoy_url}",
        f"  Admin UI   : {admin_url or 'disabled'}",
        f"  Techniques : {techniques} ({len(technique_ids)} enabled)",
        "",
    ]
    print("\n".join(lines), flush=True)


def serve(ctx, with_admin: bool = True, stop_event: threading.Event | None = None) -> None:
    """Serve the decoy (and admin) listeners until interrupted.

    Args:
        ctx: The TarpitContext.
        with_admin: Start the admin listener when enabled in config.
        stop_event: Optional event that stops the server when set (tests, Windows service wrappers).

    Returns:
        None.
    """
    from aitarpit.admin import create_admin_app
    from aitarpit.decoy import create_decoy_app
    from aitarpit.events import SYSTEM, Severity

    cfg = ctx.config
    stop = stop_event or threading.Event()
    listeners: list[Listener] = []
    d = cfg["decoy"]
    listeners.append(make_listener("decoy", create_decoy_app(ctx), d["host"], d["port"], d.get("threads", 64), d.get("server_header", "")))
    decoy_url = f"http://{d['host']}:{d['port']}"
    admin_url = None
    admin_note = "admin disabled"
    token, generated = "", False
    if with_admin and cfg["admin"]["enabled"]:
        token, generated = resolve_admin_token(cfg)
        a = cfg["admin"]
        listeners.append(make_listener("admin", create_admin_app(ctx, token), a["host"], a["port"], 8))
        admin_url = f"http://{a['host']}:{a['port']}"
        admin_note = f"admin on {admin_url}"

    print_startup_banner(decoy_url, admin_url, list(ctx.techniques))
    if generated:
        print(f"[aitarpit] no admin token configured - ephemeral token for this run: {token}", flush=True)

    def _handle(_sig, _frm) -> None:
        print("\nShutting down...", flush=True)
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle)
        except (ValueError, OSError):  # not in main thread
            pass

    for listener in listeners:
        listener.start()
    ctx.bus.emit(SYSTEM, Severity.INFO, f"AI Tarpit started: decoy on http://{d['host']}:{d['port']}, {admin_note}, "
                 f"techniques: {', '.join(ctx.techniques) or 'none'}")
    try:
        elapsed = 0.0
        while not stop.wait(POLL_INTERVAL_S):
            elapsed += POLL_INTERVAL_S
            if elapsed >= HOUSEKEEPING_INTERVAL_S:
                elapsed = 0.0
                ctx.sessions.flush()
                ctx.sessions.expire()
                for technique in ctx.techniques.values():
                    technique.tick()
    finally:
        for listener in listeners:
            listener.stop()
        ctx.bus.emit(SYSTEM, Severity.INFO, "AI Tarpit stopped")
        ctx.close()
