"""Admin surface: token-protected admin API (M0) and Web UI (M5).

Always served on its own listener (default 127.0.0.1:8443), never on the decoy.
Follows the PCB application design system backend contract: API envelope,
``check_json_data`` decorator, single-return routes delegating to the engine.
"""

from __future__ import annotations

import hmac
from functools import wraps
from typing import Any, Callable

from flask import Flask, redirect, render_template, request, url_for

from aitarpit.admin.engine import AdminEngine

TOKEN_HEADER = "X-Admin-Token"


def make_api_response(status: bool = True, message: str = "", data: dict | None = None,
                      status_code: int = 200, reflect_status: bool = False) -> Any:
    """Build the standard API envelope.

    Args:
        status: True on success.
        message: User-facing error message, empty on success.
        data: Result payload.
        status_code: HTTP status code, mirrored into the body.
        reflect_status: When True, return (body, status_code) so Flask sets the HTTP status.

    Returns:
        The response dict, or a (dict, int) tuple when reflect_status is True.
    """
    response = {
        "status": status,
        "status_code": status_code,
        "message": message,
        "data": data if data is not None else {},
    }
    return (response, status_code) if reflect_status else response


def check_json_data(f: Callable) -> Callable:
    """Parse the JSON request body and pass it as the first argument.

    Args:
        f: The view function.

    Returns:
        The decorated view; it returns a 400 envelope when the body is not valid JSON.
    """
    @wraps(f)
    def decorator(*args: Any, **kwargs: Any) -> Any:
        try:
            json_data = request.get_json(force=True, silent=False) if request.data else {}
            result = f(json_data or {}, *args, **kwargs)
        except Exception:
            result = make_api_response(False, "Wrong request format", {}, 400, True)
        return result

    return decorator


def _engine_response(outcome: tuple, fail_code: int = 422) -> Any:
    """Wrap an engine tuple in the API envelope.

    Args:
        outcome: (result, message, data) from the engine.
        fail_code: HTTP status used when result is False.

    Returns:
        A (dict, int) tuple for Flask.
    """
    (result, message, data) = outcome
    return make_api_response(result, message, data if result else {}, 200 if result else fail_code, True)


def create_admin_app(ctx, token: str) -> Flask:
    """Build the admin Flask application.

    Args:
        ctx: The TarpitContext.
        token: The admin token every API call must present
               (``Authorization: Bearer <token>`` or ``X-Admin-Token``).

    Returns:
        The Flask app serving the admin surface.
    """
    app = Flask("aitarpit.admin")
    app.config["TARPIT_CTX"] = ctx
    engine = AdminEngine(ctx)
    app.config["TARPIT_ENGINE"] = engine

    def _presented_token() -> str:
        auth = request.headers.get("Authorization", "")
        value = auth[7:] if auth.lower().startswith("bearer ") else request.headers.get(TOKEN_HEADER, "")
        return value.strip()

    @app.before_request
    def _auth() -> Any:
        result = None
        if request.path.startswith("/api/") and not hmac.compare_digest(_presented_token(), token):
            result = make_api_response(False, "Forbidden", {}, 403, True)
        return result

    @app.get("/api/admin/health")
    def api_admin_health() -> Any:
        """Liveness probe.

        Returns:
            The API envelope.
        """
        return _engine_response(engine.health({}))

    @app.get("/api/admin/status")
    def api_admin_status() -> Any:
        """Global status.

        Returns:
            The API envelope.
        """
        return _engine_response(engine.status(dict(request.args)))

    @app.get("/api/admin/sessions")
    def api_admin_sessions() -> Any:
        """Session list.

        Returns:
            The API envelope.
        """
        return _engine_response(engine.sessions(dict(request.args)))

    @app.get("/api/admin/sessions/<sid>")
    def api_admin_session(sid: str) -> Any:
        """One session in detail.

        Args:
            sid: Session id.

        Returns:
            The API envelope.
        """
        return _engine_response(engine.session({"id": sid}), 404)

    @app.get("/api/admin/events")
    def api_admin_events() -> Any:
        """Event list.

        Returns:
            The API envelope.
        """
        return _engine_response(engine.events(dict(request.args)))

    @app.get("/api/admin/config")
    def api_admin_config_get() -> Any:
        """Return the active configuration.

        Returns:
            The API envelope with the config.
        """
        return _engine_response(engine.config_get(dict(request.args)))

    @app.post("/api/admin/config/validate")
    @check_json_data
    def api_admin_config_validate(json_data: dict) -> Any:
        """Validate a candidate configuration.

        Args:
            json_data: The candidate config.

        Returns:
            The API envelope (data.errors on failure).
        """
        return _engine_response(engine.config_validate(json_data))

    @app.put("/api/admin/config")
    @check_json_data
    def api_admin_config_save(json_data: dict) -> Any:
        """Validate and persist the configuration.

        Args:
            json_data: The full config to write.

        Returns:
            The API envelope.
        """
        return _engine_response(engine.config_save(json_data))

    @app.post("/api/admin/report")
    @check_json_data
    def api_admin_report(json_data: dict) -> Any:
        """Build an activity report.

        Args:
            json_data: Optional 'since' and 'format' (text|json|csv|html).

        Returns:
            The API envelope with the report.
        """
        return _engine_response(engine.report(json_data))

    @app.post("/api/admin/testalert")
    @check_json_data
    def api_admin_testalert(json_data: dict) -> Any:
        """Send a test alert to every sink.

        Args:
            json_data: Optional 'severity' and 'message'.

        Returns:
            The API envelope.
        """
        return _engine_response(engine.testalert(json_data))

    # ------------------------------------------------------------------ Web UI pages
    def _page(name: str) -> Any:
        return render_template(f"app/{name}.html", admin_token=token)

    @app.get("/")
    def admin_root() -> Any:
        """Redirect the root to the dashboard.

        Returns:
            A redirect response.
        """
        return redirect(url_for("admin_dashboard"))

    @app.get("/admin/dashboard")
    def admin_dashboard() -> Any:
        """Serve the dashboard page.

        Returns:
            The rendered page.
        """
        return _page("dashboard")

    @app.get("/admin/sessions")
    def admin_sessions() -> Any:
        """Serve the sessions page.

        Returns:
            The rendered page.
        """
        return _page("sessions")

    @app.get("/admin/events")
    def admin_events() -> Any:
        """Serve the events page.

        Returns:
            The rendered page.
        """
        return _page("events")

    @app.get("/admin/techniques")
    def admin_techniques() -> Any:
        """Serve the techniques page.

        Returns:
            The rendered page.
        """
        return _page("techniques")

    @app.get("/admin/config")
    def admin_config() -> Any:
        """Serve the configuration page.

        Returns:
            The rendered page.
        """
        return _page("config")

    @app.get("/admin/reports")
    def admin_reports() -> Any:
        """Serve the reports page.

        Returns:
            The rendered page.
        """
        return _page("reports")

    return app
