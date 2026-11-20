"""The decoy surface: the fake-company web app/API exposed to attackers."""

from __future__ import annotations

import time

from flask import Blueprint, Flask, Response, g, request

from aitarpit.decoy import breadcrumbs as bc
from aitarpit.decoy.pages import LOGIN_FAILED, NOT_FOUND, PORTAL, render_page
from aitarpit.events import AUTH_ATTEMPT, LURE_SERVED, Severity

# Request headers never stored (they are noise or could hold our own admin token by mistake)
SKIPPED_HEADERS: frozenset[str] = frozenset({"cookie"})


def client_ip(trust_proxy: bool) -> str:
    """Return the attacker's IP for the current request.

    Args:
        trust_proxy: Use the first X-Forwarded-For hop when True.

    Returns:
        The client IP address.
    """
    ip = request.remote_addr or "0.0.0.0"
    if trust_proxy:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            ip = fwd.split(",")[0].strip() or ip
    return ip


def create_decoy_app(ctx) -> Flask:
    """Build the decoy Flask application.

    Args:
        ctx: The TarpitContext.

    Returns:
        The Flask app serving the decoy surface.
    """
    cfg = ctx.config
    dcfg = cfg["decoy"]
    scfg = cfg["storage"]
    app = Flask("aitarpit.decoy")
    app.config["MAX_CONTENT_LENGTH"] = cfg["limits"]["max_body_bytes"]
    app.config["TARPIT_CTX"] = ctx
    cookie_name = dcfg.get("session_cookie", "NWSESSID")
    server_header = dcfg.get("server_header", "nginx")

    bp = Blueprint("decoy", __name__)
    for tech in ctx.techniques.values():
        tech.register(bp)

    def crumbs() -> list:
        return bc.collect(ctx.techniques)

    # ------------------------------------------------------------------ hooks
    @app.before_request
    def _track() -> None:
        g.t0 = time.perf_counter()
        g.tarpit_technique = None
        session, _ = ctx.sessions.resolve(
            client_ip(dcfg.get("trust_proxy", False)),
            request.headers.get("User-Agent", ""),
            request.cookies.get(cookie_name),
        )
        g.tarpit_session = session
        ctx.honeytokens.scan(session)  # may add a fingerprint signal, so scan first
        ctx.fingerprint.observe(session, request)

    @app.after_request
    def _finish(resp: Response) -> Response:
        session = getattr(g, "tarpit_session", None)
        resp.headers["Server"] = server_header
        for name, value in bc.extra_headers(crumbs()).items():
            resp.headers.setdefault(name, value)
        if session is not None and request.cookies.get(cookie_name) != session.id:
            resp.set_cookie(cookie_name, session.id, httponly=True, samesite="Lax")
        if session is None:
            return resp
        technique = getattr(g, "tarpit_technique", None)
        headers = None
        if scfg.get("store_request_headers", True):
            headers = {k: v for k, v in request.headers.items() if k.lower() not in SKIPPED_HEADERS}
        body = None
        if scfg.get("store_request_bodies", True) and request.method in ("POST", "PUT", "PATCH"):
            raw = request.get_data(cache=True)[: scfg.get("max_body_bytes", 65536)]
            body = raw.decode("utf-8", errors="replace")
        base = {
            "session_id": session.id,
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode("latin-1"),
            "status": resp.status_code,
            "technique": technique,
            "headers": headers,
            "body": body,
        }
        t0 = g.t0

        def record(nbytes: int) -> None:
            duration = time.perf_counter() - t0
            ctx.store.add_request({**base, "ts": time.time(), "bytes_out": nbytes, "duration_ms": duration * 1000})
            ctx.sessions.record(session, nbytes, duration, technique)

        if resp.is_streamed:
            resp.response = _counting(resp.response, record)
        else:
            record(resp.calculate_content_length() or 0)
        return resp

    # ------------------------------------------------------------------ baseline surface
    @app.get("/")
    def portal() -> str:
        c = crumbs()
        return render_page(ctx, "Sign in", PORTAL, bc.html_comments(c), links=bc.portal_links(c))

    @app.post("/login")
    def login() -> tuple[str, int]:
        username = request.form.get("username", "")
        ctx.bus.emit(
            AUTH_ATTEMPT, Severity.MEDIUM, f"Portal login attempt for '{username[:64]}'",
            session_id=g.tarpit_session.id, src_ip=g.tarpit_session.src_ip,
            data={"username": username[:128], "password": request.form.get("password", "")[:128]},
        )
        return render_page(ctx, "Sign in", LOGIN_FAILED, username=username), 401

    @app.get("/robots.txt")
    def robots() -> Response:
        return Response(bc.robots_txt(crumbs()), mimetype="text/plain")

    @app.get("/sitemap.xml")
    def sitemap() -> Response:
        return Response(bc.sitemap_xml(crumbs(), request.host_url.rstrip("/")), mimetype="application/xml")

    @app.get("/.env")
    def dotenv() -> Response:
        ctx.bus.emit(
            LURE_SERVED, Severity.MEDIUM, "Exposed /.env fetched",
            session_id=g.tarpit_session.id, src_ip=g.tarpit_session.src_ip, data={"path": "/.env"},
        )
        return Response(bc.env_file(crumbs(), ctx.persona), mimetype="text/plain")

    @app.get("/llms.txt")
    def llms() -> Response:
        c = crumbs()
        resp: Response
        if bc.of_kind(c, "llms"):
            ctx.bus.emit(
                LURE_SERVED, Severity.MEDIUM, "AI-oriented /llms.txt fetched",
                session_id=g.tarpit_session.id, src_ip=g.tarpit_session.src_ip, data={"path": "/llms.txt"},
            )
            resp = Response(bc.llms_txt(c, ctx.persona), mimetype="text/markdown")
        else:
            resp = Response(render_template_string_404(server_header), status=404, mimetype="text/html")
        return resp

    app.register_blueprint(bp)

    @app.errorhandler(404)
    def not_found(_e) -> tuple[str, int]:
        return render_template_string_404(server_header), 404

    @app.errorhandler(405)
    def not_allowed(_e) -> tuple[str, int]:
        return render_template_string_404(server_header).replace("404 Not Found", "405 Not Allowed"), 405

    @app.errorhandler(413)
    def too_large(_e) -> tuple[str, int]:
        return render_template_string_404(server_header).replace("404 Not Found", "413 Request Entity Too Large"), 413

    return app


def render_template_string_404(server: str) -> str:
    """Render the nginx-style 404 page.

    Args:
        server: The advertised Server header value.

    Returns:
        HTML body.
    """
    from flask import render_template_string

    return render_template_string(NOT_FOUND, server=server)


class _counting:
    """Wrap a streamed response body to count bytes and record when it ends (or the client goes away)."""

    def __init__(self, iterable, on_close):
        self._it = iterable
        self._on_close = on_close
        self._n = 0
        self._closed = False

    def __iter__(self):
        try:
            for chunk in self._it:
                self._n += len(chunk) if chunk else 0
                yield chunk
        finally:
            self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            close = getattr(self._it, "close", None)
            if close:
                close()
            self._on_close(self._n)
