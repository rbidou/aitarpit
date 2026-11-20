"""Jinja templates of the decoy surface (the fake company intranet).

Kept inline (not in template files) so techniques can reuse ``LAYOUT`` with
``render_page()`` and the package has no template-path coupling. The decoy
deliberately looks like an ordinary, slightly dated corporate intranet; it
must NOT reuse the admin UI design system.
"""

from __future__ import annotations

from flask import render_template_string

LAYOUT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ title }} - {{ persona.company }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{{ persona.slug }}-portal 4.2.1">
<style>
 body{font-family:Segoe UI,Arial,sans-serif;background:#f3f5f8;color:#222;margin:0}
 header{background:#1f3b5a;color:#fff;padding:14px 28px;font-size:18px}
 header small{opacity:.7;margin-left:10px;font-size:13px}
 main{max-width:880px;margin:32px auto;background:#fff;padding:28px 36px;border:1px solid #d9dee5}
 a{color:#1f5fa8} footer{text-align:center;color:#888;font-size:12px;margin:24px}
 input{padding:8px;width:260px;margin:4px 0 12px;border:1px solid #bbb}
 button{padding:8px 18px;background:#1f3b5a;color:#fff;border:0;cursor:pointer}
 .err{color:#b00020} pre{background:#f6f8fa;padding:12px;overflow:auto}
 ul.links li{margin:6px 0}
</style>
</head>
<body>
{% for c in comments %}<!-- {{ c }} -->
{% endfor %}<header>{{ persona.company }}<small>Intranet</small></header>
<main>
{{ body|safe }}
</main>
<footer>&copy; {{ year }} {{ persona.company }} &middot; {{ persona.city }} &middot; IT Helpdesk: {{ persona.admin.email }}</footer>
</body>
</html>
"""

PORTAL = """
<h2>Welcome to the {{ persona.short_name }} intranet</h2>
<p>Please sign in with your corporate account.</p>
<form method="post" action="/login">
 <label>Username</label><br><input name="username" autocomplete="username"><br>
 <label>Password</label><br><input name="password" type="password" autocomplete="current-password"><br>
 <button type="submit">Sign in</button>
</form>
{% if links %}
<h3>Quick links</h3>
<ul class="links">{% for l in links %}<li><a href="{{ l.href }}">{{ l.label }}</a></li>{% endfor %}</ul>
{% endif %}
"""

LOGIN_FAILED = """
<h2>Sign in</h2>
<p class="err">Invalid username or password.</p>
<form method="post" action="/login">
 <label>Username</label><br><input name="username" value="{{ username }}"><br>
 <label>Password</label><br><input name="password" type="password"><br>
 <button type="submit">Sign in</button>
</form>
"""

NOT_FOUND = """<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>{{ server }}</center>
</body>
</html>
"""


def render_page(ctx, title: str, body_template: str, comments: list[str] | None = None, **values) -> str:
    """Render a decoy page inside the intranet layout.

    Args:
        ctx: The TarpitContext.
        title: Page title.
        body_template: Jinja template of the page body.
        comments: HTML comments to inject at the top of the page.
        **values: Variables for ``body_template``.

    Returns:
        The rendered HTML document.
    """
    import datetime

    body = render_template_string(body_template, persona=ctx.persona, **values)
    return render_template_string(
        LAYOUT,
        title=title,
        body=body,
        persona=ctx.persona,
        comments=comments or [],
        year=datetime.date.today().year,
    )
