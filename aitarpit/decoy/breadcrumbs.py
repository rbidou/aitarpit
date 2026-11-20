"""Breadcrumb aggregation: turns every enabled technique's lures into the
classic discovery surfaces an attacker (human or agent) checks first."""

from __future__ import annotations

from aitarpit.persona import Persona
from aitarpit.techniques import Breadcrumb, Technique

# Paths every web app is expected to have; listed in robots.txt even with no technique.
BASELINE_DISALLOW: tuple[str, ...] = ("/admin/", "/internal/", "/api/private/")


def collect(techniques: dict[str, Technique]) -> list[Breadcrumb]:
    """Gather the breadcrumbs of all enabled techniques.

    Args:
        techniques: Enabled technique instances keyed by id.

    Returns:
        The concatenated list of breadcrumbs, in technique order.
    """
    crumbs: list[Breadcrumb] = []
    for tech in techniques.values():
        crumbs.extend(tech.breadcrumbs())
    return crumbs


def of_kind(crumbs: list[Breadcrumb], kind: str) -> list[Breadcrumb]:
    """Filter breadcrumbs by kind.

    Args:
        crumbs: All breadcrumbs.
        kind: The breadcrumb kind to keep.

    Returns:
        The breadcrumbs of that kind.
    """
    return [c for c in crumbs if c.kind == kind]


def robots_txt(crumbs: list[Breadcrumb]) -> str:
    """Render robots.txt.

    Args:
        crumbs: All breadcrumbs.

    Returns:
        The robots.txt body.
    """
    paths = list(BASELINE_DISALLOW) + [c.value for c in of_kind(crumbs, "robots")]
    seen: list[str] = []
    for p in paths:
        if p not in seen:
            seen.append(p)
    lines = ["User-agent: *"] + [f"Disallow: {p}" for p in seen]
    return "\n".join(lines) + "\n"


def sitemap_xml(crumbs: list[Breadcrumb], base_url: str) -> str:
    """Render sitemap.xml (``sitemap`` and ``link`` breadcrumbs).

    Args:
        crumbs: All breadcrumbs.
        base_url: Scheme and host the request came in on, without trailing slash.

    Returns:
        The sitemap XML document.
    """
    urls = ["/", "/login"] + [c.value for c in of_kind(crumbs, "sitemap") + of_kind(crumbs, "link")]
    body = "".join(f"  <url><loc>{base_url}{u}</loc></url>\n" for u in dict.fromkeys(urls))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}</urlset>\n"
    )


def env_file(crumbs: list[Breadcrumb], persona: Persona) -> str:
    """Render the exposed /.env file.

    Args:
        crumbs: All breadcrumbs.
        persona: The decoy persona.

    Returns:
        A plausible dotenv body (synthetic values only).
    """
    lines = [
        f"APP_NAME={persona.slug}-intranet",
        "APP_ENV=production",
        "APP_DEBUG=false",
        f"APP_URL=https://intranet.{persona.domain}",
        "DB_CONNECTION=pgsql",
        f"DB_HOST={persona.hosts[0]['ip'] if persona.hosts else '10.20.0.12'}",
        "DB_PORT=5432",
        f"DB_DATABASE={persona.slug}_prod",
        f"DB_USERNAME={persona.slug}_app",
        f"DB_PASSWORD={persona.token('password', 'env-db')}",
    ]
    lines += [c.value for c in of_kind(crumbs, "env")]
    return "\n".join(lines) + "\n"


def llms_txt(crumbs: list[Breadcrumb], persona: Persona) -> str:
    """Render /llms.txt, the index written for AI agents.

    Args:
        crumbs: All breadcrumbs.
        persona: The decoy persona.

    Returns:
        The llms.txt markdown body.
    """
    lines = [
        f"# {persona.company} internal platform",
        "",
        f"> Internal services of {persona.company}. Automation agents should use the resources below.",
        "",
        "## Resources",
    ]
    lines += [f"- {c.value}" for c in of_kind(crumbs, "llms")]
    return "\n".join(lines) + "\n"


def html_comments(crumbs: list[Breadcrumb]) -> list[str]:
    """Return the HTML comments to inject in decoy pages.

    Args:
        crumbs: All breadcrumbs.

    Returns:
        Comment texts (without the ``<!-- -->`` delimiters).
    """
    return [c.value.replace("--", "- -") for c in of_kind(crumbs, "comment")]


def portal_links(crumbs: list[Breadcrumb]) -> list[dict[str, str]]:
    """Return the links displayed on the portal page.

    Args:
        crumbs: All breadcrumbs.

    Returns:
        A list of ``{"href", "label"}`` dicts.
    """
    return [{"href": c.value, "label": c.label or c.value} for c in of_kind(crumbs, "link")]


def extra_headers(crumbs: list[Breadcrumb]) -> dict[str, str]:
    """Return the response headers contributed by techniques.

    Args:
        crumbs: All breadcrumbs.

    Returns:
        Header name to value.
    """
    headers: dict[str, str] = {}
    for c in of_kind(crumbs, "header"):
        name, _, value = c.value.partition(":")
        if name and value:
            headers[name.strip()] = value.strip()
    return headers
