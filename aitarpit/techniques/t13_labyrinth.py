"""T13 - Procedural labyrinth.

An endless ``/wiki/`` tree of internal-looking pages, generated on the fly from
the seed and the path. Every page lists more child pages, a few with
"promising" names (credentials, vpn, root-password) that only lead deeper or
cross-link into other decoys. Depth is unlimited, so a crawler never reaches a
bottom. Progress is reported at depth milestones.
"""

from __future__ import annotations

import threading
from typing import Any

from flask import Blueprint, g, request

from aitarpit.decoy.pages import render_page
from aitarpit.events import TECHNIQUE_ENGAGED, TECHNIQUE_PROGRESS
from aitarpit.techniques import Breadcrumb, Technique, register_technique

_TOPICS = ["runbook", "network", "backup", "onboarding", "incident", "vpn", "database", "release",
           "architecture", "credentials", "monitoring", "procedure", "inventory", "access", "migration"]
_PROMISING = ["credentials", "root-password", "aws-keys", "vpn-config", "service-accounts", "secrets-backup"]

PAGE_BODY = """
<h2>{{ heading }}</h2>
<p>{{ intro }}</p>
<p>Last edited by {{ author }} &middot; revision {{ rev }}.</p>
<h3>Sub-pages</h3>
<ul class="links">{% for l in links %}<li><a href="{{ l.href }}">{{ l.label }}</a></li>{% endfor %}</ul>
"""


@register_technique
class Labyrinth(Technique):
    id = "T13"
    name = "Procedural labyrinth"
    summary = "Infinite wiki of generated internal pages that crawlers never exhaust"
    default_config: dict[str, Any] = {
        "root": "/wiki/",
        "links_per_page": 6,
        "depth_milestones": [10, 25, 50, 100],
    }
    config_schema = {
        "properties": {
            "root": {"type": "string", "pattern": "^/.*/$"},
            "links_per_page": {"type": "integer", "minimum": 1, "maximum": 50},
            "depth_milestones": {"type": "array", "items": {"type": "integer", "minimum": 1}},
        }
    }

    def __init__(self, ctx, config: dict[str, Any]):
        super().__init__(ctx, config)
        self._lock = threading.Lock()
        self._depth: dict[str, int] = {}

    def _cross_links(self) -> list[str]:
        """Paths of other enabled techniques, used as occasional 'promising' links.

        Returns:
            A list of decoy link paths from other techniques.
        """
        out: list[str] = []
        for tid, tech in self.ctx.techniques.items():
            if tid == self.id:
                continue
            for crumb in tech.breadcrumbs():
                if crumb.kind == "link":
                    out.append(crumb.value)
        return out

    def _links(self, sub: str, depth: int) -> list[dict[str, str]]:
        """Build the child links for a page.

        Args:
            sub: The current sub-path under the root.
            depth: Current depth.

        Returns:
            A list of ``{"href", "label"}`` links (deeper pages, plus occasional cross-links).
        """
        r = self.persona.rng("T13", "links", sub)
        root = self.config["root"]
        base = f"{root}{sub}".rstrip("/")
        links: list[dict[str, str]] = []
        cross = self._cross_links()
        for i in range(self.config["links_per_page"]):
            if cross and r.random() < 0.15:
                href = r.choice(cross)
                links.append({"href": href, "label": f"{r.choice(_PROMISING)} ({href})"})
                continue
            topic = r.choice(_TOPICS if r.random() > 0.2 else _PROMISING)
            slug = f"{topic}-{r.randint(1, 999)}"
            links.append({"href": f"{base}/{slug}", "label": slug.replace("-", " ")})
        return links

    # ------------------------------------------------------------------ routes
    def register(self, bp: Blueprint) -> None:
        @bp.get(self.config["root"])
        def t13_root() -> str:
            return self._page("")

        @bp.get(self.config["root"] + "<path:sub>")
        def t13_page(sub: str) -> str:
            return self._page(sub)

    def _page(self, sub: str) -> str:
        """Render one labyrinth page and account depth.

        Args:
            sub: The sub-path under the root.

        Returns:
            The page HTML.
        """
        depth = len([s for s in sub.split("/") if s])
        self._account(depth)
        r = self.persona.rng("T13", "page", sub)
        title = (sub.rsplit("/", 1)[-1] or "index").replace("-", " ").title()
        intro = (f"Internal documentation for {self.persona.company}. This page covers "
                 f"{r.choice(_TOPICS)} procedures for the {r.choice(self.persona.services or ['intranet'])} service. "
                 f"See the sub-pages for details.")
        return render_page(self.ctx, f"{title} - Wiki", PAGE_BODY, heading=title, intro=intro,
                           author=r.choice(self.persona.employees).username, rev=r.randint(2, 480),
                           links=self._links(sub, depth))

    def _account(self, depth: int) -> None:
        """Emit engaged on first visit and progress at depth milestones.

        Args:
            depth: The depth of the page just served.

        Returns:
            None.
        """
        session = getattr(g, "tarpit_session", None)
        if session is None:
            return
        with self._lock:
            prev = self._depth.get(session.id, -1)
            self._depth[session.id] = max(prev, depth)
            first = prev < 0
            crossed = [m for m in self.config["depth_milestones"] if prev < m <= depth]
        if first:
            self.emit(TECHNIQUE_ENGAGED, "medium", "Wiki labyrinth entered", path=request.path)
        if crossed:
            reached = max(crossed)
            self.emit(TECHNIQUE_PROGRESS, "high" if reached >= 50 else "medium",
                      f"Crawler reached wiki depth {reached}", depth=depth)

    # ------------------------------------------------------------------ breadcrumbs
    def breadcrumbs(self) -> list[Breadcrumb]:
        return [
            Breadcrumb("link", self.config["root"], "Internal wiki"),
            Breadcrumb("robots", self.config["root"]),
            Breadcrumb("sitemap", self.config["root"]),
            Breadcrumb("llms", f"[Internal wiki]({self.config['root']}): internal documentation and runbooks"),
        ]
