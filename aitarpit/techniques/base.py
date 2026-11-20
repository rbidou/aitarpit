"""Technique plugin contract.

A technique is a self-contained deception module. It:

* declares an ``id`` (``T01``..``T09`` for the Tracebit techniques, ``A``..``H``
  for the additional ones), a human ``name`` and a one-line ``summary``;
* declares ``default_config`` and a JSON-Schema fragment ``config_schema``
  for its own ``techniques.<id>`` section (``enabled`` is always present);
* registers its decoy routes on a Flask blueprint in :meth:`register`;
* exposes :meth:`breadcrumbs` - the lures that lead an agent to it
  (robots.txt entries, sitemap URLs, .env lines, HTML comments, llms.txt
  lines...). The breadcrumb layer aggregates them across techniques;
* reports activity only through ``self.emit(...)`` (never directly to sinks).

Register a technique with the :func:`register_technique` decorator in a module
imported by ``aitarpit.techniques``.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from flask import Blueprint, g

from aitarpit.events import Event, Severity

if TYPE_CHECKING:  # pragma: no cover
    from aitarpit.context import TarpitContext


@dataclass(frozen=True)
class Breadcrumb:
    """A lure pointing to a technique.

    kind: one of
      - ``robots``   : a ``Disallow:`` path in robots.txt
      - ``sitemap``  : a URL listed in sitemap.xml
      - ``link``     : a link shown on the decoy portal / docs index
      - ``comment``  : an HTML comment injected in decoy pages
      - ``env``      : a ``KEY=value`` line in the exposed /.env
      - ``llms``     : a line in /llms.txt (AI-oriented index)
      - ``header``   : an HTTP response header ``Name: value``
    """

    kind: str
    value: str
    label: str = ""


class Technique:
    id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    summary: ClassVar[str] = ""
    default_config: ClassVar[dict[str, Any]] = {}
    config_schema: ClassVar[dict[str, Any]] = {}

    def __init__(self, ctx: "TarpitContext", config: dict[str, Any]):
        self.ctx = ctx
        self.config = config

    # ------------------------------------------------------------------ class helpers
    @classmethod
    def full_default_config(cls) -> dict[str, Any]:
        d = {"enabled": True}
        d.update(copy.deepcopy(cls.default_config))
        return d

    @classmethod
    def full_config_schema(cls) -> dict[str, Any]:
        props = {"enabled": {"type": "boolean"}}
        props.update(cls.config_schema.get("properties", {}))
        schema = {"type": "object", "additionalProperties": False, "properties": props, "required": ["enabled"]}
        for key in ("$defs",):
            if key in cls.config_schema:
                schema[key] = cls.config_schema[key]
        return schema

    @classmethod
    def describe(cls) -> dict[str, str]:
        return {"id": cls.id, "name": cls.name, "summary": cls.summary}

    # ------------------------------------------------------------------ plugin API
    def register(self, bp: Blueprint) -> None:
        """Attach decoy routes to ``bp``. Default: none."""

    def breadcrumbs(self) -> list[Breadcrumb]:
        return []

    def tick(self) -> None:
        """Periodic housekeeping, called from the serve loop (every ~30 s).

        Techniques that react to a session *stopping* (idle/stop detection, e.g.
        RoE revocation honoured, replication hand-over completed) do that work
        here. Runs outside any request context, so it must not touch ``g``.
        Default: no-op.

        Returns:
            None.
        """

    # ------------------------------------------------------------------ helpers for subclasses
    @property
    def persona(self):
        return self.ctx.persona

    def emit(self, type: str, severity: "str | Severity", message: str, **data: Any) -> Event:
        """Publish an event attributed to this technique and the current request's session."""
        session = getattr(g, "tarpit_session", None)
        try:
            g.tarpit_technique = self.id
        except RuntimeError:  # outside request context
            pass
        if session is not None:
            self.ctx.sessions.mark_technique(session.id, self.id)
        return self.ctx.bus.emit(
            type, severity, message,
            technique=self.id,
            session_id=session.id if session else None,
            src_ip=session.src_ip if session else None,
            data=data,
        )

    def tag_request(self) -> None:
        """Attribute the current request to this technique without emitting an event."""
        try:
            g.tarpit_technique = self.id
        except RuntimeError:
            pass

    def emit_session(
        self, session_id: str | None, src_ip: str | None,
        type: str, severity: "str | Severity", message: str, **data: Any,
    ) -> Event:
        """Publish an event for a known session outside any request context.

        Used by :meth:`tick` (idle/stop detection), where ``g`` is not available.

        Args:
            session_id: The session the event belongs to (or None).
            src_ip: The session source IP (or None).
            type: Event type.
            severity: Event severity.
            message: Human-readable message.
            **data: Event payload.

        Returns:
            The published Event.
        """
        if session_id is not None:
            self.ctx.sessions.mark_technique(session_id, self.id)
        return self.ctx.bus.emit(
            type, severity, message,
            technique=self.id, session_id=session_id, src_ip=src_ip, data=data,
        )
