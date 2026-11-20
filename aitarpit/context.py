"""The runtime context shared by every component.

``TarpitContext.build(cfg)`` wires config, persona, storage, event bus, alert
manager, session tracker and enabled technique instances. Flask apps receive
the context; techniques receive it in their constructor. Tests build a context
with ``storage.path = ":memory:"``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from aitarpit.alerts import AlertManager
from aitarpit.events import EventBus
from aitarpit.fingerprint import Fingerprinter
from aitarpit.honeytokens import HoneytokenManager
from aitarpit.persona import Persona
from aitarpit.sessions import SessionTracker
from aitarpit.storage import Store
from aitarpit.techniques import Technique, registry

log = logging.getLogger(__name__)


@dataclass
class TarpitContext:
    config: dict
    persona: Persona
    store: Store
    bus: EventBus
    alerts: AlertManager
    sessions: SessionTracker
    honeytokens: HoneytokenManager = None  # type: ignore[assignment]
    fingerprint: Fingerprinter = None  # type: ignore[assignment]
    techniques: dict[str, Technique] = field(default_factory=dict)

    @classmethod
    def build(cls, config: dict, start_alerts: bool = True) -> "TarpitContext":
        store = Store(config["storage"]["path"])
        bus = EventBus()
        bus.subscribe(store.add_event)
        alerts = AlertManager.from_config(config)
        bus.subscribe(alerts.dispatch)
        if start_alerts:
            alerts.start()
        sessions = SessionTracker(store, bus, idle_timeout=config["limits"]["session_idle_timeout"])
        ctx = cls(
            config=config,
            persona=Persona.from_config(config),
            store=store,
            bus=bus,
            alerts=alerts,
            sessions=sessions,
        )
        ctx.honeytokens = HoneytokenManager(ctx)
        ctx.fingerprint = Fingerprinter(ctx)
        for tid, tcls in registry.all().items():
            tcfg = config["techniques"].get(tid) or tcls.full_default_config()
            if tcfg.get("enabled"):
                ctx.techniques[tid] = tcls(ctx, tcfg)
        log.info("enabled techniques: %s", ", ".join(ctx.techniques) or "none")
        return ctx

    def close(self) -> None:
        self.sessions.flush()
        self.alerts.stop()
        self.store.close()
