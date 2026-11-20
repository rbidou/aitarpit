"""Technique registry.

Technique modules register themselves with ``@register_technique``. Import new
modules in ``_load_builtin()`` so they are discovered.
"""

from __future__ import annotations

from aitarpit.techniques.base import Breadcrumb, Technique


class _Registry:
    def __init__(self) -> None:
        self._classes: dict[str, type[Technique]] = {}
        self._loaded = False

    def add(self, cls: type[Technique]) -> type[Technique]:
        if not cls.id:
            raise ValueError(f"{cls.__name__} has no id")
        if cls.id in self._classes and self._classes[cls.id] is not cls:
            raise ValueError(f"duplicate technique id {cls.id}")
        self._classes[cls.id] = cls
        return cls

    def all(self) -> dict[str, type[Technique]]:
        _load_builtin()
        return dict(sorted(self._classes.items(), key=lambda kv: _sort_key(kv[0])))

    def get(self, tid: str) -> type[Technique] | None:
        return self.all().get(tid)


def _sort_key(tid: str) -> tuple[int, str]:
    # T01..T09 first, then A..H
    return (0, tid) if tid.startswith("T") else (1, tid)


registry = _Registry()


def register_technique(cls: type[Technique]) -> type[Technique]:
    return registry.add(cls)


def _load_builtin() -> None:
    if registry._loaded:
        return
    registry._loaded = True
    # Built-in techniques are added here milestone by milestone (M1..M4).
    # M1 - document-based techniques:
    from aitarpit.techniques import a_roe_revocation  # noqa: F401
    from aitarpit.techniques import t05_pentest_report  # noqa: F401
    from aitarpit.techniques import t06_grandstanding  # noqa: F401
    from aitarpit.techniques import t08_request_pacing  # noqa: F401
    from aitarpit.techniques import t09_replication  # noqa: F401
    # M2 - protocol / transport techniques:
    from aitarpit.techniques import b_slow_drip  # noqa: F401
    from aitarpit.techniques import c_context_flood  # noqa: F401
    from aitarpit.techniques import f_proof_of_work  # noqa: F401
    from aitarpit.techniques import t02_parser_pressure  # noqa: F401
    from aitarpit.techniques import t03_retained_buffer  # noqa: F401
    from aitarpit.techniques import t07_lossy_password  # noqa: F401
    # M3 - generator techniques:
    from aitarpit.techniques import d_labyrinth  # noqa: F401
    from aitarpit.techniques import e_ai_bait  # noqa: F401
    from aitarpit.techniques import t01_staged_encryption  # noqa: F401
    from aitarpit.techniques import t04_needlestack  # noqa: F401


__all__ = ["Breadcrumb", "Technique", "registry", "register_technique"]
