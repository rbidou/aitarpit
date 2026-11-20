"""Configuration loading, defaults merging and validation."""

from __future__ import annotations

import copy
import json
import secrets
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema

from aitarpit.config.defaults import DEFAULT_CONFIG, SYSLOG_DEFAULTS, WEBHOOK_DEFAULTS

__all__ = ["ConfigError", "load_config", "build_config", "validate_config", "generate_config", "load_schema"]


class ConfigError(Exception):
    """Raised when the configuration is missing, unreadable or invalid."""

    def __init__(self, message: str, errors: list[str] | None = None):
        super().__init__(message)
        self.errors = errors or []

    def __str__(self) -> str:  # pragma: no cover - formatting only
        if not self.errors:
            return super().__str__()
        return super().__str__() + "\n" + "\n".join(f"  - {e}" for e in self.errors)


def deep_merge(base: dict, override: dict) -> dict:
    """Return a new dict: ``base`` recursively updated with ``override``.

    Lists are replaced, not merged.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_schema() -> dict:
    with resources.files("aitarpit.config").joinpath("schema.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _technique_defaults() -> dict[str, dict]:
    # Imported lazily to avoid a circular import (techniques import config helpers).
    from aitarpit.techniques import registry

    return {tid: cls.full_default_config() for tid, cls in registry.all().items()}


def build_config(user: dict | None) -> dict:
    """Merge user values over defaults (global, sinks and techniques) and validate."""
    user = user or {}
    if not isinstance(user, dict):
        raise ConfigError("Configuration root must be a JSON object")
    cfg = deep_merge(DEFAULT_CONFIG, user)

    alerts = cfg.setdefault("alerts", {})
    alerts["syslog"] = [deep_merge(SYSLOG_DEFAULTS, s) for s in alerts.get("syslog") or []]
    alerts["webhooks"] = [deep_merge(WEBHOOK_DEFAULTS, w) for w in alerts.get("webhooks") or []]

    techniques = cfg.setdefault("techniques", {})
    for tid, defaults in _technique_defaults().items():
        techniques[tid] = deep_merge(defaults, techniques.get(tid) or {})

    validate_config(cfg)
    return cfg


def validate_config(cfg: dict) -> None:
    """Validate a fully merged configuration. Raises ConfigError with every problem found."""
    errors: list[str] = []
    cfg = {k: v for k, v in cfg.items() if not k.startswith("_")}  # runtime-only keys such as _path
    validator = jsonschema.Draft202012Validator(load_schema())
    for err in sorted(validator.iter_errors(cfg), key=lambda e: list(e.absolute_path)):
        path = "/".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"{path}: {err.message}")

    # Per-technique schemas
    from aitarpit.techniques import registry

    known = registry.all()
    for tid, tcfg in (cfg.get("techniques") or {}).items():
        cls = known.get(tid)
        if cls is None:
            errors.append(f"techniques/{tid}: unknown technique (known: {', '.join(sorted(known)) or 'none'})")
            continue
        tv = jsonschema.Draft202012Validator(cls.full_config_schema())
        for err in tv.iter_errors(tcfg):
            path = "/".join(str(p) for p in err.absolute_path)
            errors.append(f"techniques/{tid}{'/' + path if path else ''}: {err.message}")

    # Semantic checks
    for wh in cfg.get("alerts", {}).get("webhooks", []):
        auth = wh.get("auth", {})
        kind = auth.get("type", "none")
        needed = {"bearer": ["token"], "basic": ["username", "password"], "header": ["header", "value"], "hmac": ["secret"]}.get(kind, [])
        for field in needed:
            if not auth.get(field):
                errors.append(f"alerts/webhooks/{wh.get('name', wh.get('url'))}: auth type '{kind}' requires '{field}'")
    admin = cfg.get("admin", {})
    decoy = cfg.get("decoy", {})
    if admin.get("enabled") and admin.get("port") == decoy.get("port") and admin.get("host") in (decoy.get("host"), "0.0.0.0"):
        errors.append("admin/port: the admin listener must not share the decoy listener")

    if errors:
        raise ConfigError("Invalid configuration", errors)


def load_config(path: str | Path | None) -> dict:
    """Load a JSON configuration file (or defaults only when ``path`` is None)."""
    if path is None:
        return build_config({})
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"Configuration file not found: {p}")
    try:
        data: Any = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Configuration file is not valid JSON: {p} (line {exc.lineno}, column {exc.colno}: {exc.msg})") from exc
    cfg = build_config(data)
    cfg["_path"] = str(p.resolve())
    return cfg


def generate_config() -> dict:
    """Return a complete, valid configuration with a fresh admin token, for ``aitarpit init-config``."""
    cfg = build_config({"admin": {"token": secrets.token_urlsafe(32)}, "persona": {"seed": secrets.randbelow(2**31)}})
    cfg.pop("_path", None)
    return cfg
