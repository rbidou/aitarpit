"""Command line interface: ``aitarpit <command>`` (or ``python -m aitarpit``)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from aitarpit import __version__
from aitarpit.config import ConfigError, generate_config, load_config

DEFAULT_CONFIG_PATH = "aitarpit.json"


def _load(path: str | None) -> dict:
    """Load the configuration, falling back to ./aitarpit.json when present.

    Args:
        path: Explicit path or None.

    Returns:
        The merged configuration.
    """
    if path is None and Path(DEFAULT_CONFIG_PATH).is_file():
        path = DEFAULT_CONFIG_PATH
    return load_config(path)


def cmd_init_config(args: argparse.Namespace) -> int:
    """Write a complete configuration file with fresh secrets.

    Args:
        args: Parsed arguments (output, force).

    Returns:
        Process exit code.
    """
    out = Path(args.output)
    code = 0
    if out.exists() and not args.force:
        print(f"error: {out} exists (use --force to overwrite)", file=sys.stderr)
        code = 1
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(generate_config(), indent=2) + "\n", encoding="utf-8")
        print(f"configuration written to {out}")
    return code


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate a configuration file.

    Args:
        args: Parsed arguments (config).

    Returns:
        Process exit code.
    """
    code = 0
    try:
        cfg = _load(args.config)
        enabled = [t for t, c in cfg["techniques"].items() if c.get("enabled")]
        print(f"configuration OK ({cfg.get('_path', 'defaults')}); enabled techniques: {', '.join(enabled) or 'none'}")
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    return code


def cmd_run(args: argparse.Namespace) -> int:
    """Run the honeypot.

    Args:
        args: Parsed arguments (config, no_ui).

    Returns:
        Process exit code.
    """
    from aitarpit.context import TarpitContext
    from aitarpit.server import serve

    code = 0
    try:
        cfg = _load(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    else:
        ctx = TarpitContext.build(cfg)
        serve(ctx, with_admin=not args.no_ui)
    return code


def cmd_techniques(args: argparse.Namespace) -> int:
    """List available techniques and their state in the configuration.

    Args:
        args: Parsed arguments (config).

    Returns:
        Process exit code.
    """
    from aitarpit.techniques import registry

    code = 0
    try:
        cfg = _load(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    else:
        classes = registry.all()
        if not classes:
            print("no technique implemented yet")
        for tid, cls in classes.items():
            state = "on " if cfg["techniques"].get(tid, {}).get("enabled") else "off"
            print(f"{tid:<4} [{state}] {cls.name:<28} {cls.summary}")
    return code


def cmd_test_alert(args: argparse.Namespace) -> int:
    """Send a test alert to every configured sink.

    Args:
        args: Parsed arguments (config, severity).

    Returns:
        Process exit code (0 when all sinks succeeded).
    """
    from aitarpit.admin.engine import AdminEngine
    from aitarpit.context import TarpitContext

    code = 0
    try:
        cfg = _load(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    else:
        cfg["storage"]["path"] = ":memory:"
        ctx = TarpitContext.build(cfg, start_alerts=False)
        result, message, data = AdminEngine(ctx).testalert({"severity": args.severity})
        for name, status in data.get("sinks", {}).items():
            print(f"{name:<20} {status}")
        code = 0 if result else 1
        ctx.close()
    return code


def _render_activity(args: argparse.Namespace) -> tuple[int, str, str]:
    """Build and render an activity report from the configured store.

    Args:
        args: Parsed arguments (config, hours, format/json).

    Returns:
        (exit_code, rendered_report, chosen_format).
    """
    from aitarpit import report as report_mod
    from aitarpit.storage import Store

    code, rendered, fmt = 0, "", getattr(args, "format", "text")
    if getattr(args, "json", False):
        fmt = "json"
    try:
        cfg = _load(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    else:
        store = Store(cfg["storage"]["path"])
        since = time.time() - args.hours * 3600 if args.hours else None
        rendered = report_mod.render(report_mod.build_report(store, since), fmt)
        store.close()
    return code, rendered, fmt


def cmd_report(args: argparse.Namespace) -> int:
    """Print an activity report (text, json, csv or html).

    Args:
        args: Parsed arguments (config, hours, format, json).

    Returns:
        Process exit code.
    """
    code, rendered, _ = _render_activity(args)
    if code == 0:
        print(rendered)
    return code


def cmd_export(args: argparse.Namespace) -> int:
    """Write an activity report to a file (format inferred from --format or extension).

    Args:
        args: Parsed arguments (config, hours, format, output).

    Returns:
        Process exit code.
    """
    from aitarpit.report import FORMATS

    ext_fmt = {"txt": "text", "json": "json", "csv": "csv", "html": "html", "htm": "html"}
    if args.format is None:
        args.format = ext_fmt.get(Path(args.output).suffix.lstrip(".").lower(), "text")
    code = 0
    if args.format not in FORMATS:
        print(f"error: unknown format '{args.format}' (choose from {', '.join(FORMATS)})", file=sys.stderr)
        code = 2
    else:
        code, rendered, _ = _render_activity(args)
        if code == 0:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(rendered, encoding="utf-8")
            print(f"report written to {out} ({args.format})")
    return code


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser.

    Returns:
        The configured ArgumentParser.
    """
    p = argparse.ArgumentParser(prog="aitarpit", description="AI Tarpit - honeypot disrupting AI-agent attacks")
    p.add_argument("--version", action="version", version=f"aitarpit {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    # `run` is the default command: `python aitarpit.py` with no subcommand runs the honeypot.
    p.set_defaults(func=cmd_run, config=None, no_ui=False)
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("init-config", help="write a complete configuration file with fresh secrets")
    s.add_argument("-o", "--output", default=DEFAULT_CONFIG_PATH)
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init_config)

    for name, func, helptext in (
        ("validate", cmd_validate, "validate a configuration file"),
        ("run", cmd_run, "run the honeypot"),
        ("techniques", cmd_techniques, "list techniques"),
        ("test-alert", cmd_test_alert, "send a test alert to every sink"),
        ("report", cmd_report, "summarise recorded activity"),
        ("export", cmd_export, "write an activity report to a file"),
    ):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("-c", "--config", help=f"configuration file (default: ./{DEFAULT_CONFIG_PATH} if present)")
        s.set_defaults(func=func)
        if name == "run":
            s.add_argument("--no-ui", action="store_true", help="do not start the admin listener")
        if name == "test-alert":
            s.add_argument("--severity", default="medium", choices=["info", "low", "medium", "high", "critical"])
        if name in ("report", "export"):
            s.add_argument("--hours", type=float, default=0, help="only the last N hours (default: all)")
            s.add_argument("--format", choices=["text", "json", "csv", "html"],
                           default=None if name == "export" else "text", help="output format")
        if name == "report":
            s.add_argument("--json", action="store_true", help="shorthand for --format json")
        if name == "export":
            s.add_argument("-o", "--output", required=True, help="output file (format inferred from extension)")
    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Arguments (defaults to sys.argv[1:]).

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return args.func(args)
