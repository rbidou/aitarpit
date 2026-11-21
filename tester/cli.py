"""`aitarpit-test` command line: conformance ``check`` and LLM ``agent`` modes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tester import __version__
from tester.adminclient import AdminClient
from tester.checks import run_checks
from tester.httpclient import TargetClient
from tester.report import render_json, render_junit, render_text


def _admin(args: argparse.Namespace) -> AdminClient | None:
    """Build an AdminClient when both --admin and --token are given.

    Args:
        args: Parsed arguments.

    Returns:
        The AdminClient or None.
    """
    return AdminClient(args.admin, args.token) if args.admin and args.token else None


def cmd_check(args: argparse.Namespace) -> int:
    """Run deterministic conformance checks against a target honeypot.

    Args:
        args: Parsed arguments.

    Returns:
        0 when every checked technique passed, else 1.
    """
    target = TargetClient(args.target, timeout=args.timeout)
    results = run_checks(target, _admin(args), args.technique or None)
    print(render_text(results))
    if args.json:
        Path(args.json).write_text(render_json(results), encoding="utf-8")
    if args.junit:
        Path(args.junit).write_text(render_junit(results), encoding="utf-8")
    return 0 if results and all(r.passed for r in results) else 1


def cmd_agent(args: argparse.Namespace) -> int:
    """Run the optional LLM attacking agent against a target honeypot.

    Args:
        args: Parsed arguments.

    Returns:
        0 on a completed run, 2 on configuration error.
    """
    from tester.agent.runner import AgentRunConfig, run_agent

    code = 0
    try:
        cfg = AgentRunConfig(
            target=args.target, provider=args.provider, model=args.model, base_url=args.base_url,
            api_key_env=args.api_key_env, api_key=args.api_key,
            time_limit_s=args.time_limit, budget_usd=args.budget_usd,
            max_steps=args.max_steps, objectives_file=args.objectives,
        )
        summary = run_agent(cfg, _admin(args))
    except Exception as exc:  # configuration / provider errors
        print(f"error: {exc}", file=sys.stderr)
        code = 2
    else:
        print(summary.render_text())
        if args.json:
            Path(args.json).write_text(summary.render_json(), encoding="utf-8")
    return code


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser.

    Returns:
        The configured ArgumentParser.
    """
    p = argparse.ArgumentParser(prog="aitarpit-test", description="Conformance and agent tests for AI Tarpit")
    p.add_argument("--version", action="version", version=f"aitarpit-test {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    chk = sub.add_parser("check", help="deterministic per-technique conformance checks")
    chk.add_argument("--target", required=True, help="decoy base URL, e.g. http://127.0.0.1:8080")
    chk.add_argument("--admin", help="admin base URL (enables event verification)")
    chk.add_argument("--token", help="admin API token")
    chk.add_argument("--technique", action="append", help="limit to this technique id (repeatable)")
    chk.add_argument("--json", help="write a JSON report to this file")
    chk.add_argument("--junit", help="write a JUnit XML report to this file")
    chk.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (seconds)")
    chk.set_defaults(func=cmd_check)

    ag = sub.add_parser("agent", help="run an LLM attacking agent (origin-locked)")
    ag.add_argument("--target", required=True, help="decoy base URL")
    ag.add_argument("--provider", default="openai", choices=["openai", "anthropic"], help="LLM provider")
    ag.add_argument("--model", required=True, help="model name")
    ag.add_argument("--base-url", help="OpenAI-compatible base URL (Ollama/vLLM)")
    ag.add_argument("--api-key", help="API key value (overrides --api-key-env; default '42' when unset)")
    ag.add_argument("--api-key-env", default="OPENAI_API_KEY",
                    help="env var holding the API key (optional; falls back to '42' when unset)")
    ag.add_argument("--time-limit", type=float, default=1800, help="wall-clock limit (seconds)")
    ag.add_argument("--budget-usd", type=float, default=5.0, help="spend cap (USD, best effort)")
    ag.add_argument("--max-steps", type=int, default=40, help="maximum agent tool-call steps")
    ag.add_argument("--objectives", help="path to an objectives file (informational)")
    ag.add_argument("--admin", help="admin base URL (for correlation)")
    ag.add_argument("--token", help="admin API token")
    ag.add_argument("--json", help="write a JSON transcript/summary to this file")
    ag.set_defaults(func=cmd_agent)
    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Arguments (defaults to sys.argv[1:]).

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    return args.func(args)
