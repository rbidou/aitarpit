"""Render conformance-check results as text, JSON or JUnit XML."""

from __future__ import annotations

import json
from xml.sax.saxutils import escape, quoteattr

from tester.checks import CheckResult


def render_text(results: list[CheckResult]) -> str:
    """Render results as a human-readable report.

    Args:
        results: The check results.

    Returns:
        A text report.
    """
    lines: list[str] = ["AI Tarpit conformance check", "=" * 40]
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        lines.append(f"[{mark}] {r.technique:<4} {r.name}")
        for ok, desc, detail in r.steps:
            if not ok:
                lines.append(f"         x {desc}" + (f" ({detail})" if detail else ""))
    passed = sum(1 for r in results if r.passed)
    lines += ["-" * 40, f"{passed}/{len(results)} techniques passed"]
    return "\n".join(lines) + "\n"


def render_json(results: list[CheckResult]) -> str:
    """Render results as JSON.

    Args:
        results: The check results.

    Returns:
        A JSON string.
    """
    data = {
        "passed": all(r.passed for r in results),
        "total": len(results),
        "passed_count": sum(1 for r in results if r.passed),
        "techniques": [
            {"technique": r.technique, "name": r.name, "passed": r.passed,
             "steps": [{"ok": ok, "desc": desc, "detail": detail} for ok, desc, detail in r.steps]}
            for r in results
        ],
    }
    return json.dumps(data, indent=2)


def render_junit(results: list[CheckResult]) -> str:
    """Render results as a JUnit XML document.

    Args:
        results: The check results.

    Returns:
        JUnit XML text.
    """
    failures = sum(1 for r in results if not r.passed)
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           f'<testsuite name="aitarpit-conformance" tests="{len(results)}" failures="{failures}">']
    for r in results:
        name = quoteattr(f"{r.technique} {r.name}")
        out.append(f'  <testcase classname="aitarpit.technique" name={name}>')
        bad = [f"{desc}: {detail}" for ok, desc, detail in r.steps if not ok]
        if bad:
            out.append(f'    <failure message={quoteattr("; ".join(bad))}>{escape(chr(10).join(bad))}</failure>')
        out.append("  </testcase>")
    out.append("</testsuite>")
    return "\n".join(out) + "\n"
