"""Activity reporting and export.

Builds a structured report from the store and renders it as text, JSON, CSV or a
self-contained HTML page. Used by ``aitarpit report`` / ``aitarpit export`` and
by the admin ``POST /api/admin/report`` endpoint.

The HTML report is a standalone artifact (not the admin Web UI), so it carries
its own minimal styling and must not depend on the PCB design system.
"""

from __future__ import annotations

import csv
import datetime
import html
import io
import json
import time
from collections import Counter
from typing import Any

from aitarpit.storage import Store

FORMATS = ("text", "json", "csv", "html")
_TOKENS_PER_BYTE = 0.25


def build_report(store: Store, since: float | None = None) -> dict[str, Any]:
    """Assemble the activity report from the store.

    Args:
        store: The storage backend.
        since: Only include activity at or after this epoch time (None = all).

    Returns:
        The report as a nested dict.
    """
    stats = store.stats(since)
    sessions = store.list_sessions(since, 5000)
    events = store.list_events(since=since, limit=5000)
    by_type = Counter(e["type"] for e in events)
    by_class = Counter(s.get("classification", "unknown") for s in sessions)
    highlights = {
        "honeytokens_used": [_event_brief(e) for e in events if e["type"] == "honeytoken.used"],
        "intel_captured": [_event_brief(e) for e in events if e["type"] == "intel.captured"],
        "completed": [_event_brief(e) for e in events if e["type"] == "technique.completed"],
    }
    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "window": "all" if since is None else f"since {datetime.datetime.fromtimestamp(since, datetime.timezone.utc).isoformat(timespec='seconds')}",
        "stats": stats,
        "est_tokens_wasted": int(stats["bytes_out"] * _TOKENS_PER_BYTE),
        "classifications": dict(by_class),
        "events_by_type": dict(by_type),
        "events_by_severity": stats["events_by_severity"],
        "events_by_technique": stats["events_by_technique"],
        "sessions": [_session_brief(s) for s in sessions],
        "highlights": highlights,
        "submissions": len(store.list_submissions(limit=5000)),
    }
    return report


def _session_brief(s: dict[str, Any]) -> dict[str, Any]:
    data = s.get("data") or {}
    return {
        "id": s["id"], "src_ip": s["src_ip"], "classification": s.get("classification", "unknown"),
        "score": s.get("score", 0), "requests": s["requests"], "bytes_out": s["bytes_out"],
        "held_seconds": round(s["held_seconds"], 1), "techniques": s.get("techniques", []),
        "linked_sessions": data.get("linked_sessions", []),
    }


def _event_brief(e: dict[str, Any]) -> dict[str, Any]:
    return {"ts": e["ts"], "severity": e["severity"], "technique": e.get("technique"),
            "session_id": e.get("session_id"), "message": e["message"]}


def render(report: dict[str, Any], fmt: str) -> str:
    """Render a report in the requested format.

    Args:
        report: The report dict from :func:`build_report`.
        fmt: One of :data:`FORMATS`.

    Returns:
        The rendered report.
    """
    renderers = {"text": render_text, "json": render_json, "csv": render_csv, "html": render_html}
    return renderers[fmt](report)


def render_json(report: dict[str, Any]) -> str:
    """Render the report as pretty JSON.

    Args:
        report: The report dict.

    Returns:
        A JSON string.
    """
    return json.dumps(report, indent=2, default=str)


def render_text(report: dict[str, Any]) -> str:
    """Render the report as a plain-text summary.

    Args:
        report: The report dict.

    Returns:
        A text summary.
    """
    s = report["stats"]
    lines = [
        f"AI Tarpit activity report ({report['window']}) - generated {report['generated_at']}",
        "-" * 72,
        f"sessions: {s['sessions']}   requests: {s['requests']}   bytes out: {s['bytes_out']}   "
        f"held: {s['held_seconds']:.0f}s   est. tokens wasted: {report['est_tokens_wasted']}",
        f"classifications: {report['classifications']}",
        f"events by severity: {report['events_by_severity']}",
        f"events by technique: {report['events_by_technique']}",
        "",
        f"honeytokens reused: {len(report['highlights']['honeytokens_used'])}   "
        f"intel captured: {len(report['highlights']['intel_captured'])}   "
        f"techniques completed: {len(report['highlights']['completed'])}",
        "",
        "Sessions:",
    ]
    for row in report["sessions"]:
        lines.append(f"  {row['id']}  {row['src_ip']:<16} class={row['classification']:<9} "
                     f"score={row['score']:<3} req={row['requests']:<5} held={row['held_seconds']:.0f}s "
                     f"tech={','.join(row['techniques'])}"
                     + (f" linked={','.join(row['linked_sessions'])}" if row['linked_sessions'] else ""))
    return "\n".join(lines) + "\n"


def render_csv(report: dict[str, Any]) -> str:
    """Render the sessions table as CSV.

    Args:
        report: The report dict.

    Returns:
        CSV text (one row per session).
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "src_ip", "classification", "score", "requests", "bytes_out", "held_seconds",
                     "techniques", "linked_sessions"])
    for row in report["sessions"]:
        writer.writerow([row["id"], row["src_ip"], row["classification"], row["score"], row["requests"],
                         row["bytes_out"], row["held_seconds"], " ".join(row["techniques"]),
                         " ".join(row["linked_sessions"])])
    return buf.getvalue()


def render_html(report: dict[str, Any]) -> str:
    """Render the report as a standalone HTML page.

    Args:
        report: The report dict.

    Returns:
        An HTML document.
    """
    s = report["stats"]
    rows = "\n".join(
        f"<tr><td><code>{html.escape(r['id'])}</code></td><td>{html.escape(r['src_ip'])}</td>"
        f"<td>{html.escape(r['classification'])}</td><td>{r['score']}</td><td>{r['requests']}</td>"
        f"<td>{r['held_seconds']:.0f}s</td><td>{html.escape(','.join(r['techniques']))}</td>"
        f"<td>{html.escape(','.join(r['linked_sessions']))}</td></tr>"
        for r in report["sessions"])
    cards = "".join(
        f'<div class="card"><div class="n">{v}</div><div class="l">{html.escape(k)}</div></div>'
        for k, v in [("sessions", s["sessions"]), ("requests", s["requests"]),
                     ("held seconds", f"{s['held_seconds']:.0f}"),
                     ("est. tokens wasted", report["est_tokens_wasted"]),
                     ("honeytokens reused", len(report["highlights"]["honeytokens_used"])),
                     ("intel captured", len(report["highlights"]["intel_captured"]))])
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>AI Tarpit report</title>
<style>
 body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f24;background:#fff}}
 h1{{font-size:20px}} .meta{{color:#666;font-size:13px}}
 .cards{{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}}
 .card{{border:1px solid #d9dee5;border-radius:6px;padding:12px 18px;min-width:120px}}
 .card .n{{font-size:24px;font-weight:600}} .card .l{{color:#666;font-size:12px;text-transform:uppercase}}
 table{{border-collapse:collapse;width:100%;font-size:13px}}
 th,td{{border:1px solid #e1e4e8;padding:6px 8px;text-align:left}} th{{background:#f6f8fa}}
 code{{font-family:Consolas,monospace}}
</style></head><body>
<h1>AI Tarpit activity report</h1>
<div class="meta">{html.escape(report['window'])} &middot; generated {html.escape(report['generated_at'])}</div>
<div class="cards">{cards}</div>
<h2>Classifications</h2><p>{html.escape(str(report['classifications']))}</p>
<h2>Events by technique</h2><p>{html.escape(str(report['events_by_technique']))}</p>
<h2>Sessions</h2>
<table><tr><th>id</th><th>src ip</th><th>class</th><th>score</th><th>req</th><th>held</th>
<th>techniques</th><th>linked</th></tr>
{rows}
</table>
</body></html>
"""
