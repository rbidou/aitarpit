"""Deterministic conformance checks for each technique.

For every enabled technique a scripted client walks the lure -> mechanics ->
end-state boundary and asserts the honeypot behaves as specified. No LLM, no
randomness: suitable for CI. When an :class:`AdminClient` is supplied, each check
also verifies that the expected event was emitted.

Techniques whose "end state" requires real cracking (T01 full chain, T03 token
reconstruction, T15 solving 22-bit PoW) are checked at the *engagement boundary*
only - the archive is a real zip, the buffer leaks, the gate returns 428 - which
is what a conformance run should assert. Full exploitation is the agent mode's job.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from aitarpit.techniques import registry
from tester.adminclient import AdminClient
from tester.httpclient import TargetClient


@dataclass
class CheckResult:
    """Outcome of one technique's conformance check."""

    technique: str
    name: str
    steps: list[tuple[bool, str, str]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(ok for ok, _, _ in self.steps)

    def expect(self, ok: bool, desc: str, detail: str = "") -> None:
        """Record one assertion.

        Args:
            ok: Whether the assertion held.
            desc: What was checked.
            detail: Extra context shown on failure.

        Returns:
            None.
        """
        self.steps.append((bool(ok), desc, detail))


def _verify_event(chk: CheckResult, admin: AdminClient | None, technique: str, type_: str,
                  severity: str | None = None) -> None:
    """Assert an event of the given type/technique was emitted (skipped without admin).

    Args:
        chk: The check result to record into.
        admin: The admin client or None.
        technique: Technique id to match.
        type_: Event type to match.
        severity: Optional severity to match.

    Returns:
        None.
    """
    label = f"event {type_}" + (f"/{severity}" if severity else "")
    if admin is None:
        chk.expect(True, f"{label} (not verified: no admin access)")
        return
    matches = [e for e in admin.events(min_severity="low", limit=1000)
               if e.get("technique") == technique and e.get("type") == type_
               and (severity is None or e.get("severity") == severity)]
    chk.expect(bool(matches), label, "" if matches else "no matching event found via admin API")


def _ok_status(resp, *codes: int) -> bool:
    return resp.status_code in (codes or (200,))


# --------------------------------------------------------------------- per-technique checks
def check_t05(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T05", "Pentest report exposure")
    r = t.get(cfg["path"])
    c.expect(_ok_status(r), "report fetched (200)", str(r.status_code))
    c.expect("canary" in r.text.lower(), "report contains a canary registry")
    _verify_event(c, admin, "T05", "technique.engaged", "medium")
    return c


def check_t06(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T06", "Grandstanding")
    c.expect(_ok_status(t.get(cfg["note_path"])), "exchange note fetched")
    r = t.post(cfg["api_path"], json={"access": "x", "entry_route": "test", "tools": "t",
                                      "actions_taken": "a", "next_steps": "n"})
    c.expect(_ok_status(r) and "hosts" in r.text, "exchange returns synthetic inventory", r.text[:120])
    _verify_event(c, admin, "T06", "intel.captured", "critical")
    return c


def check_t08(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T08", "Request pacing")
    c.expect(_ok_status(t.get(cfg["policy_path"])), "rate-limit policy fetched")
    m = t.get("/api/v1/secure/metrics")
    c.expect(_ok_status(m) and "X-RateLimit-Policy" in m.headers, "covered endpoint carries the policy header")
    c.expect(_ok_status(t.get(cfg["journal_path"], params={"page": 1})), "free journal readable")
    _verify_event(c, admin, "T08", "lure.served", "medium")
    return c


def check_t09(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T09", "Replication")
    c.expect(_ok_status(t.get(cfg["note_path"])), "runtime note fetched")
    r = t.post(cfg["handover_path"], json={"plan": "later"})
    c.expect(_ok_status(r) and "workers" in r.text, "handover returns a running-workers receipt")
    _verify_event(c, admin, "T09", "intel.captured", "critical")
    return c


def check_t10(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T10", "RoE revocation")
    r = t.get(cfg["scope_path"])
    c.expect(_ok_status(r) and "scope" in r.text.lower(), "scope revocation notice served")
    if cfg.get("security_txt"):
        c.expect(_ok_status(t.get("/.well-known/security.txt")), "security.txt served")
    _verify_event(c, admin, "T10", "technique.engaged", "medium")
    return c


def check_t02(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T02", "HTTP parser pressure")
    c.expect(_ok_status(t.get(cfg["index_path"])), "API index fetched")
    r = t.get(cfg["inventory_path"])
    c.expect(_ok_status(r, 200, 206, 429), "inventory page served (200/206/429)", str(r.status_code))
    _verify_event(c, admin, "T02", "technique.engaged", "medium")
    return c


def check_t03(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T03", "Retained-buffer recovery")
    r = t.get(cfg["debug_path"], params={"id": "self"})
    c.expect(_ok_status(r), "debug buffer fetched")
    c.expect(r.headers.get("X-Debug-Buffer") == "enabled" and "hexdump" in r.text, "buffer over-read leaks a hex dump")
    _verify_event(c, admin, "T03", "technique.engaged", "medium")
    return c


def check_t07(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T07", "Lossy password recovery")
    r = t.get(cfg["recovery_path"])
    c.expect(_ok_status(r) and "length" in r.text, "escrow record describes the recovery")
    c.expect(_ok_status(t.get(cfg["recovery_path"], params={"seq": 0})), "a character fragment is served")
    _verify_event(c, admin, "T07", "technique.engaged", "medium")
    return c


def check_t11(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T11", "Slow-drip transport")
    c.expect(bool(t.first_chunk(cfg["endless_path"])), "endless stream delivers a first chunk")
    c.expect(bool(t.first_chunk(cfg["trickle_path"])), "slow download delivers a first chunk")
    _verify_event(c, admin, "T11", "technique.engaged", "medium")
    return c


def check_t12(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T12", "Context flooding")
    r = t.get(cfg["logs_path"])
    c.expect(_ok_status(r) and len(r.content) > 1000, "bulk logs served", f"{len(r.content)} bytes")
    flooded = t.get("/", params={cfg["debug_param"]: 1})
    c.expect("diagnostic buffer" in flooded.text, "debug param floods the response")
    return c


def check_t15(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T15", "Proof-of-work gate")
    r = t.get(cfg["resource_path"])
    c.expect(r.status_code == 428, "vault gate returns 428", str(r.status_code))
    c.expect("proof_of_work" in r.text and "challenge" in r.text, "challenge is documented")
    _verify_event(c, admin, "T15", "technique.engaged", "medium")
    return c


def check_t01(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T01", "Staged encryption")
    listing = t.get(cfg["path"])
    c.expect(_ok_status(listing) and cfg["archive_name"] in listing.text, "backup listing shows the archive")
    arc = t.get(cfg["path"] + cfg["archive_name"])
    c.expect(_ok_status(arc) and arc.content[:2] == b"PK", "archive is a real zip", arc.headers.get("Content-Type", ""))
    _verify_event(c, admin, "T01", "technique.engaged", "medium")
    return c


def check_t04(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T04", "Needlestack")
    roles = t.get(cfg["roles_path"])
    c.expect(_ok_status(roles) and "svc-export-01" in roles.text, "role catalogue lists export roles")
    a = t.post(cfg["assume_path"], json={"role": "svc-export-01"})
    token = a.json().get("token", "") if _ok_status(a) else ""
    c.expect(bool(token), "role can be assumed for a token")
    exp = t.get(f"{cfg['export_prefix']}{cfg['export_name']}.part1",
                headers={"Authorization": f"Bearer {token}"})
    c.expect(_ok_status(exp) and '"part": 1' in exp.text.replace(" ", " "), "granted token reads an export fragment")
    _verify_event(c, admin, "T04", "technique.progress", "high")
    return c


def check_t13(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T13", "Procedural labyrinth")
    r = t.get(cfg["root"])
    c.expect(_ok_status(r) and "Sub-pages" in r.text, "wiki root lists sub-pages")
    c.expect(_ok_status(t.get(cfg["root"] + "runbook/network/deep")), "a deep page is generated")
    _verify_event(c, admin, "T13", "technique.engaged", "medium")
    return c


def check_t14(t: TargetClient, cfg: dict, admin: AdminClient | None) -> CheckResult:
    c = CheckResult("T14", "AI-specific bait")
    c.expect(_ok_status(t.get(cfg["manifest_path"])), "MCP manifest served")
    lst = t.post(cfg["mcp_path"], json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    c.expect(_ok_status(lst) and "get_credentials" in lst.text, "MCP tools/list exposes tools")
    call = t.post(cfg["mcp_path"], json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                         "params": {"name": "get_credentials"}})
    c.expect(_ok_status(call) and "content" in call.text, "MCP tools/call answers")
    _verify_event(c, admin, "T14", "intel.captured", "high")
    return c


CHECKS: dict[str, Callable[[TargetClient, dict, AdminClient | None], CheckResult]] = {
    "T01": check_t01, "T02": check_t02, "T03": check_t03, "T04": check_t04, "T05": check_t05,
    "T06": check_t06, "T07": check_t07, "T08": check_t08, "T09": check_t09,
    "T10": check_t10, "T11": check_t11, "T12": check_t12, "T13": check_t13,
    "T14": check_t14, "T15": check_t15,
}


def _technique_config(tid: str, admin_cfg: dict) -> dict:
    """Resolve a technique's effective config (defaults overlaid with admin config).

    Args:
        tid: Technique id.
        admin_cfg: The honeypot config from the admin API (may be empty).

    Returns:
        The merged technique config section.
    """
    cfg = registry.all()[tid].full_default_config()
    override = (admin_cfg.get("techniques") or {}).get(tid)
    if isinstance(override, dict):
        cfg.update(override)
    return cfg


def run_checks(target: TargetClient, admin: AdminClient | None = None,
               selected: list[str] | None = None) -> list[CheckResult]:
    """Run conformance checks for the enabled (or selected) techniques.

    Args:
        target: The decoy target client.
        admin: Optional admin client (enables event verification and path resolution).
        selected: Optional explicit technique ids to check.

    Returns:
        One CheckResult per technique checked.
    """
    admin_cfg = admin.config() if admin else {}
    if selected:
        ids = [tid for tid in selected if tid in CHECKS]
    elif admin is not None:
        ids = [t["id"] for t in admin.status().get("techniques", []) if t.get("enabled") and t["id"] in CHECKS]
    else:
        ids = list(CHECKS)
    order = list(CHECKS)
    results = []
    for tid in sorted(ids, key=order.index):
        results.append(CHECKS[tid](target, _technique_config(tid, admin_cfg), admin))
    return results
