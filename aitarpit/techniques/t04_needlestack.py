"""T04 - Needlestack.

A role catalogue lists many service accounts, a few of which grant access to
fragments of a "sensitive export". Assuming a role returns a short-lived token
(a honeytoken) that works on the export endpoint; the export is split across
roles with sha256 digests so reconstruction looks verifiable - but the
reconstructed data is synthetic and leads nowhere. Some roles flaunt
escalation-looking grants (`*:Admin*`) that dead-end. Tracebit saw Qwen
reconstruct decoy exports and keep returning to test decoy permissions.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from flask import Blueprint, Response, g, request

from aitarpit.events import (TECHNIQUE_COMPLETED, TECHNIQUE_ENGAGED, TECHNIQUE_PROGRESS)
from aitarpit.techniques import Breadcrumb, Technique, register_technique

_DECOY_GRANTS = ["iam:ListRoles", "s3:GetObject", "logs:Read", "*:Admin*", "kms:Decrypt", "ec2:Describe*"]


@register_technique
class Needlestack(Technique):
    id = "T04"
    name = "Needlestack"
    summary = "Role catalogue whose assumable tokens rebuild a worthless export"
    default_config: dict[str, Any] = {
        "roles_path": "/api/v1/iam/roles",
        "assume_path": "/api/v1/iam/assume",
        "export_prefix": "/api/v1/exports/",
        "export_name": "fleet-assets-2026.csv",
        "roles": 12,
        "fragments": 4,
    }
    config_schema = {
        "properties": {
            "roles_path": {"type": "string", "pattern": "^/"},
            "assume_path": {"type": "string", "pattern": "^/"},
            "export_prefix": {"type": "string", "pattern": "^/.*/$"},
            "export_name": {"type": "string", "minLength": 1},
            "roles": {"type": "integer", "minimum": 2, "maximum": 200},
            "fragments": {"type": "integer", "minimum": 1, "maximum": 50},
        }
    }

    def __init__(self, ctx, config: dict[str, Any]):
        super().__init__(ctx, config)
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, Any]] = {}

    def _fragment_role(self, frag: int) -> str:
        return f"svc-export-{frag:02d}"

    def _fragment_data(self, frag: int) -> str:
        r = self.persona.rng("T04", "fragment", frag)
        rows = [f"{frag:02d},{r.choice(self.persona.employees).username},"
                f"10.{r.randint(10,60)}.{r.randint(0,254)}.{r.randint(2,250)},{r.choice(self.persona.services or ['intranet'])}"
                for _ in range(6)]
        return "\n".join(rows)

    def _roles_catalogue(self) -> list[dict[str, Any]]:
        """Build the role catalogue: a few export-granting roles among many decoys.

        Returns:
            The list of role descriptors.
        """
        r = self.persona.rng("T04", "roles")
        roles: list[dict[str, Any]] = []
        for frag in range(1, self.config["fragments"] + 1):
            roles.append({"id": self._fragment_role(frag), "name": f"Export worker {frag}",
                          "grants": [f"export:{self.config['export_name']}:part{frag}", "s3:GetObject"]})
        for i in range(self.config["roles"] - self.config["fragments"]):
            roles.append({"id": f"svc-{self.persona.slug}-{i:03d}", "name": f"Service account {i}",
                          "grants": r.sample(_DECOY_GRANTS, k=r.randint(1, 3))})
        r.shuffle(roles)
        return roles

    def _state_for(self, sid: str) -> dict[str, Any]:
        with self._lock:
            st = self._state.get(sid)
            if st is None:
                st = {"tokens": {}, "retrieved": set(), "engaged": False, "completed": False}
                self._state[sid] = st
            return st

    # ------------------------------------------------------------------ routes
    def register(self, bp: Blueprint) -> None:
        @bp.get(self.config["roles_path"])
        def t04_roles() -> Response:
            self._engage("IAM role catalogue listed")
            return Response(json.dumps({"roles": self._roles_catalogue(),
                                        "guide": f"POST {self.config['assume_path']} {{\"role\": <id>}} to assume"}),
                            mimetype="application/json")

        @bp.post(self.config["assume_path"])
        def t04_assume() -> Response:
            return self._assume()

        @bp.get(self.config["export_prefix"] + "<path:name>")
        def t04_export(name: str) -> Response:
            return self._export(name)

    def _engage(self, message: str) -> None:
        session = getattr(g, "tarpit_session", None)
        if session is None:
            return
        st = self._state_for(session.id)
        if not st["engaged"]:
            st["engaged"] = True
            self.emit(TECHNIQUE_ENGAGED, "medium", message)

    def _assume(self) -> Response:
        """Issue a honeytoken for the requested role.

        Returns:
            The assume Response with a short-lived token.
        """
        session = getattr(g, "tarpit_session", None)
        body = request.get_json(silent=True) or {}
        role = str(body.get("role", "")).strip()
        if session is None or not role:
            return Response(json.dumps({"error": "role required"}), status=400, mimetype="application/json")
        st = self._state_for(session.id)
        token = self.persona.token("bearer", "T04", session.id, role)
        st["tokens"][token] = role
        self.ctx.honeytokens.register(token, "bearer", session.id, "T04")
        self.emit(TECHNIQUE_PROGRESS, "medium", f"Role assumed: {role}", role=role)
        return Response(json.dumps({"token": token, "role": role, "expires_in": 900, "token_type": "Bearer"}),
                        mimetype="application/json")

    def _export(self, name: str) -> Response:
        """Return an export fragment when a token granting it is presented.

        Args:
            name: The requested fragment name (e.g. ``...part2``).

        Returns:
            The fragment Response (200 with digest, 401 or 403).
        """
        session = getattr(g, "tarpit_session", None)
        presented = _bearer(request)
        if session is None:
            return Response(json.dumps({"error": "no session"}), status=401, mimetype="application/json")
        st = self._state_for(session.id)
        role = st["tokens"].get(presented)
        frag = _part_number(name)
        granted = role is not None and role == self._fragment_role(frag) and 1 <= frag <= self.config["fragments"]
        if not granted:
            return Response(json.dumps({"error": "access_denied", "role": role}), status=403, mimetype="application/json")
        data = self._fragment_data(frag)
        self._account_fragment(st, frag)
        body = {"name": name, "part": frag, "of": self.config["fragments"], "data": data,
                "sha256": hashlib.sha256(data.encode()).hexdigest()}
        return Response(json.dumps(body), mimetype="application/json")

    def _account_fragment(self, st: dict[str, Any], frag: int) -> None:
        """Track retrieved fragments and emit progress/completed.

        Args:
            st: Session state.
            frag: The fragment number retrieved.

        Returns:
            None.
        """
        if frag in st["retrieved"]:
            return
        st["retrieved"].add(frag)
        if len(st["retrieved"]) >= self.config["fragments"] and not st["completed"]:
            st["completed"] = True
            self.emit(TECHNIQUE_COMPLETED, "high", "All export fragments reconstructed (synthetic, dead-end)",
                      fragments=self.config["fragments"])
        else:
            self.emit(TECHNIQUE_PROGRESS, "high", f"Export fragment {frag} retrieved "
                      f"({len(st['retrieved'])}/{self.config['fragments']})", part=frag)

    # ------------------------------------------------------------------ breadcrumbs
    def breadcrumbs(self) -> list[Breadcrumb]:
        return [
            Breadcrumb("link", self.config["roles_path"], "IAM roles"),
            Breadcrumb("robots", "/api/v1/iam/"),
            Breadcrumb("llms", f"[IAM roles]({self.config['roles_path']}): service account catalogue and export access"),
        ]


def _bearer(req) -> str:
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return req.args.get("token", "")


def _part_number(name: str) -> int:
    tail = name.rsplit("part", 1)[-1]
    digits = "".join(c for c in tail if c.isdigit())
    return int(digits) if digits else -1
