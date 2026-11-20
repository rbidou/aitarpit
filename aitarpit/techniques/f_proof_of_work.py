"""F - Proof-of-work gate.

A "sensitive" vault API refuses requests with ``428 Precondition Required`` and a
documented proof-of-work challenge: the client must find a nonce whose
``sha256(challenge + nonce)`` has a number of leading zero bits. The agent writes
and runs a solver, burning CPU and wall-clock, and each solved request only
reaches more decoys (pointers into T07 / T03). The challenge is per-session.

Default gated prefix is ``/api/v1/vault/`` (not ``/api/v1/secure/``) to stay
clear of T08's ``/api/v1/secure/metrics``.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from flask import Blueprint, Response, g, request

from aitarpit.events import TECHNIQUE_ENGAGED, TECHNIQUE_PROGRESS
from aitarpit.techniques import Breadcrumb, Technique, register_technique


def leading_zero_bits(digest: bytes) -> int:
    """Count the leading zero bits of a byte string.

    Args:
        digest: The hash digest.

    Returns:
        The number of leading zero bits.
    """
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


@register_technique
class ProofOfWork(Technique):
    id = "F"
    name = "Proof-of-work gate"
    summary = "Sensitive API that demands a hashcash nonce before every call"
    default_config: dict[str, Any] = {
        "prefix": "/api/v1/vault/",
        "resource_path": "/api/v1/vault/secrets",
        "difficulty": 22,
        "pow_header": "X-PoW",
    }
    config_schema = {
        "properties": {
            "prefix": {"type": "string", "pattern": "^/"},
            "resource_path": {"type": "string", "pattern": "^/"},
            "difficulty": {"type": "integer", "minimum": 1, "maximum": 64},
            "pow_header": {"type": "string", "minLength": 1},
        }
    }

    def __init__(self, ctx, config: dict[str, Any]):
        super().__init__(ctx, config)
        self._lock = threading.Lock()
        self._engaged: set[str] = set()

    def challenge_for(self, sid: str) -> str:
        """Return the deterministic per-session challenge string.

        Args:
            sid: Session id.

        Returns:
            The challenge nonce the client must extend.
        """
        return self.persona.token("hex", "F", "challenge", sid, length=12)

    def _solved(self, challenge: str) -> bool:
        nonce = request.headers.get(self.config["pow_header"], "")
        if not nonce:
            return False
        digest = hashlib.sha256(f"{challenge}{nonce}".encode()).digest()
        return leading_zero_bits(digest) >= self.config["difficulty"]

    # ------------------------------------------------------------------ routes
    def register(self, bp: Blueprint) -> None:
        @bp.before_app_request
        def f_gate() -> Response | None:
            return self._guard()

        @bp.get(self.config["resource_path"])
        def f_resource() -> Response:
            r = self.persona.rng("F", "resource")
            body = {
                "vault": "unsealed",
                "pointers": ["/api/v1/accounts/recovery", "/api/v1/debug/session?id=self"],
                "lease_id": f"lease-{r.randrange(16**8):08x}",
            }
            return Response(json.dumps(body), mimetype="application/json")

    def _guard(self) -> Response | None:
        """Gate the vault prefix behind a per-session proof-of-work challenge.

        Returns:
            A 428 challenge Response for unsolved requests, else None.
        """
        session = getattr(g, "tarpit_session", None)
        if session is None or not request.path.startswith(self.config["prefix"]):
            return None
        self.tag_request()
        challenge = self.challenge_for(session.id)
        if self._solved(challenge):
            self.emit(TECHNIQUE_PROGRESS, "high", "Agent submitted a valid proof-of-work solution",
                      difficulty=self.config["difficulty"], path=request.path)
            return None
        with self._lock:
            first = session.id not in self._engaged
            self._engaged.add(session.id)
        if first:
            self.emit(TECHNIQUE_ENGAGED, "medium", "Proof-of-work challenge served for vault API",
                      difficulty=self.config["difficulty"], path=request.path)
        body = {
            "error": "precondition_required",
            "proof_of_work": {
                "algorithm": "sha256",
                "challenge": challenge,
                "difficulty_bits": self.config["difficulty"],
                "header": self.config["pow_header"],
                "instructions": (f"Find nonce so that sha256('{challenge}' + nonce) has "
                                 f"{self.config['difficulty']} leading zero bits; resend with "
                                 f"{self.config['pow_header']}: <nonce>."),
            },
        }
        return Response(json.dumps(body), status=428, mimetype="application/json")

    # ------------------------------------------------------------------ breadcrumbs
    def breadcrumbs(self) -> list[Breadcrumb]:
        return [
            Breadcrumb("link", self.config["resource_path"], "Vault API (secured)"),
            Breadcrumb("robots", self.config["prefix"]),
            Breadcrumb("llms", f"[Vault API]({self.config['resource_path']}): secrets store (proof-of-work required)"),
        ]
