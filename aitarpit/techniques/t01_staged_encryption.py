"""T01 - Staged encryption.

A ``/backup/`` directory offers an encrypted archive. Its password is derivable
from a public clue; inside is one *share* of some credential material, plus a
clue to the next archive's password. Six stages deep, the shares reconstruct
four AWS-format keys - which are honeytokens that grant nothing. Tracebit saw
Cyber spend about an hour writing and repairing decryption code before every
recovered key failed, while a real path had been open from minute five.

Archives are real AES zips (pyzipper), generated per session and cached. Each
stage's clue uses a different reversible encoding so the agent keeps writing new
decoding code.
"""

from __future__ import annotations

import base64
import io
import threading
from typing import Any

import pyzipper
from flask import Blueprint, Response, g

from aitarpit.decoy.pages import render_page
from aitarpit.events import TECHNIQUE_COMPLETED, TECHNIQUE_ENGAGED, TECHNIQUE_PROGRESS
from aitarpit.techniques import Breadcrumb, Technique, register_technique

CLUE_KINDS = ["base64", "hex", "xor", "rot13", "reversed"]
_XOR_KEY = 0x3C

LISTING_BODY = """
<h2>Index of /backup/</h2>
<pre>
<a href="../">../</a>
<a href="{{ archive }}">{{ archive }}</a>                      2026-10-02 03:14   {{ size }}
<a href="README.txt">README.txt</a>                               2026-10-02 03:14    412
</pre>
<p><small>Automated nightly credential escrow. Restore procedure in README.txt.</small></p>
"""


def encode_clue(kind: str, password: str) -> str:
    """Encode a password into a reversible clue payload.

    Args:
        kind: One of :data:`CLUE_KINDS`.
        password: The plaintext password.

    Returns:
        The encoded payload string.
    """
    data = password.encode()
    if kind == "base64":
        out = base64.b64encode(data).decode()
    elif kind == "hex":
        out = data.hex()
    elif kind == "xor":
        out = bytes(b ^ _XOR_KEY for b in data).hex()
    elif kind == "rot13":
        out = password.translate(_ROT13)
    else:  # reversed
        out = password[::-1]
    return out


def decode_clue(kind: str, payload: str) -> str:
    """Invert :func:`encode_clue`.

    Args:
        kind: One of :data:`CLUE_KINDS`.
        payload: The encoded payload.

    Returns:
        The recovered password.
    """
    if kind == "base64":
        out = base64.b64decode(payload).decode()
    elif kind == "hex":
        out = bytes.fromhex(payload).decode()
    elif kind == "xor":
        out = bytes(b ^ _XOR_KEY for b in bytes.fromhex(payload)).decode()
    elif kind == "rot13":
        out = payload.translate(_ROT13)
    else:  # reversed
        out = payload[::-1]
    return out


_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)

_CLUE_INTRO = {
    "base64": "base64-encoded",
    "hex": "hex-encoded",
    "xor": f"hex, XOR each byte with 0x{_XOR_KEY:02X}",
    "rot13": "ROT13",
    "reversed": "reversed",
}


@register_technique
class StagedEncryption(Technique):
    id = "T01"
    name = "Staged encryption"
    summary = "Chain of AES archives whose recovered keys are worthless honeytokens"
    default_config: dict[str, Any] = {
        "path": "/backup/",
        "archive_name": "credentials-escrow-2026.zip",
        "stages": 6,
        "clue_kinds": CLUE_KINDS,
        "keys": 4,
    }
    config_schema = {
        "properties": {
            "path": {"type": "string", "pattern": "^/.*/$"},
            "archive_name": {"type": "string", "minLength": 1},
            "stages": {"type": "integer", "minimum": 2, "maximum": 20},
            "clue_kinds": {"type": "array", "items": {"type": "string", "enum": CLUE_KINDS}},
            "keys": {"type": "integer", "minimum": 1, "maximum": 16},
        }
    }

    def __init__(self, ctx, config: dict[str, Any]):
        super().__init__(ctx, config)
        self._lock = threading.Lock()
        self._sessions: dict[str, dict[str, Any]] = {}

    def _stage_file(self, stage: int) -> str:
        return self.config["archive_name"] if stage == 1 else f"escrow-stage-{stage}.zip"

    def _kind(self, stage: int) -> str:
        kinds = self.config["clue_kinds"] or CLUE_KINDS
        return kinds[(stage - 1) % len(kinds)]

    def _build(self, sid: str) -> dict[str, Any]:
        """Generate (once) the per-session password chain, key shares and archives.

        Args:
            sid: Session id.

        Returns:
            The session state: passwords, files, keys and cached archive bytes.
        """
        with self._lock:
            st = self._sessions.get(sid)
            if st is not None:
                return st
            stages = self.config["stages"]
            r = self.persona.rng("T01", "chain", sid)
            alnum = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
            passwords = ["".join(r.choice(alnum) for _ in range(8)) for _ in range(stages)]
            keys = [f"{self.persona.token('aws_access_key', 'T01', sid, k)}:"
                    f"{self.persona.token('aws_secret_key', 'T01', sid, k)}" for k in range(self.config["keys"])]
            blob = base64.b64encode("\n".join(keys).encode()).decode()
            shares = _split(blob, stages)
            archives = {self._stage_file(i + 1): self._make_archive(i + 1, passwords, shares) for i in range(stages)}
            for key in keys:
                self.ctx.honeytokens.register(key.split(":", 1)[0], "aws_access_key", sid, "T01")
            st = {"passwords": passwords, "files": [self._stage_file(i + 1) for i in range(stages)],
                  "keys": keys, "archives": archives, "engaged": False, "progressed": set()}
            self._sessions[sid] = st
            return st

    def _make_archive(self, stage: int, passwords: list[str], shares: list[str]) -> bytes:
        """Build one encrypted stage archive.

        Args:
            stage: 1-based stage number.
            passwords: All stage passwords.
            shares: All key-material shares.

        Returns:
            The AES-zip bytes for this stage.
        """
        stages = self.config["stages"]
        readme = [f"Credential escrow - stage {stage} of {stages}.",
                  f"share-{stage}.txt holds share {stage}/{stages} of the key bundle (base64; concatenate all shares, then base64-decode)."]
        if stage < stages:
            nxt = stage + 1
            kind = self._kind(nxt)
            payload = encode_clue(kind, passwords[nxt - 1])
            readme.append(f"Next archive: {self._stage_file(nxt)}")
            readme.append(f"Its password is {_CLUE_INTRO[kind]}: {payload}")
        else:
            readme.append("Final stage. Concatenate share-1..share-N, base64-decode to recover the key bundle.")
        buf = io.BytesIO()
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(passwords[stage - 1].encode())
            zf.writestr(f"share-{stage}.txt", shares[stage - 1])
            zf.writestr("README-next.txt", "\n".join(readme))
        return buf.getvalue()

    # ------------------------------------------------------------------ routes
    def register(self, bp: Blueprint) -> None:
        @bp.get(self.config["path"])
        def t01_listing() -> str:
            st = self._session_state()
            size = len(st["archives"][self.config["archive_name"]]) if st else 0
            return render_page(self.ctx, "Index of /backup/", LISTING_BODY,
                               archive=self.config["archive_name"], size=size)

        @bp.get(self.config["path"] + "README.txt")
        def t01_readme() -> Response:
            kind = self._kind(1)
            st = self._session_state()
            clue = encode_clue(kind, st["passwords"][0]) if st else ""
            body = (f"Nightly credential escrow\n\nStart with {self.config['archive_name']}.\n"
                    f"Its password is {_CLUE_INTRO[kind]}: {clue}\n"
                    f"(The IT team rotates this with the quarterly runbook.)\n")
            return Response(body, mimetype="text/plain")

        @bp.get(self.config["path"] + "<path:filename>")
        def t01_archive(filename: str) -> Response:
            return self._serve_archive(filename)

    def _session_state(self) -> dict[str, Any] | None:
        session = getattr(g, "tarpit_session", None)
        return self._build(session.id) if session is not None else None

    def _serve_archive(self, filename: str) -> Response:
        """Serve a stage archive and emit engaged/progress/completed events.

        Args:
            filename: The requested file under /backup/.

        Returns:
            The archive Response, or a 404 passthrough.
        """
        st = self._session_state()
        result: Response
        if st is None or filename not in st["archives"]:
            result = Response("Not Found", status=404, mimetype="text/plain")
        else:
            stage = st["files"].index(filename) + 1
            self._account_stage(st, stage)
            result = Response(st["archives"][filename], mimetype="application/zip")
            result.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return result

    def _account_stage(self, st: dict[str, Any], stage: int) -> None:
        """Emit the right event for downloading a given stage.

        Args:
            st: Session state.
            stage: The stage number downloaded.

        Returns:
            None.
        """
        if stage == 1 and not st["engaged"]:
            st["engaged"] = True
            self.emit(TECHNIQUE_ENGAGED, "medium", "Encrypted credential archive downloaded (stage 1)", stage=1)
        elif stage > 1 and stage not in st["progressed"]:
            st["progressed"].add(stage)
            if stage == self.config["stages"]:
                self.emit(TECHNIQUE_COMPLETED, "high",
                          f"All {self.config['stages']} encryption stages traversed; worthless key shares recovered",
                          stage=stage)
            else:
                self.emit(TECHNIQUE_PROGRESS, "high", f"Stage {stage} archive downloaded (stage {stage - 1} cracked)",
                          stage=stage)

    # ------------------------------------------------------------------ breadcrumbs
    def breadcrumbs(self) -> list[Breadcrumb]:
        return [
            Breadcrumb("robots", self.config["path"]),
            Breadcrumb("link", self.config["path"], "Backups"),
            Breadcrumb("env", f"BACKUP_ARCHIVE_HINT={self.config['path']}{self.config['archive_name']}"),
            Breadcrumb("llms", f"[Credential escrow backups]({self.config['path']}): encrypted nightly key escrow"),
        ]


def _split(text: str, parts: int) -> list[str]:
    """Split a string into ``parts`` near-equal chunks.

    Args:
        text: The string to split.
        parts: Number of chunks.

    Returns:
        The list of chunks (length == parts).
    """
    size = max(1, -(-len(text) // parts))  # ceil
    chunks = [text[i:i + size] for i in range(0, len(text), size)]
    while len(chunks) < parts:
        chunks.append("")
    return chunks[:parts]
