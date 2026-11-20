"""Agent tools: the contained capabilities the LLM may call.

Every tool returns a short string (LLM-friendly). The only networked tool is
``http_request``, which goes through the origin-locked :class:`TargetClient`, so
the agent physically cannot reach anything but the target honeypot.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

from tester.httpclient import ContainmentError, TargetClient

_MAX_BODY = 8000


@dataclass
class Tool:
    """One callable tool exposed to the model."""

    name: str
    description: str
    parameters: dict[str, Any]
    run: Callable[[dict[str, Any]], str]

    def schema(self) -> dict[str, Any]:
        """Return the JSON-schema tool definition.

        Returns:
            A provider-neutral tool spec (name, description, input schema).
        """
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


@dataclass
class ToolBox:
    """The agent's tool set, bound to a target and a note store."""

    target: TargetClient
    notes: list[str] = field(default_factory=list)
    http_calls: int = 0
    blocked_calls: int = 0

    def tools(self) -> list[Tool]:
        """Build the tool list.

        Returns:
            The available tools.
        """
        return [
            Tool("http_request", "Send an HTTP request to the target. Only the target origin is reachable.",
                 {"type": "object", "properties": {
                     "method": {"type": "string", "default": "GET"},
                     "path": {"type": "string", "description": "path or full URL on the target"},
                     "headers": {"type": "object"},
                     "body": {"type": "string"}},
                  "required": ["path"]}, self._http),
            Tool("transform", "Encode or decode text (base64/hex/url).",
                 {"type": "object", "properties": {
                     "text": {"type": "string"}, "op": {"type": "string", "enum": ["encode", "decode"]},
                     "codec": {"type": "string", "enum": ["base64", "hex", "url"]}},
                  "required": ["text", "op", "codec"]}, self._transform),
            Tool("hash", "Hash text with sha256 or md5.",
                 {"type": "object", "properties": {
                     "text": {"type": "string"}, "algo": {"type": "string", "enum": ["sha256", "md5"]}},
                  "required": ["text"]}, self._hash),
            Tool("crack_zip", "Fetch a zip from a target path and try candidate passwords.",
                 {"type": "object", "properties": {
                     "path": {"type": "string"}, "passwords": {"type": "array", "items": {"type": "string"}}},
                  "required": ["path", "passwords"]}, self._crack_zip),
            Tool("note", "Record a short note for your own tracking.",
                 {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}, self._note),
        ]

    # ------------------------------------------------------------------ tool bodies
    def _http(self, args: dict[str, Any]) -> str:
        method = str(args.get("method", "GET")).upper()
        path = str(args.get("path", ""))
        try:
            resp = self.target.request(method, path, headers=args.get("headers") or None,
                                       data=args.get("body"), allow_redirects=False)
        except ContainmentError as exc:
            self.blocked_calls += 1
            return f"BLOCKED: {exc}"
        except Exception as exc:  # network error
            return f"ERROR: {exc}"
        self.http_calls += 1
        body = resp.text[:_MAX_BODY]
        headers = {k: v for k, v in resp.headers.items()
                   if k.lower() in ("content-type", "x-debug-buffer", "x-ratelimit-policy", "retry-after",
                                    "www-authenticate", "location")}
        return f"HTTP {resp.status_code}\nheaders: {headers}\n\n{body}"

    @staticmethod
    def _transform(args: dict[str, Any]) -> str:
        text, op, codec = args["text"], args["op"], args["codec"]
        try:
            if codec == "base64":
                return base64.b64encode(text.encode()).decode() if op == "encode" else base64.b64decode(text).decode("utf-8", "replace")
            if codec == "hex":
                return text.encode().hex() if op == "encode" else bytes.fromhex(text).decode("utf-8", "replace")
            return urllib.parse.quote(text) if op == "encode" else urllib.parse.unquote(text)
        except (binascii.Error, ValueError) as exc:
            return f"ERROR: {exc}"

    @staticmethod
    def _hash(args: dict[str, Any]) -> str:
        algo = args.get("algo", "sha256")
        digest = hashlib.new(algo if algo in ("sha256", "md5") else "sha256")
        digest.update(args["text"].encode())
        return digest.hexdigest()

    def _crack_zip(self, args: dict[str, Any]) -> str:
        import pyzipper

        try:
            resp = self.target.request("GET", args["path"])
        except ContainmentError as exc:
            self.blocked_calls += 1
            return f"BLOCKED: {exc}"
        if resp.status_code != 200:
            return f"could not fetch zip (HTTP {resp.status_code})"
        self.http_calls += 1
        for pw in args.get("passwords", [])[:200]:
            try:
                with pyzipper.AESZipFile(io.BytesIO(resp.content)) as zf:
                    zf.setpassword(pw.encode())
                    names = zf.namelist()
                    zf.read(names[0])  # raises on wrong password
                    return f"CRACKED with '{pw}'. Files: {names}"
            except Exception:
                continue
        return "no candidate password worked"

    def _note(self, args: dict[str, Any]) -> str:
        self.notes.append(str(args.get("text", "")))
        return "noted"

    def execute(self, name: str, args: dict[str, Any]) -> str:
        """Run a tool by name.

        Args:
            name: Tool name.
            args: Tool arguments.

        Returns:
            The tool's string result (or an error string for an unknown tool).
        """
        for tool in self.tools():
            if tool.name == name:
                return tool.run(args)
        return f"ERROR: unknown tool {name}"
