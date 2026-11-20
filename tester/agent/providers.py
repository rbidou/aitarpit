"""LLM provider adapters for the agent runner.

Both providers talk raw HTTP (via ``requests``) so neither the ``openai`` nor the
``anthropic`` package is required, and an OpenAI-compatible ``base_url`` reaches
Ollama / vLLM. A provider converts the runner's normalised transcript into the
provider's wire format and returns a :class:`ProviderResult`.

The transcript entries are:
- ``{"role": "user", "content": str}``
- ``{"role": "assistant", "content": str|None, "tool_calls": [{"id","name","arguments":dict}]}``
- ``{"role": "tool", "tool_call_id": str, "name": str, "content": str}``
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import requests

from tester.agent.tools import Tool

# Rough list prices (USD per 1M tokens) for cost estimation; unknown models -> 0.
_PRICES: dict[str, tuple[float, float]] = {
    "gpt-4o": (2.5, 10.0), "gpt-4o-mini": (0.15, 0.6), "o4-mini": (1.1, 4.4),
    "claude-opus-4-8": (5.0, 25.0), "claude-sonnet-5-5": (3.0, 15.0), "claude-haiku-5-5": (0.8, 4.0),
}


@dataclass
class ProviderResult:
    """One model turn: free text and/or tool calls, plus token usage."""

    text: str | None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost from token counts and the price table.

    Args:
        model: Model name.
        input_tokens: Prompt tokens.
        output_tokens: Completion tokens.

    Returns:
        Estimated cost in USD (0 for unknown models).
    """
    pin, pout = _PRICES.get(model, (0.0, 0.0))
    return (input_tokens * pin + output_tokens * pout) / 1_000_000


class OpenAIProvider:
    """OpenAI-compatible chat-completions provider (also Ollama / vLLM)."""

    def __init__(self, model: str, api_key: str, base_url: str | None = None, timeout: float = 120.0) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.timeout = timeout

    def complete(self, system: str, transcript: list[dict], tools: list[Tool]) -> ProviderResult:
        """Call the chat-completions endpoint and normalise the reply.

        Args:
            system: System prompt.
            transcript: The normalised conversation.
            tools: Available tools.

        Returns:
            The provider result.
        """
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in transcript:
            if m["role"] == "assistant" and m.get("tool_calls"):
                messages.append({"role": "assistant", "content": m.get("content"),
                                 "tool_calls": [{"id": tc["id"], "type": "function",
                                                 "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])}}
                                                for tc in m["tool_calls"]]})
            elif m["role"] == "tool":
                messages.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
            else:
                messages.append({"role": m["role"], "content": m.get("content") or ""})
        payload = {"model": self.model, "messages": messages,
                   "tools": [{"type": "function", "function": t.schema()} for t in tools]}
        resp = requests.post(f"{self.base_url}/chat/completions", json=payload,
                             headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        choice = data["choices"][0]["message"]
        usage = data.get("usage", {})
        calls = [{"id": tc["id"], "name": tc["function"]["name"],
                  "arguments": json.loads(tc["function"].get("arguments") or "{}")}
                 for tc in (choice.get("tool_calls") or [])]
        return ProviderResult(choice.get("content"), calls,
                              usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))


class AnthropicProvider:
    """Anthropic Messages API provider."""

    def __init__(self, model: str, api_key: str, base_url: str | None = None, timeout: float = 120.0) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = (base_url or "https://api.anthropic.com").rstrip("/")
        self.timeout = timeout

    def complete(self, system: str, transcript: list[dict], tools: list[Tool]) -> ProviderResult:
        """Call the Messages endpoint and normalise the reply.

        Args:
            system: System prompt.
            transcript: The normalised conversation.
            tools: Available tools.

        Returns:
            The provider result.
        """
        messages: list[dict[str, Any]] = []
        for m in transcript:
            if m["role"] == "assistant" and m.get("tool_calls"):
                blocks: list[dict[str, Any]] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                blocks += [{"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]}
                           for tc in m["tool_calls"]]
                messages.append({"role": "assistant", "content": blocks})
            elif m["role"] == "tool":
                messages.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}]})
            else:
                messages.append({"role": m["role"], "content": m.get("content") or ""})
        payload = {"model": self.model, "max_tokens": 2048, "system": system, "messages": messages,
                   "tools": [{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools]}
        resp = requests.post(f"{self.base_url}/v1/messages", json=payload,
                             headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                             timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        text_parts, calls = [], []
        for block in data.get("content", []):
            if block["type"] == "text":
                text_parts.append(block["text"])
            elif block["type"] == "tool_use":
                calls.append({"id": block["id"], "name": block["name"], "arguments": block.get("input", {})})
        usage = data.get("usage", {})
        return ProviderResult("\n".join(text_parts) or None, calls,
                              usage.get("input_tokens", 0), usage.get("output_tokens", 0))


def build_provider(provider: str, model: str, api_key_env: str, base_url: str | None) -> Any:
    """Construct a provider from CLI options.

    Args:
        provider: 'openai' or 'anthropic'.
        model: Model name.
        api_key_env: Environment variable holding the API key.
        base_url: Optional base URL override.

    Returns:
        A provider instance.

    Raises:
        ValueError: When the API key env var is unset.
    """
    api_key = os.environ.get(api_key_env, "")
    if not api_key:
        raise ValueError(f"API key env var {api_key_env} is not set")
    if provider == "anthropic":
        return AnthropicProvider(model, api_key, base_url)
    return OpenAIProvider(model, api_key, base_url)
